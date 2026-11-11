import { createHash } from 'node:crypto'
import lockfile from 'proper-lockfile'
import { OAuthTokens, OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { TemporarilyUnavailableError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { deleteConfigFile, describeFsError, ensureConfigDir, getConfigFilePath, readJsonFileStrict, writeJsonFile } from './mcp-auth-config'
import { debugLog, log } from './utils'

/**
 * Refresh-token coordination.
 *
 * The SDK's auth() performs the refresh_token grant itself (refreshAuthorization → fetchFn).
 * Several transports in one process, and several mcp-remote processes (one per host launch /
 * server entry), share one `<hash>_tokens.json`. The server rotates refresh tokens with reuse
 * detection (60s grace), so two refreshes with the same RT — or a later resend of an
 * already-rotated RT — revoke the whole chain and force a browser login. Incident 2026-11-05.
 *
 * Every refresh_token grant therefore goes through `createRefreshCoordinatedFetch`:
 *  1. in-process single-flight per (server hash, RT): one network refresh, result shared; a
 *     caller's abort only detaches that caller;
 *  2. cross-process lock on tokens.json (proper-lockfile: mkdir lock + heartbeat + stale
 *     takeover). Under it tokens.json is RE-READ and, if another process already rotated, its
 *     tokens are used and no refresh is sent. Failing to get the lock, a compromised lock, or an
 *     unreadable tokens.json all fail closed (TemporarilyUnavailableError, nothing sent);
 *  3. invalid_grant deletes tokens.json only if it still holds the RT that was sent;
 *  4. network errors / timeouts / 5xx / non-OAuth bodies are retried with backoff. Every send of
 *     one RT — across all flights in this process — happens within MAX_REFRESH_RETRY_WINDOW_MS of
 *     its first possibly-delivered send (< the 60s server grace). Failures surface as
 *     TemporarilyUnavailableError, which the SDK re-throws instead of opening a browser;
 *  5. the successor is persisted atomically (temp + rename, retried) before anyone uses it.
 *
 * Residual risk: if persisting the successor fails on every retry (disk broken), it is kept in
 * THIS process's memory only — this process will not resend the rotated RT, but other
 * mcp-remote processes still read the rotated RT from disk and may present it after the grace.
 */

export type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>

export interface RefreshFetchOptions {
  /** Max network attempts for one flight (default 3). */
  maxAttempts?: number
  /** Backoff base: retry n waits base * 2^(n-1) (default 500ms). */
  retryBaseDelayMs?: number
  /** Per-attempt timeout, enforced even if fetch ignores its signal (default 10s). */
  attemptTimeoutMs?: number
  /** All sends of one RT happen within this window; capped at MAX_REFRESH_RETRY_WINDOW_MS. */
  retryWindowMs?: number
  /** Lock considered abandoned when its heartbeat is older than this (default 30s, min 2s). */
  lockStaleMs?: number
  /** Lock heartbeat interval (default 5s, min 1s). */
  lockUpdateMs?: number
  /** Max total time to wait for a contended lock (default 55s). */
  lockWaitMs?: number
}

/** Server grace for re-presenting a just-rotated RT is 60s; keep every resend well inside it. */
export const MAX_REFRESH_RETRY_WINDOW_MS = 45_000

const DEFAULTS: Required<RefreshFetchOptions> = {
  maxAttempts: 3,
  retryBaseDelayMs: 500,
  attemptTimeoutMs: 10_000,
  retryWindowMs: MAX_REFRESH_RETRY_WINDOW_MS,
  lockStaleMs: 30_000,
  lockUpdateMs: 5_000,
  lockWaitMs: 55_000,
}

function withDefaults(options: RefreshFetchOptions): Required<RefreshFetchOptions> {
  const defined = Object.fromEntries(Object.entries(options).filter(([, value]) => value !== undefined))
  return { ...DEFAULTS, ...defined }
}

/** The effective window within which every send of one RT starts and finishes. */
export function refreshRetryWindowMs(options: RefreshFetchOptions): number {
  return Math.min(withDefaults(options).retryWindowMs, MAX_REFRESH_RETRY_WINDOW_MS)
}

const PERSIST_ATTEMPTS = 3
const MAX_TRACKED_WINDOWS = 1_000

/** OAuth error codes that mean "try again later", not "your grant is bad". */
const TRANSIENT_OAUTH_ERRORS = new Set(['server_error', 'temporarily_unavailable'])
/** Errors raised before the request could have reached the server. */
const NOT_DELIVERED_CODES = new Set(['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH', 'UND_ERR_CONNECT_TIMEOUT'])

interface ResponseSnapshot {
  status: number
  statusText: string
  headers: [string, string][]
  body: string
}

// Process-wide state.
const inFlight = new Map<string, Promise<ResponseSnapshot>>() // `${hash}\0${sha(rt)}`
const rtWindowOpenedAt = new Map<string, number>() // `${hash}\0${sha(rt)}` → first possibly-delivered send
const lastCoordinated = new Map<string, OAuthTokens>() // hash → tokens last persisted/adopted
const rejectedRefreshTokens = new Map<string, string>() // hash → RT rejected with invalid_grant
const unpersisted = new Map<string, { tokens: OAuthTokens; predecessor: string }>() // hash → successor

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const sha = (value: string) => createHash('sha256').update(value).digest('hex')

function toResponse(snapshot: ResponseSnapshot): Response {
  return new Response(snapshot.body, {
    status: snapshot.status,
    statusText: snapshot.statusText,
    headers: snapshot.headers,
  })
}

function tokensSnapshot(serverUrlHash: string, tokens: OAuthTokens): ResponseSnapshot {
  lastCoordinated.set(serverUrlHash, tokens)
  return {
    status: 200,
    statusText: 'OK',
    headers: [['content-type', 'application/json']],
    body: JSON.stringify(tokens),
  }
}

/** Strict tokens.json read: undefined only if missing; otherwise throws a sanitized error. */
export async function readTokensStrict(serverUrlHash: string): Promise<OAuthTokens | undefined> {
  return readJsonFileStrict<OAuthTokens>(serverUrlHash, 'tokens.json', OAuthTokensSchema)
}

/** Strict read that maps "unreadable" to TemporarilyUnavailableError (never "missing"). */
export async function readTokensOrUnavailable(serverUrlHash: string): Promise<OAuthTokens | undefined> {
  try {
    return await readTokensStrict(serverUrlHash)
  } catch (error) {
    log(`tokens.json is unreadable (${describeFsError(error)}); not using, refreshing or deleting it.`)
    throw new TemporarilyUnavailableError('tokens.json is unreadable')
  }
}

// ---------------------------------------------------------------------------------------------
// Cross-process lock: proper-lockfile on the tokens.json path (lock dir `<tokens.json>.lock`).
// ---------------------------------------------------------------------------------------------

function lockRetries(waitMs: number) {
  const minTimeout = 50
  const maxTimeout = 1_000
  let retries = 0
  let total = 0
  for (let delay = minTimeout; ; delay = Math.min(delay * 2, maxTimeout)) {
    if (total + delay > waitMs) break
    total += delay
    retries++
  }
  return { retries, minTimeout, maxTimeout, factor: 2, randomize: false }
}

export interface TokensLockOptions extends Pick<RefreshFetchOptions, 'lockStaleMs' | 'lockUpdateMs' | 'lockWaitMs'> {
  /**
   * What to do when the lock cannot be acquired. 'fail' (default) throws
   * TemporarilyUnavailableError. 'run-unlocked' runs `fn` anyway — only for writes whose loss is
   * worse than a race (persisting a fresh browser-login result).
   */
  onUnavailable?: 'fail' | 'run-unlocked'
}

/**
 * Runs `fn` while holding the cross-process tokens lock for `serverUrlHash`. `fn` receives a
 * signal that aborts if the lock is compromised (heartbeat lost); the call then rejects with
 * TemporarilyUnavailableError instead of proper-lockfile's default throw-in-a-timer.
 */
export async function withTokensLock<T>(
  serverUrlHash: string,
  fn: (signal: AbortSignal) => Promise<T>,
  options: TokensLockOptions = {},
): Promise<T> {
  const opts = withDefaults(options)
  const controller = new AbortController()
  let rejectCompromised: (error: Error) => void = () => {}
  const compromised = new Promise<never>((_, reject) => {
    rejectCompromised = reject
  })
  compromised.catch(() => {})

  let release: (() => Promise<void>) | undefined
  try {
    await ensureConfigDir()
    release = await lockfile.lock(getConfigFilePath(serverUrlHash, 'tokens.json'), {
      realpath: false,
      stale: opts.lockStaleMs,
      update: opts.lockUpdateMs,
      retries: lockRetries(opts.lockWaitMs),
      onCompromised: (error) => {
        log(`tokens lock compromised (${describeFsError(error)}); aborting the locked operation.`)
        const reason = new TemporarilyUnavailableError('tokens lock was compromised')
        controller.abort(reason)
        rejectCompromised(reason)
      },
    })
  } catch (error) {
    if (options.onUnavailable === 'run-unlocked') {
      log(`Could not lock tokens.json (${describeFsError(error)}); writing without the lock.`)
      return fn(controller.signal)
    }
    log(`Could not lock tokens.json (${describeFsError(error)}).`)
    throw new TemporarilyUnavailableError('tokens.json is locked by another mcp-remote process')
  }

  try {
    return await Promise.race([fn(controller.signal), compromised])
  } finally {
    if (!controller.signal.aborted) {
      await release().catch((error) => log(`Could not release tokens lock (${describeFsError(error)})`))
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------------------------

function refreshTokenOf(init?: RequestInit): string | undefined {
  if (!init || (init.method ?? 'GET').toUpperCase() !== 'POST') return undefined
  const body = init.body
  let params: URLSearchParams | undefined
  if (body instanceof URLSearchParams) params = body
  else if (typeof body === 'string') params = new URLSearchParams(body)
  if (!params || params.get('grant_type') !== 'refresh_token') return undefined
  return params.get('refresh_token') ?? undefined
}

async function snapshot(response: Response): Promise<ResponseSnapshot> {
  const headers: [string, string][] = []
  response.headers.forEach((value, key) => headers.push([key, value]))
  return {
    status: response.status,
    statusText: response.statusText,
    headers,
    body: await response.text(),
  }
}

function oauthErrorCode(snap: ResponseSnapshot): string | undefined {
  try {
    const parsed = JSON.parse(snap.body)
    return typeof parsed?.error === 'string' ? parsed.error : undefined
  } catch {
    return undefined
  }
}

function wasNeverDelivered(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 4; depth++) {
    if (typeof current.code === 'string' && NOT_DELIVERED_CODES.has(current.code)) return true
    current = current.cause
  }
  return false
}

type Attempt = { kind: 'ok'; tokens: OAuthTokens } | { kind: 'definitive'; snap: ResponseSnapshot }

/**
 * One network round-trip, classified. Throws (with a message that never quotes the body) for
 * transient outcomes. The timeout is enforced by racing, so a fetch that ignores its signal
 * cannot hang the refresh; a compromised lock aborts it too.
 */
async function attemptRefresh(
  baseFetch: FetchLike,
  url: string | URL,
  init: RequestInit,
  sentRefreshToken: string,
  timeoutMs: number,
  lockSignal: AbortSignal,
): Promise<Attempt> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const onLockLost = () => controller.abort(lockSignal.reason)
  lockSignal.addEventListener('abort', onLockLost, { once: true })
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`token refresh timed out after ${timeoutMs}ms`)
      controller.abort(error)
      reject(error)
    }, timeoutMs)
  })
  const work = (async (): Promise<Attempt> => {
    const response = await baseFetch(url, { ...init, signal: controller.signal })
    const snap = await snapshot(response)
    if (response.ok) {
      let body: unknown
      try {
        body = JSON.parse(snap.body)
      } catch {
        throw new Error(`token endpoint returned ${response.status} with a non-JSON body`)
      }
      const parsed = OAuthTokensSchema.safeParse(body)
      if (!parsed.success) throw new Error(`token endpoint returned ${response.status} without valid tokens`)
      // Same as the SDK: keep the sent RT if the server did not return a new one.
      return { kind: 'ok', tokens: { refresh_token: sentRefreshToken, ...parsed.data } }
    }
    const code = oauthErrorCode(snap)
    if (response.status >= 500 || response.status === 429 || !code || TRANSIENT_OAUTH_ERRORS.has(code)) {
      throw new Error(`token endpoint transient failure: HTTP ${response.status}${code ? ` (${code})` : ''}`)
    }
    return { kind: 'definitive', snap }
  })()
  work.catch(() => {}) // the race may abandon it
  try {
    return await Promise.race([work, timeout])
  } finally {
    clearTimeout(timer)
    lockSignal.removeEventListener('abort', onLockLost)
  }
}

/** Atomic write, retried (Windows EPERM/EBUSY on rename, transient I/O). */
async function persistTokens(
  serverUrlHash: string,
  tokens: OAuthTokens,
  predecessor: string,
  opts: Required<RefreshFetchOptions>,
): Promise<void> {
  let lastError: unknown
  for (let attempt = 1; attempt <= PERSIST_ATTEMPTS; attempt++) {
    try {
      await writeJsonFile(serverUrlHash, 'tokens.json', tokens)
      unpersisted.delete(serverUrlHash)
      rejectedRefreshTokens.delete(serverUrlHash)
      return
    } catch (error) {
      lastError = error
      if (attempt < PERSIST_ATTEMPTS) await sleep(opts.retryBaseDelayMs * 2 ** (attempt - 1))
    }
  }
  // In-memory fallback (this process only — see the residual-risk note at the top): tokens()
  // serves the successor and the next refresh in this process retries the write first.
  unpersisted.set(serverUrlHash, { tokens, predecessor })
  lastCoordinated.set(serverUrlHash, tokens)
  log(`Could not persist refreshed tokens (${describeFsError(lastError)}); keeping them in memory.`)
  throw new TemporarilyUnavailableError('Refreshed tokens could not be persisted to disk')
}

function openRetryWindow(rtKey: string, now: number): boolean {
  if (rtWindowOpenedAt.has(rtKey)) return false
  if (rtWindowOpenedAt.size >= MAX_TRACKED_WINDOWS) {
    const oldest = rtWindowOpenedAt.keys().next().value
    if (oldest !== undefined) rtWindowOpenedAt.delete(oldest)
  }
  rtWindowOpenedAt.set(rtKey, now)
  return true
}

async function coordinatedRefresh(
  serverUrlHash: string,
  baseFetch: FetchLike,
  url: string | URL,
  init: RequestInit,
  sentRefreshToken: string,
  opts: Required<RefreshFetchOptions>,
): Promise<ResponseSnapshot> {
  return withTokensLock(
    serverUrlHash,
    async (lockSignal) => {
      let onDisk = await readTokensOrUnavailable(serverUrlHash)

      // A successor obtained earlier by this process but not yet persisted: persist it now and
      // treat it as current (unless something newer landed on disk meanwhile).
      const pending = unpersisted.get(serverUrlHash)
      if (pending) {
        if (!onDisk?.refresh_token || onDisk.refresh_token === pending.predecessor) {
          await persistTokens(serverUrlHash, pending.tokens, pending.predecessor, opts)
          onDisk = pending.tokens
        } else {
          unpersisted.delete(serverUrlHash)
        }
      }

      // Re-read under the lock: a sibling may already have rotated this RT.
      if (onDisk?.refresh_token && onDisk.refresh_token !== sentRefreshToken) {
        log('Tokens were already refreshed by another mcp-remote process; reusing them (no refresh sent).')
        return tokensSnapshot(serverUrlHash, onDisk)
      }

      const windowMs = refreshRetryWindowMs(opts)
      const rtKey = `${serverUrlHash}\0${sha(sentRefreshToken)}`
      let lastError: unknown
      for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
        if (lockSignal.aborted) throw lockSignal.reason
        const now = Date.now()
        // Process-wide: every send of this RT starts and finishes inside the window opened by its
        // first possibly-delivered send, whichever flight made it (server grace is 60s).
        const openedAt = rtWindowOpenedAt.get(rtKey)
        const remaining = openedAt === undefined ? windowMs : openedAt + windowMs - now
        if (remaining <= 0) {
          lastError ??= new Error('retry window for this refresh token has closed')
          break
        }
        const openedHere = openRetryWindow(rtKey, now)
        let result: Attempt
        try {
          result = await attemptRefresh(baseFetch, url, init, sentRefreshToken, Math.min(opts.attemptTimeoutMs, remaining), lockSignal)
        } catch (error) {
          if (lockSignal.aborted) throw lockSignal.reason
          lastError = error
          // The request never left this machine: the server cannot have seen this RT yet.
          if (openedHere && wasNeverDelivered(error)) rtWindowOpenedAt.delete(rtKey)
          debugLog(`Token refresh attempt ${attempt}/${opts.maxAttempts} failed transiently`, {
            error: (error as Error)?.message,
          })
          if (attempt < opts.maxAttempts) {
            const delay = opts.retryBaseDelayMs * 2 ** (attempt - 1)
            const opened = rtWindowOpenedAt.get(rtKey)
            if (opened !== undefined && Date.now() + delay >= opened + windowMs) break
            await sleep(delay)
          }
          continue
        }

        if (result.kind === 'ok') {
          // Persist (atomically) before anyone gets to use the successor.
          await persistTokens(serverUrlHash, result.tokens, sentRefreshToken, opts)
          return tokensSnapshot(serverUrlHash, result.tokens)
        }

        if (oauthErrorCode(result.snap) === 'invalid_grant') {
          const current = await readTokensOrUnavailable(serverUrlHash)
          if (current?.refresh_token && current.refresh_token !== sentRefreshToken) {
            log('Refresh rejected (invalid_grant) but tokens.json holds newer tokens; keeping and using them.')
            return tokensSnapshot(serverUrlHash, current)
          }
          log('Refresh token rejected (invalid_grant) and still current on disk; clearing tokens.')
          rejectedRefreshTokens.set(serverUrlHash, sentRefreshToken)
          await deleteConfigFile(serverUrlHash, 'tokens.json')
        }
        // Definitive OAuth error: hand the original response back to the SDK.
        return result.snap
      }

      log('Token refresh failed transiently; keeping tokens, not opening a browser.')
      throw new TemporarilyUnavailableError(
        `Token refresh temporarily failed: ${(lastError as Error)?.message ?? 'retry window exhausted'}`,
      )
    },
    opts,
  )
}

function detachOnAbort<T>(promise: Promise<T>, signal: AbortSignal | null | undefined): Promise<T> {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error('aborted'))
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new Error('aborted'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      (error) => {
        signal.removeEventListener('abort', onAbort)
        reject(error)
      },
    )
  })
}

/**
 * Wraps `baseFetch` so every refresh_token grant is single-flighted per (server, RT), serialized
 * across processes, and retried on transient failures. All other requests pass through.
 */
export function createRefreshCoordinatedFetch(serverUrlHash: string, baseFetch: FetchLike, options: RefreshFetchOptions = {}): FetchLike {
  const opts = withDefaults(options)
  return async (url, init) => {
    const sentRefreshToken = refreshTokenOf(init)
    if (!sentRefreshToken || !init) return baseFetch(url, init)

    const flightKey = `${serverUrlHash}\0${sha(sentRefreshToken)}`
    let shared = inFlight.get(flightKey)
    if (shared) {
      debugLog('Joining in-flight token refresh (single-flight)')
    } else {
      // The shared flight must not inherit any one caller's signal.
      const { signal: _callerSignal, ...flightInit } = init
      shared = coordinatedRefresh(serverUrlHash, baseFetch, url, flightInit, sentRefreshToken, opts).finally(() => {
        inFlight.delete(flightKey)
      })
      shared.catch(() => {}) // every caller may have detached
      inFlight.set(flightKey, shared)
    }
    return toResponse(await detachOnAbort(shared, init.signal))
  }
}

/**
 * True when `tokens` is exactly what the coordinator last persisted (or adopted from disk) for
 * this server. The SDK echoes those tokens into provider.saveTokens() *after* the lock was
 * released; re-writing them could clobber a newer rotation by a sibling, so the echo is skipped.
 */
export function isCoordinatorPersisted(serverUrlHash: string, tokens: OAuthTokens): boolean {
  const last = lastCoordinated.get(serverUrlHash)
  return !!last && last.access_token === tokens.access_token && last.refresh_token === tokens.refresh_token
}

/** The refresh token the server most recently rejected (invalid_grant) for this server, if any. */
export function rejectedRefreshTokenFor(serverUrlHash: string): string | undefined {
  return rejectedRefreshTokens.get(serverUrlHash)
}

/** Forget a rejection once fresh tokens were saved by another path (e.g. browser login). */
export function clearRejectedRefreshToken(serverUrlHash: string): void {
  rejectedRefreshTokens.delete(serverUrlHash)
}

/**
 * This process's not-yet-persisted successor, if `onDisk` still holds its rotated predecessor —
 * callers in this process use it instead of the on-disk tokens.
 */
export function unpersistedSuccessorFor(serverUrlHash: string, onDisk: OAuthTokens | undefined): OAuthTokens | undefined {
  const pending = unpersisted.get(serverUrlHash)
  if (!pending) return undefined
  if (onDisk?.refresh_token && onDisk.refresh_token !== pending.predecessor) return undefined
  return pending.tokens
}
