import fs from 'fs/promises'
import { randomUUID } from 'node:crypto'
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
 *  1. in-process single-flight per server hash (one network refresh, result shared; a caller's
 *     abort only detaches that caller);
 *  2. cross-process lock next to tokens.json; under it tokens.json is RE-READ and, if another
 *     process already rotated, its tokens are used and no refresh is sent. An unreadable
 *     tokens.json blocks the refresh (never treated as "missing");
 *  3. invalid_grant deletes tokens.json only if it still holds the RT that was sent;
 *  4. network errors / timeouts / 5xx / non-OAuth bodies are retried with backoff, all resends of
 *     one RT inside MAX_REFRESH_RETRY_WINDOW_MS (< the 60s server grace), and finally surface as
 *     TemporarilyUnavailableError, which the SDK re-throws instead of opening a browser;
 *  5. the successor is persisted atomically (temp + rename, retried) before anyone uses it; if it
 *     cannot be persisted it is kept in memory so the rotated RT is never sent again.
 */

export type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>

export interface RefreshFetchOptions {
  /** Max network attempts for one refresh (default 3). */
  maxAttempts?: number
  /** Backoff base: retry n waits base * 2^(n-1) (default 500ms). */
  retryBaseDelayMs?: number
  /** Per-attempt timeout, enforced even if fetch ignores its signal (default 10s). */
  attemptTimeoutMs?: number
  /** All sends of one RT happen within this window; capped at MAX_REFRESH_RETRY_WINDOW_MS. */
  retryWindowMs?: number
  /** A lock older than this is considered abandoned (default 60s). */
  lockStaleMs?: number
}

/** Server grace for re-presenting a just-rotated RT is 60s; keep every resend well inside it. */
export const MAX_REFRESH_RETRY_WINDOW_MS = 45_000

const DEFAULTS: Required<RefreshFetchOptions> = {
  maxAttempts: 3,
  retryBaseDelayMs: 500,
  attemptTimeoutMs: 10_000,
  retryWindowMs: MAX_REFRESH_RETRY_WINDOW_MS,
  lockStaleMs: 60_000,
}

/** The effective window within which every send of one RT starts and finishes. */
export function refreshRetryWindowMs(options: RefreshFetchOptions): number {
  return Math.min(options.retryWindowMs ?? DEFAULTS.retryWindowMs, MAX_REFRESH_RETRY_WINDOW_MS)
}

const LOCK_FILENAME = 'tokens.json.lock'
const LOCK_POLL_MS = 50
const BREAK_TOKEN_STALE_MS = 10_000
const PERSIST_ATTEMPTS = 3

/** OAuth error codes that mean "try again later", not "your grant is bad". */
const TRANSIENT_OAUTH_ERRORS = new Set(['server_error', 'temporarily_unavailable'])

interface ResponseSnapshot {
  status: number
  statusText: string
  headers: [string, string][]
  body: string
}

// Per-server-hash state, shared by every provider / transport in this process.
const inFlight = new Map<string, Promise<ResponseSnapshot>>()
const lastCoordinated = new Map<string, OAuthTokens>()
const rejectedRefreshTokens = new Map<string, string>()
const unpersisted = new Map<string, { tokens: OAuthTokens; predecessor: string }>()

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const errCode = (error: unknown) => (error as NodeJS.ErrnoException | undefined)?.code

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

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    // EPERM: the process exists but belongs to someone else.
    return errCode(error) === 'EPERM'
  }
}

/** Reads tokens.json; undefined only if missing. Unreadable → TemporarilyUnavailableError. */
async function readTokensUnderLock(serverUrlHash: string): Promise<OAuthTokens | undefined> {
  try {
    return await readJsonFileStrict<OAuthTokens>(serverUrlHash, 'tokens.json', OAuthTokensSchema)
  } catch (error) {
    log(`tokens.json is unreadable (${describeFsError(error)}); not refreshing and not deleting it.`)
    throw new TemporarilyUnavailableError('tokens.json is unreadable; refusing to refresh')
  }
}

// ---------------------------------------------------------------------------------------------
// Cross-process lock
//
// Acquire: the lock content is written to a private temp file first and then published with
// link(temp, lock) — atomic and exclusive (EEXIST if held), and the lock is never visible
// half-written. A lock instance is identified by dev+ino+mtime.
//
// Remove (release, or breaking a stale lock): exclusive per-instance break token
// `<lock>.<id>.break` (O_EXCL). Every removal of instance <id> happens under that token after
// re-checking that the lock is still <id>; the lock cannot become a different instance without
// being removed first, so check-then-unlink cannot hit somebody else's lock.
// ---------------------------------------------------------------------------------------------

async function lockInstanceId(filePath: string): Promise<string | undefined> {
  try {
    const st = await fs.stat(filePath, { bigint: true })
    return `${st.dev}-${st.ino}-${st.mtimeNs}`
  } catch (error) {
    if (errCode(error) === 'ENOENT') return undefined
    throw error
  }
}

async function isLockStale(lockPath: string, staleMs: number): Promise<boolean> {
  let data: { pid?: unknown; timestamp?: unknown } | undefined
  try {
    data = JSON.parse(await fs.readFile(lockPath, 'utf-8'))
  } catch (error) {
    if (errCode(error) === 'ENOENT') return false
    data = undefined
  }
  if (data && typeof data.pid === 'number' && typeof data.timestamp === 'number') {
    return !isPidAlive(data.pid) || Date.now() - data.timestamp > staleMs
  }
  // Empty / unparseable / foreign lock: judge by mtime only.
  try {
    const st = await fs.stat(lockPath)
    return Date.now() - st.mtimeMs > staleMs
  } catch {
    return false
  }
}

/** Removes the lock iff it is still instance `id`. Returns without effect if someone else is on it. */
async function removeLockInstance(lockPath: string, id: string): Promise<void> {
  const token = `${lockPath}.${id}.break`
  try {
    await fs.writeFile(token, String(process.pid), { flag: 'wx', mode: 0o600 })
  } catch (error) {
    if (errCode(error) !== 'EEXIST') {
      await fs.unlink(token).catch(() => {})
      throw error
    }
    // Another process is removing this exact instance — or crashed doing so long ago.
    const st = await fs.stat(token).catch(() => undefined)
    if (st && Date.now() - st.mtimeMs > BREAK_TOKEN_STALE_MS) await fs.unlink(token).catch(() => {})
    return
  }
  try {
    if ((await lockInstanceId(lockPath)) === id) await fs.unlink(lockPath)
  } finally {
    await fs.unlink(token).catch(() => {})
  }
}

/**
 * Runs `fn` while holding the cross-process tokens lock for `serverUrlHash`.
 * Stale locks (dead owner PID, older than `lockStaleMs`, or unreadable with an old mtime) are broken.
 */
export async function withTokensLock<T>(
  serverUrlHash: string,
  fn: () => Promise<T>,
  options: Pick<RefreshFetchOptions, 'lockStaleMs'> = {},
): Promise<T> {
  const staleMs = options.lockStaleMs ?? DEFAULTS.lockStaleMs
  await ensureConfigDir()
  const lockPath = getConfigFilePath(serverUrlHash, LOCK_FILENAME)
  const tmpPath = `${lockPath}.${randomUUID()}.tmp`
  let myId: string | undefined

  try {
    try {
      await fs.writeFile(tmpPath, JSON.stringify({ pid: process.pid, timestamp: Date.now() }), {
        flag: 'wx',
        mode: 0o600,
      })
      myId = await lockInstanceId(tmpPath)
    } catch (error) {
      // Cannot create a lock at all (disk full, permissions) — not contention. Degrade to
      // unlocked rather than breaking auth; in-process single-flight still applies.
      log(`Could not create tokens lock (${describeFsError(error)}); continuing without cross-process lock.`)
      await fs.unlink(tmpPath).catch(() => {})
      return await fn()
    }

    const deadline = Date.now() + staleMs * 2
    for (;;) {
      try {
        await fs.link(tmpPath, lockPath)
        break
      } catch (error) {
        if (errCode(error) !== 'EEXIST') {
          log(`Could not publish tokens lock (${describeFsError(error)}); continuing without cross-process lock.`)
          myId = undefined
          return await fn()
        }
      }
      const heldId = await lockInstanceId(lockPath)
      if (!heldId) continue
      if (await isLockStale(lockPath, staleMs)) {
        debugLog('Breaking stale tokens lock', { lockPath })
        await removeLockInstance(lockPath, heldId)
        continue
      }
      if (Date.now() > deadline) {
        throw new TemporarilyUnavailableError('Timed out waiting for the tokens lock held by another mcp-remote process')
      }
      await sleep(LOCK_POLL_MS)
    }
    await fs.unlink(tmpPath).catch(() => {})

    return await fn()
  } finally {
    await fs.unlink(tmpPath).catch(() => {})
    if (myId) {
      await removeLockInstance(lockPath, myId).catch((error) => {
        log(`Could not release tokens lock (${describeFsError(error)})`)
      })
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

type Attempt = { kind: 'ok'; tokens: OAuthTokens } | { kind: 'definitive'; snap: ResponseSnapshot }

/**
 * One network round-trip, classified. Throws (with a message that never quotes the body) for
 * transient outcomes. The timeout is enforced by racing, so a fetch that ignores its signal
 * cannot hang the refresh.
 */
async function attemptRefresh(
  baseFetch: FetchLike,
  url: string | URL,
  init: RequestInit,
  sentRefreshToken: string,
  timeoutMs: number,
): Promise<Attempt> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
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
  // Keep the successor in memory: the predecessor is rotated server-side and must never be
  // sent again from this process. tokens() serves it; the next refresh retries the write.
  unpersisted.set(serverUrlHash, { tokens, predecessor })
  lastCoordinated.set(serverUrlHash, tokens)
  log(`Could not persist refreshed tokens (${describeFsError(lastError)}); keeping them in memory.`)
  throw new TemporarilyUnavailableError('Refreshed tokens could not be persisted to disk')
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
    async () => {
      let onDisk = await readTokensUnderLock(serverUrlHash)

      // A successor we obtained earlier but failed to persist: persist it now and treat it as
      // the current tokens (as long as nothing newer landed on disk meanwhile).
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
      let firstSendAt: number | undefined
      let lastError: unknown
      for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
        const now = Date.now()
        // Every send of this RT must start and finish inside the window (server grace is 60s).
        const remaining = firstSendAt === undefined ? windowMs : firstSendAt + windowMs - now
        if (remaining <= 0) break
        firstSendAt ??= now
        let result: Attempt
        try {
          result = await attemptRefresh(baseFetch, url, init, sentRefreshToken, Math.min(opts.attemptTimeoutMs, remaining))
        } catch (error) {
          lastError = error
          debugLog(`Token refresh attempt ${attempt}/${opts.maxAttempts} failed transiently`, {
            error: (error as Error)?.message,
          })
          if (attempt < opts.maxAttempts) {
            const delay = opts.retryBaseDelayMs * 2 ** (attempt - 1)
            if (Date.now() + delay >= firstSendAt + windowMs) break
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
          const current = await readTokensUnderLock(serverUrlHash)
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
 * Wraps `baseFetch` so every refresh_token grant is single-flighted per server, serialized
 * across processes, and retried on transient failures. All other requests pass through.
 */
export function createRefreshCoordinatedFetch(serverUrlHash: string, baseFetch: FetchLike, options: RefreshFetchOptions = {}): FetchLike {
  const opts: Required<RefreshFetchOptions> = { ...DEFAULTS, ...options }
  return async (url, init) => {
    const sentRefreshToken = refreshTokenOf(init)
    if (!sentRefreshToken || !init) return baseFetch(url, init)

    let shared = inFlight.get(serverUrlHash)
    if (shared) {
      debugLog('Joining in-flight token refresh (single-flight)')
    } else {
      // The shared flight must not inherit any one caller's signal.
      const { signal: _callerSignal, ...flightInit } = init
      shared = coordinatedRefresh(serverUrlHash, baseFetch, url, flightInit, sentRefreshToken, opts).finally(() => {
        inFlight.delete(serverUrlHash)
      })
      shared.catch(() => {}) // every caller may have detached
      inFlight.set(serverUrlHash, shared)
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
 * A successor that could not be persisted yet, if `onDisk` still holds its (rotated)
 * predecessor — callers must use it instead of the on-disk tokens.
 */
export function unpersistedSuccessorFor(serverUrlHash: string, onDisk: OAuthTokens | undefined): OAuthTokens | undefined {
  const pending = unpersisted.get(serverUrlHash)
  if (!pending) return undefined
  if (onDisk?.refresh_token && onDisk.refresh_token !== pending.predecessor) return undefined
  return pending.tokens
}

/** Strict tokens.json read for callers that must not confuse "unreadable" with "missing". */
export async function readTokensStrict(serverUrlHash: string): Promise<OAuthTokens | undefined> {
  return readJsonFileStrict<OAuthTokens>(serverUrlHash, 'tokens.json', OAuthTokensSchema)
}
