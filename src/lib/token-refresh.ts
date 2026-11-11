import fs from 'fs/promises'
import { randomUUID } from 'node:crypto'
import { OAuthTokens, OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { TemporarilyUnavailableError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { deleteConfigFile, ensureConfigDir, getConfigFilePath, readJsonFile, writeJsonFile } from './mcp-auth-config'
import { debugLog, log } from './utils'

/**
 * Refresh-token coordination.
 *
 * The SDK's auth() performs the refresh_token grant itself (refreshAuthorization → fetchFn).
 * Several transports in one process, and several mcp-remote processes (one per host launch /
 * server entry), share one `<hash>_tokens.json`. The server rotates refresh tokens with reuse
 * detection, so two refreshes with the same RT — or a later resend of an already-rotated RT —
 * revoke the whole chain and force a browser login. Incident 2026-11-05.
 *
 * Every refresh_token grant therefore goes through `refreshCoordinatedFetch`:
 *  1. in-process single-flight per server hash (one network refresh, result shared);
 *  2. cross-process O_EXCL lock next to tokens.json; under it tokens.json is RE-READ and, if
 *     another process already rotated, its tokens are used and no refresh is sent;
 *  3. invalid_grant deletes tokens.json only if it still holds the RT that was sent;
 *  4. network errors / timeouts / 5xx / non-OAuth bodies are retried with backoff and finally
 *     surface as TemporarilyUnavailableError, which the SDK re-throws instead of opening a browser;
 *  5. the successor is persisted atomically (temp + rename) before anyone uses it.
 */

export type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>

export interface RefreshFetchOptions {
  /** Total network attempts for one refresh (default 3). */
  maxAttempts?: number
  /** Backoff base: attempt n waits base * 2^(n-1) (default 500ms). */
  retryBaseDelayMs?: number
  /** Per-attempt timeout (default 10s). */
  attemptTimeoutMs?: number
  /** A lock older than this is considered abandoned (default 60s). */
  lockStaleMs?: number
}

export interface RefreshCoordinatorHooks {
  /** Called when the server definitively rejected `refreshToken` (invalid_grant). */
  onRefreshTokenRejected?: (refreshToken: string) => void
}

const DEFAULTS: Required<RefreshFetchOptions> = {
  maxAttempts: 3,
  retryBaseDelayMs: 500,
  attemptTimeoutMs: 10_000,
  lockStaleMs: 60_000,
}

const LOCK_FILENAME = 'tokens.json.lock'
const LOCK_POLL_MS = 50

/** OAuth error codes that mean "try again later", not "your grant is bad". */
const TRANSIENT_OAUTH_ERRORS = new Set(['server_error', 'temporarily_unavailable'])

interface ResponseSnapshot {
  status: number
  statusText: string
  headers: [string, string][]
  body: string
}

const inFlight = new Map<string, Promise<ResponseSnapshot>>()
const lastCoordinated = new Map<string, OAuthTokens>()

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

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
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

async function readPersistedTokens(serverUrlHash: string): Promise<OAuthTokens | undefined> {
  return readJsonFile<OAuthTokens>(serverUrlHash, 'tokens.json', OAuthTokensSchema)
}

/**
 * Runs `fn` while holding the cross-process tokens lock for `serverUrlHash`.
 * Stale locks (dead owner PID or older than `lockStaleMs`) are broken.
 */
export async function withTokensLock<T>(
  serverUrlHash: string,
  fn: () => Promise<T>,
  options: Pick<RefreshFetchOptions, 'lockStaleMs'> = {},
): Promise<T> {
  const staleMs = options.lockStaleMs ?? DEFAULTS.lockStaleMs
  await ensureConfigDir()
  const lockPath = getConfigFilePath(serverUrlHash, LOCK_FILENAME)
  const owner = randomUUID()
  const deadline = Date.now() + staleMs * 2

  for (;;) {
    try {
      const handle = await fs.open(lockPath, 'wx', 0o600)
      try {
        await handle.writeFile(JSON.stringify({ pid: process.pid, timestamp: Date.now(), owner }))
      } finally {
        await handle.close()
      }
      break
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        // Lock cannot be created at all (not contention): degrade to unlocked rather than
        // breaking auth entirely. In-process single-flight still applies.
        log('Could not create tokens lock; continuing without cross-process lock:', error)
        return fn()
      }
    }

    let stale = false
    try {
      const raw = JSON.parse(await fs.readFile(lockPath, 'utf-8'))
      const age = Date.now() - Number(raw?.timestamp)
      stale = !isPidAlive(Number(raw?.pid)) || !Number.isFinite(age) || age > staleMs
    } catch (error) {
      // Vanished between open and read → just retry. Unparseable (owner mid-write) → wait.
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue
    }
    if (stale) {
      debugLog('Breaking stale tokens lock', { lockPath })
      await fs.unlink(lockPath).catch(() => {})
      continue
    }
    if (Date.now() > deadline) {
      throw new TemporarilyUnavailableError('Timed out waiting for the tokens lock held by another mcp-remote process')
    }
    await sleep(LOCK_POLL_MS)
  }

  try {
    return await fn()
  } finally {
    try {
      const raw = JSON.parse(await fs.readFile(lockPath, 'utf-8'))
      if (raw?.owner === owner) await fs.unlink(lockPath)
    } catch {
      // Already gone (broken as stale by someone else) — nothing to release.
    }
  }
}

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

type Attempt = { kind: 'ok'; tokens: OAuthTokens; snap: ResponseSnapshot } | { kind: 'definitive'; snap: ResponseSnapshot }

/** One network round-trip, classified. Throws for transient outcomes. */
async function attemptRefresh(
  baseFetch: FetchLike,
  url: string | URL,
  init: RequestInit,
  sentRefreshToken: string,
  timeoutMs: number,
): Promise<Attempt> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error(`token refresh timed out after ${timeoutMs}ms`)), timeoutMs)
  const outer = init.signal
  const onOuterAbort = () => controller.abort(outer?.reason)
  if (outer) {
    if (outer.aborted) controller.abort(outer.reason)
    else outer.addEventListener('abort', onOuterAbort, { once: true })
  }
  try {
    const response = await baseFetch(url, { ...init, signal: controller.signal })
    const snap = await snapshot(response)
    if (response.ok) {
      const parsed = OAuthTokensSchema.safeParse(JSON.parse(snap.body))
      if (!parsed.success) throw new Error(`token endpoint returned ${response.status} without valid tokens`)
      // Same as the SDK: keep the sent RT if the server did not return a new one.
      return { kind: 'ok', tokens: { refresh_token: sentRefreshToken, ...parsed.data }, snap }
    }
    const code = oauthErrorCode(snap)
    if (response.status >= 500 || response.status === 429 || !code || TRANSIENT_OAUTH_ERRORS.has(code)) {
      throw new Error(`token endpoint transient failure: HTTP ${response.status}${code ? ` (${code})` : ''}`)
    }
    return { kind: 'definitive', snap }
  } finally {
    clearTimeout(timer)
    outer?.removeEventListener('abort', onOuterAbort)
  }
}

async function coordinatedRefresh(
  serverUrlHash: string,
  baseFetch: FetchLike,
  url: string | URL,
  init: RequestInit,
  sentRefreshToken: string,
  opts: Required<RefreshFetchOptions>,
  hooks: RefreshCoordinatorHooks,
): Promise<ResponseSnapshot> {
  return withTokensLock(
    serverUrlHash,
    async () => {
      // Re-read under the lock: a sibling may already have rotated this RT.
      const onDisk = await readPersistedTokens(serverUrlHash)
      if (onDisk?.refresh_token && onDisk.refresh_token !== sentRefreshToken) {
        log('Tokens were already refreshed by another mcp-remote process; reusing them (no refresh sent).')
        return tokensSnapshot(serverUrlHash, onDisk)
      }

      let lastError: unknown
      for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
        let result: Attempt
        try {
          result = await attemptRefresh(baseFetch, url, init, sentRefreshToken, opts.attemptTimeoutMs)
        } catch (error) {
          if (init.signal?.aborted) throw error
          lastError = error
          debugLog(`Token refresh attempt ${attempt}/${opts.maxAttempts} failed transiently`, {
            error: (error as Error)?.message,
          })
          if (attempt < opts.maxAttempts) await sleep(opts.retryBaseDelayMs * 2 ** (attempt - 1))
          continue
        }

        if (result.kind === 'ok') {
          // Persist (atomically) before anyone gets to use the successor.
          await writeJsonFile(serverUrlHash, 'tokens.json', result.tokens)
          return tokensSnapshot(serverUrlHash, result.tokens)
        }

        if (oauthErrorCode(result.snap) === 'invalid_grant') {
          const current = await readPersistedTokens(serverUrlHash)
          if (current?.refresh_token && current.refresh_token !== sentRefreshToken) {
            log('Refresh rejected (invalid_grant) but tokens.json holds newer tokens; keeping and using them.')
            return tokensSnapshot(serverUrlHash, current)
          }
          log('Refresh token rejected (invalid_grant) and still current on disk; clearing tokens.')
          hooks.onRefreshTokenRejected?.(sentRefreshToken)
          await deleteConfigFile(serverUrlHash, 'tokens.json')
        }
        // Definitive OAuth error: hand the original response back to the SDK.
        return result.snap
      }

      log(`Token refresh failed after ${opts.maxAttempts} attempts; keeping tokens, not opening a browser.`)
      throw new TemporarilyUnavailableError(
        `Token refresh temporarily failed after ${opts.maxAttempts} attempts: ${(lastError as Error)?.message ?? lastError}`,
      )
    },
    opts,
  )
}

/**
 * Wraps `baseFetch` so every refresh_token grant is single-flighted per server, serialized
 * across processes, and retried on transient failures. All other requests pass through.
 */
export function createRefreshCoordinatedFetch(
  serverUrlHash: string,
  baseFetch: FetchLike,
  options: RefreshFetchOptions = {},
  hooks: RefreshCoordinatorHooks = {},
): FetchLike {
  const opts: Required<RefreshFetchOptions> = { ...DEFAULTS, ...options }
  return async (url, init) => {
    const sentRefreshToken = refreshTokenOf(init)
    if (!sentRefreshToken || !init) return baseFetch(url, init)

    let shared = inFlight.get(serverUrlHash)
    if (shared) {
      debugLog('Joining in-flight token refresh (single-flight)')
    } else {
      shared = coordinatedRefresh(serverUrlHash, baseFetch, url, init, sentRefreshToken, opts, hooks).finally(() => {
        inFlight.delete(serverUrlHash)
      })
      inFlight.set(serverUrlHash, shared)
    }
    return toResponse(await shared)
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
