import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import openBrowser from 'open'
import { auth } from '@modelcontextprotocol/sdk/client/auth.js'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { getConfigFilePath } from './mcp-auth-config'
import { log } from './utils'
import * as tokenRefresh from './token-refresh'

// Real filesystem (temp MCP_REMOTE_CONFIG_DIR), real SDK auth(), fake OAuth server.
vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: 'refresh-test',
}))
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('open', () => ({ default: vi.fn().mockResolvedValue(undefined) }))

type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>
type TokenHandler = (params: URLSearchParams, call: number) => Promise<Response> | Response

const SERVER_URL = 'https://mcp.example.test/mcp'
// Unique per test: the coordinator keeps per-server-hash state at module level.
let HASH = ''
let seq = 0
const FAST_RETRY = { retryBaseDelayMs: 5, attemptTimeoutMs: 2_000 }

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const tokensFor = (rt: string, at = `at-for-${rt}`) => ({
  access_token: at,
  token_type: 'Bearer',
  expires_in: 3600,
  refresh_token: rt,
})

/** Fake authorization server: discovery + token endpoint routed to `onToken`. */
function fakeServer(onToken: TokenHandler) {
  const refreshCalls: string[] = []
  const fetchFn: FetchLike = async (input, init) => {
    const url = new URL(String(input))
    if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) return new Response('nope', { status: 404 })
    if (url.pathname.startsWith('/.well-known/oauth-authorization-server') || url.pathname.startsWith('/.well-known/openid')) {
      return json(200, {
        issuer: 'https://mcp.example.test',
        authorization_endpoint: 'https://mcp.example.test/authorize',
        token_endpoint: 'https://mcp.example.test/token',
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
      })
    }
    if (url.pathname === '/token') {
      const params = new URLSearchParams(String(init?.body ?? ''))
      if (params.get('grant_type') === 'refresh_token') refreshCalls.push(params.get('refresh_token') ?? '')
      return onToken(params, refreshCalls.length)
    }
    return new Response('not found', { status: 404 })
  }
  return { fetchFn, refreshCalls }
}

let configDir: string

async function writeTokens(tokens: unknown) {
  await fs.writeFile(getConfigFilePath(HASH, 'tokens.json'), JSON.stringify(tokens))
}
async function readTokens(): Promise<any | undefined> {
  try {
    return JSON.parse(await fs.readFile(getConfigFilePath(HASH, 'tokens.json'), 'utf-8'))
  } catch {
    return undefined
  }
}

function newProvider() {
  return new NodeOAuthClientProvider({
    serverUrl: SERVER_URL,
    serverUrlHash: HASH,
    callbackPort: 33418,
    host: 'localhost',
  } as any)
}

/** The fetch the transports hand to the SDK's auth(): the provider's refresh-coordinated wrapper. */
function wrapped(provider: NodeOAuthClientProvider, base: FetchLike, extra: Record<string, number> = {}): FetchLike {
  const p = provider as any
  return typeof p.wrapFetch === 'function' ? p.wrapFetch(base, { ...FAST_RETRY, ...extra }) : base
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

beforeEach(async () => {
  HASH = `refresh-test-${++seq}`
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-refresh-'))
  process.env.MCP_REMOTE_CONFIG_DIR = configDir
  await fs.mkdir(path.dirname(getConfigFilePath(HASH, 'x')), { recursive: true })
  await fs.writeFile(
    getConfigFilePath(HASH, 'client_info.json'),
    JSON.stringify({ client_id: 'client-1', redirect_uris: ['http://localhost:33418/oauth/callback'] }),
  )
  await writeTokens(tokensFor('rt-0', 'at-0'))
  vi.mocked(openBrowser).mockClear()
  vi.mocked(log).mockClear()
})

afterEach(async () => {
  vi.restoreAllMocks()
  delete process.env.MCP_REMOTE_CONFIG_DIR
  await fs.rm(configDir, { recursive: true, force: true })
})

describe('refresh single-flight + cross-process lock', () => {
  it('two concurrent refreshes in one process send ONE network refresh and share the result', async () => {
    const server = fakeServer(async () => {
      await sleep(50)
      return json(200, tokensFor('rt-1', 'at-1'))
    })
    const providerA = newProvider()
    const providerB = newProvider()

    const [ra, rb] = await Promise.all([
      auth(providerA, { serverUrl: SERVER_URL, fetchFn: wrapped(providerA, server.fetchFn) }),
      auth(providerB, { serverUrl: SERVER_URL, fetchFn: wrapped(providerB, server.fetchFn) }),
    ])

    expect(ra).toBe('AUTHORIZED')
    expect(rb).toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
    expect(openBrowser).not.toHaveBeenCalled()
  })

  it('a second process that finds the file already rotated under the lock does not refresh', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-WRONG')))
    const provider = newProvider()
    const lockPath = getConfigFilePath(HASH, 'tokens.json.lock')

    // "Process A" holds the tokens lock while its refresh is in flight.
    await fs.writeFile(lockPath, JSON.stringify({ pid: process.pid, timestamp: Date.now(), owner: 'process-a' }))

    const pending = auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    // Process A finishes: persists its successor, then releases the lock.
    await sleep(150)
    await writeTokens(tokensFor('rt-1', 'at-1'))
    await fs.unlink(lockPath)

    await expect(pending).resolves.toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual([])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
    expect(openBrowser).not.toHaveBeenCalled()
  })

  it('a stale lock (dead PID) does not block refresh', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const provider = newProvider()
    await fs.writeFile(
      getConfigFilePath(HASH, 'tokens.json.lock'),
      JSON.stringify({ pid: 2 ** 22 + 12345, timestamp: Date.now(), owner: 'dead' }),
    )

    await expect(auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })).resolves.toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
  })

  it('invalid_grant while tokens.json holds a DIFFERENT (newer) RT keeps the file and uses the newer tokens', async () => {
    const server = fakeServer(async () => {
      // Another writer rotated (e.g. a sibling's browser login) while our request was in flight.
      await writeTokens(tokensFor('rt-NEW', 'at-NEW'))
      return json(400, { error: 'invalid_grant', error_description: 'refresh token reused' })
    })
    const provider = newProvider()

    const result = await auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    expect(result).toBe('AUTHORIZED')
    expect(server.refreshCalls[0]).toBe('rt-0')
    expect((await readTokens())?.refresh_token).toBe('rt-NEW')
    expect(openBrowser).not.toHaveBeenCalled()
  })

  it('invalid_grant while tokens.json still holds the SAME RT deletes tokens and falls back to browser auth', async () => {
    const server = fakeServer(() => json(400, { error: 'invalid_grant', error_description: 'revoked' }))
    const provider = newProvider()

    const result = await auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    expect(result).toBe('REDIRECT')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect(await readTokens()).toBeUndefined()
    expect(openBrowser).toHaveBeenCalledTimes(1)
  })

  it('network errors during refresh are retried and never open the browser', async () => {
    const server = fakeServer((_params, call) => {
      if (call < 3) throw new TypeError('fetch failed')
      return json(200, tokensFor('rt-1', 'at-1'))
    })
    const provider = newProvider()

    const result = await auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    expect(result).toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual(['rt-0', 'rt-0', 'rt-0'])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
    expect(openBrowser).not.toHaveBeenCalled()
  })

  it('persistent 5xx during refresh gives up without deleting tokens or opening the browser', async () => {
    const server = fakeServer(() => new Response('<html>bad gateway</html>', { status: 502 }))
    const provider = newProvider()

    await expect(auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })).rejects.toThrow()

    expect(server.refreshCalls).toEqual(['rt-0', 'rt-0', 'rt-0'])
    expect((await readTokens())?.refresh_token).toBe('rt-0')
    expect(openBrowser).not.toHaveBeenCalled()
  })

  it('persists refreshed tokens atomically (no temp files left, valid JSON on disk)', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-1', 'at-1')))
    const provider = newProvider()

    await auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    const files = await fs.readdir(path.dirname(getConfigFilePath(HASH, 'x')))
    expect(files.filter((f) => f.endsWith('.tmp'))).toEqual([])
    expect(files.filter((f) => f.endsWith('.lock'))).toEqual([])
    expect(await readTokens()).toMatchObject({ refresh_token: 'rt-1', access_token: 'at-1' })
  })

  it('invalidateCredentials("tokens") keeps a tokens.json that a sibling rotated after we last read it', async () => {
    const provider = newProvider()
    await provider.tokens() // we observed rt-0
    await writeTokens(tokensFor('rt-SIBLING')) // sibling rotated

    await provider.invalidateCredentials('tokens')

    expect((await readTokens())?.refresh_token).toBe('rt-SIBLING')
  })
})

const TOKEN_URL = 'https://mcp.example.test/token'
const refreshInit = (rt: string, signal?: AbortSignal): RequestInit => ({
  method: 'POST',
  body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt }),
  signal,
})
const never = () => new Promise<Response>(() => {})
const lockFile = () => getConfigFilePath(HASH, 'tokens.json.lock')
const leftovers = async () =>
  (await fs.readdir(path.dirname(getConfigFilePath(HASH, 'x')))).filter((f) => /\.(tmp|lock|break|aside)$/.test(f))

describe('review blockers', () => {
  it('an empty/unreadable lock file older than lockStaleMs is treated as stale (no wedge)', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const provider = newProvider()
    await fs.writeFile(lockFile(), '') // 0-byte lock left by a crashed writer
    const old = new Date(Date.now() - 60 * 60 * 1000)
    await fs.utimes(lockFile(), old, old)

    await expect(
      auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn, { lockStaleMs: 1_000 }) }),
    ).resolves.toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect(await leftovers()).toEqual([])
  }, 4_000)

  it('a failure while writing the lock leaves no lock behind and does not block refresh', async () => {
    const realWriteFile = fs.writeFile.bind(fs)
    vi.spyOn(fs, 'writeFile').mockImplementation(async (file: any, ...rest: any[]) => {
      if (String(file).includes('tokens.json.lock')) throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' })
      return (realWriteFile as any)(file, ...rest)
    })
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const provider = newProvider()

    await expect(auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })).resolves.toBe('AUTHORIZED')
    expect(await leftovers()).toEqual([])
  })

  it('concurrent takeover of a stale lock admits exactly one holder at a time', async () => {
    await fs.writeFile(lockFile(), JSON.stringify({ pid: 2 ** 22 + 12345, timestamp: Date.now(), owner: 'dead' }))
    // Force the TOCTOU interleaving: a lock read returns its snapshot only after a delay,
    // so a contender can judge the *dead* lock stale after another one already replaced it.
    const realReadFile = fs.readFile.bind(fs)
    vi.spyOn(fs, 'readFile').mockImplementation(async (file: any, ...rest: any[]) => {
      const content = await (realReadFile as any)(file, ...rest)
      if (String(file).endsWith('tokens.json.lock')) await sleep(Math.random() * 25)
      return content
    })
    let inside = 0
    let maxInside = 0
    await Promise.all(
      Array.from({ length: 12 }, () =>
        tokenRefresh.withTokensLock(HASH, async () => {
          inside++
          maxInside = Math.max(maxInside, inside)
          await sleep(15)
          inside--
        }),
      ),
    )
    expect(maxInside).toBe(1)
    expect(await leftovers()).toEqual([])
  }, 10_000)

  it('a failed write of the successor is retried (EPERM/EBUSY on rename)', async () => {
    const realRename = fs.rename.bind(fs)
    let failures = 2
    vi.spyOn(fs, 'rename').mockImplementation(async (from: any, to: any) => {
      if (String(to).endsWith('_tokens.json') && failures-- > 0) throw Object.assign(new Error('EBUSY'), { code: 'EBUSY' })
      return realRename(from, to)
    })
    const server = fakeServer(() => json(200, tokensFor('rt-1', 'at-1')))
    const provider = newProvider()

    await expect(auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })).resolves.toBe('AUTHORIZED')
    expect((await readTokens())?.refresh_token).toBe('rt-1')
    expect(server.refreshCalls).toEqual(['rt-0'])
  })

  it('if the successor cannot be persisted it is kept in memory, the old RT is never resent, and no browser opens', async () => {
    const realRename = fs.rename.bind(fs)
    let broken = true
    vi.spyOn(fs, 'rename').mockImplementation(async (from: any, to: any) => {
      if (broken && String(to).endsWith('_tokens.json')) throw Object.assign(new Error('EPERM'), { code: 'EPERM' })
      return realRename(from, to)
    })
    const server = fakeServer(() => json(200, tokensFor('rt-1', 'at-1')))
    const provider = newProvider()
    const fetchFn = wrapped(provider, server.fetchFn)

    const err = await auth(provider, { serverUrl: SERVER_URL, fetchFn }).catch((e) => e)
    expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
    expect(openBrowser).not.toHaveBeenCalled()
    expect((await provider.tokens())?.refresh_token).toBe('rt-1') // served from memory

    broken = false
    // A stale caller still holding rt-0 must get the successor, not a network refresh with rt-0.
    const res = await fetchFn(TOKEN_URL, refreshInit('rt-0'))
    expect((await res.json()).refresh_token).toBe('rt-1')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
  })

  it('the retry window for one RT is bounded below the 60s server grace', () => {
    expect(tokenRefresh.MAX_REFRESH_RETRY_WINDOW_MS).toBeLessThanOrEqual(45_000)
    expect(tokenRefresh.refreshRetryWindowMs({})).toBeLessThanOrEqual(45_000)
    expect(tokenRefresh.refreshRetryWindowMs({ retryWindowMs: 10 * 60_000 })).toBe(45_000)
  })

  it('resends of the same RT stop at the retry window even with long timeouts and many attempts', async () => {
    const sends: number[] = []
    const server = fakeServer(() => {
      sends.push(Date.now())
      return never()
    })
    const provider = newProvider()
    const fetchFn = wrapped(provider, server.fetchFn, {
      maxAttempts: 50,
      attemptTimeoutMs: 150,
      retryBaseDelayMs: 10,
      retryWindowMs: 400,
    })

    await expect(fetchFn(TOKEN_URL, refreshInit('rt-0'))).rejects.toThrow()
    const done = Date.now()
    expect(sends.length).toBeGreaterThan(1)
    expect(sends[sends.length - 1] - sends[0]).toBeLessThan(400)
    expect(done - sends[0]).toBeLessThan(400 + 150)
    expect((await readTokens())?.refresh_token).toBe('rt-0')
  })

  it('attemptTimeoutMs holds even when the underlying fetch ignores the abort signal', async () => {
    const server = fakeServer(() => never())
    const provider = newProvider()
    const started = Date.now()

    const err = await auth(provider, {
      serverUrl: SERVER_URL,
      fetchFn: wrapped(provider, server.fetchFn, { attemptTimeoutMs: 50, maxAttempts: 2 }),
    }).catch((e) => e)

    expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
    expect(Date.now() - started).toBeLessThan(1_500)
    expect(server.refreshCalls).toEqual(['rt-0', 'rt-0'])
    expect(openBrowser).not.toHaveBeenCalled()
  }, 4_000)

  it("a caller's abort only detaches that caller; the shared flight is not cancelled", async () => {
    let flightSignalAborted: boolean | undefined
    const base: FetchLike = async (_url, init) => {
      const params = new URLSearchParams(String(init?.body ?? ''))
      calls.push(params.get('refresh_token') ?? '')
      await sleep(80)
      flightSignalAborted = init?.signal?.aborted ?? false
      return json(200, tokensFor('rt-1', 'at-1'))
    }
    const calls: string[] = []
    const provider = newProvider()
    const fetchFn = wrapped(provider, base)
    const ctrl = new AbortController()

    const first = fetchFn(TOKEN_URL, refreshInit('rt-0', ctrl.signal))
    const second = fetchFn(TOKEN_URL, refreshInit('rt-0'))
    setTimeout(() => ctrl.abort(), 20)

    await expect(first).rejects.toThrow()
    const res = await second
    expect(res.status).toBe(200)
    expect((await res.json()).refresh_token).toBe('rt-1')
    expect(calls).toEqual(['rt-0'])
    expect(flightSignalAborted).toBe(false)
  })

  it('an unreadable tokens.json under the lock blocks the refresh and is not deleted', async () => {
    const garbage = 'SECRET-RT-FRAGMENT not json'
    await fs.writeFile(getConfigFilePath(HASH, 'tokens.json'), garbage)
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const provider = newProvider()

    await expect(wrapped(provider, server.fetchFn)(TOKEN_URL, refreshInit('rt-0'))).rejects.toThrow()
    expect(server.refreshCalls).toEqual([])
    expect(await fs.readFile(getConfigFilePath(HASH, 'tokens.json'), 'utf-8')).toBe(garbage)

    await provider.invalidateCredentials('tokens')
    expect(await fs.readFile(getConfigFilePath(HASH, 'tokens.json'), 'utf-8')).toBe(garbage)
  })

  it('invalidateCredentials("tokens") without a known-rejected RT fails closed (keeps tokens)', async () => {
    const provider = newProvider()
    await provider.tokens()

    await provider.invalidateCredentials('tokens')

    expect((await readTokens())?.refresh_token).toBe('rt-0')
  })

  it('the rejected RT is shared per server hash, not tied to the provider that refreshed', async () => {
    const server = fakeServer(() => json(400, { error: 'invalid_grant' }))
    const starter = newProvider()
    const other = newProvider()
    await wrapped(starter, server.fetchFn)(TOKEN_URL, refreshInit('rt-0'))
    // Something re-persisted the very RT the server just rejected.
    await writeTokens(tokensFor('rt-0'))

    await other.invalidateCredentials('tokens')

    expect(await readTokens()).toBeUndefined()
  })

  it('never logs token file contents when tokens.json is malformed', async () => {
    await fs.writeFile(getConfigFilePath(HASH, 'tokens.json'), 'SECRET-RT-FRAGMENT not json')
    const provider = newProvider()

    await provider.tokens()

    const logged = JSON.stringify(vi.mocked(log).mock.calls.map((c) => c.map((a) => (a instanceof Error ? a.message : a))))
    expect(logged).not.toContain('SECRET')
  })
})
