import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import http from 'node:http'
import { spawn } from 'node:child_process'
import lockfile from 'proper-lockfile'
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
const TOKEN_URL = 'https://mcp.example.test/token'
// Unique per test: the coordinator keeps per-server-hash / per-RT state at module level.
let HASH = ''
let seq = 0
const FAST_RETRY = { retryBaseDelayMs: 5, attemptTimeoutMs: 2_000 }
const REPO_ROOT = path.resolve(__dirname, '../..')

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
        token_endpoint: TOKEN_URL,
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

const tokensPath = () => getConfigFilePath(HASH, 'tokens.json')
const lockDir = () => `${tokensPath()}.lock`
async function writeTokens(tokens: unknown) {
  await fs.writeFile(tokensPath(), JSON.stringify(tokens))
}
async function readTokens(): Promise<any | undefined> {
  try {
    return JSON.parse(await fs.readFile(tokensPath(), 'utf-8'))
  } catch {
    return undefined
  }
}
const leftovers = async () => (await fs.readdir(path.dirname(getConfigFilePath(HASH, 'x')))).filter((f) => /\.(tmp|lock|break)$/.test(f))

function newProvider() {
  return new NodeOAuthClientProvider({
    serverUrl: SERVER_URL,
    serverUrlHash: HASH,
    callbackPort: 33418,
    host: 'localhost',
  } as any)
}

/** The fetch the transports hand to the SDK's auth(): the provider's refresh-coordinated wrapper. */
function wrapped(provider: NodeOAuthClientProvider, base: FetchLike, extra: Record<string, unknown> = {}): FetchLike {
  const p = provider as any
  return typeof p.wrapFetch === 'function' ? p.wrapFetch(base, { ...FAST_RETRY, ...extra }) : base
}

const refreshInit = (rt: string, signal?: AbortSignal): RequestInit => ({
  method: 'POST',
  body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt }),
  signal,
})
const never = () => new Promise<Response>(() => {})
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

describe('refresh single-flight', () => {
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

  it("a caller's abort only detaches that caller; the shared flight is not cancelled", async () => {
    let flightSignalAborted: boolean | undefined
    const calls: string[] = []
    const base: FetchLike = async (_url, init) => {
      calls.push(new URLSearchParams(String(init?.body ?? '')).get('refresh_token') ?? '')
      await sleep(80)
      flightSignalAborted = init?.signal?.aborted ?? false
      return json(200, tokensFor('rt-1', 'at-1'))
    }
    const fetchFn = wrapped(newProvider(), base)
    const ctrl = new AbortController()

    const first = fetchFn(TOKEN_URL, refreshInit('rt-0', ctrl.signal))
    const second = fetchFn(TOKEN_URL, refreshInit('rt-0'))
    setTimeout(() => ctrl.abort(), 20)

    await expect(first).rejects.toThrow()
    const res = await second
    expect((await res.json()).refresh_token).toBe('rt-1')
    expect(calls).toEqual(['rt-0'])
    expect(flightSignalAborted).toBe(false)
  })

  it("a caller with a DIFFERENT refresh token does not join another RT's flight", async () => {
    const server = fakeServer(async (params) => {
      if (params.get('refresh_token') === 'rt-0') {
        await sleep(60)
        return json(400, { error: 'invalid_grant' })
      }
      return json(200, tokensFor('rt-X1'))
    })
    const fetchFn = wrapped(newProvider(), server.fetchFn)

    const a = fetchFn(TOKEN_URL, refreshInit('rt-0'))
    await sleep(10)
    const b = fetchFn(TOKEN_URL, refreshInit('rt-X'))

    expect((await a).status).toBe(400)
    const rb = await b
    expect(rb.status).toBe(200)
    expect((await rb.json()).refresh_token).toBe('rt-X1')
    expect(server.refreshCalls).toEqual(['rt-0', 'rt-X'])
  })

  it('undefined option values fall back to defaults', async () => {
    const server = fakeServer((_p, call) => {
      if (call < 3) throw new TypeError('fetch failed')
      return json(200, tokensFor('rt-1'))
    })
    const fetchFn = wrapped(newProvider(), server.fetchFn, { maxAttempts: undefined, retryWindowMs: undefined })

    const res = await fetchFn(TOKEN_URL, refreshInit('rt-0'))

    expect(res.status).toBe(200)
    expect(server.refreshCalls).toEqual(['rt-0', 'rt-0', 'rt-0'])
  })
})

describe('cross-process lock (proper-lockfile on tokens.json)', () => {
  it('a second process that finds the file already rotated under the lock does not refresh', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-WRONG')))
    const provider = newProvider()

    // "Process A" holds the tokens lock while its refresh is in flight.
    const release = await lockfile.lock(tokensPath(), { realpath: false })
    const pending = auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    // Process A finishes: persists its successor, then releases the lock.
    await sleep(200)
    await writeTokens(tokensFor('rt-1', 'at-1'))
    await release()

    await expect(pending).resolves.toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual([])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
    expect(openBrowser).not.toHaveBeenCalled()
  })

  it('two real processes refreshing at once send ONE network refresh', async () => {
    const refreshes: string[] = []
    let n = 0
    const srv = http.createServer((req, res) => {
      let body = ''
      req.on('data', (c) => (body += c))
      req.on('end', () => {
        const base = `http://127.0.0.1:${(srv.address() as any).port}`
        res.setHeader('content-type', 'application/json')
        if (req.url?.startsWith('/.well-known/oauth-authorization-server')) {
          return res.end(
            JSON.stringify({
              issuer: base,
              authorization_endpoint: `${base}/authorize`,
              token_endpoint: `${base}/token`,
              response_types_supported: ['code'],
              code_challenge_methods_supported: ['S256'],
            }),
          )
        }
        if (req.url === '/token') {
          refreshes.push(new URLSearchParams(body).get('refresh_token') ?? '')
          n++
          return setTimeout(() => res.end(JSON.stringify(tokensFor(`rt-p${n}`))), 300)
        }
        res.statusCode = 404
        res.end('{}')
      })
    })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    const serverUrl = `http://127.0.0.1:${(srv.address() as any).port}/mcp`
    const runChild = () =>
      new Promise<string>((resolve) => {
        const child = spawn(
          path.join(REPO_ROOT, 'node_modules/.bin/tsx'),
          [path.join(__dirname, 'test-fixtures/refresh-child.ts'), serverUrl, HASH],
          { cwd: REPO_ROOT, env: { ...process.env, MCP_REMOTE_CONFIG_DIR: configDir } },
        )
        let out = ''
        child.stdout.on('data', (d) => (out += d))
        child.on('exit', () => resolve(out.trim().split('\n').pop() ?? ''))
      })
    // The child uses the real package version for the config subdir.
    const version = JSON.parse(await fs.readFile(path.join(REPO_ROOT, 'package.json'), 'utf-8')).version
    const childDir = path.join(configDir, `mcp-remote-${version}`)
    await fs.mkdir(childDir, { recursive: true })
    await fs.copyFile(getConfigFilePath(HASH, 'client_info.json'), path.join(childDir, `${HASH}_client_info.json`))
    await fs.copyFile(tokensPath(), path.join(childDir, `${HASH}_tokens.json`))

    try {
      const outs = await Promise.all([runChild(), runChild()])
      expect(outs.map((o) => JSON.parse(o || '{}').r)).toEqual(['AUTHORIZED', 'AUTHORIZED'])
      expect(outs.map((o) => JSON.parse(o || '{}').rt)).toEqual(['rt-p1', 'rt-p1'])
      expect(refreshes).toEqual(['rt-0'])
    } finally {
      srv.close()
    }
  }, 30_000)

  it('a lock whose holder stopped heartbeating (dead process) is taken over', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const provider = newProvider()
    await fs.mkdir(lockDir())
    const old = new Date(Date.now() - 60 * 60 * 1000)
    await fs.utimes(lockDir(), old, old)

    await expect(auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })).resolves.toBe('AUTHORIZED')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect(await leftovers()).toEqual([])
  }, 4_000)

  it('a lock left by a crashed (SIGKILLed) process recovers after the stale time', async () => {
    const script = `
      const lockfile = require(${JSON.stringify(path.join(REPO_ROOT, 'node_modules/proper-lockfile'))});
      lockfile.lock(${JSON.stringify(tokensPath())}, { realpath: false }).then(() => process.kill(process.pid, 'SIGKILL'));
    `
    await new Promise((resolve) => spawn(process.execPath, ['-e', script]).on('exit', resolve))
    expect((await fs.stat(lockDir())).isDirectory()).toBe(true) // left behind by the crash

    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const res = await wrapped(newProvider(), server.fetchFn, { lockStaleMs: 2_000 })(TOKEN_URL, refreshInit('rt-0'))

    expect(res.status).toBe(200)
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect(await leftovers()).toEqual([])
  }, 10_000)

  it('failing to acquire the lock fails closed: TemporarilyUnavailable, no refresh sent', async () => {
    const release = await lockfile.lock(tokensPath(), { realpath: false }) // live, heartbeating holder
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    try {
      const err = await wrapped(newProvider(), server.fetchFn, { lockWaitMs: 300 })(TOKEN_URL, refreshInit('rt-0')).catch((e) => e)
      expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
      expect(server.refreshCalls).toEqual([])
      expect((await readTokens())?.refresh_token).toBe('rt-0')
    } finally {
      await release()
    }
  }, 4_000)

  it('a compromised lock aborts the in-flight refresh with TemporarilyUnavailable (no timer throw)', async () => {
    const server = fakeServer(() => never())
    const fetchFn = wrapped(newProvider(), server.fetchFn, {
      lockStaleMs: 2_000,
      lockUpdateMs: 1_000,
      attemptTimeoutMs: 20_000,
    })
    const pending = fetchFn(TOKEN_URL, refreshInit('rt-0')).catch((e) => e)
    await sleep(200)
    await fs.rm(lockDir(), { recursive: true, force: true }) // someone yanked our lock

    const err = await pending
    expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
    expect((await readTokens())?.refresh_token).toBe('rt-0')
  }, 6_000)

  it('withTokensLock admits exactly one holder at a time, also when taking over a stale lock', async () => {
    await fs.mkdir(lockDir())
    const old = new Date(Date.now() - 60 * 60 * 1000)
    await fs.utimes(lockDir(), old, old)
    let inside = 0
    let maxInside = 0
    await Promise.all(
      Array.from({ length: 8 }, () =>
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
})

describe('refresh outcomes', () => {
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

  it('persists refreshed tokens atomically (no temp/lock files left, valid JSON on disk)', async () => {
    const server = fakeServer(() => json(200, tokensFor('rt-1', 'at-1')))
    const provider = newProvider()

    await auth(provider, { serverUrl: SERVER_URL, fetchFn: wrapped(provider, server.fetchFn) })

    expect(await leftovers()).toEqual([])
    expect(await readTokens()).toMatchObject({ refresh_token: 'rt-1', access_token: 'at-1' })
  })

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
  })

  it('if the successor cannot be persisted it is kept in memory and the old RT is not resent by this process', async () => {
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
    const res = await fetchFn(TOKEN_URL, refreshInit('rt-0'))
    expect((await res.json()).refresh_token).toBe('rt-1')
    expect(server.refreshCalls).toEqual(['rt-0'])
    expect((await readTokens())?.refresh_token).toBe('rt-1')
  })
})

describe('retry window per refresh token (server grace 60s)', () => {
  it('is bounded below the 60s server grace', () => {
    expect(tokenRefresh.MAX_REFRESH_RETRY_WINDOW_MS).toBeLessThanOrEqual(45_000)
    expect(tokenRefresh.refreshRetryWindowMs({})).toBeLessThanOrEqual(45_000)
    expect(tokenRefresh.refreshRetryWindowMs({ retryWindowMs: 10 * 60_000 })).toBe(45_000)
  })

  it('resends inside one flight stop at the window even with long timeouts and many attempts', async () => {
    const sends: number[] = []
    const server = fakeServer(() => {
      sends.push(Date.now())
      return never()
    })
    const fetchFn = wrapped(newProvider(), server.fetchFn, {
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
  })

  it('a NEW flight with the same RT respects the window opened by the first flight', async () => {
    const server = fakeServer(() => never())
    const opts = { maxAttempts: 5, attemptTimeoutMs: 150, retryBaseDelayMs: 10, retryWindowMs: 300 }

    await expect(wrapped(newProvider(), server.fetchFn, opts)(TOKEN_URL, refreshInit('rt-0'))).rejects.toThrow()
    const sentInFirstFlight = server.refreshCalls.length
    await sleep(350)

    const err = await wrapped(newProvider(), server.fetchFn, opts)(TOKEN_URL, refreshInit('rt-0')).catch((e) => e)
    expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
    expect(server.refreshCalls.length).toBe(sentInFirstFlight)
  })

  it('connect errors (request never left the client) do not open the window', async () => {
    let offline = true
    const server = fakeServer(() => {
      if (offline) throw new TypeError('fetch failed', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) })
      return json(200, tokensFor('rt-1'))
    })
    const opts = { maxAttempts: 2, retryBaseDelayMs: 10, retryWindowMs: 200 }

    await expect(wrapped(newProvider(), server.fetchFn, opts)(TOKEN_URL, refreshInit('rt-0'))).rejects.toThrow()
    await sleep(250)
    offline = false

    const res = await wrapped(newProvider(), server.fetchFn, opts)(TOKEN_URL, refreshInit('rt-0'))
    expect(res.status).toBe(200)
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
})

describe('reading and invalidating tokens.json', () => {
  const garbage = 'SECRET-RT-FRAGMENT not json'

  it('an unreadable tokens.json under the lock blocks the refresh and is not deleted', async () => {
    await fs.writeFile(tokensPath(), garbage)
    const server = fakeServer(() => json(200, tokensFor('rt-1')))
    const provider = newProvider()

    await expect(wrapped(provider, server.fetchFn)(TOKEN_URL, refreshInit('rt-0'))).rejects.toThrow()
    expect(server.refreshCalls).toEqual([])

    await provider.invalidateCredentials('tokens')
    expect(await fs.readFile(tokensPath(), 'utf-8')).toBe(garbage)
  })

  it('provider.tokens() throws TemporarilyUnavailable on an unreadable tokens.json and never logs its contents', async () => {
    await fs.writeFile(tokensPath(), garbage)
    const provider = newProvider()

    const err = await provider.tokens().catch((e) => e)

    expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
    const logged = JSON.stringify(vi.mocked(log).mock.calls.map((c) => c.map((a) => (a instanceof Error ? a.message : a))))
    expect(logged).not.toContain('SECRET')
  })

  it('hasSiblingRefreshedToken() throws TemporarilyUnavailable on an unreadable tokens.json', async () => {
    const provider = newProvider()
    await provider.tokens()
    await fs.writeFile(tokensPath(), garbage)

    const err = await provider.hasSiblingRefreshedToken().catch((e) => e)

    expect(err?.constructor?.name).toBe('TemporarilyUnavailableError')
  })

  it('invalidateCredentials("tokens") keeps a tokens.json that a sibling rotated', async () => {
    const provider = newProvider()
    await provider.tokens()
    await writeTokens(tokensFor('rt-SIBLING'))

    await provider.invalidateCredentials('tokens')

    expect((await readTokens())?.refresh_token).toBe('rt-SIBLING')
  })

  it('invalidateCredentials("tokens") without a known-rejected RT fails closed (keeps tokens)', async () => {
    const provider = newProvider()
    await provider.tokens()

    await provider.invalidateCredentials('tokens')

    expect((await readTokens())?.refresh_token).toBe('rt-0')
  })

  it('the rejected RT is shared per server hash, not tied to the provider that refreshed', async () => {
    const server = fakeServer(() => json(400, { error: 'invalid_grant' }))
    await wrapped(newProvider(), server.fetchFn)(TOKEN_URL, refreshInit('rt-0'))
    await writeTokens(tokensFor('rt-0')) // something re-persisted the very RT the server rejected

    await newProvider().invalidateCredentials('tokens')

    expect(await readTokens()).toBeUndefined()
  })
})
