import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import openBrowser from 'open'
import { auth } from '@modelcontextprotocol/sdk/client/auth.js'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { getConfigFilePath } from './mcp-auth-config'

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
const HASH = 'refresh-test-hash'
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
function wrapped(provider: NodeOAuthClientProvider, base: FetchLike): FetchLike {
  const p = provider as any
  return typeof p.wrapFetch === 'function' ? p.wrapFetch(base, FAST_RETRY) : base
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

beforeEach(async () => {
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-refresh-'))
  process.env.MCP_REMOTE_CONFIG_DIR = configDir
  await fs.mkdir(path.dirname(getConfigFilePath(HASH, 'x')), { recursive: true })
  await fs.writeFile(
    getConfigFilePath(HASH, 'client_info.json'),
    JSON.stringify({ client_id: 'client-1', redirect_uris: ['http://localhost:33418/oauth/callback'] }),
  )
  await writeTokens(tokensFor('rt-0', 'at-0'))
  vi.mocked(openBrowser).mockClear()
})

afterEach(async () => {
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
