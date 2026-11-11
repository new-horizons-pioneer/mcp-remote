import { describe, it, expect, vi } from 'vitest'

// Capture the options every transport is constructed with.
const constructed: Array<{ kind: string; opts: any }> = vi.hoisted(() => [])

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => {
  class StreamableHTTPClientTransport {
    constructor(_url: URL, opts: any) {
      constructed.push({ kind: 'http', opts })
    }
    async start() {}
  }
  class StreamableHTTPError extends Error {
    code?: number
  }
  return { StreamableHTTPClientTransport, StreamableHTTPError }
})
vi.mock('@modelcontextprotocol/sdk/client/sse.js', () => {
  class SSEClientTransport {
    constructor(_url: URL, opts: any) {
      constructed.push({ kind: 'sse', opts })
    }
    async start() {}
  }
  return { SSEClientTransport }
})
vi.mock('@modelcontextprotocol/sdk/client/index.js', () => {
  class Client {
    async connect(transport: any) {
      await transport.start()
    }
  }
  return { Client }
})

import { connectToRemoteServer } from './utils'

describe('connectToRemoteServer wires the provider refresh-coordinated fetch into transports', () => {
  it.each(['http-only', 'sse-only'] as const)('%s transport gets provider.wrapFetch(...)', async (strategy) => {
    constructed.length = 0
    const coordinatedFetch = vi.fn()
    const provider: any = {
      wrapFetch: vi.fn(() => coordinatedFetch),
      tokens: vi.fn(async () => undefined),
    }

    await connectToRemoteServer(null, 'https://mcp.example.test/mcp', provider, {}, vi.fn() as any, strategy)

    expect(provider.wrapFetch).toHaveBeenCalled()
    expect(constructed.length).toBeGreaterThan(0)
    for (const { opts } of constructed) {
      expect(opts.fetch).toBe(coordinatedFetch)
    }
  })
})
