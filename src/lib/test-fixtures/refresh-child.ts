// Child process for token-refresh.test.ts: one real mcp-remote-like process running the SDK's
// auth() through the provider's refresh-coordinated fetch against a shared config dir.
import { auth } from '@modelcontextprotocol/sdk/client/auth.js'
import { NodeOAuthClientProvider } from '../node-oauth-client-provider'

async function main() {
  const [serverUrl, serverUrlHash] = process.argv.slice(2)
  const provider = new NodeOAuthClientProvider({ serverUrl, serverUrlHash, callbackPort: 33419, host: 'localhost' })
  const r = await auth(provider, { serverUrl, fetchFn: provider.wrapFetch(globalThis.fetch) })
  const tokens = await provider.tokens()
  console.log(JSON.stringify({ pid: process.pid, r, rt: tokens?.refresh_token }))
}

main().catch((error) => {
  console.log(JSON.stringify({ error: String(error?.name ?? error) }))
  process.exit(1)
})
