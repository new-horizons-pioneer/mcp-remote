import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { log, debugLog, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'
import {
  createRefreshCoordinatedFetch,
  clearRejectedRefreshToken,
  isCoordinatorPersisted,
  readTokensStrict,
  rejectedRefreshTokenFor,
  unpersistedSuccessorFor,
  withTokensLock,
  type FetchLike,
  type RefreshFetchOptions,
} from './token-refresh'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined
  // The access token most recently served to a transport via `tokens()`. Used to
  // detect when a *sibling* mcp-remote process (sharing this token store) has
  // refreshed the token out from under us, so we can reuse its result instead of
  // opening a redundant interactive browser flow. See redirectToAuthorization().
  private lastReadAccessToken: string | undefined
  // Grace period to let a sibling's in-flight refresh land before we give up and
  // open a browser. Only applied to re-auth (never to a cold first authorization).
  private static readonly SIBLING_REFRESH_GRACE_MS = 400

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
    this._clientInfo = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      scope: effectiveScope,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  private getEffectiveScope(): string {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    if (this.protectedResourceMetadata?.scopes_supported?.length) {
      const scope = this.protectedResourceMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: this.protectedResourceMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if available
    if (this.authorizationServerMetadata?.scopes_supported?.length) {
      const scope = this.authorizationServerMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: this.authorizationServerMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default
    debugLog('Using fallback default scope')
    return 'openid email profile'
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('Saving client info', { client_id: clientInformation.client_id })
    this._clientInfo = clientInformation
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  /**
   * Reads the persisted tokens from disk WITHOUT mutating `lastReadAccessToken`.
   * Used by the concurrent-refresh guards so their bookkeeping reads don't
   * clobber the "token we last served to a transport" signal.
   */
  private async readPersistedTokens(): Promise<OAuthTokens | undefined> {
    return readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)
  }

  /**
   * True when a sibling process has persisted an access token different from the
   * one we last served — i.e. a concurrent refresh succeeded and we should reuse
   * it rather than starting a fresh interactive authorization. Non-mutating.
   */
  async hasSiblingRefreshedToken(): Promise<boolean> {
    const lastUsed = this.lastReadAccessToken
    if (!lastUsed) return false // cold start — nothing was ever served, so no sibling race
    const persisted = await this.readPersistedTokens()
    return !!persisted?.access_token && persisted.access_token !== lastUsed
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    debugLog('Token request stack trace:', new Error().stack)

    const persisted = await this.readPersistedTokens()
    // A refreshed pair that could not be written to disk yet wins over its rotated predecessor.
    const tokens = unpersistedSuccessorFor(this.serverUrlHash, persisted) ?? persisted
    this.lastReadAccessToken = tokens?.access_token

    if (tokens) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      debugLog('Token result:', {
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        isExpired: timeLeft <= 0,
        expiresInValue: tokens.expires_in,
      })
    } else {
      debugLog('Token result: Not found')
    }

    return tokens
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    debugLog('Saving tokens', {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
    })

    if (isCoordinatorPersisted(this.serverUrlHash, tokens)) {
      // The SDK echoing a refresh result the coordinator already persisted under the lock.
      // Re-writing it now (outside the lock) could clobber a newer rotation by a sibling.
      debugLog('Tokens already persisted by refresh coordinator; skipping duplicate write')
      return
    }

    await withTokensLock(this.serverUrlHash, () => writeJsonFile(this.serverUrlHash, 'tokens.json', tokens))
    clearRejectedRefreshToken(this.serverUrlHash)
  }

  /**
   * Wraps the fetch handed to the SDK transports so that every refresh_token grant is
   * single-flighted in-process, serialized across mcp-remote processes via a lock next to
   * tokens.json, retried on transient failures, and persisted atomically. See token-refresh.ts.
   */
  wrapFetch(baseFetch: FetchLike, options?: RefreshFetchOptions): FetchLike {
    return createRefreshCoordinatedFetch(this.serverUrlHash, baseFetch, options)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Concurrent-refresh guard.
    //
    // Reaching this method means the SDK decided a *new* authorization is needed
    // (our token refresh failed). But hosts like Claude Desktop run several
    // mcp-remote processes against one shared token store, and the server rotates
    // refresh tokens: when the short-lived access token expires, multiple
    // transports race to refresh and only one wins — the losers land here even
    // though a perfectly good token was just persisted by the winner. Opening a
    // browser in that case is pointless (and its loopback callback usually races
    // against process teardown, surfacing as ERR_CONNECTION_REFUSED).
    //
    // So: if a sibling already refreshed, skip the browser. Returning without
    // opening makes the SDK surface UnauthorizedError, which connectToRemoteServer
    // recovers from by reconnecting with the freshly-persisted token. We only do
    // this for re-auth (lastReadAccessToken set), never a cold first login, and we
    // allow a short grace for a sibling's in-flight refresh to land.
    if (this.lastReadAccessToken) {
      let siblingRefreshed = await this.hasSiblingRefreshedToken()
      if (!siblingRefreshed) {
        await new Promise((resolve) => setTimeout(resolve, NodeOAuthClientProvider.SIBLING_REFRESH_GRACE_MS))
        siblingRefreshed = await this.hasSiblingRefreshedToken()
      }
      if (siblingRefreshed) {
        log('A sibling process already refreshed the token; skipping interactive authorization.')
        debugLog('redirectToAuthorization: sibling-refreshed token detected, skipping browser')
        return
      }
    }

    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    const effectiveScope = this.getEffectiveScope()
    authorizationUrl.searchParams.set('scope', effectiveScope)
    debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this._clientInfo = undefined
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens': {
        // The SDK calls this after any invalid_grant. Fail closed: delete only when tokens.json
        // is absent (idempotent) or still holds the RT the server rejected for this server hash
        // (recorded by the refresh coordinator, shared by every provider in this process).
        // Unknown rejected RT, a sibling's newer pair, or an unreadable file → keep it.
        const rejected = rejectedRefreshTokenFor(this.serverUrlHash)
        await withTokensLock(this.serverUrlHash, async () => {
          let onDisk: OAuthTokens | undefined
          try {
            onDisk = await readTokensStrict(this.serverUrlHash)
          } catch {
            log('Keeping tokens.json: it is unreadable, so it is not known to hold the rejected token.')
            return
          }
          if (onDisk && !(rejected && onDisk.refresh_token === rejected)) {
            log('Keeping tokens.json: it does not hold a refresh token known to be rejected.')
            debugLog('invalidateCredentials(tokens): not deleting', { hasRejected: !!rejected })
            return
          }
          await deleteConfigFile(this.serverUrlHash, 'tokens.json')
          debugLog('OAuth tokens invalidated')
        })
        break
      }

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
