# WebTools Kanban Authorization Server

Spring Authorization Server built with Spring Boot 3.4.2 and Java 21. It authenticates people through configured identity providers (currently Google) and issues OAuth 2.0 access tokens to registered clients, including Claude and optional MCP integrations such as ChatGPT and Gemini, as well as the Kanban web client.

The authorization server does not own Kanban user records or passwords. After federated sign-in, it asks the Kanban backend to resolve the external identity to a Kanban user.

## Sign-in and token flow

1. An OAuth client redirects the browser to `/oauth2/authorize` using Authorization Code and PKCE (`S256`).
2. If there is no authorization-server session, the user is sent to `/login` to authenticate with a configured identity provider.
3. The provider returns to the Spring Security OAuth2 login callback.
4. `FederatedLoginSuccessHandler` normalizes the identity and calls the backend's internal federated-user endpoint. The backend resolves or creates the Kanban user and returns the user ID and email.
5. The authorization server establishes the authenticated principal and completes OAuth authorization.
6. The client exchanges the authorization code at `/oauth2/token` for a signed JWT access token.

The Kanban backend remains the authority for user identity and resource authorization. The authorization server maps the federated identity to a Kanban user; it does not grant application permissions by itself.

## Token claims and keys

Access tokens include standard claims such as `iss`, `sub`, `aud`, `exp`, `jti` and `scope`, plus the Kanban user ID (`uid`) and email where available. MCP client tokens receive the configured MCP resource URI as their `aud` value. The web client is not assigned the MCP audience.

JWTs are signed asymmetrically. Resource servers validate signatures using the public keys published at:

```text
https://auth.ikoyski.top/oauth2/jwks
```

The issuer is:

```text
https://auth.ikoyski.top
```

Keep the issuer stable and consistent with gateway and MCP JWT validation configuration. Persist the signing key across restarts; an ephemeral key invalidates previously issued tokens after restart.

## Registered OAuth clients

Clients are seeded/upserted by `ClientSeeder` at application startup from Config Server properties. Do not edit `oauth2_registered_client` manually.

| Client | Purpose | Typical security model |
|---|---|---|
| Claude | MCP access | Configurable public or confidential client; PKCE |
| ChatGPT | MCP access | Optional; PKCE; public without a secret, confidential with a secret |
| Gemini | MCP access | Optional; PKCE; public without a secret, confidential with a secret |
| Kanban web | Browser application | Public client with PKCE |

MCP clients are assigned the configured resource URI through a custom registered-client setting. The access-token customizer copies that URI into the access token's `aud` claim. The browser client does not receive this MCP audience.

Optional ChatGPT and Gemini clients are seeded only when their client ID and at least one redirect URI are configured. A configured secret enables confidential-client authentication and rotating refresh tokens where supported by the client configuration. Public ChatGPT/Gemini clients do not receive refresh-token grants. Provider behavior and supported grants must be verified against the exact product integration.

### Redirect URI rules

- Register exact redirect URIs supplied by the OAuth client product. Never use wildcards.
- For ChatGPT, use the exact callback URL shown in the connector setup UI. Depending on the integration flow, this may be a callback-specific URL rather than the stable `/connector_platform_oauth_redirect` URI. The server's authorization-response issuer-identification behavior must also match the callback requirements.
- The configured Gemini callback is specific to the Gemini/Vertex AI integration that supplied it. Do not assume it applies to consumer Gemini, Gemini CLI or every Google AI product.
- Test the complete authorization-code flow with each product before enabling it for users.

## Config Server properties

The authorization server expects its issuer, database, federated-login provider, backend integration, signing-key paths and client registrations to be supplied through external configuration.

Representative MCP client configuration:

```yaml
auth:
  issuer: https://auth.ikoyski.top
  client:
    mcp:
      resource: https://api.ikoyski.top/kanban-mcp/mcp
    claude:
      # Existing Claude client configuration
    chatgpt:
      client-id: kanban-chatgpt
      client-secret: ${AUTH_CHATGPT_CLIENT_SECRET:}
      redirect-uris:
        - ${CHATGPT_OAUTH_REDIRECT_URI}
    gemini:
      client-id: kanban-gemini
      client-secret: ${AUTH_GEMINI_CLIENT_SECRET:}
      redirect-uris:
        - ${GEMINI_OAUTH_REDIRECT_URI}
```

The MCP resource URI must match the audience expected by the MCP resource server and the gateway's protected-resource configuration. It is a configured resource binding; the current implementation does not dynamically validate arbitrary RFC 8707 `resource` request parameters. Do not describe this as full dynamic RFC 8707 resource-indicator support.

Secrets and environment-specific values belong in the private Config Server/secret store or deployment environment, not in application source.

## Google identity provider setup

For Google sign-in, configure a Web application OAuth client and register the exact Spring Security callback:

```text
https://auth.ikoyski.top/login/oauth2/code/google
```

Configure the required OpenID Connect scopes (`openid`, `email`, `profile`) and publish/authorize the consent configuration for the intended users. Use a dedicated provider client for this server.

## Signing key setup

Generate and securely store an RSA key pair using an approved secret-management process. The private key must never be committed to Git. Configure the application with persistent private/public key file paths. Ensure the public key exposed through JWKS corresponds to the private signing key.

## Run and verify

Requirements: JDK 21, Maven, reachable PostgreSQL database, Config Server configuration, identity-provider credentials, backend internal integration and persistent signing keys.

```bash
./mvnw clean verify
./mvnw spring-boot:run
```

Inspect the published metadata and keys:

```bash
curl -s https://auth.ikoyski.top/.well-known/oauth-authorization-server
curl -s https://auth.ikoyski.top/oauth2/jwks
```

Verify the issuer, authorization-code grant, PKCE `S256`, token endpoint and signing key set. Then test a complete login and code exchange for every registered client.

## Deployment and operational notes

The service is deployed separately from the API gateway. Restrict and rate-limit public authentication endpoints such as `/oauth2/token` and login routes at the edge. Ensure the database, signing keys and authorization-server session configuration survive normal restarts.

## Development rules

- Keep the Kanban backend as the source of truth for Kanban users.
- Never log access tokens, client secrets, private keys or backend internal credentials.
- Keep redirect URI matching exact.
- Preserve PKCE for public and confidential authorization-code clients.
- Ensure only intended MCP clients receive the MCP resource audience.
- Keep client seeding idempotent and config-driven.
- Update README and `CLAUDE.md` when client registration, claims, login, key management or deployment behavior changes.
- Run `./mvnw clean verify`; do not claim live provider flows were tested unless they were actually executed.

## Related components

- `webtools-config-server` — externalized application configuration.
- `webtools-api-gateway` — public routing and gateway-side token/resource protection.
- `webtools-kanban-mcp` — MCP resource server that validates the issued JWT and forwards it to the Kanban API.
- `webtools-kanban` — Kanban frontend and user experience.
