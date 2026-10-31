# WebTools Identity Server

Spring Authorization Server built with Spring Boot 3.4.2 and Java 21. It is the shared identity provider for first-party Webtools applications and registered integrations. It authenticates people through configured identity providers (currently Google and GitHub), maintains a central person record, and issues OAuth 2.0 / OpenID Connect tokens to separate clients.

The identity server owns platform-wide identities and linked provider subjects in its own database. It does not own application data or application roles. Each resource server provisions its own local profile against the stable central identity ID and makes its own authorization decisions.

## Sign-in and token flow

1. An OAuth client redirects the browser to `/oauth2/authorize` using Authorization Code and PKCE (`S256`).
2. If there is no authorization-server session, the user is sent to the branded `/login` page, where they choose a configured identity provider.
3. The provider returns to the Spring Security OAuth2 login callback.
4. `FederatedLoginSuccessHandler` normalizes the provider identity and resolves or creates a central identity in the Auth Server's own database.
5. The authorization server establishes the central UUID as the authenticated principal and completes authorization.
6. The client exchanges the authorization code at `/oauth2/token` for a signed JWT access token and, when `openid` was requested, an OIDC ID token.
7. Each resource server validates issuer, signature, audience and its application scopes, then provisions/loads its own local user profile and applies application-specific permissions.

## Branded login page

The authorization server serves its provider-selection UI from `src/main/resources/static/login.html`. Requests to `/login` are routed by `LoginPageController` to that static page. Its Google and GitHub buttons use Spring Security's standard `/oauth2/authorization/{registrationId}` endpoints.

The page is presentation only. Provider registration, callback URLs, verified-identity handling, central identity resolution, OAuth authorization and token issuance remain server-side.

The same login session is shared across registered clients at this issuer (SSO). The identity server authenticates people; it does not grant Kanban board roles, Ipon permissions or other application permissions. Resource servers remain responsible for their own authorization.

## Token claims and keys

The stable central identity UUID is the token subject (`sub`) and is also emitted as the legacy `uid` claim so the current gateway can migrate without breaking. Tokens include `email` and, when available, `name` and `picture`. OIDC ID tokens include standard `email`, `email_verified`, `name` and `picture` claims for the requested scopes.

Each first-party application client can be assigned its own API resource URI. That URI is emitted as the access token `aud`; MCP clients continue to receive the configured MCP resource audience. Configure an exact audience for every resource server and reject tokens intended for other applications.

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
| Kanban web | Browser application | Public OIDC client with PKCE |
| Additional first-party apps | Configured browser applications | One public OIDC client per app, PKCE and app-specific API audience |

MCP clients are assigned the configured MCP resource URI. The access-token customizer copies it into `aud`. The Kanban web client has a separate `auth.client.web.resource-uri` setting. Additional first-party browser clients are configured under `auth.clients.applications`; each requires its own exact redirect URI list, scopes and API `resource-uri`.

Optional ChatGPT is seeded only when its client ID and at least one redirect URI are configured. Gemini is seeded when its client ID and MCP resource are configured; its redirect-uris list may be empty because Gemini supplies a user-bound callback at authorization time. A configured secret enables confidential-client authentication and rotating refresh tokens where supported by the client configuration. Public ChatGPT/Gemini clients do not receive refresh-token grants. Provider behavior and supported grants must be verified against the exact product integration.

### Redirect URI rules

- Register exact redirect URIs supplied by the OAuth client product. Never use wildcards.
- For ChatGPT, use the exact callback URL shown in the connector setup UI. Depending on the integration flow, this may be a callback-specific URL rather than the stable `/connector_platform_oauth_redirect` URI. The server's authorization-response issuer-identification behavior must also match the callback requirements.
- Gemini MCP uses a per-user callback under `https://oauth-redirect.googleusercontent.com/r/`. The auth server accepts only the Google redirect host and a `user_bound_custom-mcp-...` path whose final resource-host slug matches the configured MCP resource host. No per-user callback is stored in Config Server. The client seeder stores a reserved placeholder URI only because Spring requires a redirect URI on authorization-code client registrations; the Gemini validator never accepts that placeholder. This rule is limited to the Gemini client; every other client retains exact redirect URI matching.
- Test the complete authorization-code flow with each product before enabling it for users.

## Config Server properties

The identity server expects its issuer, database, federated-provider credentials, signing-key paths and OAuth client registrations to be supplied through external configuration.

For GitHub sign-in, the Config Server provides the `spring.security.oauth2.client.registration.github` properties (`client-id`, `client-secret`, and scopes `read:user`, `user:email`). Keep the OAuth App secret in the private configuration/secret store, not in the frontend repository.

Representative MCP client configuration:

```yaml
auth:
  issuer: https://auth.ikoyski.top
  client:
    web:
      resource-uri: https://api.example.com/kanban-backend
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
      redirect-uris: [] # Gemini supplies a per-user callback; validated by the auth server
```

The MCP resource URI must match the audience expected by the MCP resource server and the gateway's protected-resource configuration. It is a configured resource binding; the current implementation does not dynamically validate arbitrary RFC 8707 `resource` request parameters. Do not describe this as full dynamic RFC 8707 resource-indicator support.

Secrets and environment-specific values belong in the private Config Server/secret store or deployment environment, not in application source.

## Google identity provider setup

For Google sign-in, configure a Web application OAuth client and register the exact Spring Security callback:

```text
https://auth.ikoyski.top/login/oauth2/code/google
```

Configure the required OpenID Connect scopes (`openid`, `email`, `profile`) and publish/authorize the consent configuration for the intended users. Use a dedicated provider client for this server.

## GitHub identity provider setup

Create a GitHub OAuth App and configure its callback URL as:

```text
https://auth.ikoyski.top/login/oauth2/code/github
```

The Config Server registration uses the GitHub OAuth App's client ID and client secret with the `read:user` and `user:email` scopes. Spring Security loads the GitHub profile, and `GitHubOAuth2UserService` calls `GET https://api.github.com/user/emails` to select the primary email only when GitHub marks it as verified. The numeric GitHub account ID is the stable identity subject; the mutable GitHub login name and email are not used as identifiers.

The auth server must have the exact callback URL registered in the GitHub OAuth App. Do not request repository scopes: Kanban sign-in only needs the user's profile and verified email address.

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

- Keep this database as the source of truth for platform identity and provider-subject links.
- Never silently link two provider accounts by email; add account linking only as an explicit authenticated flow.
- Keep application profiles, memberships, roles and permissions in each application's own resource server.
- Never log access tokens, client secrets, private keys or backend internal credentials.
- Keep redirect URI matching exact for all clients except the narrowly validated Gemini user-bound callback. Never introduce wildcard matching.
- Preserve PKCE for public and confidential authorization-code clients.
- Ensure each resource client receives only its configured audience; never reuse one application's audience for another.
- Require exact audience and application-specific scopes at every resource server.
- Keep OIDC enabled and retain the stable central UUID as the subject.
- Keep client seeding idempotent and config-driven.
- Update README and `CLAUDE.md` when client registration, claims, login, key management or deployment behavior changes.
- Run `./mvnw clean verify`; do not claim live provider flows were tested unless they were actually executed.

## Related components

- `webtools-config-server` — externalized application configuration.
- `webtools-api-gateway` — public routing and gateway-side token/resource protection.
- `webtools-kanban-mcp` — MCP resource server that validates the issued JWT and forwards it to the Kanban API.
- `webtools-kanban` — Kanban frontend and user experience.
