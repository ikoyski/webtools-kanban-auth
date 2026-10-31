# CLAUDE.md

## Project role

This repository is the shared Webtools Identity Server. It uses Spring Authorization Server on Spring Boot 3.4.2 / Java 21 and supports OAuth 2.0 plus OpenID Connect.

It authenticates people through configured federated identity providers and owns central person records plus linked provider subjects in its own database. It does not own application data, app-local profiles, memberships, roles or permissions. Each resource server provisions its local profile against the central UUID and makes its own authorization decisions.

## Core sign-in flow

- OAuth clients use Authorization Code with PKCE (`S256`).
- Spring Security redirects unauthenticated users to the federated login page.
- The identity-provider callback is normalized by `IdentityNormalizer`.
- `FederatedLoginSuccessHandler` resolves/creates the person through `CentralIdentityService` and the Auth Server's own database.
- The authenticated principal name is the stable central identity UUID. This becomes token `sub` and the compatibility `uid` claim.
- OpenID Connect is enabled; requests with `openid` receive an ID token and can use the UserInfo endpoint.
- Resource access tokens carry the audience configured for their OAuth client and application-specific scopes.

Never call an application backend to establish the platform identity. Never store app roles or permissions in this service. Do not link identities solely because their email addresses match.

## Client registration and seeding

`ClientSeeder` creates or updates registered clients at startup using Config Server properties. Keep this idempotent and config-driven; do not instruct operators to edit the registered-client database table manually.

Current client types include:
- Claude MCP client.
- Optional ChatGPT MCP client.
- Optional Gemini MCP client.
- Kanban browser/web client.
- Additional first-party browser applications configured under `auth.clients.applications`.

ChatGPT registration is optional and requires a client ID plus at least one exact redirect URI. Gemini registration is optional and requires a client ID plus the configured MCP resource; its redirect URI list may be empty because Gemini generates a per-user callback. PKCE is required for both. A configured client secret makes the client confidential and enables client authentication; public clients use no client authentication and do not receive refresh-token grants. Keep provider-specific behavior aligned with the actual integration product.

## Federated identity providers

Currently enabled: Google (OIDC) and GitHub (OAuth 2.0).

- Google identity normalization uses the OIDC subject and the provider's `email_verified` claim.
- GitHub is a plain OAuth 2.0 provider. `GitHubOAuth2UserService` loads the profile and fetches `/user/emails` with the `user:email` scope. Accept only the email GitHub marks both `primary` and `verified`.
- Use the numeric GitHub account `id` as the stable subject. Never use the mutable GitHub login name or email as the identity key.
- `CentralIdentityService.ALLOWED_PROVIDERS` must allow each enabled provider. Never merge a new provider identity into an existing account just because the emails match. Account linking must be an explicit authenticated flow.
- GitHub callback: `https://auth.ikoyski.top/login/oauth2/code/github`. Keep it exact in the GitHub OAuth App settings.

## Branded login page

- The provider-selection UI is `src/main/resources/static/login.html`; it is plain HTML/CSS and must not require a frontend build or template engine.
- `LoginPageController` maps `GET /login` to the static `/login.html` resource.
- `SecurityConfig` must set `oauth2Login().loginPage("/login")` and permit anonymous access to `/login` and `/login.html`. The authorization-server HTML entry point remains `/login`.
- Provider buttons use the standard `/oauth2/authorization/google` and `/oauth2/authorization/github` endpoints. Styling changes must not alter provider registration IDs, callbacks, identity normalization, success handling, client registrations, PKCE or token behavior.
- The static page is shared by all OAuth clients that need interactive sign-in; do not move provider selection into the Kanban frontend.

## MCP resource audience

Each resource client has a fixed audience. MCP clients use `auth.client.mcp.resource`; the Kanban web client uses `auth.client.web.resource-uri`; additional first-party browser clients use their `resource-uri` under `auth.clients.applications`. The access-token customizer emits only that registered client's audience. Keep MCP and first-party API audiences separate.

This is a fixed per-client resource binding, not dynamic RFC 8707 resource-indicator support. Every gateway/resource server must validate the exact expected audience and required application scopes. A valid signature and issuer alone are not sufficient.

## Redirect URI requirements

- Redirect URI matching must remain exact for every client except the Gemini-specific validated callback described below; never add wildcard callbacks.
- Gemini user-bound callbacks must use HTTPS, the exact host `oauth-redirect.googleusercontent.com`, and the `/r/user_bound_custom-mcp-...-<resource-host-slug>` path. The suffix is derived from the host of `auth.client.mcp.resource` by replacing dots with underscores. Reject ports, user-info, query strings, fragments, other hosts and malformed paths. Config Server may set `redirect-uris: []`; `ClientSeeder` adds a reserved placeholder because Spring requires a redirect URI on authorization-code client registrations, and the validator must never accept that placeholder.
- Mark only the Gemini registered client with `gemini.dynamic-redirect-uri=true`; the authorization endpoint uses that marker to select the Gemini validator. All other clients continue to use Spring Authorization Server's default exact-match redirect validator. Keep the default scope validator for every client.
- Use the callback URL shown by the specific OAuth client product.
- ChatGPT may show a callback-specific connector URI; do not assume the stable callback is universally correct. Confirm the authorization server's issuer-identification behavior against the product requirements.
- Test a full browser authorization and token exchange for each provider/client before enabling it in production.

## Important implementation areas

- `ClientSeeder` — config-driven client creation/update, public/confidential client behavior, MCP resource binding and the Gemini dynamic-redirect client marker.
- `GeminiRedirectUriValidator` — strict validation of Gemini's user-bound callback against the configured MCP resource host.
- `AuthorizationServerConfig` — authorization server components and JWT access-token customization.
- `FederatedLoginSuccessHandler` — federated login completion and central identity resolution.
- `CentralIdentityService` — owns central identities and provider-subject mappings.
- `ApplicationClientProperties` / `ClientSeeder` — registers app-specific browser clients.
- `IdentityNormalizer` — provider identity normalization.
- `GitHubOAuth2UserService` — GitHub profile loading and verified-primary-email resolution.
- `src/main/resources` — application and Config Server configuration.
- `db/migration` — Flyway schema migrations.

Inspect the current implementation before changing any assumptions. Keep documentation aligned with actual source behavior.

## JWT and signing keys

- Issuer: configured by `auth.issuer`; production services must use the exact same issuer.
- JWKS endpoint: `/oauth2/jwks`.
- Access tokens are asymmetrically signed.
- Resource servers validate the signature using the published JWKS, plus issuer, expiry and audience.
- The signing key must persist across restarts. An ephemeral key invalidates previously issued tokens.
- Never commit private keys or log key material.

Keep custom claims limited to required identity/resource data. Ensure MCP audience customization applies only to the intended MCP clients and only to access tokens.

## Configuration and secrets

Runtime configuration is primarily externalized through the private Spring Config Server. It includes issuer, database connectivity, federated provider credentials, signing-key paths, app client registrations and exact resource audiences.

Never commit secrets, client credentials, backend internal keys, database passwords or private keys. Do not copy production secret values into examples or test fixtures.

## Security invariants

- Require PKCE for authorization-code clients.
- Keep redirect URIs exact for all clients except the narrowly validated Gemini user-bound callback.
- Do not weaken client authentication for confidential clients.
- Never grant one application's audience to another client.
- Require per-application scopes and exact audience checks at resource servers.
- Keep app-specific roles and permissions out of the identity server.
- Do not issue tokens for unverified or incorrectly linked external identities.
- Treat external provider attributes as untrusted until validated by the configured provider service and normalized by the server.
- Never let a client supply its own identity, roles, scopes or audience claims.
- Never log tokens, secrets or private key material.
- Keep authorization-server issuer and JWKS configuration aligned with the gateway and MCP resource server.

## Development workflow

Use JDK 21 and Maven Wrapper:

```bash
./mvnw clean verify
./mvnw spring-boot:run
```

Before completing a change:
1. Add or update tests for client seeding, token claims, identity mapping or security behavior as appropriate.
2. Run `./mvnw clean verify`.
3. Verify the relevant OAuth metadata and JWKS.
4. For provider/client changes, test a real authorization-code + PKCE flow using the exact redirect URI.
5. Update README and this file when behavior or operations change.

Never report a build, provider integration or end-to-end OAuth test as passing unless it was actually run.
