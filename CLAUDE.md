# CLAUDE.md

## Project role

This repository is the OAuth 2.0 / OpenID Connect authorization server for the Kanban platform. It uses Spring Authorization Server on Spring Boot 3.4.2 / Java 21.

It authenticates people through configured federated identity providers and maps those identities to Kanban users through the backend's internal federated-user API. The Kanban backend remains the source of truth for users and application authorization. This service owns OAuth client registrations, authorizations, consents and token issuance—not Kanban passwords or board data.

## Core sign-in flow

- OAuth clients use Authorization Code with PKCE (`S256`).
- Spring Security redirects unauthenticated users to the federated login page.
- The identity-provider callback is normalized by `IdentityNormalizer`.
- `FederatedLoginSuccessHandler` resolves the identity through the backend internal API.
- The authenticated principal is the Kanban user identity.
- Spring Authorization Server issues signed JWT access tokens.

Do not bypass federated identity resolution or create a separate user store in this service.

## Client registration and seeding

`ClientSeeder` creates or updates registered clients at startup using Config Server properties. Keep this idempotent and config-driven; do not instruct operators to edit the registered-client database table manually.

Current client types include:
- Claude MCP client.
- Optional ChatGPT MCP client.
- Optional Gemini MCP client.
- Kanban browser/web client.

ChatGPT registration is optional and requires a client ID plus at least one exact redirect URI. Gemini registration is optional and requires a client ID plus the configured MCP resource; its redirect URI list may be empty because Gemini generates a per-user callback. PKCE is required for both. A configured client secret makes the client confidential and enables client authentication; public clients use no client authentication and do not receive refresh-token grants. Keep provider-specific behavior aligned with the actual integration product.

## Federated identity providers

Currently enabled: Google (OIDC) and GitHub (OAuth 2.0).

- Google identity normalization uses the OIDC subject and the provider's `email_verified` claim.
- GitHub is a plain OAuth 2.0 provider. `GitHubOAuth2UserService` loads the profile and fetches `/user/emails` with the `user:email` scope. Accept only the email GitHub marks both `primary` and `verified`.
- Use the numeric GitHub account `id` as the stable subject. Never use the mutable GitHub login name or email as the identity key.
- The backend's `InternalUserService.ALLOWED_PROVIDERS` must allow each provider. Never merge a new provider identity into an existing account just because the emails match.
- GitHub callback: `https://auth.ikoyski.top/login/oauth2/code/github`. Keep it exact in the GitHub OAuth App settings.

## MCP resource audience

The MCP resource URI is configured under `auth.client.mcp.resource`. `ClientSeeder` stores it as a custom registered-client setting for MCP clients. The access-token customizer adds this configured URI to the JWT `aud` claim for those clients. The web client must not receive the MCP audience.

This is a fixed per-client resource binding. The current implementation does not dynamically validate arbitrary RFC 8707 `resource` parameters. Do not claim full dynamic resource-indicator support unless that implementation is added and tested.

The MCP audience must exactly match the MCP service's configured `security.oauth2.audience` and the gateway's protected-resource configuration.

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
- `FederatedLoginSuccessHandler` — federated login completion and Kanban user resolution.
- `IdentityNormalizer` — provider identity normalization.
- `GitHubOAuth2UserService` — GitHub profile loading and verified-primary-email resolution.
- `InternalUserService` — backend user lookup/provisioning integration.
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

Runtime configuration is primarily externalized through the private Spring Config Server. It includes issuer, database connectivity, federated provider credentials, backend internal API settings, signing-key paths and OAuth client settings.

Never commit secrets, client credentials, backend internal keys, database passwords or private keys. Do not copy production secret values into examples or test fixtures.

## Security invariants

- Require PKCE for authorization-code clients.
- Keep redirect URIs exact for all clients except the narrowly validated Gemini user-bound callback.
- Do not weaken client authentication for confidential clients.
- Do not grant MCP audience to the browser client.
- Do not issue tokens for unverified or incorrectly linked external identities.
- Do not trust client-supplied identity claims as a substitute for backend identity resolution.
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
