# Onboarding a first-party Webtools application

This guide registers a browser application with the shared Webtools Identity Server and connects its API to the gateway. The identity server authenticates the person; the new application owns its local profile, roles, memberships and permissions.

## 1. Choose the application's resource boundary

Assign the application a unique, stable API resource URI, for example:

- Kanban API: `https://api.ikoyski.top/kanban-backend`
- Ipon API: `https://api.ikoyski.top/ipon-api`

The value must be identical in the Identity Server client registration and the API Gateway route. Do not reuse another application's audience.

Define application-specific scopes. Use a read scope for safe methods and a write scope for mutations (for example, `ipon.read` and `ipon.write`). Keep application roles and fine-grained permissions in the application's own database.

## 2. Register the browser OAuth client

Add an entry under `auth.clients.applications` in the private Config Server configuration for `webtools-kanban-auth`:

```yaml
auth:
  clients:
    applications:
      - client-id: ipon-web
        name: Ipon
        redirect-uris:
          - https://ipon.ikoyski.top/auth/callback
        scopes:
          - openid
          - profile
          - email
          - ipon.read
          - ipon.write
        resource-uri: https://api.ikoyski.top/ipon-api
```

Requirements:

- Use a unique client ID per browser application.
- Register every callback URL exactly, including scheme, host, path and trailing slash.
- Browser clients are public clients: do not configure a client secret.
- Authorization Code with PKCE (`S256`) is required.
- Request `openid` when the client needs an OIDC ID token. Request `profile` and `email` only when those standard claims are needed.
- The API audience is set from `resource-uri`; it is not a scope and must not be sent as one.
- Do not include another application's audience or scopes.

The Identity Server's Google and GitHub provider callbacks remain on the Identity Server (for example, `https://auth.ikoyski.top/login/oauth2/code/google`). They are not the browser application's callback URLs.

## 3. Configure CORS and logout redirects

Add the browser origin to the Identity Server's `auth.cors.allowed-origins` list so the browser can exchange its authorization code at `/oauth2/token` and call OIDC UserInfo when needed.

Add the exact post-logout return URL to `auth.logout.allowed-redirects`. The application should call the Identity Server's `/logout?redirect=<url>` endpoint with that allow-listed URL. Never use an unrestricted redirect or wildcard.

Also add the browser origin to the API Gateway's CORS allow-list. Allow only the methods and headers the application needs (normally `Authorization` and `Content-Type`); do not enable credentialed CORS unless cookie-based cross-origin access is deliberately required.

## 4. Configure the API Gateway route

For the protected application API route, configure the exact resource audience and both method scopes:

```yaml
- id: ipon-api-protected
  uri: lb://ipon-api
  predicates:
    - Path=/ipon-api/v1/**
  filters:
    - name: AuthenticationFilter
      args:
        audience: https://api.ikoyski.top/ipon-api
        readScope: ipon.read
        writeScope: ipon.write
```

Keep `AuthenticationFilter` before user-keyed rate limiting. Public routes must not trust caller-supplied `X-User-*` headers; remove those headers on public routes. Protected routes replace identity headers from the verified token.

CORS preflight requests must be handled by the Gateway CORS layer before the authentication filter. Do not solve preflight failures by allowing unauthenticated application API requests.

## 5. Provision and authorize local users

The gateway validates the token's signature, issuer, expiry, audience and required scope. It forwards identity claims from the verified token, including the central UUID (`sub`, also exposed as compatibility `uid`), email and optional profile fields.

The application must:

1. Treat the central UUID as the external identity key.
2. Create or load its own local user profile on first authenticated use.
3. Store application-specific roles, memberships and permissions locally.
4. Enforce its own authorization rules on every protected operation.
5. Never query another application's user database or rely on identity headers from unprotected routes.

If a service is directly reachable by untrusted clients, forwarded identity headers can be forged. Restrict downstream network access to the trusted Gateway or make that service independently validate JWTs.

## 6. Apply and verify the registration

1. Add the client and allow-list entries to the private Config Server repository.
2. Restart or refresh the Identity Server so `ClientSeeder` upserts the registration.
3. Restart or refresh the Gateway so its route and CORS configuration are active.
4. Verify the authorization request uses the exact registered redirect URI and PKCE `S256`.
5. Sign in with Google and GitHub and confirm both resolve to the same central identity only when they are explicitly linked; matching email addresses alone must not link accounts.
6. Decode a test access token and verify `iss`, `sub`, `uid`, `aud`, `exp` and `scope`.
7. Confirm a token for another application's audience is rejected with `401`, and a missing method scope is rejected with `403`.
8. Verify the app provisions its local profile and enforces its own permissions.

### Special case: delegated MCP clients

A client whose service forwards the user's delegated access token to a second API needs both resource audiences. For Kanban MCP, configure the MCP resource and the backing Kanban API resource using `auth.client.mcp.resource` and `auth.client.mcp.backend-resource`. The Gateway's MCP route validates the MCP audience; the backing API route independently validates the Kanban API audience and Kanban scopes.

Ordinary browser clients must receive only their own API audience.
