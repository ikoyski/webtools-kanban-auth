# webtools-auth-server

Spring Authorization Server (Spring Boot 3.4.2, Java 21). People sign in with Google (more providers later);
this server then issues OAuth access tokens to registered clients: the Claude connector now, the Kanban web UI next.
It owns no users and no passwords: the kanban backend owns the users, and this server asks it which user an
identity belongs to.

## How a sign-in works

1. A client (Claude) sends the browser to `https://auth.ikoyski.top/oauth2/authorize` (PKCE required).
2. Not signed in yet: the browser is sent to `/login`, which lists "Google".
3. Google authenticates the person and sends the browser back to `/login/oauth2/code/google`.
4. `FederatedLoginSuccessHandler` normalizes the Google identity and calls the backend
   `POST /internal/v1/users/federated`. The backend finds the user, or creates it on first sign-in, and returns `{id, email}`.
   It refuses unverified emails (403) and an email that belongs to another user (409).
5. The session's principal becomes the Kanban user id, the consent screen is shown (Claude only), and a code is issued.
6. The client exchanges the code at `/oauth2/token` for an access token (JWT).
   - **Claude connector:** a confidential client (client secret + PKCE). Access token 1 hour, refresh token 30 days, rotated on use.
   - **Kanban web UI:** a public client (PKCE, no secret). Spring Authorization Server never issues refresh tokens to public
     clients, so the UI gets a longer access token (default 8 hours) and signs in again when it expires. That is silent while the
     auth server's own session (7 days) is valid.

Access token claims: `sub` = user id, `uid` = user id, `email`, `iss`, `aud`, `exp`, `jti`, `scope`. The signing key is
asymmetric; services verify tokens with the public keys at `/oauth2/jwks`.

## 1. Google Cloud

- APIs & Services > Credentials > Create OAuth client ID > **Web application**.
- Authorized redirect URI: `https://auth.ikoyski.top/login/oauth2/code/google` (exactly).
- OAuth consent screen: scopes `openid`, `email`, `profile`; **publish it to production**, otherwise only listed test users can sign in.
- Keep the client ID and secret for the environment below. Use a separate OAuth client from any Google button in the web UI.

## 2. Signing key (once)

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out auth-private.pem
    openssl rsa -in auth-private.pem -pubout -out auth-public.pem

Keep `auth-private.pem` out of git (add `*.pem` to `.gitignore` first). Without a key the app generates an ephemeral one
and logs a warning; tokens then stop validating after a restart.

## 3. Environment

    AUTH_ISSUER=https://auth.ikoyski.top
    AUTH_DB_URL=jdbc:postgresql://<host>:5432/authdb
    AUTH_DB_USER=auth
    AUTH_DB_PASSWORD=...
    AUTH_GOOGLE_CLIENT_ID=...
    AUTH_GOOGLE_CLIENT_SECRET=...
    AUTH_BACKEND_BASE_URL=http://<backend internal host>:<port>/kanban-backend   # internal, never the public gateway
    AUTH_BACKEND_INTERNAL_KEY=<long random string; same value as the backend's INTERNAL_API_KEY>
    AUTH_JWK_PRIVATE_KEY_FILE=/path/auth-private.pem
    AUTH_JWK_PUBLIC_KEY_FILE=/path/auth-public.pem

Claude connector secret (generate one with `openssl rand -base64 36`; you enter the same value in the connector's advanced settings):

    AUTH_CLAUDE_CLIENT_SECRET=...

Optional, for the web UI (leave empty until the UI signs in through this server):

    AUTH_WEB_CLIENT_ID=kanban-web
    AUTH_WEB_REDIRECT_URIS=https://pages.ikoyski.top/<callback page>
    AUTH_CORS_ALLOWED_ORIGINS=https://pages.ikoyski.top
    AUTH_LOGOUT_REDIRECTS=https://pages.ikoyski.top/kanban/kanban.html
    AUTH_WEB_ACCESS_TOKEN_TTL=PT8H

The app refuses to start without the Google settings or `AUTH_BACKEND_INTERNAL_KEY`. Do not set a servlet context path:
the issuer must be a bare origin. Create the `authdb` database and role first; Flyway (`db/migration/V1__oauth2_schema.sql`) creates the tables.

## 4. Run and check

    mvn spring-boot:run

    curl -s https://auth.ikoyski.top/.well-known/oauth-authorization-server | jq .
    curl -s https://auth.ikoyski.top/oauth2/jwks | jq .

Expect the issuer `https://auth.ikoyski.top`, `S256` in `code_challenge_methods_supported`, and one RSA key.
Then open `https://auth.ikoyski.top/login` in a browser: it should list Google.

## 5. Cloudflare

Add a second public hostname on the existing tunnel: `auth.ikoyski.top` -> `http://<this host>:8086`.
This host is not behind the gateway, so add a Cloudflare rate-limiting rule for `/oauth2/token` and `/login/**`.

## 6. Adding another provider

Add a registration under `spring.security.oauth2.client.registration`, one branch in `IdentityNormalizer`, and the
provider name to `InternalUserService.ALLOWED_PROVIDERS` in the backend. No schema change. Microsoft and GitHub need care
with email: see the comments in `IdentityNormalizer`.

## 7. Clients are config-driven

`ClientSeeder` creates or updates the clients on every start, so changing a redirect URI, the secret or a lifetime is a config
change plus a restart. Do not edit `oauth2_registered_client` by hand. `GET /logout?redirect=<url>` signs the person out of this
server and returns them to an allow-listed URL.

## 8. Still to do elsewhere

- Gateway: verify tokens from this issuer (JWKS) in `AuthenticationFilter`, next to the existing login tokens, and read
  `uid` and `email` from them.
- MCP route: answer unauthenticated requests with a `WWW-Authenticate` header pointing at the protected-resource
  metadata, and serve that document.
- Web UI: sign in through this server (authorization code + PKCE) instead of the password form.
