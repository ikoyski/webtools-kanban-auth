package com.ikoyski.webtools.authserver.config;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * Registers the OAuth clients from configuration on every start (created if missing, updated if it
 * already exists), so the configuration is the source of truth. Dynamic client registration is off.
 *
 * IMPORTANT: Spring Authorization Server never issues refresh tokens to PUBLIC clients (no client secret).
 *   - Claude connector: registered as a CONFIDENTIAL client (client secret, PKCE still required) so it gets
 *     refresh tokens and stays connected. Claude's cloud holds the secret; you enter it in the connector's
 *     advanced settings. Set auth.client.claude.client-secret. Without a secret it falls back to a public
 *     client with a warning, and the connector would have to sign in again every time the access token expires.
 *   - Kanban web UI: a public client (a browser app cannot keep a secret), PKCE required, no refresh token.
 *     It gets a longer-lived access token instead and signs in again, silently if the auth session is
 *     still valid, when it expires. Registered only when its client id and redirect URIs are set.
 */
@Component
public class ClientSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ClientSeeder.class);

    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final String claudeClientId;
    private final String claudeClientSecret;
    private final List<String> claudeRedirectUris;
    private final String webClientId;
    private final List<String> webRedirectUris;
    private final Duration webAccessTokenTtl;

    public ClientSeeder(RegisteredClientRepository clients,
                        PasswordEncoder passwordEncoder,
                        @Value("${auth.client.claude.client-id}") String claudeClientId,
                        @Value("${auth.client.claude.client-secret:}") String claudeClientSecret,
                        @Value("${auth.client.claude.redirect-uris}") List<String> claudeRedirectUris,
                        @Value("${auth.client.web.client-id:}") String webClientId,
                        @Value("${auth.client.web.redirect-uris:}") List<String> webRedirectUris,
                        @Value("${auth.client.web.access-token-ttl:PT8H}") Duration webAccessTokenTtl) {
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.claudeClientId = claudeClientId;
        this.claudeClientSecret = claudeClientSecret;
        this.claudeRedirectUris = claudeRedirectUris;
        this.webClientId = webClientId;
        this.webRedirectUris = webRedirectUris;
        this.webAccessTokenTtl = webAccessTokenTtl;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedClaude();
        seedWeb();
    }

    private void seedClaude() {
        List<String> uris = clean(claudeRedirectUris);
        if (isBlank(claudeClientId) || uris.isEmpty()) {
            return;
        }
        boolean confidential = !isBlank(claudeClientSecret);
        if (!confidential) {
            log.warn("auth.client.claude.client-secret is not set: registering '{}' as a PUBLIC client. "
                    + "No refresh tokens will be issued, so the connector must sign in again whenever its access token expires.",
                    claudeClientId);
        }

        RegisteredClient.Builder builder = base(claudeClientId, "Claude connector", uris)
                .scope("kanban.read")
                .scope("kanban.write")
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build());
        builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        if (confidential) {
            builder.clientSecret(passwordEncoder.encode(claudeClientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }
        save(builder.build());
    }

    private void seedWeb() {
        List<String> uris = clean(webRedirectUris);
        if (isBlank(webClientId) || uris.isEmpty()) {
            return;
        }
        RegisteredClient.Builder builder = base(webClientId, "Kanban web UI", uris)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .scope("kanban.read")
                .scope("kanban.write")
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(webAccessTokenTtl)
                        .build());
        save(builder.build());
    }

    /** Reuses the stored id when the client already exists, so saving updates the row instead of inserting. */
    private RegisteredClient.Builder base(String clientId, String name, List<String> redirectUris) {
        RegisteredClient existing = clients.findByClientId(clientId);
        RegisteredClient.Builder builder = RegisteredClient
                .withId(existing != null ? existing.getId() : UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(name)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        redirectUris.forEach(builder::redirectUri);
        return builder;
    }

    private void save(RegisteredClient client) {
        clients.save(client);
        log.info("Registered OAuth client '{}' ({})", client.getClientId(),
                client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE) ? "public" : "confidential");
    }

    private static List<String> clean(List<String> values) {
        return values.stream().map(String::trim).filter(v -> !v.isEmpty()).toList();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
