package com.ikoyski.webtools.authserver.config;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * Pre-registers the OAuth clients. Dynamic client registration is off, so this is the only way in.
 * Both are public clients (no secret) that must use PKCE:
 *   - the Claude connector: asks the user for consent;
 *   - the Kanban web UI: first-party, so no consent screen. Registered only when
 *     auth.client.web.client-id and its redirect URIs are set.
 * A client is created only if it does not exist yet; to change its redirect URIs later, delete the row
 * from oauth2_registered_client and restart.
 */
@Component
public class ClientSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ClientSeeder.class);

    private final RegisteredClientRepository clients;
    private final String claudeClientId;
    private final List<String> claudeRedirectUris;
    private final String webClientId;
    private final List<String> webRedirectUris;

    public ClientSeeder(RegisteredClientRepository clients,
                        @Value("${auth.client.claude.client-id}") String claudeClientId,
                        @Value("${auth.client.claude.redirect-uris}") List<String> claudeRedirectUris,
                        @Value("${auth.client.web.client-id:}") String webClientId,
                        @Value("${auth.client.web.redirect-uris:}") List<String> webRedirectUris) {
        this.clients = clients;
        this.claudeClientId = claudeClientId;
        this.claudeRedirectUris = claudeRedirectUris;
        this.webClientId = webClientId;
        this.webRedirectUris = webRedirectUris;
    }

    @Override
    public void run(ApplicationArguments args) {
        seed(claudeClientId, "Claude connector", claudeRedirectUris, true,
                Duration.ofHours(1), Duration.ofDays(30));
        seed(webClientId, "Kanban web UI", webRedirectUris, false,
                Duration.ofMinutes(30), Duration.ofDays(7));
    }

    private void seed(String clientId, String name, List<String> redirectUris, boolean requireConsent,
                      Duration accessTtl, Duration refreshTtl) {
        List<String> uris = redirectUris.stream().map(String::trim).filter(u -> !u.isEmpty()).toList();
        if (clientId == null || clientId.isBlank() || uris.isEmpty()) {
            return;
        }
        if (clients.findByClientId(clientId) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(name)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("kanban.read")
                .scope("kanban.write")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(requireConsent)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(accessTtl)
                        .refreshTokenTimeToLive(refreshTtl)
                        .reuseRefreshTokens(false)
                        .build());
        uris.forEach(builder::redirectUri);
        clients.save(builder.build());
        log.info("Registered OAuth client '{}'", clientId);
    }
}
