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
 * Registers OAuth clients from configuration on every start (created if missing, updated if it
 * already exists), so configuration remains the source of truth.
 *
 * MCP clients are public OAuth clients and therefore use authorization code + PKCE. Each MCP
 * client is bound to the configured MCP resource URI; the token customizer uses that binding as
 * the access-token audience. Public clients do not receive refresh tokens from Spring Authorization
 * Server, so clients may need to re-authorize when their access token expires.
 */
@Component
public class ClientSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ClientSeeder.class);
    public static final String MCP_RESOURCE_SETTING = "mcp.resource";

    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final String claudeClientId;
    private final String claudeClientSecret;
    private final List<String> claudeRedirectUris;
    private final String webClientId;
    private final List<String> webRedirectUris;
    private final Duration webAccessTokenTtl;
    private final String mcpResource;
    private final String chatgptClientId;
    private final String chatgptClientSecret;
    private final List<String> chatgptRedirectUris;
    private final String geminiClientId;
    private final String geminiClientSecret;
    private final List<String> geminiRedirectUris;

    public ClientSeeder(RegisteredClientRepository clients,
                        PasswordEncoder passwordEncoder,
                        @Value("${auth.client.claude.client-id}") String claudeClientId,
                        @Value("${auth.client.claude.client-secret:}") String claudeClientSecret,
                        @Value("${auth.client.claude.redirect-uris}") List<String> claudeRedirectUris,
                        @Value("${auth.client.web.client-id:}") String webClientId,
                        @Value("${auth.client.web.redirect-uris:}") List<String> webRedirectUris,
                        @Value("${auth.client.web.access-token-ttl:PT8H}") Duration webAccessTokenTtl,
                        @Value("${auth.client.mcp.resource:}") String mcpResource,
                        @Value("${auth.client.chatgpt.client-id:}") String chatgptClientId,
                        @Value("${auth.client.chatgpt.client-secret:}") String chatgptClientSecret,
                        @Value("${auth.client.chatgpt.redirect-uris:}") List<String> chatgptRedirectUris,
                        @Value("${auth.client.gemini.client-id:}") String geminiClientId,
                        @Value("${auth.client.gemini.client-secret:}") String geminiClientSecret,
                        @Value("${auth.client.gemini.redirect-uris:}") List<String> geminiRedirectUris) {
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.claudeClientId = claudeClientId;
        this.claudeClientSecret = claudeClientSecret;
        this.claudeRedirectUris = claudeRedirectUris;
        this.webClientId = webClientId;
        this.webRedirectUris = webRedirectUris;
        this.webAccessTokenTtl = webAccessTokenTtl;
        this.mcpResource = mcpResource == null ? "" : mcpResource.trim();
        this.chatgptClientId = chatgptClientId;
        this.chatgptClientSecret = chatgptClientSecret;
        this.chatgptRedirectUris = chatgptRedirectUris;
        this.geminiClientId = geminiClientId;
        this.geminiClientSecret = geminiClientSecret;
        this.geminiRedirectUris = geminiRedirectUris;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedClaude();
        seedWeb();
        seedMcpClient(chatgptClientId, chatgptClientSecret, "ChatGPT MCP connector", chatgptRedirectUris);
        seedMcpClient(geminiClientId, geminiClientSecret, "Gemini MCP connector", geminiRedirectUris);
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
                .clientSettings(mcpClientSettings(true))
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

    private void seedMcpClient(String clientId, String clientSecret, String clientName, List<String> redirectUris) {
        List<String> uris = clean(redirectUris);
        if (isBlank(clientId) || uris.isEmpty()) {
            return;
        }
        if (isBlank(mcpResource)) {
            log.error("Cannot register MCP OAuth client '{}': auth.client.mcp.resource is not configured", clientId);
            return;
        }

        boolean confidential = !isBlank(clientSecret);
        TokenSettings.Builder tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofHours(1));
        RegisteredClient.Builder builder = base(clientId, clientName, uris)
                .scope("kanban.read")
                .scope("kanban.write")
                .clientSettings(mcpClientSettings(true))
                .tokenSettings(confidential
                        ? tokenSettings.refreshTokenTimeToLive(Duration.ofDays(30)).reuseRefreshTokens(false).build()
                        : tokenSettings.build());

        if (confidential) {
            builder.clientSecret(passwordEncoder.encode(clientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }
        save(builder.build());
    }

    private ClientSettings mcpClientSettings(boolean requireConsent) {
        ClientSettings.Builder builder = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(requireConsent);
        if (!isBlank(mcpResource)) {
            builder.setting(MCP_RESOURCE_SETTING, mcpResource);
        }
        return builder.build();
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
        return values == null ? List.of() : values.stream().map(String::trim).filter(v -> !v.isEmpty()).toList();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
