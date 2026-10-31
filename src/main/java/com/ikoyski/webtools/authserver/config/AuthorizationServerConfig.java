package com.ikoyski.webtools.authserver.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.ikoyski.webtools.authserver.identity.CentralIdentityService;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(@Value("${auth.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, clients);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                         RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients);
    }

    /**
     * Access tokens carry the stable central identity ID in the compatibility uid claim. Each configured
     * resource client receives only its own audience. OIDC ID tokens carry standard profile claims.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(CentralIdentityService identities) {
        return context -> {
            boolean accessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            boolean idToken = OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue());
            if (!accessToken && !idToken) {
                return;
            }

            Authentication principal = context.getPrincipal();
            CentralIdentityService.Identity user;
            try {
                user = identities.findById(principal.getName()).orElse(null);
            } catch (RuntimeException e) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Central identity lookup failed", null), e);
            }
            if (user == null || !user.active()) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, "Central identity no longer exists", null));
            }

            if (accessToken) {
                Object resource = context.getRegisteredClient().getClientSettings()
                        .getSetting(ClientSeeder.RESOURCE_URI_SETTING);
                if (!(resource instanceof String)) {
                    resource = context.getRegisteredClient().getClientSettings()
                            .getSetting(ClientSeeder.MCP_RESOURCE_SETTING);
                }
                if (resource instanceof String resourceUri && !resourceUri.isBlank()) {
                    List<String> audiences = new java.util.ArrayList<>();
                    audiences.add(resourceUri);
                    Object additionalResource = context.getRegisteredClient().getClientSettings()
                            .getSetting(ClientSeeder.MCP_BACKEND_RESOURCE_SETTING);
                    if (additionalResource instanceof String additionalUri && !additionalUri.isBlank()
                            && !audiences.contains(additionalUri)) {
                        audiences.add(additionalUri);
                    }
                    context.getClaims().audience(audiences);
                }
                // uid remains for compatibility with existing gateways; it is now the central identity ID.
                context.getClaims().claim("uid", user.id()).claim("email", user.email());
                if (user.displayName() != null) context.getClaims().claim("name", user.displayName());
                if (user.avatarUrl() != null) context.getClaims().claim("picture", user.avatarUrl());
            } else {
                // OIDC profile claims are returned only when the matching standard scope was granted.
                if (context.getAuthorizedScopes().contains("email")) {
                    context.getClaims().claim("email", user.email()).claim("email_verified", true);
                }
                if (context.getAuthorizedScopes().contains("profile")) {
                    if (user.displayName() != null) context.getClaims().claim("name", user.displayName());
                    if (user.avatarUrl() != null) context.getClaims().claim("picture", user.avatarUrl());
                }
            }
        };
    }
}
