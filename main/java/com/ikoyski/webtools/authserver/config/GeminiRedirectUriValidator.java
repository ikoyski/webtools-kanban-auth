package com.ikoyski.webtools.authserver.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.stereotype.Component;

@Component
public final class GeminiRedirectUriValidator {
    private static final String GOOGLE_REDIRECT_HOST = "oauth-redirect.googleusercontent.com";
    private static final String CALLBACK_PREFIX = "/r/user_bound_custom-mcp-";
    private final String resourceHostSlug;

    public GeminiRedirectUriValidator(@Value("${auth.client.mcp.resource:}") String mcpResource) {
        this.resourceHostSlug = resourceHostSlug(mcpResource);
    }

    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        String redirectUri = context.getAuthentication().getRedirectUri();
        if (!isValidRedirectUri(redirectUri, resourceHostSlug)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Invalid Gemini redirect URI", null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }

    static boolean isValidRedirectUri(String redirectUri, String expectedResourceHostSlug) {
        if (redirectUri == null || expectedResourceHostSlug == null || expectedResourceHostSlug.isBlank()) {
            return false;
        }
        try {
            URI uri = new URI(redirectUri);
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || !GOOGLE_REDIRECT_HOST.equalsIgnoreCase(uri.getHost())
                    || uri.getPort() != -1
                    || uri.getRawUserInfo() != null
                    || uri.getRawQuery() != null
                    || uri.getRawFragment() != null
                    || uri.isOpaque()) {
                return false;
            }
            String pathPattern = Pattern.quote(CALLBACK_PREFIX)
                    + "[A-Za-z0-9_-]{1,256}-" + Pattern.quote(expectedResourceHostSlug);
            return Pattern.matches(pathPattern, uri.getRawPath());
        } catch (URISyntaxException ex) {
            return false;
        }
    }

    private static String resourceHostSlug(String resource) {
        if (resource == null || resource.isBlank()) {
            return null;
        }
        try {
            URI uri = new URI(resource);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getPort() != -1 || uri.getRawUserInfo() != null) {
                return null;
            }
            return uri.getHost().toLowerCase(Locale.ROOT).replace('.', '_');
        } catch (URISyntaxException ex) {
            return null;
        }
    }
}