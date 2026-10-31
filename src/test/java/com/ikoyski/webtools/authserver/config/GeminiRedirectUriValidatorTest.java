package com.ikoyski.webtools.authserver.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class GeminiRedirectUriValidatorTest {

    private static final String RESOURCE_HOST_SLUG = "api_ikoyski_top";

    @Test
    void acceptsGeminiUserBoundCallbackForConfiguredMcpHost() {
        assertTrue(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-108973557860806982617-api_ikoyski_top",
                RESOURCE_HOST_SLUG));
    }

    @Test
    void acceptsDifferentUserBoundCallbackIdentifiers() {
        assertTrue(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-another_user-123-api_ikoyski_top",
                RESOURCE_HOST_SLUG));
    }

    @Test
    void rejectsOtherHostsAndInsecureSchemes() {
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://example.com/r/user_bound_custom-mcp-123-api_ikoyski_top", RESOURCE_HOST_SLUG));
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "http://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-api_ikoyski_top",
                RESOURCE_HOST_SLUG));
    }

    @Test
    void rejectsPortsQueriesFragmentsAndUserInfo() {
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com:443/r/user_bound_custom-mcp-123-api_ikoyski_top",
                RESOURCE_HOST_SLUG));
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-api_ikoyski_top?next=https://evil.example",
                RESOURCE_HOST_SLUG));
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-api_ikoyski_top#fragment",
                RESOURCE_HOST_SLUG));
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://user@oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-api_ikoyski_top",
                RESOURCE_HOST_SLUG));
    }

    @Test
    void rejectsUnexpectedResourceHostSuffixAndMalformedPaths() {
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-other_server",
                RESOURCE_HOST_SLUG));
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-api_ikoyski_top/extra",
                RESOURCE_HOST_SLUG));
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp--api_ikoyski_top",
                RESOURCE_HOST_SLUG));
    }

    @Test
    void rejectsWhenMcpResourceHostCannotBeDerived() {
        assertFalse(GeminiRedirectUriValidator.isValidRedirectUri(
                "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-123-api_ikoyski_top",
                null));
    }
}