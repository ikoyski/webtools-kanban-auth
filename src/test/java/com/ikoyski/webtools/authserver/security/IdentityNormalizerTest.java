package com.ikoyski.webtools.authserver.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import com.ikoyski.webtools.authserver.identity.CentralIdentityService.FederatedIdentity;

class IdentityNormalizerTest {

    private final IdentityNormalizer normalizer = new IdentityNormalizer();

    private static DefaultOidcUser googleUser(Object emailVerified) {
        OidcIdToken token = OidcIdToken.withTokenValue("t")
                .subject("google-sub-1")
                .claim("email", "ann@example.com")
                .claim("email_verified", emailVerified)
                .claim("name", "Ann Example")
                .claim("picture", "https://example.com/a.png")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")), token);
    }

    @Test
    void googleIdentityIsNormalized() {
        FederatedIdentity identity = normalizer.normalize("google", googleUser(true));

        assertEquals("GOOGLE", identity.provider());
        assertEquals("google-sub-1", identity.subject());
        assertEquals("ann@example.com", identity.email());
        assertTrue(identity.emailVerified());
        assertEquals("Ann Example", identity.displayName());
        assertEquals("https://example.com/a.png", identity.avatarUrl());
    }

    @Test
    void missingEmailVerifiedClaimCountsAsNotVerified() {
        assertFalse(normalizer.normalize("google", googleUser(false)).emailVerified());
    }

    @Test
    void githubIdentityIsNormalized() {
        Map<String, Object> attributes = Map.of(
                "id", 12345678L,
                "login", "ann-github",
                "name", "Ann Example",
                "email", "ann@example.com",
                "email_verified", true,
                "avatar_url", "https://avatars.example.com/ann.png");
        DefaultOAuth2User githubUser = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "id");

        FederatedIdentity identity = normalizer.normalize("github", githubUser);

        assertEquals("GITHUB", identity.provider());
        assertEquals("12345678", identity.subject());
        assertEquals("ann@example.com", identity.email());
        assertTrue(identity.emailVerified());
        assertEquals("Ann Example", identity.displayName());
        assertEquals("https://avatars.example.com/ann.png", identity.avatarUrl());
    }

    @Test
    void unknownProviderIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> normalizer.normalize("unsupported", googleUser(true)));
    }
}
