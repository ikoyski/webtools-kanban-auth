package com.ikoyski.webtools.authserver.security;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import com.ikoyski.webtools.authserver.client.BackendUserClient.FederatedIdentity;

/**
 * Turns whatever a login provider returns into one provider-neutral shape. Adding a provider means
 * a new registration under spring.security.oauth2.client.registration plus one branch here:
 *   - microsoft (OIDC): use the "oid" (or "sub") claim as the subject; do NOT trust its email claim,
 *     it is mutable and not proof of ownership, so report emailVerified=false unless you can prove it;
 *   - github (plain OAuth2, no ID token): read the numeric "id" attribute as the subject and fetch the
 *     verified primary address from /user/emails.
 * The backend still decides what is allowed (InternalUserService.ALLOWED_PROVIDERS).
 */
@Component
public class IdentityNormalizer {

    public FederatedIdentity normalize(String registrationId, OAuth2User user) {
        if ("google".equals(registrationId) && user instanceof OidcUser oidc) {
            return new FederatedIdentity(
                    "GOOGLE",
                    oidc.getSubject(),
                    oidc.getEmail(),
                    Boolean.TRUE.equals(oidc.getEmailVerified()),
                    oidc.getFullName(),
                    oidc.getPicture());
        }
        throw new IllegalArgumentException("Unsupported identity provider: " + registrationId);
    }
}
