package com.ikoyski.webtools.authserver.security;

import java.io.IOException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import com.ikoyski.webtools.authserver.identity.CentralIdentityService;
import com.ikoyski.webtools.authserver.identity.CentralIdentityService.FederatedIdentity;
import com.ikoyski.webtools.authserver.identity.CentralIdentityService.FederatedResult;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Runs after the configured identity provider has authenticated the person. It asks the backend which
 * Kanban user that identity is (creating it on first sign-in) and then REPLACES the provider's
 * authentication with a plain one whose principal name is the Kanban user id. That keeps the stored
 * authorization small and serializable, and makes the token "sub" the user id.
 * The browser is then sent back to the saved /oauth2/authorize request.
 */
@Component
public class FederatedLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(FederatedLoginSuccessHandler.class);

    private final CentralIdentityService identities;
    private final IdentityNormalizer normalizer;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SavedRequestAwareAuthenticationSuccessHandler redirectToSavedRequest =
            new SavedRequestAwareAuthenticationSuccessHandler();

    public FederatedLoginSuccessHandler(CentralIdentityService identities, IdentityNormalizer normalizer) {
        this.identities = identities;
        this.normalizer = normalizer;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            reject(request, response, 500, "Unexpected sign-in result. Please try again.");
            return;
        }

        FederatedResult result;
        try {
            FederatedIdentity identity = normalizer.normalize(
                    token.getAuthorizedClientRegistrationId(), token.getPrincipal());
            result = identities.federated(identity);
        } catch (IllegalArgumentException e) {
            log.warn("Sign-in rejected: {}", e.getMessage());
            reject(request, response, 403, "This sign-in method is not enabled.");
            return;
        } catch (RuntimeException e) {
            log.error("Could not resolve the central identity", e);
            reject(request, response, 503, "Sign-in is temporarily unavailable. Please try again in a moment.");
            return;
        }

        switch (result.status()) {
            case OK -> signIn(request, response, result.identity());
            case EMAIL_NOT_VERIFIED -> reject(request, response, 403,
                    "Your account's email address has not been verified, so it cannot be used to sign in.");
            case EMAIL_IN_USE -> reject(request, response, 409,
                    "This verified email is already associated with another sign-in identity. "
                            + "Account linking must be completed from an authenticated session.");
            case REJECTED -> reject(request, response, 403, "This account cannot be used to sign in.");
        }
    }

    private void signIn(HttpServletRequest request, HttpServletResponse response,
                        BackendUserClient.InternalUser user) throws IOException, ServletException {
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        User principal = new User(user.id(), "", authorities);   // principal name = Kanban user id
        Authentication authenticated = UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authenticated);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        redirectToSavedRequest.onAuthenticationSuccess(request, response, authenticated);
    }

    /** Drops the provider's authentication and shows a short message. Messages are static text only. */
    private void reject(HttpServletRequest request, HttpServletResponse response, int status, String message)
            throws IOException {
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        response.setStatus(status);
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in failed</title></head>"
                + "<body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem\">"
                + "<h1>Sign-in failed</h1><p>" + message + "</p></body></html>");
    }
}
