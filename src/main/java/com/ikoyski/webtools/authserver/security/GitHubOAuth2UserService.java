package com.ikoyski.webtools.authserver.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

/**
 * Loads the GitHub profile and resolves the authenticated user's verified primary email.
 * GitHub's profile email may be absent or private, so it is not suitable as the authoritative
 * email source. The user:email scope allows the server to query /user/emails.
 */
@Component
public class GitHubOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final ParameterizedTypeReference<List<Map<String, Object>>> EMAILS_TYPE =
            new ParameterizedTypeReference<>() {};

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final RestClient githubApi;

    public GitHubOAuth2UserService() {
        var requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(3_000);
        requestFactory.setReadTimeout(5_000);
        this.githubApi = RestClient.builder()
                .baseUrl("https://api.github.com")
                .requestFactory(requestFactory)
                .defaultHeader(HttpHeaders.ACCEPT, "application/vnd.github+json")
                .defaultHeader("X-GitHub-Api-Version", "2022-11-28")
                .build();
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User profile = delegate.loadUser(request);
        if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
            return profile;
        }

        List<Map<String, Object>> emails;
        try {
            emails = githubApi.get()
                    .uri("/user/emails")
                    .headers(headers -> headers.setBearerAuth(request.getAccessToken().getTokenValue()))
                    .retrieve()
                    .body(EMAILS_TYPE);
        } catch (RestClientException exception) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "Could not retrieve the verified GitHub email address", null),
                    exception);
        }

        Map<String, Object> primaryVerifiedEmail = emails == null ? null : emails.stream()
                .filter(email -> Boolean.TRUE.equals(email.get("primary"))
                        && Boolean.TRUE.equals(email.get("verified")))
                .findFirst()
                .orElse(null);

        Map<String, Object> attributes = new HashMap<>(profile.getAttributes());
        attributes.put("email", primaryVerifiedEmail == null ? null : primaryVerifiedEmail.get("email"));
        attributes.put("email_verified", primaryVerifiedEmail != null);

        // The GitHub numeric account ID is the stable provider subject, not the login name.
        return new DefaultOAuth2User(profile.getAuthorities(), attributes, "id");
    }
}
