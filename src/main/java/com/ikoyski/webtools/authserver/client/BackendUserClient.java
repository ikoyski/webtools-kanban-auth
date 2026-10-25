package com.ikoyski.webtools.authserver.client;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Talks to the kanban backend's INTERNAL identity API. The backend owns the users: this server
 * only proves who someone is (via Google) and asks the backend which user that is.
 *
 *   POST /internal/v1/users/federated  {provider, subject, email, emailVerified, displayName, avatarUrl}
 *        -> 200 {id, email} | 400 | 403 email_not_verified | 409 email_in_use
 *   POST /internal/v1/users/lookup     {id}  -> 200 {id, email} | 404
 *
 * Both require the header X-Internal-Key.
 */
@Component
public class BackendUserClient {

    /** What an identity provider told us about a person, normalized across providers. */
    public record FederatedIdentity(String provider, String subject, String email, boolean emailVerified,
                                    String displayName, String avatarUrl) {}

    public record InternalUser(String id, String email) {}

    public record FederatedResult(Status status, InternalUser user) {
        public enum Status { OK, EMAIL_NOT_VERIFIED, EMAIL_IN_USE, REJECTED }
    }

    private final RestClient http;

    public BackendUserClient(
            @Value("${auth.backend.base-url}") String baseUrl,
            @Value("${auth.backend.internal-key}") String internalKey,
            @Value("${auth.backend.connect-timeout-ms}") int connectTimeoutMs,
            @Value("${auth.backend.read-timeout-ms}") int readTimeoutMs) {

        if (internalKey == null || internalKey.isBlank()) {
            // Fail closed: never start without the shared secret.
            throw new IllegalStateException("auth.backend.internal-key must be set (AUTH_BACKEND_INTERNAL_KEY)");
        }
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout(readTimeoutMs);

        this.http = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(factory)
                .defaultHeader("X-Internal-Key", internalKey)
                .build();
    }

    /**
     * Finds or creates the Kanban user for an external identity. Business refusals come back as a
     * status; anything else (wrong internal key, backend down) is thrown as an exception.
     */
    public FederatedResult federated(FederatedIdentity identity) {
        Map<String, Object> body = new HashMap<>();
        body.put("provider", identity.provider());
        body.put("subject", identity.subject());
        body.put("email", identity.email());
        body.put("emailVerified", identity.emailVerified());
        body.put("displayName", identity.displayName());
        body.put("avatarUrl", identity.avatarUrl());
        try {
            Map<?, ?> response = http.post().uri("/internal/v1/users/federated")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve().body(Map.class);
            InternalUser user = toUser(response);
            return user == null
                    ? new FederatedResult(FederatedResult.Status.REJECTED, null)
                    : new FederatedResult(FederatedResult.Status.OK, user);
        } catch (HttpClientErrorException e) {
            return switch (e.getStatusCode().value()) {
                case 403 -> new FederatedResult(FederatedResult.Status.EMAIL_NOT_VERIFIED, null);
                case 409 -> new FederatedResult(FederatedResult.Status.EMAIL_IN_USE, null);
                case 400 -> new FederatedResult(FederatedResult.Status.REJECTED, null);
                default -> throw e;   // 401 means a wrong internal key: a configuration problem
            };
        }
    }

    /** Returns the user for an id, or empty if the user no longer exists. */
    public Optional<InternalUser> lookupById(String id) {
        try {
            Map<?, ?> response = http.post().uri("/internal/v1/users/lookup")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("id", id))
                    .retrieve().body(Map.class);
            return Optional.ofNullable(toUser(response));
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        }
    }

    private static InternalUser toUser(Map<?, ?> body) {
        if (body == null) {
            return null;
        }
        Object id = body.get("id");
        Object email = body.get("email");
        if (id == null || email == null || id.toString().isBlank() || email.toString().isBlank()) {
            return null;
        }
        return new InternalUser(id.toString(), email.toString());
    }
}
