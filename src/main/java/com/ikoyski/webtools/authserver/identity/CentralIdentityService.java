package com.ikoyski.webtools.authserver.identity;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Owns the platform-wide person record and the external identities linked to it.
 *
 * A provider subject is the identity key. Email is a verified contact attribute and is never
 * used to silently link two provider accounts. Account linking must be an explicit, authenticated
 * flow added separately.
 */
@Service
public class CentralIdentityService {

    private static final Set<String> ALLOWED_PROVIDERS = Set.of("GOOGLE", "GITHUB");
    private static final int MAX_SUBJECT = 255;
    private static final int MAX_EMAIL = 255;
    private static final int MAX_DISPLAY_NAME = 100;
    private static final int MAX_AVATAR_URL = 512;

    private final JdbcTemplate jdbc;

    public CentralIdentityService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record FederatedIdentity(String provider, String subject, String email, boolean emailVerified,
                                    String displayName, String avatarUrl) {}

    public record Identity(String id, String email, String displayName, String avatarUrl) {}

    public record FederatedResult(Status status, Identity identity) {
        public enum Status { OK, INVALID, EMAIL_NOT_VERIFIED, EMAIL_IN_USE, REJECTED }

        static FederatedResult ok(Identity identity) {
            return new FederatedResult(Status.OK, identity);
        }

        static FederatedResult of(Status status) {
            return new FederatedResult(status, null);
        }
    }

    /** Resolve an existing provider identity or create a new central identity on first sign-in. */
    @Transactional
    public FederatedResult federated(FederatedIdentity input) {
        String provider = input.provider() == null ? "" : input.provider().trim().toUpperCase(Locale.ROOT);
        String subject = input.subject() == null ? "" : input.subject().trim();
        String email = input.email() == null ? "" : input.email().trim().toLowerCase(Locale.ROOT);
        String displayName = clean(input.displayName(), MAX_DISPLAY_NAME);
        String avatarUrl = clean(input.avatarUrl(), MAX_AVATAR_URL);

        if (!ALLOWED_PROVIDERS.contains(provider) || subject.isEmpty() || subject.length() > MAX_SUBJECT
                || email.isEmpty() || email.length() > MAX_EMAIL) {
            return FederatedResult.of(FederatedResult.Status.INVALID);
        }
        if (!input.emailVerified()) {
            return FederatedResult.of(FederatedResult.Status.EMAIL_NOT_VERIFIED);
        }

        Optional<Identity> known = findByProviderSubject(provider, subject);
        if (known.isPresent()) {
            Identity existing = known.get();
            if (emailBelongsToAnotherUser(email, existing.id())) {
                return FederatedResult.of(FederatedResult.Status.EMAIL_IN_USE);
            }

            int updated = jdbc.update("""
                    UPDATE auth_user
                       SET email = ?, display_name = COALESCE(?, display_name),
                           avatar_url = COALESCE(?, avatar_url), updated_at = now()
                     WHERE id = ?
                    """, email, displayName, avatarUrl, UUID.fromString(existing.id()));
            if (updated != 1) {
                return FederatedResult.of(FederatedResult.Status.REJECTED);
            }
            return FederatedResult.ok(findById(existing.id()).orElse(existing));
        }

        // Do not merge accounts just because two providers report the same email.
        if (emailBelongsToAnotherUser(email, null)) {
            return FederatedResult.of(FederatedResult.Status.EMAIL_IN_USE);
        }

        UUID userId = UUID.randomUUID();
        int insertedUser = jdbc.update("""
                INSERT INTO auth_user (id, email, display_name, avatar_url, email_verified)
                VALUES (?, ?, ?, ?, true)
                ON CONFLICT (email) DO NOTHING
                """, userId, email, displayName, avatarUrl);
        if (insertedUser != 1) {
            return FederatedResult.of(FederatedResult.Status.EMAIL_IN_USE);
        }

        int insertedIdentity = jdbc.update("""
                INSERT INTO auth_identity (id, user_id, provider_type, provider_subject)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (provider_type, provider_subject) DO NOTHING
                """, UUID.randomUUID(), userId, provider, subject);
        if (insertedIdentity != 1) {
            // Another concurrent first login may have won the identity insert. Remove the unused
            // person row and resolve to the winner rather than creating duplicate accounts.
            jdbc.update("DELETE FROM auth_user WHERE id = ?", userId);
            return findByProviderSubject(provider, subject)
                    .map(FederatedResult::ok)
                    .orElseGet(() -> FederatedResult.of(FederatedResult.Status.REJECTED));
        }

        return FederatedResult.ok(new Identity(userId.toString(), email, displayName, avatarUrl));
    }

    @Transactional(readOnly = true)
    public Optional<Identity> findById(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        try {
            return jdbc.query("""
                    SELECT id, email, display_name, avatar_url
                      FROM auth_user
                     WHERE id = ?
                    """, (rs, rowNum) -> new Identity(
                            rs.getString("id"), rs.getString("email"),
                            rs.getString("display_name"), rs.getString("avatar_url")),
                    UUID.fromString(id.trim())).stream().findFirst();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private Optional<Identity> findByProviderSubject(String provider, String subject) {
        return jdbc.query("""
                SELECT u.id, u.email, u.display_name, u.avatar_url
                  FROM auth_identity i
                  JOIN auth_user u ON u.id = i.user_id
                 WHERE i.provider_type = ? AND i.provider_subject = ?
                """, (rs, rowNum) -> new Identity(
                        rs.getString("id"), rs.getString("email"),
                        rs.getString("display_name"), rs.getString("avatar_url")),
                provider, subject).stream().findFirst();
    }

    private boolean emailBelongsToAnotherUser(String email, String currentUserId) {
        if (currentUserId == null) {
            return Boolean.TRUE.equals(jdbc.queryForObject(
                    "SELECT EXISTS (SELECT 1 FROM auth_user WHERE email = ?)", Boolean.class, email));
        }
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM auth_user WHERE email = ? AND id <> ?)",
                Boolean.class, email, UUID.fromString(currentUserId)));
    }

    private static String clean(String value, int maxLength) {
        if (value == null || value.isBlank() || value.length() > maxLength) {
            return null;
        }
        return value.trim();
    }
}
