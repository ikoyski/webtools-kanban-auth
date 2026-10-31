-- Central person records and provider identities owned by the Webtools Identity Server.
-- Account linking is intentionally not inferred from matching email addresses.

CREATE TABLE auth_user (
    id              UUID PRIMARY KEY,
    email           VARCHAR(255) NOT NULL UNIQUE,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    display_name    VARCHAR(100),
    avatar_url      VARCHAR(512),
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                    CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_identity (
    id                UUID PRIMARY KEY,
    user_id           UUID NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
    provider_type     VARCHAR(50) NOT NULL,
    provider_subject  VARCHAR(255) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_auth_identity_provider_subject UNIQUE (provider_type, provider_subject),
    CONSTRAINT uq_auth_identity_user_provider UNIQUE (user_id, provider_type)
);

CREATE INDEX idx_auth_identity_user_id ON auth_identity(user_id);
