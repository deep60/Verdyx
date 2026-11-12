-- Google / GitHub accounts linked to a Verdyx user. A user can have several;
-- each provider account belongs to exactly one user.
CREATE TABLE IF NOT EXISTS user_oauth_identities (
    provider          VARCHAR(16)  NOT NULL,
    provider_user_id  VARCHAR(255) NOT NULL,
    user_id           UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email             VARCHAR(255) NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_oauth_identities_user
    ON user_oauth_identities(user_id);
