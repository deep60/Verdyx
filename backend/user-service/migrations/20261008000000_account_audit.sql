-- Audit trail for account changes. Identity updates and deletion are owned by
-- user-service; other services must not write the users table for these actions.
CREATE TABLE IF NOT EXISTS account_audit_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    action      VARCHAR(64) NOT NULL,
    actor_id    UUID NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_account_audit_user
    ON account_audit_events(user_id, created_at DESC);
