-- Audit log: who did what, when, from where.
--
-- Append-only: rows can't be changed (trigger below). They are deleted only by
-- the gateway's retention job (AUDIT_RETENTION_DAYS, default 365).
--
-- No foreign keys: the log outlives the accounts, teams and keys it mentions.

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- e.g. "team.member.removed"; the list is in src/services/audit.rs
    action VARCHAR(64) NOT NULL,
    -- Who did it. NULL when nobody was signed in (e.g. a failed sign-in).
    actor_id UUID,
    -- How: "session", "api_key" or "system".
    via VARCHAR(16) NOT NULL DEFAULT 'session',
    api_key_id UUID,
    -- The team the event belongs to, if any.
    organization_id UUID,
    -- The account the event is about, when that isn't the actor
    -- (a failed sign-in to it, a role change made to it).
    subject_user_id UUID,
    target_type VARCHAR(32),
    target_id VARCHAR(64),
    ip VARCHAR(45),
    user_agent VARCHAR(256),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id, id DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_events(subject_user_id, id DESC) WHERE subject_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_team ON audit_events(organization_id, id DESC) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(occurred_at);

CREATE OR REPLACE FUNCTION audit_events_read_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit events cannot be changed';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_read_only();
