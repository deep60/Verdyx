-- Live hunts: YARA rules that run on every new upload in their scope and
-- record a match when they hit.
--
-- The gateway owns these tables; the analysis engine reads the enabled hunts
-- for each new file and writes matches (through GATEWAY_DATABASE_URL).

CREATE TABLE IF NOT EXISTS live_hunts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    -- Match this team's uploads; NULL matches the person's own.
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    rule_text TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    matches INTEGER NOT NULL DEFAULT 0,
    last_match_at TIMESTAMPTZ,
    -- Set by the engine when the rule doesn't compile; it also turns the hunt off.
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_live_hunts_user ON live_hunts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_live_hunts_team ON live_hunts(organization_id) WHERE enabled;

-- No foreign key to submissions: a scan deleted later just drops out of the
-- list (it's joined against submissions when read).
CREATE TABLE IF NOT EXISTS live_hunt_matches (
    hunt_id UUID NOT NULL REFERENCES live_hunts(id) ON DELETE CASCADE,
    submission_id UUID NOT NULL,
    rules TEXT[] NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (hunt_id, submission_id)
);
CREATE INDEX IF NOT EXISTS idx_live_hunt_matches_recent ON live_hunt_matches(hunt_id, matched_at DESC);
