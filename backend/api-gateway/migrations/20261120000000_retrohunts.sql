-- Retrohunt: run a YARA rule over past uploads.
--
-- The gateway queues a job; the analysis engine compiles the rule and scans
-- the stored files in scope (the person's own scans, or a team's), writing
-- matches as it goes.

CREATE TABLE IF NOT EXISTS retrohunt_jobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    -- Hunt in this team's scans; NULL hunts in the person's own.
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    rule_text TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    files_total INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_failed INTEGER NOT NULL DEFAULT 0,
    matches INTEGER NOT NULL DEFAULT 0,
    -- Why it failed (e.g. the compiler's message), or a note on how it ended.
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_retrohunt_user ON retrohunt_jobs(user_id, created_at DESC);

-- No foreign key to submissions: a scan deleted later just drops out of the
-- results.
CREATE TABLE IF NOT EXISTS retrohunt_matches (
    job_id UUID NOT NULL REFERENCES retrohunt_jobs(id) ON DELETE CASCADE,
    submission_id UUID NOT NULL,
    rules TEXT[] NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, submission_id)
);
