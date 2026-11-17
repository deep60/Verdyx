-- Data retention.
--
-- - `users.scan_retention_days` / `organizations.scan_retention_days`: delete
--   that person's (or team's) scans after this many days. NULL keeps them.
-- - `submissions.file_purged_at`: when the stored sample file was deleted
--   (after SAMPLE_RETENTION_DAYS). The scan and its results stay.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scan_retention_days INTEGER
        CHECK (scan_retention_days IS NULL OR scan_retention_days IN (30, 90, 180, 365));

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS scan_retention_days INTEGER
        CHECK (scan_retention_days IS NULL OR scan_retention_days IN (30, 90, 180, 365));

ALTER TABLE submissions ADD COLUMN IF NOT EXISTS file_purged_at TIMESTAMPTZ;

-- The retention job scans by age.
CREATE INDEX IF NOT EXISTS idx_submissions_created ON submissions(created_at);
