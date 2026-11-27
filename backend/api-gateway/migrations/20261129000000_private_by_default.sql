-- Private by default.
--
-- share_files_with_virustotal (users, organizations): may Behavioral
--   analysis upload a file to VirusTotal when VirusTotal has no report for
--   it? Off unless the account, or the team the scan is saved to, turns it on.
--   Hash lookups don't need it: they send only the hash.
-- submissions.may_upload_file: that choice, recorded when the scan is made,
--   so changing the setting later never reaches back to earlier scans.
--   Existing scans get FALSE.
-- submissions.shared_by_link: anyone with the report's link may open it.
--   Off by default; the owner turns it on and off.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS share_files_with_virustotal BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS share_files_with_virustotal BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE submissions
    ADD COLUMN IF NOT EXISTS may_upload_file BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS shared_by_link BOOLEAN NOT NULL DEFAULT FALSE;
