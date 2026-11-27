-- Cloud storage scanning: a team connects an S3-compatible bucket (Amazon
-- S3, Cloudflare R2, Google Cloud Storage, MinIO, ...) and Verdyx scans the
-- files that arrive in it.

CREATE TABLE IF NOT EXISTS storage_connections (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Who set it up; the scans are made in their name, saved to the team.
    created_by UUID NOT NULL,
    name TEXT NOT NULL,
    -- A label for the website: aws, r2, gcs or other.
    provider TEXT NOT NULL DEFAULT 'other'
        CHECK (provider IN ('aws', 'r2', 'gcs', 'other')),
    -- https://host for providers other than Amazon S3; NULL for Amazon S3.
    endpoint TEXT,
    region TEXT NOT NULL,
    bucket TEXT NOT NULL,
    prefix TEXT NOT NULL DEFAULT '',
    access_key_id TEXT NOT NULL,
    -- Sealed with the integration key, like SIEM credentials.
    secret_access_key TEXT NOT NULL,
    analysis_type TEXT NOT NULL DEFAULT 'full'
        CHECK (analysis_type IN ('quick', 'full', 'deep')),
    interval_minutes INTEGER NOT NULL DEFAULT 60
        CHECK (interval_minutes BETWEEN 15 AND 1440),
    max_object_mb INTEGER NOT NULL DEFAULT 32
        CHECK (max_object_mb BETWEEN 1 AND 100),
    -- Files changed before this aren't scanned (when the connection was made,
    -- unless the team asked to scan what's already there).
    scan_since TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Where a pass over a large bucket stopped; the next run continues there.
    list_token TEXT,
    run_requested BOOLEAN NOT NULL DEFAULT FALSE,
    running_since TIMESTAMPTZ,
    last_run_at TIMESTAMPTZ,
    last_error TEXT,
    last_scanned INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_storage_connections_org
    ON storage_connections (organization_id);
CREATE INDEX IF NOT EXISTS idx_storage_connections_due
    ON storage_connections (last_run_at) WHERE enabled;

-- Every file looked at, so each version is scanned once.
CREATE TABLE IF NOT EXISTS storage_objects (
    connection_id UUID NOT NULL REFERENCES storage_connections(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    etag TEXT NOT NULL,
    size BIGINT NOT NULL,
    last_modified TIMESTAMPTZ,
    -- queued: a scan was made; too_large: over the size limit;
    -- failed: it couldn't be downloaded.
    status TEXT NOT NULL CHECK (status IN ('queued', 'too_large', 'failed')),
    error TEXT,
    submission_id UUID,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connection_id, key, etag)
);

CREATE INDEX IF NOT EXISTS idx_storage_objects_recent
    ON storage_objects (connection_id, seen_at DESC);
