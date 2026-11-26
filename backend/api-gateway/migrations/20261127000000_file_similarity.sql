-- Similarity search: fuzzy hashes of each uploaded file.
--
-- The analysis engine fills this in for every uploaded file (and backfills
-- earlier uploads whose file is still stored). TLSH and ssdeep are compared
-- in the gateway, since Postgres can't index them; imphash is matched here.
-- See shared::similarity.

CREATE TABLE IF NOT EXISTS file_similarity (
    submission_id UUID PRIMARY KEY REFERENCES submissions(id) ON DELETE CASCADE,
    tlsh          TEXT,
    ssdeep        TEXT,
    imphash       CHAR(32),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_file_similarity_imphash
    ON file_similarity(imphash) WHERE imphash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_file_similarity_recent
    ON file_similarity(created_at DESC);
