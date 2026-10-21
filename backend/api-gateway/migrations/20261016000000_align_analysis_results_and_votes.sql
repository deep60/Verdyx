-- Align analysis_results with analysis-engine queue worker columns,
-- add missing voter_id to submission_votes, ensure payouts table exists,
-- and seed built-in security engines.

ALTER TABLE analysis_results
    DROP CONSTRAINT IF EXISTS analysis_results_engine_id_fkey;

ALTER TABLE analysis_results
    ALTER COLUMN engine_id DROP NOT NULL,
    ALTER COLUMN confidence_score DROP NOT NULL,
    ALTER COLUMN confidence_score TYPE DOUBLE PRECISION USING confidence_score::DOUBLE PRECISION;

ALTER TABLE analysis_results
    ADD COLUMN IF NOT EXISTS engine_name VARCHAR(100),
    ADD COLUMN IF NOT EXISTS engine_version VARCHAR(50),
    ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS severity VARCHAR(50),
    ADD COLUMN IF NOT EXISTS categories JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS processing_time_ms BIGINT DEFAULT 0;

-- Allow voting on both bounty_submissions and file submissions, and track voter_id
ALTER TABLE submission_votes
    DROP CONSTRAINT IF EXISTS submission_votes_submission_id_fkey,
    ADD COLUMN IF NOT EXISTS voter_id UUID;

CREATE INDEX IF NOT EXISTS idx_submission_votes_voter
    ON submission_votes(submission_id, voter_id);

-- Ensure payouts table exists in gateway DB for user stats and wallet queries
CREATE TABLE IF NOT EXISTS payouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bounty_id UUID,
    recipient_id UUID,
    recipient VARCHAR(100) NOT NULL DEFAULT '',
    amount NUMERIC(36, 18) NOT NULL DEFAULT 0,
    tx_hash VARCHAR(66),
    transaction_hash VARCHAR(66),
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

ALTER TABLE payouts
    ADD COLUMN IF NOT EXISTS recipient_id UUID,
    ADD COLUMN IF NOT EXISTS tx_hash VARCHAR(66);

CREATE INDEX IF NOT EXISTS idx_payouts_recipient ON payouts(recipient);
CREATE INDEX IF NOT EXISTS idx_payouts_recipient_id ON payouts(recipient_id);

-- Drop restrictive FK on api_keys, bounties, and webhooks so user-service identities work even before sync
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_user_id_fkey;

-- Seed built-in security engines into engines table if not already present
INSERT INTO engines (id, name, engine_type, description, accuracy_rate, total_analyses, is_active, created_at, updated_at)
VALUES
    ('11111111-1111-4111-8111-111111111101', 'ClamAV Antivirus', 'signature', 'Multi-platform signature and archive malware scanner', 0.9640, 1280, true, NOW(), NOW()),
    ('11111111-1111-4111-8111-111111111102', 'YARA Rule Engine', 'signature', 'Pattern-matching rule engine for APTs, packers, and malware families', 0.9810, 1540, true, NOW(), NOW()),
    ('11111111-1111-4111-8111-111111111103', 'PE & Binary Heuristic Analyzer', 'ml', 'Static PE/ELF/Mach-O structural, import, and section entropy analyzer', 0.9350, 980, true, NOW(), NOW()),
    ('11111111-1111-4111-8111-111111111104', 'Decompilation & String Inspector', 'hybrid', 'Automated control-flow, suspicious API, and obfuscated indicator extractor', 0.9120, 760, true, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;
