-- Convert submissions.confidence_score from DECIMAL(5,4) to DOUBLE PRECISION
-- so 0..100 confidence scores and f64 bindings from analysis-engine do not overflow or fail type checks.

ALTER TABLE submissions
    ALTER COLUMN confidence_score TYPE DOUBLE PRECISION USING confidence_score::DOUBLE PRECISION;
