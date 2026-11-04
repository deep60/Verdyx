-- 20261016000000 seeded four "built-in" engines with invented accuracy and
-- analysis counts (e.g. ClamAV 96.40%, 1280 analyses), two of which don't
-- exist. Because GET /engines lists active rows first, they hid the live
-- engine status the gateway now reads from the analysis engine.
--
-- Deactivate them and clear the made-up numbers. They are not deleted:
-- analyses reference engines with ON DELETE CASCADE.
UPDATE engines
SET is_active = false,
    accuracy_rate = NULL,
    total_analyses = NULL,
    correct_analyses = NULL,
    updated_at = NOW()
WHERE id IN (
    '11111111-1111-4111-8111-111111111101',
    '11111111-1111-4111-8111-111111111102',
    '11111111-1111-4111-8111-111111111103',
    '11111111-1111-4111-8111-111111111104'
);
