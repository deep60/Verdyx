-- Plans and quotas: every team is on a plan (Free unless a Verdyx
-- administrator sets another), optionally with limits overridden for that
-- team. Free keeps the limits teams already had.

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free',
    ADD COLUMN IF NOT EXISTS plan_limits JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS plan_changed_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organizations_plan_check'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_plan_check
            CHECK (plan IN ('free', 'team', 'enterprise'));
    END IF;
END $$;

-- People's best plan is looked up on every scan; only paid or customised
-- teams are worth finding.
CREATE INDEX IF NOT EXISTS idx_organizations_paid
    ON organizations (id) WHERE plan <> 'free' OR plan_limits <> '{}'::jsonb;
