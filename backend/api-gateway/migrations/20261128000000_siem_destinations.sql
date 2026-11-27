-- SIEM destinations: a webhook can now send to Splunk (HTTP Event Collector)
-- or Microsoft Sentinel (Logs Ingestion API) instead of a plain URL.
--
-- kind        webhook | splunk | sentinel
-- config      the destination's settings (index, tenant, rule, stream...)
-- credential  the HEC token or the Entra app's client key, sealed with
--             AES-256-GCM by the gateway; never returned by the API
-- has_credential  lets the API say one is set without reading it

ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'webhook',
    ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS credential TEXT;

ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS has_credential BOOLEAN
        GENERATED ALWAYS AS (credential IS NOT NULL) STORED;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'webhooks_kind_check') THEN
        ALTER TABLE webhooks
            ADD CONSTRAINT webhooks_kind_check CHECK (kind IN ('webhook', 'splunk', 'sentinel'));
    END IF;
END $$;
