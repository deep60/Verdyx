-- Webhook delivery: webhook_deliveries becomes an outbox.
--
-- A service that wants to send an event inserts one 'pending' row per
-- subscribed webhook (shared::webhooks::ENQUEUE_SQL). The gateway's delivery
-- worker sends due rows, signs them with the webhook's secret, and retries
-- failures with backoff until the webhook's retry_max_attempts.

ALTER TABLE webhook_deliveries
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Only rows still waiting to be sent are scanned by the worker.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries(next_attempt_at)
    WHERE status IN ('pending', 'retrying');

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook
    ON webhook_deliveries(webhook_id, triggered_at DESC);
