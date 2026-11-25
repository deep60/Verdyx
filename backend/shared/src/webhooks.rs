//! Webhook events: their names, and how a service queues one for delivery.
//!
//! Delivery uses an outbox in the gateway's database. A service that wants to
//! send an event runs [`ENQUEUE_SQL`], which inserts one pending row in
//! `webhook_deliveries` per active webhook of that user subscribed to the
//! event. The gateway's delivery worker sends them, signs them and retries.

/// Events that are delivered, with a description for the API's event list.
pub const EVENTS: [(&str, &str); 4] = [
    (
        ANALYSIS_COMPLETED,
        "A scan you submitted finished, with its verdict",
    ),
    (
        ANALYSIS_UPDATED,
        "A finished scan's verdict changed (e.g. a sandbox report arrived)",
    ),
    (
        LIVEHUNT_MATCH,
        "One of your live hunts matched a new upload",
    ),
    (TEST, "Sent by the test button; never by a real event"),
];

pub const ANALYSIS_COMPLETED: &str = "analysis.completed";
pub const ANALYSIS_UPDATED: &str = "analysis.updated";
pub const LIVEHUNT_MATCH: &str = "livehunt.match";
pub const TEST: &str = "webhook.test";

/// Subscribing to this receives every event.
pub const ALL: &str = "*";

/// True for an event name a webhook may subscribe to.
pub fn is_known_event(name: &str) -> bool {
    name == ALL || EVENTS.iter().any(|(e, _)| *e == name)
}

/// Queue an event for every active webhook of a user that subscribes to it
/// (by name, or with `*`).
///
/// `$1` the user, `$2` the event name, `$3` the event's data (JSONB). The
/// delivery id is the row id, which receivers can use to drop duplicates.
pub const ENQUEUE_SQL: &str = r#"
INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, attempt_number, next_attempt_at)
SELECT gen_random_uuid(), w.id, $2, $3, 'pending', 1, NOW()
FROM webhooks w
WHERE w.user_id = $1
  AND COALESCE(w.is_active, TRUE)
  AND ($2 = ANY(w.events) OR '*' = ANY(w.events))
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_events() {
        assert!(is_known_event("analysis.completed"));
        assert!(is_known_event("livehunt.match"));
        assert!(is_known_event("*"));
        assert!(!is_known_event("bounty.created"));
        assert!(!is_known_event(""));
    }
}
