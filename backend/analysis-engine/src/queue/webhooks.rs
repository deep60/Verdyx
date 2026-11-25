//! Queues webhook events for the gateway's delivery worker.
//!
//! An event becomes one pending row per subscribed webhook of the user
//! (`shared::webhooks::ENQUEUE_SQL`, in the gateway's database). Queueing
//! never fails a scan: errors are logged.

use serde_json::{json, Value};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

/// Queue `event` for `user`'s webhooks. Anonymous scans have nobody to tell.
pub async fn enqueue(db: &PgPool, user: Option<Uuid>, event: &str, data: Value) {
    let Some(user) = user.filter(|u| !u.is_nil()) else {
        return;
    };
    if let Err(e) = sqlx::query(shared::webhooks::ENQUEUE_SQL)
        .bind(user)
        .bind(event)
        .bind(&data)
        .execute(db)
        .await
    {
        warn!("could not queue {event} for {user}: {e}");
    }
}

/// The data of `analysis.completed` and `analysis.updated`.
#[allow(clippy::too_many_arguments)]
pub fn analysis_data(
    submission_id: Uuid,
    kind: &str,
    target: Option<&str>,
    sha256: Option<&str>,
    is_malicious: bool,
    confidence: f64,
    engines: usize,
    team: Option<Uuid>,
) -> Value {
    json!({
        "submissionId": submission_id,
        "status": "completed",
        "type": kind,
        "target": target,
        "sha256": sha256,
        "isMalicious": is_malicious,
        "confidence": confidence,
        "engineResults": engines,
        "teamId": team,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_data_shape() {
        let id = Uuid::nil();
        let v = analysis_data(id, "file", Some("a.exe"), Some("ab"), true, 0.75, 9, None);
        assert_eq!(v["submissionId"], json!(id));
        assert_eq!(v["isMalicious"], true);
        assert_eq!(v["target"], "a.exe");
        assert!(v["teamId"].is_null());
    }
}
