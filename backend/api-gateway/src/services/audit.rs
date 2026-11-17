//! The audit log: an append-only record of who did what, when, and from where.
//!
//! Handlers record an [`Event`] after an action succeeds:
//!
//! ```ignore
//! audit::Event::by(&claims, "team.member.removed")
//!     .team(org_id)
//!     .subject(user_id)
//!     .record(state.db.pool())
//!     .await;
//! ```
//!
//! The browser's IP and user agent come from [`with_request_meta`], a
//! middleware around every request, so handlers don't pass them. Recording
//! never fails the request: an error is logged instead.
//!
//! **Actions** (keep `docs/API.md` in step):
//!
//! | action | when |
//! |---|---|
//! | `auth.register` | an account was created |
//! | `auth.login` | a sign-in succeeded (`details.method`: password or a provider) |
//! | `auth.login_failed` | a wrong password for an existing account (subject = that account) |
//! | `auth.password_reset_requested` | a reset link was asked for (subject = that account) |
//! | `account.updated` | profile changed (`details.fields`) |
//! | `account.deleted` | the account was deleted |
//! | `api_key.created`, `api_key.revoked` | personal keys |
//! | `team.created`, `team.renamed`, `team.deleted` | |
//! | `team.member.role_changed`, `team.member.removed`, `team.member.left` | |
//! | `team.invitation.sent`, `team.invitation.withdrawn`, `team.invitation.accepted`, `team.invitation.declined` | |
//! | `team.api_key.created`, `team.api_key.revoked` | |
//! | `scan.created` | a file, URL or email was submitted |
//! | `scan.deleted` | someone deleted a scan |
//! | `scan.expired` | retention deleted scans (`details.count`; via "system") |
//! | `account.retention_changed`, `team.retention_changed` | a scan retention choice changed |
//! | `account.exported` | someone downloaded their data |
//! | `retrohunt.started` | a YARA hunt over past uploads was queued (`details.rules`) |

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request},
    middleware::Next,
    response::Response,
};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::middleware::{auth::Claims, rate_limiter::ClientIp};

/// Events older than this many days are deleted.
pub const DEFAULT_RETENTION_DAYS: i64 = 365;
const USER_AGENT_MAX: usize = 256;

#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

tokio::task_local! {
    static REQUEST_META: RequestMeta;
}

/// Middleware: makes the caller's IP and user agent available to [`Event::record`].
pub async fn with_request_meta(
    client_ip: ClientIp,
    request: Request<Body>,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let ip = client_ip.resolve(request.headers(), peer);
    let meta = RequestMeta {
        ip: (ip != "unknown").then_some(ip),
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().take(USER_AGENT_MAX).collect()),
    };
    REQUEST_META.scope(meta, next.run(request)).await
}

fn current_meta() -> RequestMeta {
    REQUEST_META.try_with(Clone::clone).unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct Event {
    pub action: &'static str,
    pub actor_id: Option<Uuid>,
    pub via: &'static str,
    pub api_key_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub subject_user_id: Option<Uuid>,
    pub target_type: Option<&'static str>,
    pub target_id: Option<String>,
    pub details: Map<String, Value>,
}

impl Event {
    /// An event with nobody signed in.
    pub fn anonymous(action: &'static str) -> Self {
        Self {
            action,
            actor_id: None,
            via: "session",
            api_key_id: None,
            organization_id: None,
            subject_user_id: None,
            target_type: None,
            target_id: None,
            details: Map::new(),
        }
    }

    /// An event done by Verdyx itself (retention).
    pub fn system(action: &'static str) -> Self {
        Self {
            via: "system",
            ..Self::anonymous(action)
        }
    }

    /// An event done by a known user who isn't carrying claims here (sign-in).
    pub fn by_user(user_id: Uuid, action: &'static str) -> Self {
        Self {
            actor_id: Some(user_id),
            ..Self::anonymous(action)
        }
    }

    /// An event done by the caller: a session, or an API key acting for them.
    pub fn by(claims: &Claims, action: &'static str) -> Self {
        let key = claims.token_type == "api_key";
        Self {
            actor_id: Some(claims.sub),
            via: if key { "api_key" } else { "session" },
            api_key_id: if key {
                Uuid::parse_str(&claims.jti).ok()
            } else {
                None
            },
            // A team key's actions belong to its team.
            organization_id: claims.org_id,
            ..Self::anonymous(action)
        }
    }

    pub fn team(mut self, org_id: Uuid) -> Self {
        self.organization_id = Some(org_id);
        self
    }

    pub fn subject(mut self, user_id: Uuid) -> Self {
        self.subject_user_id = Some(user_id);
        self
    }

    pub fn target(mut self, kind: &'static str, id: impl ToString) -> Self {
        self.target_type = Some(kind);
        self.target_id = Some(id.to_string().chars().take(64).collect());
        self
    }

    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }

    /// Writes the event. Never fails the caller.
    pub async fn record(self, pool: &sqlx::PgPool) {
        let meta = current_meta();
        let result = sqlx::query(
            r#"INSERT INTO audit_events
                 (action, actor_id, via, api_key_id, organization_id, subject_user_id,
                  target_type, target_id, ip, user_agent, details)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(self.action)
        .bind(self.actor_id)
        .bind(self.via)
        .bind(self.api_key_id)
        .bind(self.organization_id)
        .bind(self.subject_user_id)
        .bind(self.target_type)
        .bind(&self.target_id)
        .bind(&meta.ip)
        .bind(&meta.user_agent)
        .bind(Value::Object(self.details))
        .execute(pool)
        .await;
        if let Err(e) = result {
            tracing::error!(action = self.action, "failed to record audit event: {e}");
        }
    }
}

/// The account a sign-in identifier (email or username) belongs to, if any,
/// so a failed attempt can be shown to its owner.
pub async fn user_for_identifier(pool: &sqlx::PgPool, identifier: &str) -> Option<Uuid> {
    let id = identifier.trim();
    if id.is_empty() || id.len() > 255 {
        return None;
    }
    sqlx::query_scalar(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($1) LIMIT 1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

pub fn retention_days() -> i64 {
    std::env::var("AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|d| *d >= 30)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// Deletes events older than the retention period. Runs at start-up and daily.
pub fn spawn_retention(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut daily = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
        loop {
            daily.tick().await;
            let days = retention_days();
            match sqlx::query(
                "DELETE FROM audit_events WHERE occurred_at < NOW() - make_interval(days => $1)",
            )
            .bind(days as i32)
            .execute(&pool)
            .await
            {
                Ok(r) if r.rows_affected() > 0 => {
                    tracing::info!(
                        "deleted {} audit events older than {days} days",
                        r.rows_affected()
                    )
                }
                Ok(_) => {}
                Err(e) => tracing::error!("audit retention failed: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(token_type: &str, jti: &str, org: Option<Uuid>) -> Claims {
        let mut c: Claims = serde_json::from_value(json!({
            "sub": Uuid::nil(), "email": "a@example.com", "exp": 0,
            "token_type": token_type, "jti": jti
        }))
        .unwrap();
        c.org_id = org;
        c
    }

    #[test]
    fn sessions_and_keys_are_told_apart() {
        let session = Event::by(&claims("access", "abc", None), "x");
        assert_eq!(session.via, "session");
        assert_eq!(session.api_key_id, None);

        let key_id = Uuid::new_v4();
        let team = Uuid::new_v4();
        let key = Event::by(&claims("api_key", &key_id.to_string(), Some(team)), "x");
        assert_eq!(key.via, "api_key");
        assert_eq!(key.api_key_id, Some(key_id));
        assert_eq!(
            key.organization_id,
            Some(team),
            "team keys act for the team"
        );
    }

    #[test]
    fn builder_fills_fields_and_trims_targets() {
        let (team, who) = (Uuid::new_v4(), Uuid::new_v4());
        let e = Event::anonymous("auth.login_failed")
            .team(team)
            .subject(who)
            .target("submission", "x".repeat(100))
            .detail("method", "password");
        assert_eq!(e.actor_id, None);
        assert_eq!(e.organization_id, Some(team));
        assert_eq!(e.subject_user_id, Some(who));
        assert_eq!(e.target_id.as_ref().unwrap().len(), 64);
        assert_eq!(e.details["method"], "password");
    }

    #[tokio::test]
    async fn request_meta_is_scoped_to_the_request() {
        assert!(current_meta().ip.is_none());
        let meta = RequestMeta {
            ip: Some("203.0.113.9".into()),
            user_agent: Some("curl/8".into()),
        };
        let seen = REQUEST_META.scope(meta, async { current_meta() }).await;
        assert_eq!(seen.ip.as_deref(), Some("203.0.113.9"));
        assert!(current_meta().ip.is_none());
    }
}
