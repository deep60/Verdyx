//! Reading the audit log.
//!
//! - `GET /users/me/audit`: what you did, and what happened to your account
//!   (failed sign-ins, reset requests, role changes made to you). Includes
//!   the IP address and browser of each event.
//! - `GET /orgs/{id}/audit`: everything in a team, for its owners and admins.
//!   Leaves out IP addresses and browsers, which stay personal.
//!
//! Both take `limit` (default 50, at most 200), `before` (an event id, for the
//! next page), `action` (a prefix such as `team.member`) and `format=csv`
//! (up to 10,000 events, newest first).

#![allow(clippy::type_complexity)]

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::middleware::auth::Claims;
use crate::AppState;

const PAGE_DEFAULT: i64 = 50;
const PAGE_MAX: i64 = 200;
const CSV_MAX: i64 = 10_000;

#[derive(Debug, Deserialize, Default)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub before: Option<i64>,
    pub action: Option<String>,
    pub format: Option<String>,
}

enum Scope {
    Person(Uuid),
    Team(Uuid),
}

fn bad(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
        .into_response()
}

/// Only letters, dots and underscores: the filter goes into a LIKE pattern.
pub fn clean_action_filter(raw: Option<&str>) -> Result<Option<String>, &'static str> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(a)
            if a.len() <= 64
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_') =>
        {
            Ok(Some(a.to_string()))
        }
        Some(_) => Err("action filter may only contain lowercase letters, dots and underscores"),
    }
}

/// One CSV field: always quoted, quotes doubled, and a leading `= + - @`
/// defused so a spreadsheet won't run it as a formula.
pub fn csv_field(value: &str) -> String {
    let defused = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", defused.replace('"', "\"\""))
}

struct Row {
    id: i64,
    occurred_at: DateTime<Utc>,
    action: String,
    actor_id: Option<Uuid>,
    actor_name: Option<String>,
    via: String,
    api_key_id: Option<Uuid>,
    organization_id: Option<Uuid>,
    subject_id: Option<Uuid>,
    subject_name: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
    details: Value,
}

async fn fetch(
    state: &AppState,
    scope: &Scope,
    q: &AuditQuery,
    limit: i64,
) -> Result<Vec<Row>, sqlx::Error> {
    let action = q.action.clone().unwrap_or_default();
    let (filter, id) = match scope {
        Scope::Person(u) => ("(e.actor_id = $1 OR e.subject_user_id = $1)", *u),
        Scope::Team(t) => ("e.organization_id = $1", *t),
    };
    let sql = format!(
        r#"SELECT e.id, e.occurred_at, e.action, e.actor_id, a.username, e.via, e.api_key_id,
                  e.organization_id, e.subject_user_id, s.username, e.target_type, e.target_id,
                  e.ip, e.user_agent, e.details
           FROM audit_events e
           LEFT JOIN users a ON a.id = e.actor_id
           LEFT JOIN users s ON s.id = e.subject_user_id
           WHERE {filter}
             AND ($2::BIGINT IS NULL OR e.id < $2)
             AND ($3 = '' OR e.action LIKE $3 || '%')
           ORDER BY e.id DESC
           LIMIT $4"#
    );
    let rows: Vec<(
        i64,
        DateTime<Utc>,
        String,
        Option<Uuid>,
        Option<String>,
        String,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Value,
    )> = sqlx::query_as(&sql)
        .bind(id)
        .bind(q.before)
        .bind(&action)
        .bind(limit)
        .fetch_all(state.db.pool())
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Row {
            id: r.0,
            occurred_at: r.1,
            action: r.2,
            actor_id: r.3,
            actor_name: r.4,
            via: r.5,
            api_key_id: r.6,
            organization_id: r.7,
            subject_id: r.8,
            subject_name: r.9,
            target_type: r.10,
            target_id: r.11,
            ip: r.12,
            user_agent: r.13,
            details: r.14,
        })
        .collect())
}

fn to_json(r: &Row, personal: bool) -> Value {
    let mut v = json!({
        "id": r.id,
        "occurredAt": r.occurred_at,
        "action": r.action,
        "actor": r.actor_id.map(|id| json!({ "id": id, "username": r.actor_name })),
        "via": r.via,
        "apiKeyId": r.api_key_id,
        "teamId": r.organization_id,
        "subject": r.subject_id.map(|id| json!({ "id": id, "username": r.subject_name })),
        "targetType": r.target_type,
        "targetId": r.target_id,
        "details": r.details,
    });
    if personal {
        v["ip"] = json!(r.ip);
        v["userAgent"] = json!(r.user_agent);
    }
    v
}

fn to_csv(rows: &[Row], personal: bool) -> String {
    let mut out = String::from(if personal {
        "time,action,actor,via,subject,target_type,target_id,ip,user_agent,details\n"
    } else {
        "time,action,actor,via,subject,target_type,target_id,details\n"
    });
    let name = |n: &Option<String>, id: &Option<Uuid>| {
        n.clone()
            .or_else(|| id.map(|i| i.to_string()))
            .unwrap_or_default()
    };
    for r in rows {
        let mut fields = vec![
            r.occurred_at.to_rfc3339(),
            r.action.clone(),
            name(&r.actor_name, &r.actor_id),
            r.via.clone(),
            name(&r.subject_name, &r.subject_id),
            r.target_type.clone().unwrap_or_default(),
            r.target_id.clone().unwrap_or_default(),
        ];
        if personal {
            fields.push(r.ip.clone().unwrap_or_default());
            fields.push(r.user_agent.clone().unwrap_or_default());
        }
        fields.push(r.details.to_string());
        out.push_str(
            &fields
                .iter()
                .map(|f| csv_field(f))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

async fn respond(state: &AppState, scope: Scope, q: AuditQuery, filename: &str) -> Response {
    let action = match clean_action_filter(q.action.as_deref()) {
        Ok(a) => a,
        Err(m) => return bad(StatusCode::BAD_REQUEST, m),
    };
    let q = AuditQuery { action, ..q };
    let personal = matches!(scope, Scope::Person(_));
    let csv = q.format.as_deref() == Some("csv");
    let limit = if csv {
        CSV_MAX
    } else {
        q.limit.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX)
    };
    let rows = match fetch(state, &scope, &q, limit).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("audit query failed: {e}");
            return bad(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong");
        }
    };
    if csv {
        let mut resp = to_csv(&rows, personal).into_response();
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
            h.insert(header::CONTENT_DISPOSITION, v);
        }
        return resp;
    }
    let next = if rows.len() as i64 == limit {
        rows.last().map(|r| r.id)
    } else {
        None
    };
    Json(json!({
        "events": rows.iter().map(|r| to_json(r, personal)).collect::<Vec<_>>(),
        "nextBefore": next,
    }))
    .into_response()
}

/// `GET /users/me/audit`
pub async fn my_audit(
    State(state): State<AppState>,
    claims: Claims,
    Query(q): Query<AuditQuery>,
) -> Response {
    respond(&state, Scope::Person(claims.sub), q, "verdyx-activity.csv").await
}

/// `GET /orgs/{id}/audit` (owners and admins)
pub async fn team_audit(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Query(q): Query<AuditQuery>,
) -> Response {
    match crate::handlers::organization::member_role(state.db.pool(), org_id, claims.sub).await {
        Ok(Some(role)) if crate::handlers::organization::can_manage(&role) => {}
        Ok(Some(_)) => {
            return bad(
                StatusCode::FORBIDDEN,
                "only owners and admins can read the team's audit log",
            )
        }
        Ok(None) => return bad(StatusCode::NOT_FOUND, "team not found"),
        Err(e) => {
            tracing::error!("team audit membership check failed: {e}");
            return bad(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong");
        }
    }
    respond(&state, Scope::Team(org_id), q, "verdyx-team-audit.csv").await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ip: Option<&str>) -> Row {
        Row {
            id: 7,
            occurred_at: "2026-11-17T10:00:00Z".parse().unwrap(),
            action: "team.member.removed".into(),
            actor_id: Some(Uuid::nil()),
            actor_name: Some("ana".into()),
            via: "session".into(),
            api_key_id: None,
            organization_id: Some(Uuid::nil()),
            subject_id: Some(Uuid::nil()),
            subject_name: None,
            target_type: None,
            target_id: None,
            ip: ip.map(str::to_string),
            user_agent: Some("=HYPERLINK(\"x\")".into()),
            details: json!({"role": "viewer"}),
        }
    }

    #[test]
    fn action_filters_are_restricted() {
        assert_eq!(clean_action_filter(None).unwrap(), None);
        assert_eq!(clean_action_filter(Some("  ")).unwrap(), None);
        assert_eq!(
            clean_action_filter(Some("team.member")).unwrap().as_deref(),
            Some("team.member")
        );
        for bad in ["team%", "a'b", "TEAM", "team member"] {
            assert!(clean_action_filter(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn csv_fields_are_quoted_and_defused() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_field("-5"), "\"'-5\"");
    }

    #[test]
    fn team_exports_leave_out_ip_and_browser() {
        let personal = to_csv(&[row(Some("203.0.113.9"))], true);
        assert!(personal.starts_with(
            "time,action,actor,via,subject,target_type,target_id,ip,user_agent,details\n"
        ));
        assert!(personal.contains("203.0.113.9"));
        assert!(personal.contains("\"'=HYPERLINK(\"\"x\"\")\""));

        let team = to_csv(&[row(Some("203.0.113.9"))], false);
        assert!(!team.contains("203.0.113.9"));
        assert!(!team.contains("HYPERLINK"));
        let j = to_json(&row(Some("203.0.113.9")), false);
        assert!(j.get("ip").is_none());
        assert_eq!(j["actor"]["username"], "ana");
        // A deleted account shows by its id.
        assert!(team.contains(&Uuid::nil().to_string()));
    }
}
