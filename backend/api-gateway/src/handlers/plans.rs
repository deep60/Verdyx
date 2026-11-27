//! Plans and usage: what a team and a person may do, and how much of it is
//! used ([`crate::services::plans`]), and the administrator's routes that set
//! a team's plan.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::organization::member_role;
use crate::middleware::auth::Claims;
use crate::services::{audit, plans};
use crate::AppState;

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T> = Result<T, ApiError>;

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("plans query failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

/// `GET /orgs/{id}/usage`: the team's plan, limits and use, for any member.
pub async fn team_usage(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let pool = state.db.pool();
    member_role(pool, org_id, claims.sub)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "team not found"))?;
    Ok(Json(plans::team_usage(pool, org_id).await.map_err(db_err)?))
}

/// `GET /users/me/usage`: the caller's own scan limits (the best plan among
/// their teams) and their scans in the last 24 hours.
pub async fn my_usage(State(state): State<AppState>, claims: Claims) -> ApiResult<Json<Value>> {
    let pool = state.db.pool();
    let (per_minute, per_day) = plans::person_limits(pool, claims.sub)
        .await
        .map_err(db_err)?;
    let last_day: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM submissions
         WHERE submitter_id = $1 AND created_at > NOW() - INTERVAL '24 hours'",
    )
    .bind(claims.sub)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let teams: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT o.id, o.name, o.plan FROM organizations o
         JOIN organization_members m ON m.organization_id = o.id
         WHERE m.user_id = $1 ORDER BY o.name",
    )
    .bind(claims.sub)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let best = teams
        .iter()
        .map(|t| t.2.as_str())
        .max_by_key(|p| plans::rank(p))
        .unwrap_or("free");
    Ok(Json(json!({
        "plan": best,
        "limits": { "scansPerMinute": per_minute, "scansPerDay": per_day },
        "usage": { "scansLast24Hours": last_day },
        "teams": teams.into_iter().map(|(id, name, plan)| json!({
            "id": id, "name": name, "plan": plan,
        })).collect::<Vec<_>>(),
    })))
}

// ─── Administrators ──────────────────────────────────────────────

/// Only a Verdyx administrator's session. API keys never carry the flag.
fn require_admin(claims: &Claims) -> ApiResult<()> {
    if claims.org_id.is_none() && (claims.is_admin || claims.role == "admin") {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "only Verdyx administrators can change plans",
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct TeamSearch {
    pub q: Option<String>,
    pub limit: Option<i64>,
}

/// `GET /admin/teams?q=`: teams by name or id, with their plans.
pub async fn admin_list_teams(
    State(state): State<AppState>,
    claims: Claims,
    Query(search): Query<TeamSearch>,
) -> ApiResult<Json<Value>> {
    require_admin(&claims)?;
    let q = search.q.unwrap_or_default().trim().to_lowercase();
    let limit = search.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<(Uuid, String, String, Value, i64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT o.id, o.name, o.plan, o.plan_limits,
                (SELECT COUNT(*) FROM organization_members m WHERE m.organization_id = o.id),
                o.created_at
         FROM organizations o
         WHERE $1 = '' OR LOWER(o.name) LIKE '%' || $1 || '%' OR o.id::text = $1
         ORDER BY o.created_at DESC
         LIMIT $2",
    )
    .bind(&q)
    .bind(limit)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    Ok(Json(json!({
        "teams": rows.into_iter().map(|(id, name, plan, overrides, members, created_at)| json!({
            "id": id,
            "name": name,
            "plan": plan,
            "overrides": overrides,
            "members": members,
            "createdAt": created_at,
        })).collect::<Vec<_>>(),
    })))
}

/// `GET /admin/teams/{id}/plan`
pub async fn admin_get_plan(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_admin(&claims)?;
    let pool = state.db.pool();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)")
            .bind(org_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    if !exists {
        return Err(err(StatusCode::NOT_FOUND, "team not found"));
    }
    let plan = plans::team_plan(pool, org_id).await.map_err(db_err)?;
    let mut usage = plans::team_usage(pool, org_id).await.map_err(db_err)?;
    usage["overrides"] = json!(plan.overrides);
    Ok(Json(usage))
}

#[derive(Debug, Deserialize)]
pub struct SetPlan {
    pub plan: String,
    /// Replaces the team's overrides; leave out to clear them.
    #[serde(default)]
    pub overrides: plans::Overrides,
}

/// What's wrong with a plan change, if anything.
pub fn check_change(body: &SetPlan) -> Result<(), &'static str> {
    if !plans::PLANS.contains(&body.plan.as_str()) {
        return Err("plan must be free, team or enterprise");
    }
    plans::check_overrides(&body.overrides)
}

/// `PUT /admin/teams/{id}/plan`: `{"plan": "team", "overrides": {...}}`.
pub async fn admin_set_plan(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<SetPlan>,
) -> ApiResult<Json<Value>> {
    require_admin(&claims)?;
    check_change(&body).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let pool = state.db.pool();
    let before: Option<String> = sqlx::query_scalar(
        "UPDATE organizations o SET plan = $2, plan_limits = $3, plan_changed_at = NOW()
         FROM (SELECT id, plan AS old_plan FROM organizations WHERE id = $1 FOR UPDATE) prev
         WHERE o.id = prev.id
         RETURNING prev.old_plan",
    )
    .bind(org_id)
    .bind(&body.plan)
    .bind(json!(body.overrides))
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let Some(before) = before else {
        return Err(err(StatusCode::NOT_FOUND, "team not found"));
    };
    audit::Event::by(&claims, "team.plan_changed")
        .team(org_id)
        .target("team", org_id)
        .detail("from", before)
        .detail("plan", body.plan.clone())
        .detail("custom", body.overrides != plans::Overrides::default())
        .record(pool)
        .await;
    Ok(Json(plans::team_usage(pool, org_id).await.map_err(db_err)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(role: &str, is_admin: bool, team_key: bool) -> Claims {
        let mut c = Claims::new(Uuid::new_v4(), "a@example.com".into(), role.into(), 1);
        c.is_admin = is_admin;
        if team_key {
            c.org_id = Some(Uuid::new_v4());
        }
        c
    }

    #[test]
    fn only_an_administrators_own_session_may_change_plans() {
        assert!(require_admin(&claims("admin", false, false)).is_ok());
        assert!(require_admin(&claims("user", true, false)).is_ok());
        assert!(require_admin(&claims("user", false, false)).is_err());
        assert!(require_admin(&claims("moderator", false, false)).is_err());
        assert!(require_admin(&claims("admin", true, true)).is_err());
    }

    #[test]
    fn plan_changes_are_checked() {
        let ok: SetPlan =
            serde_json::from_value(json!({ "plan": "enterprise", "overrides": { "seats": 5000 } }))
                .unwrap();
        assert!(check_change(&ok).is_ok());
        let bare: SetPlan = serde_json::from_value(json!({ "plan": "team" })).unwrap();
        assert_eq!(bare.overrides, plans::Overrides::default());
        let unknown: SetPlan = serde_json::from_value(json!({ "plan": "gold" })).unwrap();
        assert!(check_change(&unknown).is_err());
        let zero: SetPlan =
            serde_json::from_value(json!({ "plan": "team", "overrides": { "seats": 0 } })).unwrap();
        assert!(check_change(&zero).is_err());
    }
}
