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
    /// Only teams on this plan; `custom` for teams with custom limits.
    pub plan: Option<String>,
    pub limit: Option<i64>,
}

/// The `plan` filter as SQL takes it: a plan name, `custom`, or empty for all.
pub fn plan_filter(plan: Option<&str>) -> Result<String, &'static str> {
    match plan.map(str::trim).unwrap_or("") {
        "" | "all" => Ok(String::new()),
        p if p == "custom" || plans::PLANS.contains(&p) => Ok(p.to_string()),
        _ => Err("plan must be free, team, enterprise or custom"),
    }
}

/// `GET /admin/teams?q=&plan=`: teams by name or id, with their plans and
/// this month's scans.
pub async fn admin_list_teams(
    State(state): State<AppState>,
    claims: Claims,
    Query(search): Query<TeamSearch>,
) -> ApiResult<Json<Value>> {
    require_admin(&claims)?;
    let plan = plan_filter(search.plan.as_deref()).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let q = search.q.unwrap_or_default();
    let limit = search.limit.unwrap_or(50).clamp(1, 200);
    let teams = list_teams(state.db.pool(), &q, &plan, limit)
        .await
        .map_err(db_err)?;
    Ok(Json(json!({ "teams": teams })))
}

/// Teams matching a name or id (`q`) and a [`plan_filter`], newest first.
async fn list_teams(
    pool: &sqlx::PgPool,
    q: &str,
    plan: &str,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let q = q.trim().to_lowercase();
    let (month_start, _) = plans::month_bounds(Utc::now());
    let rows: Vec<AdminTeamRow> = sqlx::query_as(
        "SELECT o.id, o.name, o.plan, o.plan_limits AS overrides,
                (SELECT COUNT(*) FROM organization_members m WHERE m.organization_id = o.id) AS members,
                (SELECT COUNT(*) FROM submissions s
                 WHERE s.organization_id = o.id AND s.created_at >= $3) AS scans_this_month,
                o.plan_changed_at, o.created_at
         FROM organizations o
         WHERE ($1 = '' OR LOWER(o.name) LIKE '%' || $1 || '%' OR o.id::text = $1)
           AND ($4 = ''
                OR ($4 = 'custom' AND o.plan_limits <> '{}'::jsonb)
                OR o.plan = $4)
         ORDER BY o.created_at DESC
         LIMIT $2",
    )
    .bind(&q)
    .bind(limit)
    .bind(month_start)
    .bind(plan)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
            "id": r.id,
            "name": r.name,
            "plan": r.plan,
            "custom": r.overrides != json!({}),
            "overrides": r.overrides,
            "members": r.members,
            "scansThisMonth": r.scans_this_month,
            "planChangedAt": r.plan_changed_at,
            "createdAt": r.created_at,
            })
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct AdminTeamRow {
    id: Uuid,
    name: String,
    plan: String,
    overrides: Value,
    members: i64,
    scans_this_month: i64,
    plan_changed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

/// `GET /admin/teams/{id}/plan`
pub async fn admin_get_plan(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_admin(&claims)?;
    let pool = state.db.pool();
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    let Some(name) = name else {
        return Err(err(StatusCode::NOT_FOUND, "team not found"));
    };
    let plan = plans::team_plan(pool, org_id).await.map_err(db_err)?;
    let mut usage = plans::team_usage(pool, org_id).await.map_err(db_err)?;
    usage["name"] = json!(name);
    usage["overrides"] = json!(plan.overrides);
    usage["history"] = json!(plan_history(pool, org_id).await.map_err(db_err)?);
    Ok(Json(usage))
}

/// The team's last plan changes, newest first, from its activity log.
async fn plan_history(pool: &sqlx::PgPool, org_id: Uuid) -> Result<Vec<Value>, sqlx::Error> {
    let rows: Vec<(DateTime<Utc>, Option<Uuid>, Value)> = sqlx::query_as(
        "SELECT occurred_at, actor_id, details FROM audit_events
         WHERE organization_id = $1 AND action = 'team.plan_changed'
         ORDER BY id DESC LIMIT 10",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(at, actor, d)| {
            json!({
                "at": at,
                "actorId": actor,
                "from": d.get("from"),
                "plan": d.get("plan"),
                "custom": d.get("custom").and_then(Value::as_bool).unwrap_or(false),
                "overrides": d.get("overrides"),
            })
        })
        .collect())
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
        .detail("overrides", json!(body.overrides))
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
    fn the_team_list_filters_by_plan() {
        assert_eq!(plan_filter(None), Ok(String::new()));
        assert_eq!(plan_filter(Some("all")), Ok(String::new()));
        assert_eq!(plan_filter(Some(" team ")), Ok("team".into()));
        assert_eq!(plan_filter(Some("custom")), Ok("custom".into()));
        assert!(plan_filter(Some("gold")).is_err());
        assert!(plan_filter(Some("free' OR 1=1")).is_err());
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

    /// Against a real database; runs only when API_GATEWAY_DATABASE_URL is
    /// set, and removes what it adds.
    #[tokio::test]
    async fn admin_views_hold_in_the_database() {
        let Ok(url) = std::env::var("API_GATEWAY_DATABASE_URL") else {
            eprintln!("skipping: API_GATEWAY_DATABASE_URL not set");
            return;
        };
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        let tag = Uuid::new_v4().simple().to_string();
        let (plain, custom, person) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for (t, name) in [
            (plain, format!("Plain {tag}")),
            (custom, format!("Custom {tag}")),
        ] {
            sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, $2, $3)")
                .bind(t)
                .bind(name)
                .bind(person)
                .execute(&db)
                .await
                .unwrap();
        }
        sqlx::query(
            "UPDATE organizations SET plan = 'team', plan_limits = '{\"seats\": 500}', plan_changed_at = NOW()
             WHERE id = $1",
        )
        .bind(custom)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO audit_events (action, actor_id, organization_id, details)
             VALUES ('team.plan_changed', $1, $2,
                     '{\"from\": \"free\", \"plan\": \"team\", \"custom\": true, \"overrides\": {\"seats\": 500}}')",
        )
        .bind(person)
        .bind(custom)
        .execute(&db)
        .await
        .unwrap();

        // Search by name, in any case.
        let all = list_teams(&db, &tag.to_uppercase(), "", 50).await.unwrap();
        assert_eq!(all.len(), 2);
        let found = list_teams(&db, &format!("custom {tag}"), "", 50)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["plan"], "team");
        assert_eq!(found[0]["custom"], true);
        assert_eq!(found[0]["overrides"]["seats"], 500);
        assert_eq!(found[0]["scansThisMonth"], 0);
        assert!(found[0]["planChangedAt"].is_string());
        // By id, and by plan.
        assert_eq!(
            list_teams(&db, &plain.to_string(), "", 50)
                .await
                .unwrap()
                .len(),
            1
        );
        let custom_only = list_teams(&db, &tag, "custom", 50).await.unwrap();
        assert_eq!(custom_only.len(), 1);
        assert_eq!(custom_only[0]["id"], custom.to_string());
        let free_only = list_teams(&db, &tag, "free", 50).await.unwrap();
        assert_eq!(free_only.len(), 1);
        assert_eq!(free_only[0]["custom"], false);
        assert!(list_teams(&db, &tag, "enterprise", 50)
            .await
            .unwrap()
            .is_empty());

        // The plan history comes from the activity log.
        let history = plan_history(&db, custom).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(
            (history[0]["from"].as_str(), history[0]["plan"].as_str()),
            (Some("free"), Some("team"))
        );
        assert_eq!(history[0]["overrides"]["seats"], 500);
        assert!(plan_history(&db, plain).await.unwrap().is_empty());

        // Audit rows are append-only by design, so only the teams go.
        sqlx::query("DELETE FROM organizations WHERE id = ANY($1)")
            .bind(vec![plain, custom])
            .execute(&db)
            .await
            .unwrap();
    }
}
