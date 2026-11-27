//! Plans and quotas.
//!
//! A team is on a plan: **Free** (every team, the limits Verdyx has always
//! had), **Team** or **Enterprise**. A plan sets:
//!
//! - how many scans each person may start a minute and a day (the in-memory
//!   limiter in [`crate::middleware::rate_limiter`] reads these);
//! - how many scans the team may save in a calendar month (UTC), counted
//!   from the `submissions` table, so it survives restarts and holds across
//!   gateway instances;
//! - seats (members plus open invitations), active team API keys and storage
//!   connections.
//!
//! A Verdyx administrator sets a team's plan, and may override any limit for
//! that team (an Enterprise contract, say), with `PUT /admin/teams/{id}/plan`.
//! There's no checkout: paid plans are arranged with Verdyx.
//!
//! A person's own limits come from the best plan among their teams, so
//! someone in a Team-plan team gets its per-person limits for all their
//! scans. Signed-out scans and people in no paid team get Free's.

use chrono::{DateTime, Datelike, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub const PLANS: [&str; 3] = ["free", "team", "enterprise"];

/// A plan's limits. `None` is unlimited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub scans_per_minute: u32,
    pub scans_per_day: u32,
    pub team_scans_per_month: Option<i64>,
    pub seats: i64,
    pub team_keys: i64,
    pub storage_connections: i64,
}

/// Overrides an administrator set for one team. Missing fields take the
/// plan's value; `teamScansPerMonth: null` isn't an override (use
/// `unlimitedMonthlyScans`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans_per_minute: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans_per_day: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_scans_per_month: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unlimited_monthly_scans: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seats: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_keys: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_connections: Option<i64>,
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

/// A plan's own limits, before any override. Free's per-person limits are
/// `SCAN_RATE_LIMIT_PER_MINUTE` and `SCAN_RATE_LIMIT_PER_DAY` (10 and 100),
/// as before plans existed; a paid plan is never below them.
pub fn base(plan: &str) -> Limits {
    let free_minute = env_u32("SCAN_RATE_LIMIT_PER_MINUTE", 10);
    let free_day = env_u32("SCAN_RATE_LIMIT_PER_DAY", 100);
    match plan {
        "team" => Limits {
            scans_per_minute: free_minute.max(60),
            scans_per_day: free_day.max(2_000),
            team_scans_per_month: Some(50_000),
            seats: 200,
            team_keys: 50,
            storage_connections: 10,
        },
        "enterprise" => Limits {
            scans_per_minute: free_minute.max(300),
            scans_per_day: free_day.max(20_000),
            team_scans_per_month: None,
            seats: 1_000,
            team_keys: 200,
            storage_connections: 25,
        },
        _ => Limits {
            scans_per_minute: free_minute,
            scans_per_day: free_day,
            // Free during the beta: only the per-person limits apply.
            team_scans_per_month: None,
            seats: 50,
            team_keys: 10,
            storage_connections: 5,
        },
    }
}

/// A plan's limits with a team's overrides applied.
pub fn limits(plan: &str, overrides: &Overrides) -> Limits {
    let b = base(plan);
    Limits {
        scans_per_minute: overrides.scans_per_minute.unwrap_or(b.scans_per_minute),
        scans_per_day: overrides.scans_per_day.unwrap_or(b.scans_per_day),
        team_scans_per_month: if overrides.unlimited_monthly_scans {
            None
        } else {
            overrides.team_scans_per_month.or(b.team_scans_per_month)
        },
        seats: overrides.seats.unwrap_or(b.seats),
        team_keys: overrides.team_keys.unwrap_or(b.team_keys),
        storage_connections: overrides
            .storage_connections
            .unwrap_or(b.storage_connections),
    }
}

/// How plans rank, for picking a person's best plan.
pub fn rank(plan: &str) -> u8 {
    match plan {
        "enterprise" => 2,
        "team" => 1,
        _ => 0,
    }
}

/// Why overrides aren't acceptable, if they aren't.
pub fn check_overrides(o: &Overrides) -> Result<(), &'static str> {
    let pos32 = |v: Option<u32>| v.is_none_or(|n| (1..=1_000_000).contains(&n));
    let pos64 = |v: Option<i64>| v.is_none_or(|n| (1..=100_000_000).contains(&n));
    if !pos32(o.scans_per_minute) || !pos32(o.scans_per_day) {
        return Err("scan limits must be between 1 and 1,000,000");
    }
    if !pos64(o.team_scans_per_month)
        || !pos64(o.seats)
        || !pos64(o.team_keys)
        || !pos64(o.storage_connections)
    {
        return Err("limits must be positive whole numbers");
    }
    if o.unlimited_monthly_scans && o.team_scans_per_month.is_some() {
        return Err("set either teamScansPerMonth or unlimitedMonthlyScans, not both");
    }
    Ok(())
}

/// The start of this calendar month and of the next (UTC).
pub fn month_bounds(now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let start = Utc
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .unwrap_or(now);
    let (y, m) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };
    let next = Utc
        .with_ymd_and_hms(y, m, 1, 0, 0, 0)
        .single()
        .unwrap_or(now);
    (start, next)
}

// ─── The database ────────────────────────────────────────────────────

/// A team's plan and limits.
#[derive(Debug, Clone)]
pub struct TeamPlan {
    pub plan: String,
    pub overrides: Overrides,
    pub limits: Limits,
}

/// A team's plan; Free for a team that isn't found.
pub async fn team_plan(pool: &sqlx::PgPool, org_id: Uuid) -> Result<TeamPlan, sqlx::Error> {
    let row: Option<(String, Value)> =
        sqlx::query_as("SELECT plan, plan_limits FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(pool)
            .await?;
    let (plan, raw) = row.unwrap_or_else(|| ("free".to_string(), json!({})));
    let overrides: Overrides = serde_json::from_value(raw).unwrap_or_default();
    let limits = limits(&plan, &overrides);
    Ok(TeamPlan {
        plan,
        overrides,
        limits,
    })
}

/// The per-person limits for `user`: the most generous among their teams'
/// plans, or Free's. (scans a minute, scans a day)
pub async fn person_limits(pool: &sqlx::PgPool, user: Uuid) -> Result<(u32, u32), sqlx::Error> {
    let rows: Vec<(String, Value)> = sqlx::query_as(
        "SELECT o.plan, o.plan_limits FROM organizations o
         JOIN organization_members m ON m.organization_id = o.id
         WHERE m.user_id = $1 AND (o.plan <> 'free' OR o.plan_limits <> '{}'::jsonb)",
    )
    .bind(user)
    .fetch_all(pool)
    .await?;
    let free = base("free");
    Ok(rows
        .into_iter()
        .map(|(plan, raw)| limits(&plan, &serde_json::from_value(raw).unwrap_or_default()))
        .fold((free.scans_per_minute, free.scans_per_day), |(m, d), l| {
            (m.max(l.scans_per_minute), d.max(l.scans_per_day))
        }))
}

/// Scans saved to the team this calendar month.
pub async fn team_scans_this_month(pool: &sqlx::PgPool, org_id: Uuid) -> Result<i64, sqlx::Error> {
    let (start, _) = month_bounds(Utc::now());
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM submissions WHERE organization_id = $1 AND created_at >= $2",
    )
    .bind(org_id)
    .bind(start)
    .fetch_one(pool)
    .await
}

/// The team's monthly scans are used up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaReached {
    pub limit: i64,
    pub resets_at: DateTime<Utc>,
}

impl QuotaReached {
    pub fn message(&self) -> String {
        format!(
            "This team has used its {} scans for the month. The count starts again on {}. Ask Verdyx about a higher limit.",
            self.limit,
            self.resets_at.format("%-d %B")
        )
    }

    /// 429 with the same shape as the rate limiter's answers.
    pub fn response(&self) -> (axum::http::StatusCode, axum::Json<Value>) {
        let retry = (self.resets_at - Utc::now()).num_seconds().max(0);
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({
                "error": "QUOTA_EXCEEDED",
                "message": self.message(),
                "limit": self.limit,
                "resets_at": self.resets_at,
                "retry_after_seconds": retry,
                "status": 429,
            })),
        )
    }
}

/// Whether the team may save `n` more scans this month.
pub fn quota_allows(used: i64, n: i64, limit: Option<i64>) -> bool {
    limit.is_none_or(|l| used + n <= l)
}

/// `Err` when the team has no monthly scans left.
pub async fn check_team_quota(
    pool: &sqlx::PgPool,
    org_id: Uuid,
) -> Result<Result<(), QuotaReached>, sqlx::Error> {
    let plan = team_plan(pool, org_id).await?;
    let Some(limit) = plan.limits.team_scans_per_month else {
        return Ok(Ok(()));
    };
    let used = team_scans_this_month(pool, org_id).await?;
    if quota_allows(used, 1, Some(limit)) {
        Ok(Ok(()))
    } else {
        Ok(Err(QuotaReached {
            limit,
            resets_at: month_bounds(Utc::now()).1,
        }))
    }
}

/// A team's plan, limits and how much of them is used.
pub async fn team_usage(pool: &sqlx::PgPool, org_id: Uuid) -> Result<Value, sqlx::Error> {
    let plan = team_plan(pool, org_id).await?;
    let (start, next) = month_bounds(Utc::now());
    let (scans, seats, keys, storage): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM submissions WHERE organization_id = $1 AND created_at >= $2),
            (SELECT COUNT(*) FROM organization_members WHERE organization_id = $1)
              + (SELECT COUNT(*) FROM organization_invitations
                 WHERE organization_id = $1 AND accepted_at IS NULL AND expires_at > NOW()),
            (SELECT COUNT(*) FROM api_keys WHERE organization_id = $1 AND is_active = TRUE
                AND (expires_at IS NULL OR expires_at > NOW())),
            (SELECT COUNT(*) FROM storage_connections WHERE organization_id = $1)",
    )
    .bind(org_id)
    .bind(start)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "plan": plan.plan,
        "custom": plan.overrides != Overrides::default(),
        "limits": plan.limits,
        "usage": {
            "scansThisMonth": scans,
            "seats": seats,
            "teamKeys": keys,
            "storageConnections": storage,
        },
        "periodStart": start,
        "resetsAt": next,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_keeps_the_limits_verdyx_always_had() {
        let free = base("free");
        assert_eq!(
            (free.seats, free.team_keys, free.storage_connections),
            (50, 10, 5)
        );
        assert_eq!(free.team_scans_per_month, None);
        assert_eq!(base("unknown"), free);
    }

    #[test]
    fn paid_plans_only_raise_limits() {
        let free = base("free");
        for plan in ["team", "enterprise"] {
            let p = base(plan);
            assert!(p.scans_per_minute >= free.scans_per_minute, "{plan}");
            assert!(p.scans_per_day >= free.scans_per_day, "{plan}");
            assert!(
                p.seats > free.seats && p.team_keys > free.team_keys,
                "{plan}"
            );
            assert!(p.storage_connections > free.storage_connections, "{plan}");
        }
        assert!(rank("enterprise") > rank("team") && rank("team") > rank("free"));
    }

    #[test]
    fn overrides_replace_only_what_they_name() {
        let o: Overrides =
            serde_json::from_value(json!({ "seats": 5000, "teamScansPerMonth": 1_000_000 }))
                .unwrap();
        let l = limits("enterprise", &o);
        assert_eq!(l.seats, 5000);
        assert_eq!(l.team_scans_per_month, Some(1_000_000));
        assert_eq!(l.team_keys, base("enterprise").team_keys);

        let unlimited = Overrides {
            unlimited_monthly_scans: true,
            ..Default::default()
        };
        assert_eq!(limits("team", &unlimited).team_scans_per_month, None);
        assert!(serde_json::from_value::<Overrides>(json!({ "seat": 1 })).is_err());
    }

    #[test]
    fn overrides_are_checked() {
        assert!(check_overrides(&Overrides::default()).is_ok());
        for bad in [
            json!({ "seats": 0 }),
            json!({ "scansPerDay": 0 }),
            json!({ "teamKeys": -1 }),
            json!({ "teamScansPerMonth": 10, "unlimitedMonthlyScans": true }),
        ] {
            let o: Overrides = serde_json::from_value(bad.clone()).unwrap();
            assert!(check_overrides(&o).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_month_runs_from_the_first_to_the_first() {
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        assert_eq!(
            month_bounds(at("2026-11-27T19:00:00Z")),
            (at("2026-11-01T00:00:00Z"), at("2026-12-01T00:00:00Z"))
        );
        assert_eq!(
            month_bounds(at("2026-12-31T23:59:59Z")).1,
            at("2027-01-01T00:00:00Z")
        );
    }

    /// Against a real database; runs only when API_GATEWAY_DATABASE_URL is
    /// set, and removes what it adds.
    #[tokio::test]
    async fn plans_hold_in_the_database() {
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

        let (free_team, paid_team, person, outsider) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        for t in [free_team, paid_team] {
            sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, 'Acme', $2)")
                .bind(t)
                .bind(person)
                .execute(&db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'owner')")
                .bind(t)
                .bind(person)
                .execute(&db)
                .await
                .unwrap();
        }

        // Every team starts on Free, with the limits teams always had.
        let p = team_plan(&db, free_team).await.unwrap();
        assert_eq!((p.plan.as_str(), p.limits.seats), ("free", 50));
        assert_eq!(person_limits(&db, person).await.unwrap(), {
            let f = base("free");
            (f.scans_per_minute, f.scans_per_day)
        });
        // Free has no monthly quota.
        assert_eq!(check_team_quota(&db, free_team).await.unwrap(), Ok(()));

        // An unknown plan can't be stored.
        assert!(
            sqlx::query("UPDATE organizations SET plan = 'gold' WHERE id = $1")
                .bind(paid_team)
                .execute(&db)
                .await
                .is_err()
        );

        // A Team plan with a small custom quota.
        sqlx::query("UPDATE organizations SET plan = 'team', plan_limits = $2 WHERE id = $1")
            .bind(paid_team)
            .bind(json!({ "teamScansPerMonth": 2, "seats": 3 }))
            .execute(&db)
            .await
            .unwrap();
        let p = team_plan(&db, paid_team).await.unwrap();
        assert_eq!(
            (p.limits.seats, p.limits.team_keys),
            (3, base("team").team_keys)
        );
        // Its members get Team's per-person limits everywhere; others don't.
        let team = base("team");
        assert_eq!(
            person_limits(&db, person).await.unwrap(),
            (team.scans_per_minute, team.scans_per_day)
        );
        assert_eq!(
            person_limits(&db, outsider).await.unwrap().1,
            base("free").scans_per_day
        );

        for _ in 0..2 {
            assert_eq!(check_team_quota(&db, paid_team).await.unwrap(), Ok(()));
            sqlx::query(
                "INSERT INTO submissions (id, submitter_id, original_filename, file_hash, file_size,
                     mime_type, submission_type, analysis_status, organization_id)
                 VALUES ($1, $2, 'a.bin', 'h', 1, 'application/octet-stream', 'file', 'pending', $3)",
            )
            .bind(Uuid::new_v4())
            .bind(person)
            .bind(paid_team)
            .execute(&db)
            .await
            .unwrap();
        }
        let reached = check_team_quota(&db, paid_team).await.unwrap().unwrap_err();
        assert_eq!(reached.limit, 2);
        let usage = team_usage(&db, paid_team).await.unwrap();
        assert_eq!(usage["usage"]["scansThisMonth"], 2);
        assert_eq!(usage["usage"]["seats"], 1);
        assert_eq!(usage["custom"], true);

        sqlx::query("DELETE FROM submissions WHERE organization_id = $1")
            .bind(paid_team)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = ANY($1)")
            .bind(vec![free_team, paid_team])
            .execute(&db)
            .await
            .unwrap();
    }

    #[test]
    fn the_quota_counts_the_scan_being_made() {
        assert!(quota_allows(9, 1, Some(10)));
        assert!(!quota_allows(10, 1, Some(10)));
        assert!(quota_allows(1_000_000, 1, None));
        let q = QuotaReached {
            limit: 50_000,
            resets_at: Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap(),
        };
        assert!(q.message().contains("50000 scans for the month"));
        assert!(q.message().contains("1 December"));
        assert_eq!(q.response().0, axum::http::StatusCode::TOO_MANY_REQUESTS);
    }
}
