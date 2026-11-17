//! Teams (organisations).
//!
//! A team has members, each with one role:
//!
//! | role   | see team scans | scan into the team | invite, remove, change roles, team keys | rename | delete |
//! |--------|:-:|:-:|:-:|:-:|:-:|
//! | owner  | ✓ | ✓ | ✓ (any role)              | ✓ | ✓ |
//! | admin  | ✓ | ✓ | ✓ (not owners, not to owner) | ✓ |   |
//! | member | ✓ | ✓ |                           |   |   |
//! | viewer | ✓ |   |                           |   |   |
//!
//! A team always keeps at least one owner. Anyone may leave, except its last
//! owner.
//!
//! **Invitations** are bound to an email address. The inviter gets a link to
//! pass on; only the person signed in with that address can use it. Someone
//! whose address is verified can also accept from their own list of
//! invitations, without the link.
//!
//! **Team API keys** belong to the team: scans made with one are saved to the
//! team, and it can only read the team's scans. It is made by an admin and
//! stops working if that person stops being an admin or owner.

// Query rows are read as plain tuples.
#![allow(clippy::type_complexity)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::middleware::{api_key, auth::Claims};
use crate::services::audit;
use crate::AppState;

pub const ROLES: [&str; 4] = ["owner", "admin", "member", "viewer"];
/// Teams one person may own.
pub const MAX_OWNED_TEAMS: i64 = 5;
/// Members plus open invitations in one team.
pub const MAX_SEATS: i64 = 50;
/// Active keys one team may hold.
pub const MAX_TEAM_KEYS: i64 = 10;
pub const INVITE_DAYS: i64 = 7;

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T> = Result<T, ApiError>;

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("team query failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

/// Not a member and no such team look the same, so ids can't be probed.
fn not_found() -> ApiError {
    err(StatusCode::NOT_FOUND, "team not found")
}

// ─── Rules (pure, unit-tested) ─────────────────────────────────────

fn rank(role: &str) -> u8 {
    match role {
        "owner" => 3,
        "admin" => 2,
        "member" => 1,
        _ => 0,
    }
}

pub fn is_role(role: &str) -> bool {
    ROLES.contains(&role)
}

/// Owners and admins run the team.
pub fn can_manage(role: &str) -> bool {
    rank(role) >= 2
}

/// Viewers can only look.
pub fn can_scan(role: &str) -> bool {
    rank(role) >= 1
}

/// May `actor` give someone whose role is `current` (None: not yet a member)
/// the role `new_role`?
pub fn can_assign(actor: &str, current: Option<&str>, new_role: &str) -> Result<(), &'static str> {
    if !is_role(new_role) {
        return Err("unknown role; use owner, admin, member or viewer");
    }
    match actor {
        "owner" => Ok(()),
        "admin" if current == Some("owner") => Err("only an owner can change an owner's role"),
        "admin" if new_role == "owner" => Err("only an owner can make someone an owner"),
        "admin" => Ok(()),
        _ => Err("only owners and admins can manage members"),
    }
}

/// May `actor_id` (role `actor`) remove `target_id` (role `target`)?
/// Removing yourself is leaving, which anyone may do.
pub fn can_remove(
    actor: &str,
    actor_id: Uuid,
    target: &str,
    target_id: Uuid,
) -> Result<(), &'static str> {
    if actor_id == target_id {
        return Ok(());
    }
    match actor {
        "owner" => Ok(()),
        "admin" if target == "owner" => Err("only an owner can remove an owner"),
        "admin" => Ok(()),
        _ => Err("only owners and admins can remove members"),
    }
}

pub fn clean_name(raw: Option<&str>) -> Result<String, &'static str> {
    let name: String = raw
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() {
        return Err("give the team a name");
    }
    if name.chars().count() > 100 {
        return Err("team names are at most 100 characters");
    }
    Ok(name)
}

pub fn clean_email(raw: &str) -> Option<String> {
    let e = raw.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    let ok = !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && e.len() <= 255
        && !e.chars().any(char::is_whitespace);
    ok.then_some(e)
}

fn new_invite_code() -> String {
    format!("inv_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn hash_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.trim().as_bytes()))
}

// ─── Shared lookups (also used by scans and API keys) ──────────────

/// The caller's role in a team, or None if they aren't in it.
pub async fn member_role(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Takes someone out of every team, for account deletion. A team they alone
/// own passes to its longest-standing admin (or member, then viewer); a team
/// with nobody else in it is deleted. Their team keys stop working.
pub async fn leave_all(pool: &sqlx::PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let teams: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT organization_id, role FROM organization_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await?;
    for (org_id, role) in teams {
        if role == "owner" {
            let other_owners: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM organization_members
                 WHERE organization_id = $1 AND role = 'owner' AND user_id <> $2",
            )
            .bind(org_id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
            if other_owners == 0 {
                let promoted = sqlx::query(
                    "UPDATE organization_members SET role = 'owner'
                     WHERE (organization_id, user_id) = (
                        SELECT organization_id, user_id FROM organization_members
                        WHERE organization_id = $1 AND user_id <> $2
                        ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'member' THEN 1 ELSE 2 END, joined_at
                        LIMIT 1)",
                )
                .bind(org_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
                if promoted.rows_affected() == 0 {
                    sqlx::query("DELETE FROM organizations WHERE id = $1")
                        .bind(org_id)
                        .execute(&mut *tx)
                        .await?;
                    continue;
                }
            }
        }
        sqlx::query("DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE api_keys SET is_active = FALSE WHERE user_id = $1 AND organization_id IS NOT NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// The caller's role, or 404. Team keys can't use these endpoints (the key
/// middleware refuses them), so `claims.sub` is always a person here.
async fn require_member(state: &AppState, org_id: Uuid, claims: &Claims) -> ApiResult<String> {
    member_role(state.db.pool(), org_id, claims.sub)
        .await
        .map_err(db_err)?
        .ok_or_else(not_found)
}

async fn require_manager(state: &AppState, org_id: Uuid, claims: &Claims) -> ApiResult<String> {
    let role = require_member(state, org_id, claims).await?;
    if can_manage(&role) {
        Ok(role)
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "only owners and admins can do this",
        ))
    }
}

async fn owner_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM organization_members WHERE organization_id = $1 AND role = 'owner'",
    )
    .bind(org_id)
    .fetch_one(&mut **tx)
    .await
}

/// Locks the team row so concurrent role changes can't remove the last owner.
async fn lock_team(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(org_id)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

// ─── Teams ─────────────────────────────────────────────────────────

/// `GET /orgs`: the caller's teams.
pub async fn list_teams(State(state): State<AppState>, claims: Claims) -> ApiResult<Json<Value>> {
    let rows: Vec<(Uuid, String, String, i64, DateTime<Utc>)> = sqlx::query_as(
        r#"SELECT o.id, o.name, m.role,
                  (SELECT COUNT(*) FROM organization_members x WHERE x.organization_id = o.id),
                  o.created_at
           FROM organizations o
           JOIN organization_members m ON m.organization_id = o.id AND m.user_id = $1
           ORDER BY o.name"#,
    )
    .bind(claims.sub)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|(id, name, role, members, created_at)| {
                json!({ "id": id, "name": name, "role": role, "memberCount": members, "createdAt": created_at })
            })
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct TeamBody {
    pub name: Option<String>,
}

/// `POST /orgs`: create a team; the caller becomes its owner.
pub async fn create_team(
    State(state): State<AppState>,
    claims: Claims,
    Json(body): Json<TeamBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let name = clean_name(body.name.as_deref()).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let owned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organization_members WHERE user_id = $1 AND role = 'owner'",
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .map_err(db_err)?;
    if owned >= MAX_OWNED_TEAMS {
        return Err(err(
            StatusCode::CONFLICT,
            "you already own 5 teams; delete one first",
        ));
    }
    let id = Uuid::new_v4();
    let mut tx = state.db.pool().begin().await.map_err(db_err)?;
    sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&name)
        .bind(claims.sub)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(id)
    .bind(claims.sub)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    audit::Event::by(&claims, "team.created")
        .team(id)
        .detail("name", name.clone())
        .record(state.db.pool())
        .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "name": name, "role": "owner", "memberCount": 1 })),
    ))
}

/// `GET /orgs/{id}`: the team, its members, and (for owners and admins) its
/// open invitations.
pub async fn get_team(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let role = require_member(&state, org_id, &claims).await?;
    let (name, created_at, retention_days): (String, DateTime<Utc>, Option<i32>) = sqlx::query_as(
        "SELECT name, created_at, scan_retention_days FROM organizations WHERE id = $1",
    )
    .bind(org_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(db_err)?;
    let members: Vec<(Uuid, String, DateTime<Utc>, Option<String>, Option<String>)> =
        sqlx::query_as(
            r#"SELECT m.user_id, m.role, m.joined_at, u.username, u.email
               FROM organization_members m
               LEFT JOIN users u ON u.id = m.user_id
               WHERE m.organization_id = $1
               ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'member' THEN 2 ELSE 3 END,
                        m.joined_at"#,
        )
        .bind(org_id)
        .fetch_all(state.db.pool())
        .await
        .map_err(db_err)?;
    let invitations = if can_manage(&role) {
        let rows: Vec<(Uuid, String, String, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
            r#"SELECT id, email, role, created_at, expires_at FROM organization_invitations
               WHERE organization_id = $1 AND accepted_at IS NULL
               ORDER BY created_at DESC"#,
        )
        .bind(org_id)
        .fetch_all(state.db.pool())
        .await
        .map_err(db_err)?;
        let now = Utc::now();
        rows.into_iter()
            .map(|(id, email, role, created_at, expires_at)| {
                json!({ "id": id, "email": email, "role": role, "createdAt": created_at,
                        "expiresAt": expires_at, "expired": expires_at <= now })
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(Json(json!({
        "id": org_id,
        "name": name,
        "role": role,
        "createdAt": created_at,
        "scanRetentionDays": retention_days,
        "members": members.into_iter().map(|(user_id, role, joined_at, username, email)| json!({
            "userId": user_id, "role": role, "joinedAt": joined_at,
            "username": username, "email": email, "isYou": user_id == claims.sub,
        })).collect::<Vec<_>>(),
        "invitations": invitations,
    })))
}

/// `PATCH /orgs/{id}`: rename (owners and admins).
pub async fn rename_team(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<TeamBody>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let name = clean_name(body.name.as_deref()).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    sqlx::query("UPDATE organizations SET name = $2, updated_at = NOW() WHERE id = $1")
        .bind(org_id)
        .bind(&name)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    audit::Event::by(&claims, "team.renamed")
        .team(org_id)
        .detail("name", name.clone())
        .record(state.db.pool())
        .await;
    Ok(Json(json!({ "id": org_id, "name": name })))
}

/// `DELETE /orgs/{id}`: owners only. The team's scans go back to whoever
/// uploaded them; its keys and invitations are deleted.
pub async fn delete_team(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let role = require_member(&state, org_id, &claims).await?;
    if role != "owner" {
        return Err(err(
            StatusCode::FORBIDDEN,
            "only an owner can delete the team",
        ));
    }
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    audit::Event::by(&claims, "team.deleted")
        .team(org_id)
        .record(state.db.pool())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Members ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RoleBody {
    pub role: String,
}

/// `PATCH /orgs/{id}/members/{user_id}`: change someone's role.
pub async fn set_member_role(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleBody>,
) -> ApiResult<Json<Value>> {
    let actor = require_member(&state, org_id, &claims).await?;
    let mut tx = state.db.pool().begin().await.map_err(db_err)?;
    lock_team(&mut tx, org_id).await.map_err(db_err)?;
    let current: Option<String> = sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let current = current.ok_or_else(|| err(StatusCode::NOT_FOUND, "not a member of this team"))?;
    can_assign(&actor, Some(&current), &body.role).map_err(|m| err(StatusCode::FORBIDDEN, m))?;
    if current == "owner"
        && body.role != "owner"
        && owner_count(&mut tx, org_id).await.map_err(db_err)? <= 1
    {
        return Err(err(
            StatusCode::CONFLICT,
            "a team needs an owner; make someone else owner first",
        ));
    }
    sqlx::query(
        "UPDATE organization_members SET role = $3 WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(&body.role)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if !can_manage(&body.role) {
        // Keys this person made for the team stop working with their admin rights.
        sqlx::query(
            "UPDATE api_keys SET is_active = FALSE WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }
    tx.commit().await.map_err(db_err)?;
    audit::Event::by(&claims, "team.member.role_changed")
        .team(org_id)
        .subject(user_id)
        .detail("from", current.clone())
        .detail("to", body.role.clone())
        .record(state.db.pool())
        .await;
    Ok(Json(json!({ "userId": user_id, "role": body.role })))
}

/// `DELETE /orgs/{id}/members/{user_id}`: remove someone, or leave (your own id).
pub async fn remove_member(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let actor = require_member(&state, org_id, &claims).await?;
    let mut tx = state.db.pool().begin().await.map_err(db_err)?;
    lock_team(&mut tx, org_id).await.map_err(db_err)?;
    let target: Option<String> = sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let target = target.ok_or_else(|| err(StatusCode::NOT_FOUND, "not a member of this team"))?;
    can_remove(&actor, claims.sub, &target, user_id).map_err(|m| err(StatusCode::FORBIDDEN, m))?;
    if target == "owner" && owner_count(&mut tx, org_id).await.map_err(db_err)? <= 1 {
        return Err(err(
            StatusCode::CONFLICT,
            "a team needs an owner; make someone else owner, or delete the team",
        ));
    }
    sqlx::query("DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "UPDATE api_keys SET is_active = FALSE WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    let action = if user_id == claims.sub {
        "team.member.left"
    } else {
        "team.member.removed"
    };
    audit::Event::by(&claims, action)
        .team(org_id)
        .subject(user_id)
        .detail("role", target.clone())
        .record(state.db.pool())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Invitations ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InviteBody {
    pub email: String,
    pub role: Option<String>,
}

/// `POST /orgs/{id}/invitations`: invite an address. Returns the link code,
/// once; inviting the same address again replaces the old invitation.
pub async fn invite(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<InviteBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let actor = require_manager(&state, org_id, &claims).await?;
    let email = clean_email(&body.email)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "enter a valid email address"))?;
    let role = body.role.unwrap_or_else(|| "member".to_string());
    if role == "owner" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invite as admin, member or viewer; make them owner once they've joined",
        ));
    }
    can_assign(&actor, None, &role).map_err(|m| err(StatusCode::FORBIDDEN, m))?;

    let already: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM organization_members m JOIN users u ON u.id = m.user_id
                          WHERE m.organization_id = $1 AND LOWER(u.email) = $2)"#,
    )
    .bind(org_id)
    .bind(&email)
    .fetch_one(state.db.pool())
    .await
    .map_err(db_err)?;
    if already {
        return Err(err(StatusCode::CONFLICT, "they're already in this team"));
    }

    let mut tx = state.db.pool().begin().await.map_err(db_err)?;
    lock_team(&mut tx, org_id).await.map_err(db_err)?;
    sqlx::query(
        "DELETE FROM organization_invitations WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL",
    )
    .bind(org_id)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    let seats: i64 = sqlx::query_scalar(
        r#"SELECT (SELECT COUNT(*) FROM organization_members WHERE organization_id = $1)
                + (SELECT COUNT(*) FROM organization_invitations
                   WHERE organization_id = $1 AND accepted_at IS NULL AND expires_at > NOW())"#,
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    if seats >= MAX_SEATS {
        return Err(err(
            StatusCode::CONFLICT,
            "a team can have 50 members and open invitations",
        ));
    }
    let id = Uuid::new_v4();
    let code = new_invite_code();
    let expires_at = Utc::now() + Duration::days(INVITE_DAYS);
    sqlx::query(
        r#"INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, invited_by, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(org_id)
    .bind(&email)
    .bind(&role)
    .bind(hash_code(&code))
    .bind(claims.sub)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    audit::Event::by(&claims, "team.invitation.sent")
        .team(org_id)
        .target("invitation", id)
        .detail("email", email.clone())
        .detail("role", role.clone())
        .record(state.db.pool())
        .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id, "email": email, "role": role, "expiresAt": expires_at,
            // Shown once. The website turns it into /teams?invite=<code>.
            "code": code,
        })),
    ))
}

/// `DELETE /orgs/{id}/invitations/{invitation_id}`: withdraw an invitation.
pub async fn revoke_invitation(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    require_manager(&state, org_id, &claims).await?;
    let done = sqlx::query(
        "DELETE FROM organization_invitations WHERE id = $1 AND organization_id = $2 AND accepted_at IS NULL",
    )
    .bind(invitation_id)
    .bind(org_id)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    if done.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "invitation not found"));
    }
    audit::Event::by(&claims, "team.invitation.withdrawn")
        .team(org_id)
        .target("invitation", invitation_id)
        .record(state.db.pool())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /invitations`: open invitations for the caller's address.
pub async fn my_invitations(
    State(state): State<AppState>,
    claims: Claims,
) -> ApiResult<Json<Value>> {
    let email = claims.email.trim().to_lowercase();
    let rows: Vec<(Uuid, Uuid, String, String, DateTime<Utc>, Option<String>)> = sqlx::query_as(
        r#"SELECT i.id, o.id, o.name, i.role, i.expires_at, u.username
           FROM organization_invitations i
           JOIN organizations o ON o.id = i.organization_id
           LEFT JOIN users u ON u.id = i.invited_by
           WHERE i.email = $1 AND i.accepted_at IS NULL AND i.expires_at > NOW()
           ORDER BY i.created_at DESC"#,
    )
    .bind(&email)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|(id, org_id, name, role, expires_at, by)| {
                json!({ "id": id, "teamId": org_id, "teamName": name, "role": role,
                        "expiresAt": expires_at, "invitedBy": by })
            })
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct AcceptBody {
    /// The code from an invitation link.
    pub code: Option<String>,
    /// An invitation from the caller's own list (needs a verified address).
    pub id: Option<Uuid>,
}

/// `POST /invitations/accept`: join a team.
pub async fn accept_invitation(
    State(state): State<AppState>,
    claims: Claims,
    Json(body): Json<AcceptBody>,
) -> ApiResult<Json<Value>> {
    let email = claims.email.trim().to_lowercase();
    let mut tx = state.db.pool().begin().await.map_err(db_err)?;
    let row: Option<(Uuid, Uuid, String, String, DateTime<Utc>)> = match (&body.code, body.id) {
        (Some(code), _) => sqlx::query_as(
            r#"SELECT id, organization_id, email, role, expires_at FROM organization_invitations
               WHERE token_hash = $1 AND accepted_at IS NULL FOR UPDATE"#,
        )
        .bind(hash_code(code))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?,
        (None, Some(id)) => {
            let verified: Option<bool> =
                sqlx::query_scalar("SELECT is_verified FROM users WHERE id = $1")
                    .bind(claims.sub)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .flatten();
            if verified != Some(true) {
                return Err(err(
                    StatusCode::FORBIDDEN,
                    "verify your email address first, or use the invitation link",
                ));
            }
            sqlx::query_as(
                r#"SELECT id, organization_id, email, role, expires_at FROM organization_invitations
                   WHERE id = $1 AND accepted_at IS NULL FOR UPDATE"#,
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?
        }
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "send the invitation code")),
    };
    let not_valid = || {
        err(
            StatusCode::NOT_FOUND,
            "this invitation isn't valid any more; ask for a new one",
        )
    };
    let (invitation_id, org_id, invited_email, role, expires_at) = row.ok_or_else(not_valid)?;
    if expires_at <= Utc::now() {
        return Err(not_valid());
    }
    if invited_email != email {
        return Err(err(
            StatusCode::FORBIDDEN,
            "this invitation is for a different email address; sign in with that one",
        ));
    }
    sqlx::query(
        r#"INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)
           ON CONFLICT (organization_id, user_id) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(claims.sub)
    .bind(&role)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "UPDATE organization_invitations SET accepted_at = NOW(), accepted_by = $2 WHERE id = $1",
    )
    .bind(invitation_id)
    .bind(claims.sub)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    let name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    audit::Event::by(&claims, "team.invitation.accepted")
        .team(org_id)
        .target("invitation", invitation_id)
        .detail("role", role.clone())
        .record(state.db.pool())
        .await;
    Ok(Json(
        json!({ "teamId": org_id, "teamName": name, "role": role }),
    ))
}

/// `DELETE /invitations/{id}`: turn down an invitation to your address.
pub async fn decline_invitation(
    State(state): State<AppState>,
    claims: Claims,
    Path(invitation_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let team: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM organization_invitations WHERE id = $1 AND email = $2 AND accepted_at IS NULL
         RETURNING organization_id",
    )
    .bind(invitation_id)
    .bind(claims.email.trim().to_lowercase())
    .fetch_optional(state.db.pool())
    .await
    .map_err(db_err)?;
    let team = team.ok_or_else(|| err(StatusCode::NOT_FOUND, "invitation not found"))?;
    audit::Event::by(&claims, "team.invitation.declined")
        .team(team)
        .target("invitation", invitation_id)
        .record(state.db.pool())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Team API keys ─────────────────────────────────────────────────

/// `GET /orgs/{id}/api-keys` (owners and admins).
pub async fn list_team_keys(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let rows: Vec<(
        Uuid,
        String,
        Option<String>,
        Vec<String>,
        Option<bool>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<String>,
    )> = sqlx::query_as(
        r#"SELECT k.id, k.name, k.key_prefix, COALESCE(k.permissions, ARRAY['read']), k.is_active,
                  k.last_used_at, k.created_at, k.expires_at, u.username
           FROM api_keys k LEFT JOIN users u ON u.id = k.user_id
           WHERE k.organization_id = $1
           ORDER BY k.created_at DESC"#,
    )
    .bind(org_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    let now = Utc::now();
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(
                |(
                    id,
                    name,
                    prefix,
                    permissions,
                    active,
                    last_used_at,
                    created_at,
                    expires_at,
                    by,
                )| {
                    let expired = expires_at.is_some_and(|e| e <= now);
                    json!({
                        "id": id, "name": name, "prefix": prefix, "permissions": permissions,
                        "isActive": active.unwrap_or(true) && !expired, "expired": expired,
                        "lastUsedAt": last_used_at, "createdAt": created_at,
                        "expiresAt": expires_at, "createdBy": by,
                    })
                },
            )
            .collect(),
    )))
}

/// `POST /orgs/{id}/api-keys` (owners and admins). Same body as personal keys:
/// `name`, `scopes`, `expires_in_days`.
pub async fn create_team_key(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_manager(&state, org_id, &claims).await?;
    let name: String = body
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or("Team key")
        .chars()
        .take(100)
        .collect();
    let scopes =
        api_key::parse_scopes(body.get("scopes")).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    let expires_at = match body.get("expires_in_days") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let days = v
                .as_i64()
                .filter(|d| (1..=365).contains(d))
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "expires_in_days must be 1 to 365"))?;
            Some(Utc::now() + Duration::days(days))
        }
    };
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_keys WHERE organization_id = $1 AND is_active = TRUE
           AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(org_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(db_err)?;
    if active >= MAX_TEAM_KEYS {
        return Err(err(
            StatusCode::CONFLICT,
            "this team already has 10 active keys; revoke one first",
        ));
    }
    let raw_key = api_key::generate();
    let key_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO api_keys (id, user_id, organization_id, key_hash, key_prefix, name, permissions, created_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)"#,
    )
    .bind(key_id)
    .bind(claims.sub)
    .bind(org_id)
    .bind(api_key::hash(&raw_key))
    .bind(api_key::display_prefix(&raw_key))
    .bind(&name)
    .bind(&scopes)
    .bind(expires_at)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    audit::Event::by(&claims, "team.api_key.created")
        .team(org_id)
        .target("api_key", key_id)
        .detail("name", name.clone())
        .detail("scopes", scopes.clone())
        .detail("prefix", api_key::display_prefix(&raw_key))
        .record(state.db.pool())
        .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "api_key": raw_key, "key_id": key_id, "name": name,
            "prefix": api_key::display_prefix(&raw_key), "scopes": scopes, "expires_at": expires_at,
        })),
    ))
}

/// `DELETE /orgs/{id}/api-keys/{key_id}` (owners and admins).
pub async fn revoke_team_key(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, key_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    require_manager(&state, org_id, &claims).await?;
    let done = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND organization_id = $2")
        .bind(key_id)
        .bind(org_id)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    if done.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "key not found"));
    }
    audit::Event::by(&claims, "team.api_key.revoked")
        .team(org_id)
        .target("api_key", key_id)
        .record(state.db.pool())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_rank_as_documented() {
        assert!(can_manage("owner") && can_manage("admin"));
        assert!(!can_manage("member") && !can_manage("viewer"));
        assert!(can_scan("owner") && can_scan("admin") && can_scan("member"));
        assert!(!can_scan("viewer") && !can_scan("nobody"));
    }

    #[test]
    fn who_can_assign_which_roles() {
        assert!(can_assign("owner", Some("owner"), "admin").is_ok());
        assert!(can_assign("owner", Some("member"), "owner").is_ok());
        assert!(can_assign("admin", Some("member"), "admin").is_ok());
        assert!(can_assign("admin", None, "viewer").is_ok());
        assert!(can_assign("admin", Some("member"), "owner").is_err());
        assert!(can_assign("admin", Some("owner"), "member").is_err());
        assert!(can_assign("member", Some("viewer"), "member").is_err());
        assert!(can_assign("viewer", None, "viewer").is_err());
        assert!(can_assign("owner", Some("member"), "superuser").is_err());
    }

    #[test]
    fn who_can_remove_whom() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(
            can_remove("viewer", a, "viewer", a).is_ok(),
            "anyone may leave"
        );
        assert!(can_remove("member", a, "viewer", b).is_err());
        assert!(can_remove("admin", a, "member", b).is_ok());
        assert!(can_remove("admin", a, "admin", b).is_ok());
        assert!(can_remove("admin", a, "owner", b).is_err());
        assert!(can_remove("owner", a, "owner", b).is_ok());
    }

    #[test]
    fn names_and_emails_are_cleaned() {
        assert_eq!(clean_name(Some("  Blue   Team ")).unwrap(), "Blue Team");
        assert!(clean_name(Some("   ")).is_err());
        assert!(clean_name(None).is_err());
        assert!(clean_name(Some(&"x".repeat(101))).is_err());
        assert_eq!(
            clean_email(" Ana@Example.COM ").as_deref(),
            Some("ana@example.com")
        );
        for bad in [
            "",
            "ana",
            "@example.com",
            "ana@",
            "ana@example",
            "a b@example.com",
            "a@b@c.com",
            "a@.com",
        ] {
            assert!(clean_email(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn invite_codes_are_random_and_hashed() {
        let c = new_invite_code();
        assert!(c.starts_with("inv_") && c.len() == 68);
        assert_ne!(c, new_invite_code());
        assert_eq!(hash_code(&c), hash_code(&format!(" {c} ")));
        assert_eq!(hash_code(&c).len(), 64);
    }
}
