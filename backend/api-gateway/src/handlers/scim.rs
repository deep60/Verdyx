//! SCIM 2.0 provisioning (RFC 7643, 7644), at `/scim/v2`.
//!
//! A team's identity provider (Okta, Microsoft Entra ID, OneLogin, ...) adds
//! people to the team, and takes them out, as they're assigned the Verdyx app
//! or leave the company. It authenticates with the team's provisioning token
//! (`Authorization: Bearer scim_…`), made on the team's SSO settings.
//!
//! - **Create** makes (or finds) the Verdyx account for the address, which
//!   must be in one of the team's proven domains, and adds it to the team
//!   with the team's join role.
//! - **Deactivate** (`active: false`) or **delete** takes the person out of
//!   the team and stops their team keys. Their own account and own scans stay
//!   theirs. Owners are never removed this way, so the team keeps an owner.
//! - Only users are supported; group requests get an empty list.
//!
//! The SCIM `id` is the Verdyx user id.

#![allow(clippy::type_complexity)]
// Helpers return the finished SCIM error response, so handlers can return it as is.
#![allow(clippy::result_large_err)]

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::organization::clean_email;
use crate::handlers::sso::{self, hash_token, join_team, provision_account, verified_domains};
use crate::services::audit;
use crate::AppState;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const MAX_PAGE: i64 = 200;
const MAX_BODY: usize = 64 * 1024;

fn scim(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        body.to_string(),
    )
        .into_response()
}

fn error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        "status": status.as_u16().to_string(),
        "detail": detail,
    });
    if let Some(t) = scim_type {
        body["scimType"] = json!(t);
    }
    scim(status, body)
}

fn db_error(e: sqlx::Error) -> Response {
    tracing::error!("SCIM query failed: {e}");
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        None,
        "something went wrong",
    )
}

/// The team a provisioning token belongs to.
async fn team(state: &AppState, headers: &HeaderMap) -> Result<Uuid, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| t.starts_with("scim_") && t.len() < 200);
    let unauthorized = || {
        error(
            StatusCode::UNAUTHORIZED,
            None,
            "a valid provisioning token is required",
        )
    };
    let Some(token) = token else {
        return Err(unauthorized());
    };
    sqlx::query_scalar::<_, Uuid>("SELECT organization_id FROM team_sso WHERE scim_token_hash = $1")
        .bind(hash_token(token))
        .fetch_optional(state.db.pool())
        .await
        .map_err(db_error)?
        .ok_or_else(unauthorized)
}

fn parse_body(body: &Bytes) -> Result<Value, Response> {
    if body.len() > MAX_BODY {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            None,
            "the request is too large",
        ));
    }
    serde_json::from_slice(body).map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "the body isn't JSON",
        )
    })
}

// ─── The user resource ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Fields {
    pub user_name: Option<String>,
    pub external_id: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub display_name: Option<String>,
    pub active: Option<bool>,
}

fn text(v: &Value) -> Option<String> {
    v.as_str()
        .map(|s| s.trim().chars().take(255).collect::<String>())
        .filter(|s| !s.is_empty())
}

/// Entra sends `"False"` as a string.
fn flag(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// The fields of a full user resource (create, replace).
pub fn fields_of(user: &Value) -> Fields {
    let primary_email = user
        .get("emails")
        .and_then(|e| e.as_array())
        .and_then(|list| {
            list.iter()
                .find(|e| e.get("primary").and_then(flag) == Some(true))
                .or_else(|| list.first())
                .and_then(|e| e.get("value"))
                .and_then(text)
        });
    let user_name = user
        .get("userName")
        .and_then(text)
        .filter(|u| clean_email(u).is_some())
        .or(primary_email);
    Fields {
        user_name: user_name.and_then(|u| clean_email(&u)),
        external_id: user.get("externalId").and_then(text),
        given_name: user.pointer("/name/givenName").and_then(text),
        family_name: user.pointer("/name/familyName").and_then(text),
        display_name: user.get("displayName").and_then(text),
        active: user.get("active").and_then(flag),
    }
}

/// Apply a PATCH request's operations to `f`. Paths and op names are
/// case-insensitive, and a value object without a path sets each key in it.
pub fn apply_patch(f: &mut Fields, body: &Value) -> Result<(), String> {
    let ops = body
        .get("Operations")
        .or_else(|| body.get("operations"))
        .and_then(|o| o.as_array())
        .ok_or("the request has no Operations")?;
    for op in ops {
        let kind = op
            .get("op")
            .and_then(|o| o.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let path = op
            .get("path")
            .and_then(|p| p.as_str())
            .map(|p| p.to_ascii_lowercase());
        let value = op.get("value").cloned().unwrap_or(Value::Null);
        match kind.as_str() {
            "add" | "replace" => {}
            "remove" => {
                match path.as_deref() {
                    Some("externalid") => f.external_id = None,
                    Some("displayname") => f.display_name = None,
                    Some("name.givenname") => f.given_name = None,
                    Some("name.familyname") => f.family_name = None,
                    _ => {}
                }
                continue;
            }
            other => return Err(format!("the operation {other:?} isn't supported")),
        }
        let pairs: Vec<(String, Value)> = match (&path, &value) {
            (Some(p), v) => vec![(p.clone(), v.clone())],
            (None, Value::Object(map)) => {
                let mut out = Vec::new();
                for (k, v) in map {
                    match (k.to_ascii_lowercase().as_str(), v) {
                        ("name", Value::Object(name)) => {
                            for (nk, nv) in name {
                                out.push((format!("name.{}", nk.to_ascii_lowercase()), nv.clone()));
                            }
                        }
                        (key, _) => out.push((key.to_string(), v.clone())),
                    }
                }
                out
            }
            _ => continue,
        };
        for (p, v) in pairs {
            match p.as_str() {
                "active" => f.active = flag(&v).or(f.active),
                "externalid" => f.external_id = text(&v),
                "displayname" => f.display_name = text(&v),
                "name.givenname" => f.given_name = text(&v),
                "name.familyname" => f.family_name = text(&v),
                "username" => f.user_name = text(&v).and_then(|u| clean_email(&u)),
                // Other attributes (title, emails, …) aren't kept.
                _ => {}
            }
        }
    }
    Ok(())
}

/// A filter Verdyx answers: `userName eq "x"`, `externalId eq "x"` or
/// `emails.value eq "x"`. Returns (column, value).
pub fn parse_filter(raw: &str) -> Option<(&'static str, String)> {
    let lower = raw.to_ascii_lowercase();
    let at = lower.find(" eq ")?;
    let attr = lower[..at].trim();
    let value = raw[at + 4..].trim().trim_matches('"').to_string();
    let column = match attr {
        "username" | "emails.value" | "emails[type eq \"work\"].value" => "user_name",
        "externalid" => "external_id",
        _ => return None,
    };
    let value = if column == "user_name" {
        value.to_lowercase()
    } else {
        value
    };
    Some((column, value))
}

type Row = (
    Uuid,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    DateTime<Utc>,
    DateTime<Utc>,
);

const COLUMNS: &str = "user_id, external_id, user_name, given_name, family_name, display_name, active, created_at, updated_at";

fn resource(r: &Row) -> Value {
    let (id, external_id, user_name, given, family, display, active, created, updated) = r;
    json!({
        "schemas": [USER_SCHEMA],
        "id": id,
        "externalId": external_id,
        "userName": user_name,
        "name": { "givenName": given, "familyName": family },
        "displayName": display,
        "emails": [{ "value": user_name, "type": "work", "primary": true }],
        "active": active,
        "meta": {
            "resourceType": "User",
            "created": created,
            "lastModified": updated,
            "location": format!("{}/Users/{id}", sso::scim_base_url()),
        },
    })
}

async fn load(state: &AppState, org_id: Uuid, user_id: Uuid) -> Result<Option<Row>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM scim_users WHERE organization_id = $1 AND user_id = $2"
    ))
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
}

async fn join_role(state: &AppState, org_id: Uuid) -> String {
    sqlx::query_scalar("SELECT join_role FROM team_sso WHERE organization_id = $1")
        .bind(org_id)
        .fetch_optional(state.db.pool())
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "member".to_string())
}

/// Put team membership in line with `active`. Owners are never removed.
async fn set_membership(
    state: &AppState,
    org_id: Uuid,
    user_id: Uuid,
    active: bool,
) -> Result<(), sqlx::Error> {
    let pool = state.db.pool();
    if active {
        if join_team(pool, org_id, user_id, &join_role(state, org_id).await).await? {
            audit::Event::system("team.member.provisioned")
                .team(org_id)
                .subject(user_id)
                .record(pool)
                .await;
        }
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let removed = sqlx::query(
        "DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2 AND role <> 'owner'",
    )
    .bind(org_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if removed > 0 {
        sqlx::query(
            "UPDATE api_keys SET is_active = FALSE WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    if removed > 0 {
        audit::Event::system("team.member.deprovisioned")
            .team(org_id)
            .subject(user_id)
            .record(pool)
            .await;
    }
    Ok(())
}

// ─── Endpoints ─────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListParams {
    filter: Option<String>,
    start_index: Option<i64>,
    count: Option<i64>,
}

/// `GET /scim/v2/Users`
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<ListParams>,
) -> Response {
    let org_id = match team(&state, &headers).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let start = p.start_index.unwrap_or(1).max(1);
    let count = p.count.unwrap_or(100).clamp(0, MAX_PAGE);
    let filter = match p.filter.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => match parse_filter(f) {
            Some(x) => Some(x),
            None => {
                return error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    "only userName, externalId and emails.value eq \"…\" filters are supported",
                )
            }
        },
        None => None,
    };
    let (where_extra, value) = match &filter {
        Some((col, v)) => (format!(" AND {col} = $2"), Some(v.clone())),
        None => (String::new(), None),
    };
    let pool = state.db.pool();
    let total: i64 = {
        let q = format!("SELECT COUNT(*) FROM scim_users WHERE organization_id = $1{where_extra}");
        let mut q = sqlx::query_scalar(&q).bind(org_id);
        if let Some(v) = &value {
            q = q.bind(v);
        }
        match q.fetch_one(pool).await {
            Ok(n) => n,
            Err(e) => return db_error(e),
        }
    };
    let rows: Vec<Row> = {
        let n = if value.is_some() { 3 } else { 2 };
        let q = format!(
            "SELECT {COLUMNS} FROM scim_users WHERE organization_id = $1{where_extra}
             ORDER BY created_at, user_id LIMIT ${n} OFFSET ${}",
            n + 1
        );
        let mut q = sqlx::query_as(&q).bind(org_id);
        if let Some(v) = &value {
            q = q.bind(v);
        }
        match q.bind(count).bind(start - 1).fetch_all(pool).await {
            Ok(r) => r,
            Err(e) => return db_error(e),
        }
    };
    scim(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": rows.len(),
            "Resources": rows.iter().map(resource).collect::<Vec<_>>(),
        }),
    )
}

/// `GET /scim/v2/Users/{id}`
pub async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let org_id = match team(&state, &headers).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let Ok(user_id) = id.parse::<Uuid>() else {
        return error(StatusCode::NOT_FOUND, None, "user not found");
    };
    match load(&state, org_id, user_id).await {
        Ok(Some(r)) => scim(StatusCode::OK, resource(&r)),
        Ok(None) => error(StatusCode::NOT_FOUND, None, "user not found"),
        Err(e) => db_error(e),
    }
}

/// `POST /scim/v2/Users`
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let org_id = match team(&state, &headers).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let body = match parse_body(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let f = fields_of(&body);
    let Some(email) = f.user_name.clone() else {
        return error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "userName (or a primary email) must be an email address",
        );
    };
    let pool = state.db.pool();
    let domains = match verified_domains(pool, org_id).await {
        Ok(d) => d,
        Err(e) => return db_error(e),
    };
    if !sso::in_domains(&email, &domains) {
        return error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "the address isn't in one of the team's proven domains",
        );
    }
    let exists: Result<bool, _> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM scim_users WHERE organization_id = $1 AND user_name = $2)",
    )
    .bind(org_id)
    .bind(&email)
    .fetch_one(pool)
    .await;
    match exists {
        Ok(true) => {
            return error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "this user is already provisioned",
            )
        }
        Ok(false) => {}
        Err(e) => return db_error(e),
    }

    let subject = format!("scim:{}", f.external_id.as_deref().unwrap_or(&email));
    let name_hint = f.display_name.clone().or_else(|| f.given_name.clone());
    let account =
        match provision_account(&state, org_id, &subject, &email, name_hint.as_deref()).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(%org_id, "SCIM account provisioning failed: {e}");
                return error(
                    StatusCode::BAD_GATEWAY,
                    None,
                    "couldn't create the account; try again",
                );
            }
        };
    let active = f.active.unwrap_or(true);
    let inserted = sqlx::query(
        "INSERT INTO scim_users (organization_id, user_id, external_id, user_name, given_name, family_name, display_name, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(org_id)
    .bind(account.id)
    .bind(&f.external_id)
    .bind(&email)
    .bind(&f.given_name)
    .bind(&f.family_name)
    .bind(&f.display_name)
    .bind(active)
    .execute(pool)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return error(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "this user is already provisioned",
            )
        }
        Err(e) => return db_error(e),
    }
    if let Err(e) = set_membership(&state, org_id, account.id, active).await {
        return db_error(e);
    }
    match load(&state, org_id, account.id).await {
        Ok(Some(r)) => scim(StatusCode::CREATED, resource(&r)),
        Ok(None) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "something went wrong",
        ),
        Err(e) => db_error(e),
    }
}

/// Save `f` and bring membership in line with it.
async fn save(state: &AppState, org_id: Uuid, user_id: Uuid, before: &Row, f: Fields) -> Response {
    if let Some(u) = &f.user_name {
        if u != &before.2 {
            return error(
                StatusCode::BAD_REQUEST,
                Some("mutability"),
                "userName can't be changed; deprovision the user and provision the new address",
            );
        }
    }
    let active = f.active.unwrap_or(before.6);
    let updated = sqlx::query(
        "UPDATE scim_users SET external_id = $3, given_name = $4, family_name = $5, display_name = $6,
                active = $7, updated_at = NOW()
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(&f.external_id)
    .bind(&f.given_name)
    .bind(&f.family_name)
    .bind(&f.display_name)
    .bind(active)
    .execute(state.db.pool())
    .await;
    if let Err(e) = updated {
        return db_error(e);
    }
    if active != before.6 {
        if let Err(e) = set_membership(state, org_id, user_id, active).await {
            return db_error(e);
        }
    }
    match load(state, org_id, user_id).await {
        Ok(Some(r)) => scim(StatusCode::OK, resource(&r)),
        Ok(None) => error(StatusCode::NOT_FOUND, None, "user not found"),
        Err(e) => db_error(e),
    }
}

fn fields_from_row(r: &Row) -> Fields {
    Fields {
        user_name: Some(r.2.clone()),
        external_id: r.1.clone(),
        given_name: r.3.clone(),
        family_name: r.4.clone(),
        display_name: r.5.clone(),
        active: Some(r.6),
    }
}

async fn existing(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(Uuid, Uuid, Row), Response> {
    let org_id = team(state, headers).await?;
    let user_id = id
        .parse::<Uuid>()
        .map_err(|_| error(StatusCode::NOT_FOUND, None, "user not found"))?;
    let row = load(state, org_id, user_id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, None, "user not found"))?;
    Ok((org_id, user_id, row))
}

/// `PUT /scim/v2/Users/{id}`
pub async fn replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (org_id, user_id, row) = match existing(&state, &headers, &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let body = match parse_body(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    save(&state, org_id, user_id, &row, fields_of(&body)).await
}

/// `PATCH /scim/v2/Users/{id}`
pub async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (org_id, user_id, row) = match existing(&state, &headers, &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let body = match parse_body(&body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut f = fields_from_row(&row);
    if let Err(m) = apply_patch(&mut f, &body) {
        return error(StatusCode::BAD_REQUEST, Some("invalidSyntax"), &m);
    }
    save(&state, org_id, user_id, &row, f).await
}

/// `DELETE /scim/v2/Users/{id}`
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (org_id, user_id, _) = match existing(&state, &headers, &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(e) = set_membership(&state, org_id, user_id, false).await {
        return db_error(e);
    }
    let gone = sqlx::query("DELETE FROM scim_users WHERE organization_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(state.db.pool())
        .await;
    match gone {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(e),
    }
}

/// `GET /scim/v2/Groups`: groups aren't supported, so there are none.
pub async fn list_groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = team(&state, &headers).await {
        return r;
    }
    scim(
        StatusCode::OK,
        json!({ "schemas": [LIST_SCHEMA], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": [] }),
    )
}

/// `GET /scim/v2/ServiceProviderConfig`
pub async fn service_provider_config() -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://github.com/deep60/Verdyx/blob/main/docs/integrations/sso.md",
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_PAGE },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Provisioning token",
                "description": "The team's provisioning token, from its single sign-on settings",
                "primary": true,
            }],
        }),
    )
}

/// `GET /scim/v2/ResourceTypes`
pub async fn resource_types() -> Response {
    scim(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": 1,
            "Resources": [{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User", "name": "User", "endpoint": "/Users", "schema": USER_SCHEMA,
            }],
        }),
    )
}

/// `GET /scim/v2/Schemas`
pub async fn schemas() -> Response {
    let attr = |name: &str, kind: &str| {
        json!({ "name": name, "type": kind, "multiValued": false, "required": name == "userName",
                "mutability": if name == "userName" { "immutable" } else { "readWrite" } })
    };
    scim(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": 1,
            "Resources": [{
                "id": USER_SCHEMA, "name": "User",
                "attributes": [
                    attr("userName", "string"), attr("externalId", "string"),
                    attr("displayName", "string"), attr("active", "boolean"),
                    { "name": "name", "type": "complex", "multiValued": false,
                      "subAttributes": [attr("givenName", "string"), attr("familyName", "string")] },
                ],
            }],
        }),
    )
}

/// Anything else under `/scim/v2`.
pub async fn not_supported() -> Response {
    error(StatusCode::NOT_FOUND, None, "not supported")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    #[test]
    fn a_user_resource_is_read_from_okta_or_entra_shapes() {
        let okta = json!({
            "schemas": [USER_SCHEMA], "userName": "Ada@Acme.com",
            "name": { "givenName": "Ada", "familyName": "Lovelace" },
            "emails": [{ "primary": true, "value": "ada@acme.com", "type": "work" }],
            "displayName": "Ada Lovelace", "active": true, "externalId": "00u1"
        });
        let f = fields_of(&okta);
        assert_eq!(f.user_name.as_deref(), Some("ada@acme.com"));
        assert_eq!(f.external_id.as_deref(), Some("00u1"));
        assert_eq!(f.given_name.as_deref(), Some("Ada"));
        assert_eq!(f.active, Some(true));

        // userName that isn't an address: fall back to the primary email.
        let entra = json!({ "userName": "ada", "active": "True",
            "emails": [{ "value": "x@acme.com" }, { "value": "ada@acme.com", "primary": "true" }] });
        let f = fields_of(&entra);
        assert_eq!(f.user_name.as_deref(), Some("ada@acme.com"));
        assert_eq!(f.active, Some(true));
    }

    #[test]
    fn patch_handles_paths_value_objects_and_string_booleans() {
        let mut f = Fields {
            user_name: Some("a@acme.com".into()),
            active: Some(true),
            ..Default::default()
        };
        // Okta.
        apply_patch(
            &mut f,
            &json!({ "schemas": [PATCH_SCHEMA],
            "Operations": [{ "op": "replace", "value": { "active": false } }] }),
        )
        .unwrap();
        assert_eq!(f.active, Some(false));
        // Entra.
        apply_patch(
            &mut f,
            &json!({ "Operations": [
            { "op": "Replace", "path": "active", "value": "True" },
            { "op": "Add", "path": "name.givenName", "value": "Ada" },
            { "op": "replace", "value": { "name": { "familyName": "L" }, "displayName": "Ada L" } },
        ] }),
        )
        .unwrap();
        assert_eq!(f.active, Some(true));
        assert_eq!(f.given_name.as_deref(), Some("Ada"));
        assert_eq!(f.family_name.as_deref(), Some("L"));
        assert_eq!(f.display_name.as_deref(), Some("Ada L"));
        apply_patch(
            &mut f,
            &json!({ "Operations": [{ "op": "remove", "path": "displayName" }] }),
        )
        .unwrap();
        assert_eq!(f.display_name, None);
        assert!(apply_patch(&mut f, &json!({ "Operations": [{ "op": "move" }] })).is_err());
        assert!(apply_patch(&mut f, &json!({})).is_err());
    }

    #[test]
    fn filters() {
        assert_eq!(
            parse_filter("userName eq \"Ada@Acme.com\""),
            Some(("user_name", "ada@acme.com".into()))
        );
        assert_eq!(
            parse_filter("externalId eq \"00uAbC\""),
            Some(("external_id", "00uAbC".into()))
        );
        assert_eq!(
            parse_filter("emails.value EQ \"a@b.com\""),
            Some(("user_name", "a@b.com".into()))
        );
        assert_eq!(parse_filter("displayName eq \"x\""), None);
        assert_eq!(parse_filter("userName sw \"a\""), None);
    }

    #[test]
    fn errors_use_the_scim_shape() {
        let r = error(StatusCode::CONFLICT, Some("uniqueness"), "taken");
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/scim+json"
        );
    }
}
