//! Single sign-on for teams, through the team's own OpenID Connect provider.
//!
//! **Setting up** (team owners and admins, `/orgs/{id}/sso`):
//! 1. Add the company's email domain, and prove it with a DNS TXT record.
//!    Until a domain is proven, nobody can sign in or be provisioned with it:
//!    otherwise a team could vouch for anyone's address and take over their
//!    Verdyx account.
//! 2. Enter the identity provider's issuer URL, client ID and client secret.
//!    The secret is stored sealed, like SIEM credentials.
//! 3. Turn it on. Optionally require it, so people with an address in the
//!    team's domains can't use a password, Google or GitHub instead. The
//!    team's owners still can, so a broken identity provider can't lock the
//!    team out.
//!
//! **Signing in** (`/auth/sso/start?domain=` then `/auth/sso/callback`): the
//! browser goes to the provider and back, the ID token is checked
//! ([`crate::services::oidc`]), and its address must be in one of the team's
//! proven domains. user-service then finds or makes the account, trusting a
//! one-minute grant the gateway signs ([`grant`]). Someone not yet in the team
//! joins it with the team's chosen role.

// Query rows are read as plain tuples.
#![allow(clippy::type_complexity)]

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::handlers::auth::{sync_user_to_gateway_db, UsAuthResponse};
use crate::handlers::identity::UserIdentity;
use crate::handlers::organization::{can_manage, member_role, MAX_SEATS};
use crate::middleware::auth::{cookie, session_cookies, Claims};
use crate::services::{audit, oidc, siem::CredentialKey};
use crate::AppState;

pub const MAX_DOMAINS: i64 = 10;
const STATE_COOKIE: &str = "verdyx_sso_state";
const STATE_COOKIE_PATH: &str = "/api/v1/auth/sso";
const STATE_TTL_SECS: u32 = 600;
pub const TXT_PREFIX: &str = "verdyx-domain-verification=";
pub const GRANT_ISSUER: &str = "verdyx-api-gateway";
pub const GRANT_AUDIENCE: &str = "verdyx-sso-grant";

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T> = Result<T, ApiError>;

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("SSO query failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

pub fn site_url() -> String {
    std::env::var("PUBLIC_SITE_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://verdyx.dev".to_string())
}

pub fn callback_url() -> String {
    format!("{}/api/v1/auth/sso/callback", site_url())
}

fn api_url() -> String {
    std::env::var("PUBLIC_API_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://api.verdyx.dev".to_string())
}

pub fn scim_base_url() -> String {
    format!("{}/scim/v2", api_url())
}

// ─── Rules (pure, unit-tested) ─────────────────────────────────────

/// A domain as typed ("Acme.com", "@acme.com", "https://acme.com/") or why not.
pub fn clean_domain(raw: &str) -> Result<String, &'static str> {
    let d = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches('@')
        .trim_end_matches('/')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        return Err("enter a domain such as example.com");
    }
    let labels_ok = d.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !labels_ok
        || d.rsplit('.')
            .next()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
    {
        return Err("enter a domain such as example.com");
    }
    Ok(d)
}

/// The TXT record that proves a domain: (name, value).
pub fn txt_record(domain: &str, code: &str) -> (String, String) {
    (
        format!("_verdyx-challenge.{domain}"),
        format!("{TXT_PREFIX}{code}"),
    )
}

/// Whether DNS answered with the expected value. TXT data arrives quoted, and
/// long values may be split into several quoted strings.
pub fn txt_matches(answers: &[String], expected: &str) -> bool {
    answers.iter().any(|a| {
        let joined: String = if a.contains('"') {
            // "part one" "part two": the text inside the quotes, joined.
            a.split('"').skip(1).step_by(2).collect()
        } else {
            a.clone()
        };
        joined.trim() == expected
    })
}

/// Is `email` in one of the proven `domains`? Subdomains count only if listed.
pub fn in_domains(email: &str, domains: &[String]) -> bool {
    let d = oidc::domain_of(email);
    !d.is_empty() && domains.iter().any(|x| x == d)
}

fn new_code() -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

// ─── The grant user-service trusts ────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Grant {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub team: Uuid,
    pub subject: String,
    pub email: String,
    pub name_hint: Option<String>,
}

/// A one-minute grant, signed with the key the services share. It has no
/// `sub`, so it can never pass as a session token.
pub fn grant(
    signing_key: &str,
    team: Uuid,
    subject: &str,
    email: &str,
    name_hint: Option<&str>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &Grant {
            iss: GRANT_ISSUER.into(),
            aud: GRANT_AUDIENCE.into(),
            exp: now + 60,
            iat: now,
            team,
            subject: subject.into(),
            email: email.into(),
            name_hint: name_hint.map(|n| n.chars().take(64).collect()),
        },
        &jsonwebtoken::EncodingKey::from_secret(signing_key.as_bytes()),
    )
}

/// Ask user-service for the account (`session` false) or a session.
pub async fn ask_user_service(
    state: &AppState,
    session: bool,
    team: Uuid,
    subject: &str,
    email: &str,
    name_hint: Option<&str>,
) -> Result<reqwest::Response, String> {
    let token = grant(
        &state.config.security.jwt_secret,
        team,
        subject,
        email,
        name_hint,
    )
    .map_err(|e| format!("couldn't sign the grant: {e}"))?;
    let path = if session {
        "/api/v1/internal/sso/session"
    } else {
        "/api/v1/internal/sso/user"
    };
    state
        .proxy
        .post(
            "user-service",
            path,
            json!({}),
            Some(HashMap::from([("x-verdyx-grant".to_string(), token)])),
        )
        .await
        .map_err(|e| format!("user-service unreachable: {e}"))
}

/// The account for an address a team vouches for, made if needed, and copied
/// into the gateway's users table.
pub async fn provision_account(
    state: &AppState,
    team: Uuid,
    subject: &str,
    email: &str,
    name_hint: Option<&str>,
) -> Result<UserIdentity, String> {
    let resp = ask_user_service(state, false, team, subject, email, name_hint).await?;
    if !resp.status().is_success() {
        return Err(format!(
            "user-service answered HTTP {}",
            resp.status().as_u16()
        ));
    }
    let user: UserIdentity = resp
        .json()
        .await
        .map_err(|e| format!("invalid user-service answer: {e}"))?;
    sync_user_to_gateway_db(state, &user).await;
    Ok(user)
}

// ─── Lookups ───────────────────────────────────────────────────────

pub async fn verified_domains(
    pool: &sqlx::PgPool,
    org_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT domain FROM team_domains WHERE organization_id = $1 AND verified_at IS NOT NULL ORDER BY domain",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
}

/// Is SSO required for this person? Returns the team's name. Owners of the
/// team are exempt, so the team can't be locked out.
pub async fn required_for(pool: &sqlx::PgPool, user_id: Uuid, email: &str) -> Option<String> {
    let domain = oidc::domain_of(&email.trim().to_lowercase()).to_string();
    if domain.is_empty() {
        return None;
    }
    sqlx::query_scalar(
        r#"SELECT o.name FROM team_domains d
           JOIN team_sso s ON s.organization_id = d.organization_id
           JOIN organizations o ON o.id = d.organization_id
           WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND s.enabled AND s.required
             AND NOT EXISTS (SELECT 1 FROM organization_members m
                             WHERE m.organization_id = d.organization_id AND m.user_id = $2 AND m.role = 'owner')
           LIMIT 1"#,
    )
    .bind(&domain)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::error!("SSO requirement lookup failed: {e}");
        None
    })
}

/// The message shown when SSO is required.
pub fn required_message(team: &str) -> String {
    format!("{team} signs in with single sign-on. Use \"Sign in with SSO\" and your work email.")
}

/// Add someone to the team with `role`, unless they're in it already or the
/// team is full. Returns whether they joined.
pub async fn join_team(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    let seats: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM organization_members WHERE organization_id = $1)
              + (SELECT COUNT(*) FROM organization_invitations WHERE organization_id = $1 AND accepted_at IS NULL)",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    if seats >= MAX_SEATS {
        tracing::warn!(%org_id, "team is full; SSO user not added");
        return Ok(false);
    }
    let added = sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    tx.commit().await?;
    Ok(added)
}

// ─── Settings ──────────────────────────────────────────────────────

async fn require_manager(state: &AppState, org_id: Uuid, claims: &Claims) -> ApiResult<String> {
    let role = member_role(state.db.pool(), org_id, claims.sub)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "team not found"))?;
    if can_manage(&role) {
        Ok(role)
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "only owners and admins can change single sign-on",
        ))
    }
}

fn key(state: &AppState) -> CredentialKey {
    CredentialKey::from_config(&state.config.security.jwt_secret)
}

/// `GET /orgs/{id}/sso`
pub async fn get_settings(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let domains: Vec<(String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT domain, verify_code, verified_at FROM team_domains WHERE organization_id = $1 ORDER BY domain",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let row: Option<(
        Option<String>,
        Option<String>,
        bool,
        bool,
        bool,
        String,
        Option<String>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT issuer, client_id, client_secret IS NOT NULL, enabled, required, join_role,
                scim_token_hint, scim_token_created_at
         FROM team_sso WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let (issuer, client_id, has_secret, enabled, required, join_role, hint, token_at) =
        row.unwrap_or((None, None, false, false, false, "member".into(), None, None));
    let provisioned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scim_users WHERE organization_id = $1 AND active")
            .bind(org_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    Ok(Json(json!({
        "domains": domains.into_iter().map(|(domain, code, verified_at)| {
            let (name, value) = txt_record(&domain, &code);
            json!({
                "domain": domain,
                "verified": verified_at.is_some(),
                "verifiedAt": verified_at,
                "record": { "type": "TXT", "name": name, "value": value },
            })
        }).collect::<Vec<_>>(),
        "sso": {
            "issuer": issuer,
            "clientId": client_id,
            "hasClientSecret": has_secret,
            "enabled": enabled,
            "required": required,
            "joinRole": join_role,
        },
        "callbackUrl": callback_url(),
        "signInUrl": format!("{}/login?sso=1", site_url()),
        "scim": {
            "baseUrl": scim_base_url(),
            "hasToken": hint.is_some(),
            "tokenHint": hint,
            "tokenCreatedAt": token_at,
            "provisionedUsers": provisioned,
        },
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsBody {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    /// Leave out to keep the stored one.
    pub client_secret: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub required: bool,
    pub join_role: Option<String>,
}

/// `PUT /orgs/{id}/sso`. Turning it on checks that the provider answers, and
/// that the team has a proven domain.
pub async fn put_settings(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<SettingsBody>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let bad = |m: &str| err(StatusCode::BAD_REQUEST, m);

    let issuer = match body
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(oidc::clean_issuer(raw).map_err(bad)?),
        None => None,
    };
    let client_id = body
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if client_id.as_ref().is_some_and(|c| c.len() > 255) {
        return Err(bad("the client ID is too long"));
    }
    let new_secret = body
        .client_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if new_secret.is_some_and(|s| s.len() > 512) {
        return Err(bad("the client secret is too long"));
    }
    let join_role = body.join_role.as_deref().unwrap_or("member");
    if !["admin", "member", "viewer"].contains(&join_role) {
        return Err(bad("new people can join as admin, member or viewer"));
    }
    if body.required && !body.enabled {
        return Err(bad("turn single sign-on on before requiring it"));
    }

    let stored_secret: Option<String> =
        sqlx::query_scalar("SELECT client_secret FROM team_sso WHERE organization_id = $1")
            .bind(org_id)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?
            .flatten();
    let sealed = match new_secret {
        Some(s) => Some(key(&state).seal(s)),
        None => stored_secret,
    };

    if body.enabled {
        let (Some(issuer), Some(_), Some(_)) = (&issuer, &client_id, &sealed) else {
            return Err(bad(
                "enter the issuer URL, client ID and client secret before turning it on",
            ));
        };
        if verified_domains(pool, org_id)
            .await
            .map_err(db_err)?
            .is_empty()
        {
            return Err(bad("prove at least one email domain before turning it on"));
        }
        let http = crate::services::webhook_delivery::client(false);
        oidc::discover(&http, issuer).await.map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                &format!("couldn't read the provider's OpenID configuration: {e}"),
            )
        })?;
    }

    sqlx::query(
        r#"INSERT INTO team_sso (organization_id, issuer, client_id, client_secret, enabled, required, join_role)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (organization_id) DO UPDATE SET
             issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
             client_secret = EXCLUDED.client_secret, enabled = EXCLUDED.enabled,
             required = EXCLUDED.required, join_role = EXCLUDED.join_role, updated_at = NOW()"#,
    )
    .bind(org_id)
    .bind(&issuer)
    .bind(&client_id)
    .bind(&sealed)
    .bind(body.enabled)
    .bind(body.required)
    .bind(join_role)
    .execute(pool)
    .await
    .map_err(db_err)?;

    audit::Event::by(&claims, "team.sso_changed")
        .team(org_id)
        .detail("enabled", body.enabled)
        .detail("required", body.required)
        .detail("joinRole", join_role.to_string())
        .detail("issuer", issuer.clone().unwrap_or_default())
        .detail("clientSecretChanged", new_secret.is_some())
        .record(pool)
        .await;
    get_settings(State(state), claims, Path(org_id)).await
}

#[derive(Deserialize)]
pub struct DomainBody {
    pub domain: String,
}

/// `POST /orgs/{id}/sso/domains`
pub async fn add_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<DomainBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let domain = clean_domain(&body.domain).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM team_domains WHERE organization_id = $1")
            .bind(org_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    if count >= MAX_DOMAINS {
        return Err(err(
            StatusCode::CONFLICT,
            "a team can have at most 10 domains",
        ));
    }
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM team_domains WHERE domain = $1 AND verified_at IS NOT NULL AND organization_id <> $2)",
    )
    .bind(&domain)
    .bind(org_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    if taken {
        return Err(err(
            StatusCode::CONFLICT,
            "another team has already proven this domain",
        ));
    }
    let code = new_code();
    sqlx::query(
        "INSERT INTO team_domains (organization_id, domain, verify_code) VALUES ($1, $2, $3)
         ON CONFLICT (organization_id, domain) DO NOTHING",
    )
    .bind(org_id)
    .bind(&domain)
    .bind(&code)
    .execute(pool)
    .await
    .map_err(db_err)?;
    let code: String = sqlx::query_scalar(
        "SELECT verify_code FROM team_domains WHERE organization_id = $1 AND domain = $2",
    )
    .bind(org_id)
    .bind(&domain)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    audit::Event::by(&claims, "team.domain_added")
        .team(org_id)
        .detail("domain", domain.clone())
        .record(pool)
        .await;
    let (name, value) = txt_record(&domain, &code);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "domain": domain,
            "verified": false,
            "record": { "type": "TXT", "name": name, "value": value },
        })),
    ))
}

/// TXT records for `name`, through Cloudflare's DNS-over-HTTPS resolver, so
/// the answer doesn't depend on the server's own resolver or cache.
async fn txt_lookup(name: &str) -> Result<Vec<String>, String> {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(rename = "type")]
        kind: u16,
        data: String,
    }
    #[derive(Deserialize)]
    struct Reply {
        #[serde(rename = "Status")]
        status: u16,
        #[serde(rename = "Answer", default)]
        answer: Vec<Answer>,
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("Verdyx")
        .build()
        .map_err(|e| e.to_string())?;
    let reply: Reply = http
        .get("https://cloudflare-dns.com/dns-query")
        .query(&[("name", name), ("type", "TXT")])
        .header("Accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?;
    // 3 is NXDOMAIN: the record isn't there.
    if reply.status != 0 && reply.status != 3 {
        return Err(format!("DNS lookup failed (status {})", reply.status));
    }
    Ok(reply
        .answer
        .into_iter()
        .filter(|a| a.kind == 16)
        .map(|a| a.data)
        .collect())
}

/// `POST /orgs/{id}/sso/domains/{domain}/verify`
pub async fn verify_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, domain)): Path<(Uuid, String)>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let domain = clean_domain(&domain).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT verify_code, verified_at FROM team_domains WHERE organization_id = $1 AND domain = $2",
    )
    .bind(org_id)
    .bind(&domain)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let (code, verified_at) = row.ok_or_else(|| err(StatusCode::NOT_FOUND, "domain not found"))?;
    if verified_at.is_some() {
        return Ok(Json(json!({ "domain": domain, "verified": true })));
    }
    let (name, value) = txt_record(&domain, &code);
    let answers = txt_lookup(&name)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &e))?;
    if !txt_matches(&answers, &value) {
        return Err(err(
            StatusCode::CONFLICT,
            &format!(
                "the TXT record wasn't found yet. Add a TXT record named {name} with the value {value}; DNS changes can take a few minutes to appear"
            ),
        ));
    }
    let done = sqlx::query(
        "UPDATE team_domains SET verified_at = NOW() WHERE organization_id = $1 AND domain = $2",
    )
    .bind(org_id)
    .bind(&domain)
    .execute(pool)
    .await;
    match done {
        Ok(_) => {}
        // The unique index: another team proved it first.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(err(
                StatusCode::CONFLICT,
                "another team has already proven this domain",
            ))
        }
        Err(e) => return Err(db_err(e)),
    }
    audit::Event::by(&claims, "team.domain_verified")
        .team(org_id)
        .detail("domain", domain.clone())
        .record(pool)
        .await;
    Ok(Json(json!({ "domain": domain, "verified": true })))
}

/// `DELETE /orgs/{id}/sso/domains/{domain}`
pub async fn remove_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, domain)): Path<(Uuid, String)>,
) -> ApiResult<StatusCode> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let domain = clean_domain(&domain).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let gone = sqlx::query("DELETE FROM team_domains WHERE organization_id = $1 AND domain = $2")
        .bind(org_id)
        .bind(&domain)
        .execute(pool)
        .await
        .map_err(db_err)?
        .rows_affected();
    if gone == 0 {
        return Err(err(StatusCode::NOT_FOUND, "domain not found"));
    }
    // Without a proven domain, SSO can't sign anyone in.
    if verified_domains(pool, org_id)
        .await
        .map_err(db_err)?
        .is_empty()
    {
        sqlx::query("UPDATE team_sso SET enabled = FALSE, required = FALSE, updated_at = NOW() WHERE organization_id = $1")
            .bind(org_id)
            .execute(pool)
            .await
            .map_err(db_err)?;
    }
    audit::Event::by(&claims, "team.domain_removed")
        .team(org_id)
        .detail("domain", domain)
        .record(pool)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /orgs/{id}/sso/scim-token`: a new provisioning token, shown once.
/// It replaces any earlier one.
pub async fn new_scim_token(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let token = format!("scim_{}", oidc::random());
    let hint = format!("scim_…{}", &token[token.len() - 4..]);
    sqlx::query(
        r#"INSERT INTO team_sso (organization_id, scim_token_hash, scim_token_hint, scim_token_created_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (organization_id) DO UPDATE SET
             scim_token_hash = EXCLUDED.scim_token_hash, scim_token_hint = EXCLUDED.scim_token_hint,
             scim_token_created_at = NOW(), updated_at = NOW()"#,
    )
    .bind(org_id)
    .bind(hash_token(&token))
    .bind(&hint)
    .execute(pool)
    .await
    .map_err(db_err)?;
    audit::Event::by(&claims, "team.scim_token_created")
        .team(org_id)
        .record(pool)
        .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": token, "tokenHint": hint, "baseUrl": scim_base_url() })),
    ))
}

/// `DELETE /orgs/{id}/sso/scim-token`
pub async fn revoke_scim_token(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    sqlx::query(
        "UPDATE team_sso SET scim_token_hash = NULL, scim_token_hint = NULL, scim_token_created_at = NULL, updated_at = NOW()
         WHERE organization_id = $1",
    )
    .bind(org_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    audit::Event::by(&claims, "team.scim_token_revoked")
        .team(org_id)
        .record(pool)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Signing in ────────────────────────────────────────────────────

/// Shown on /login after a failed attempt. Fixed codes, so a crafted link
/// can't put arbitrary text on the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    NotSetUp,
    Cancelled,
    Expired,
    NoEmail,
    UnverifiedEmail,
    WrongDomain,
    TwoFactor,
    Suspended,
    Provider,
    Failed,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotSetUp => "not_set_up",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::NoEmail => "no_email",
            Self::UnverifiedEmail => "unverified_email",
            Self::WrongDomain => "wrong_domain",
            Self::TwoFactor => "two_factor",
            Self::Suspended => "suspended",
            Self::Provider => "provider",
            Self::Failed => "failed",
        }
    }
}

fn append_cookie(headers: &mut HeaderMap, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.append(header::SET_COOKIE, v);
    }
}

fn clear_state_cookie() -> String {
    format!("{STATE_COOKIE}=; Path={STATE_COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

fn back_to_login(failure: Failure) -> Response {
    tracing::info!(reason = failure.code(), "SSO sign-in did not complete");
    let mut headers = HeaderMap::new();
    append_cookie(&mut headers, &clear_state_cookie());
    (
        headers,
        Redirect::to(&format!("/login?sso_error={}", failure.code())),
    )
        .into_response()
}

/// What the browser carries between start and callback.
#[derive(Debug, PartialEq, Eq)]
pub struct Pending {
    pub team: Uuid,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

impl Pending {
    pub fn cookie_value(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.team, self.state, self.nonce, self.verifier
        )
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split('.');
        let p = Self {
            team: parts.next()?.parse().ok()?,
            state: parts.next()?.to_string(),
            nonce: parts.next()?.to_string(),
            verifier: parts.next()?.to_string(),
        };
        let ok = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        (parts.next().is_none() && ok(&p.state) && ok(&p.nonce) && ok(&p.verifier)).then_some(p)
    }

    /// Constant-time compare of the callback's `state`.
    pub fn state_matches(&self, got: Option<&str>) -> bool {
        let Some(got) = got else { return false };
        self.state.len() == got.len()
            && self
                .state
                .bytes()
                .zip(got.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

struct TeamSso {
    org_id: Uuid,
    issuer: String,
    client_id: String,
    client_secret: String,
    join_role: String,
}

async fn team_sso(state: &AppState, org_id: Uuid) -> Option<TeamSso> {
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT issuer, client_id, client_secret, join_role FROM team_sso
         WHERE organization_id = $1 AND enabled AND issuer IS NOT NULL
           AND client_id IS NOT NULL AND client_secret IS NOT NULL",
    )
    .bind(org_id)
    .fetch_optional(state.db.pool())
    .await
    .ok()
    .flatten();
    let (issuer, client_id, sealed, join_role) = row?;
    let client_secret = key(state).open(&sealed)?;
    Some(TeamSso {
        org_id,
        issuer,
        client_id,
        client_secret,
        join_role,
    })
}

#[derive(Deserialize)]
pub struct StartParams {
    /// The work email's domain. The site sends only the domain, so the
    /// address itself never lands in a URL or a log.
    domain: Option<String>,
}

/// `GET /auth/sso/start?domain=acme.com`: send the browser to the team's
/// identity provider.
pub async fn start(State(state): State<AppState>, Query(params): Query<StartParams>) -> Response {
    let Some(domain) = params.domain.as_deref().and_then(|d| clean_domain(d).ok()) else {
        return back_to_login(Failure::NotSetUp);
    };
    let org_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT d.organization_id FROM team_domains d
         JOIN team_sso s ON s.organization_id = d.organization_id
         WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND s.enabled",
    )
    .bind(&domain)
    .fetch_optional(state.db.pool())
    .await
    .ok()
    .flatten();
    let Some(team) = (match org_id {
        Some(id) => team_sso(&state, id).await,
        None => None,
    }) else {
        return back_to_login(Failure::NotSetUp);
    };
    let http = crate::services::webhook_delivery::client(false);
    let discovery = match oidc::discover(&http, &team.issuer).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(org = %team.org_id, "SSO discovery failed: {e}");
            return back_to_login(Failure::Provider);
        }
    };
    let pending = Pending {
        team: team.org_id,
        state: oidc::random(),
        nonce: oidc::random(),
        verifier: oidc::random(),
    };
    let url = match oidc::authorize_url(
        &discovery,
        &team.client_id,
        &callback_url(),
        &pending.state,
        &pending.nonce,
        &pending.verifier,
        None,
    ) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(org = %team.org_id, "SSO authorize URL refused: {e}");
            return back_to_login(Failure::Provider);
        }
    };
    let mut headers = HeaderMap::new();
    append_cookie(
        &mut headers,
        &format!(
            "{STATE_COOKIE}={}; Path={STATE_COOKIE_PATH}; Max-Age={STATE_TTL_SECS}; HttpOnly; Secure; SameSite=Lax",
            pending.cookie_value()
        ),
    );
    (headers, Redirect::to(&url)).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/sso/callback`: finish signing in.
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let Some(pending) = cookie(&headers, STATE_COOKIE).and_then(Pending::parse) else {
        return back_to_login(Failure::Expired);
    };
    if params.error.is_some() {
        return back_to_login(Failure::Cancelled);
    }
    if !pending.state_matches(params.state.as_deref()) {
        return back_to_login(Failure::Expired);
    }
    let Some(code) = params.code.filter(|c| !c.is_empty() && c.len() <= 4096) else {
        return back_to_login(Failure::Failed);
    };
    let Some(team) = team_sso(&state, pending.team).await else {
        return back_to_login(Failure::NotSetUp);
    };

    let http = crate::services::webhook_delivery::client(false);
    let checked = async {
        let d = oidc::discover(&http, &team.issuer).await?;
        let id_token = oidc::exchange(
            &http,
            &d,
            &team.client_id,
            &team.client_secret,
            &code,
            &callback_url(),
            &pending.verifier,
        )
        .await?;
        let keys = oidc::keys(&http, &d).await?;
        oidc::verify_id_token(&id_token, &keys, &d.issuer, &team.client_id, &pending.nonce)
    }
    .await;
    let claims = match checked {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(org = %team.org_id, "SSO sign-in refused: {e}");
            return back_to_login(Failure::Provider);
        }
    };
    let email = match oidc::work_email(&claims) {
        Ok(e) => e,
        Err("unverified_email") => return back_to_login(Failure::UnverifiedEmail),
        Err(_) => return back_to_login(Failure::NoEmail),
    };
    let domains = match verified_domains(state.db.pool(), team.org_id).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("SSO domain lookup failed: {e}");
            return back_to_login(Failure::Failed);
        }
    };
    if !in_domains(&email, &domains) {
        tracing::warn!(org = %team.org_id, domain = oidc::domain_of(&email), "SSO address outside the team's domains");
        return back_to_login(Failure::WrongDomain);
    }

    let resp = match ask_user_service(
        &state,
        true,
        team.org_id,
        &claims.sub,
        &email,
        claims.name.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("SSO session failed: {e}");
            return back_to_login(Failure::Failed);
        }
    };
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let message = resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_default();
        return back_to_login(match status {
            401 if message.contains("two-factor") => Failure::TwoFactor,
            403 => Failure::Suspended,
            _ => Failure::Failed,
        });
    }
    let auth: UsAuthResponse = match resp.json().await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Invalid user-service SSO response: {e}");
            return back_to_login(Failure::Failed);
        }
    };

    sync_user_to_gateway_db(&state, &auth.user).await;
    let pool = state.db.pool();
    // Someone the identity provider deprovisioned doesn't rejoin by signing in.
    let deprovisioned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM scim_users WHERE organization_id = $1 AND user_id = $2 AND NOT active)",
    )
    .bind(team.org_id)
    .bind(auth.user.id)
    .fetch_one(pool)
    .await
    .unwrap_or(true);
    let joined = if deprovisioned {
        Ok(false)
    } else {
        join_team(pool, team.org_id, auth.user.id, &team.join_role).await
    };
    match joined {
        Ok(true) => {
            audit::Event::by_user(auth.user.id, "team.member.joined_sso")
                .team(team.org_id)
                .subject(auth.user.id)
                .detail("role", team.join_role.clone())
                .record(pool)
                .await
        }
        Ok(false) => {}
        Err(e) => tracing::error!("SSO team join failed: {e}"),
    }
    audit::Event::by_user(auth.user.id, "auth.login")
        .detail("method", "sso")
        .team(team.org_id)
        .record(pool)
        .await;
    let expires_in = if auth.expires_in > 0 {
        auth.expires_in
    } else {
        3600
    };
    let mut out = session_cookies(&auth.access_token, &auth.refresh_token, expires_in);
    append_cookie(&mut out, &clear_state_cookie());
    (out, Redirect::to("/dashboard")).into_response()
}

/// `GET /auth/sso/check?domain=acme.com`: does this domain sign in with SSO?
/// Lets the login page say so before sending the browser away.
pub async fn check(
    State(state): State<AppState>,
    Query(params): Query<StartParams>,
) -> Json<Value> {
    let enabled = match params.domain.as_deref().and_then(|d| clean_domain(d).ok()) {
        Some(domain) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_domains d JOIN team_sso s ON s.organization_id = d.organization_id
                            WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND s.enabled)",
        )
        .bind(&domain)
        .fetch_one(state.db.pool())
        .await
        .unwrap_or(false),
        None => false,
    };
    Json(json!({ "sso": enabled }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_cleaned_or_refused() {
        assert_eq!(clean_domain(" @Acme.COM ").unwrap(), "acme.com");
        assert_eq!(
            clean_domain("https://eu.acme.co.uk/").unwrap(),
            "eu.acme.co.uk"
        );
        for bad in [
            "",
            "acme",
            "acme..com",
            "-acme.com",
            "acme.com/x",
            "1.2.3.4",
            "a b.com",
            "ac_me.com",
        ] {
            assert!(clean_domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_txt_record_must_match() {
        let (name, value) = txt_record("acme.com", "abc");
        assert_eq!(name, "_verdyx-challenge.acme.com");
        assert_eq!(value, "verdyx-domain-verification=abc");
        assert!(txt_matches(
            &["\"verdyx-domain-verification=abc\"".into()],
            &value
        ));
        assert!(txt_matches(
            &["\"verdyx-domain-\" \"verification=abc\"".into()],
            &value
        ));
        assert!(txt_matches(
            &["verdyx-domain-verification=abc".into()],
            &value
        ));
        assert!(!txt_matches(
            &["\"verdyx-domain-verification=abcd\"".into()],
            &value
        ));
        assert!(!txt_matches(&["\"v=spf1 -all\"".into()], &value));
        assert!(!txt_matches(&[], &value));
    }

    #[test]
    fn only_proven_domains_count() {
        let d = vec!["acme.com".to_string()];
        assert!(in_domains("ada@acme.com", &d));
        assert!(
            !in_domains("ada@eu.acme.com", &d),
            "subdomains must be listed"
        );
        assert!(!in_domains("ada@acme.com.evil.io", &d));
        assert!(!in_domains("ada@evilacme.com", &d));
        assert!(!in_domains("no-at-sign", &d));
    }

    #[test]
    fn the_pending_cookie_round_trips_and_rejects_junk() {
        let p = Pending {
            team: Uuid::new_v4(),
            state: oidc::random(),
            nonce: oidc::random(),
            verifier: oidc::random(),
        };
        let back = Pending::parse(&p.cookie_value()).unwrap();
        assert_eq!(back, p);
        assert!(back.state_matches(Some(&p.state)));
        assert!(!back.state_matches(Some(&oidc::random())));
        assert!(!back.state_matches(None));
        assert!(Pending::parse("x.y.z.w").is_none());
        assert!(Pending::parse(&format!("{}.extra", p.cookie_value())).is_none());
    }

    #[test]
    fn the_grant_is_short_lived_and_for_user_service_only() {
        let t = grant("k", Uuid::nil(), "sub-1", "ada@acme.com", Some("Ada")).unwrap();
        let mut v = jsonwebtoken::Validation::default();
        v.set_audience(&[GRANT_AUDIENCE]);
        v.set_issuer(&[GRANT_ISSUER]);
        let g =
            jsonwebtoken::decode::<Grant>(&t, &jsonwebtoken::DecodingKey::from_secret(b"k"), &v)
                .unwrap()
                .claims;
        assert_eq!(g.exp - g.iat, 60);
        assert_eq!(g.email, "ada@acme.com");
        // A session token decoder (no audience set) refuses it.
        let plain = jsonwebtoken::Validation::default();
        assert!(jsonwebtoken::decode::<Value>(
            &t,
            &jsonwebtoken::DecodingKey::from_secret(b"k"),
            &plain
        )
        .is_err());
        // And it has no `sub`, so it can't be read as session claims.
        let mut loose = jsonwebtoken::Validation::default();
        loose.validate_aud = false;
        assert!(jsonwebtoken::decode::<Claims>(
            &t,
            &jsonwebtoken::DecodingKey::from_secret(b"k"),
            &loose
        )
        .is_err());
    }

    /// Against a real database; runs only when API_GATEWAY_DATABASE_URL is
    /// set, and removes what it adds.
    #[tokio::test]
    async fn sso_rules_hold_in_the_database() {
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

        let (owner, member, team, other_team) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let domain = format!("t{}.example.com", &team.simple().to_string()[..12]);
        for t in [team, other_team] {
            sqlx::query(
                "INSERT INTO organizations (id, name, created_by) VALUES ($1, 'Acme SOC', $2)",
            )
            .bind(t)
            .bind(owner)
            .execute(&db)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(team)
            .bind(owner)
            .execute(&db)
            .await
            .unwrap();
        let ada = format!("ada@{domain}");

        // An unproven domain requires nothing, even with SSO on and required.
        sqlx::query(
            "INSERT INTO team_domains (organization_id, domain, verify_code) VALUES ($1, $2, $3)",
        )
        .bind(team)
        .bind(&domain)
        .bind(new_code())
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO team_sso (organization_id, issuer, client_id, client_secret, enabled, required)
             VALUES ($1, 'https://idp.example.com', 'c', 'v1:x', TRUE, TRUE)",
        )
        .bind(team)
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(required_for(&db, member, &ada).await, None);
        assert!(verified_domains(&db, team).await.unwrap().is_empty());

        // Once proven, it's required for everyone in the domain but the owner.
        sqlx::query("UPDATE team_domains SET verified_at = NOW() WHERE organization_id = $1")
            .bind(team)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            required_for(&db, member, &ada).await.as_deref(),
            Some("Acme SOC")
        );
        assert_eq!(
            required_for(&db, Uuid::nil(), &ada.to_uppercase())
                .await
                .as_deref(),
            Some("Acme SOC")
        );
        assert_eq!(
            required_for(&db, owner, &format!("boss@{domain}")).await,
            None
        );
        assert_eq!(
            required_for(&db, member, "ada@elsewhere.example").await,
            None
        );
        assert_eq!(
            verified_domains(&db, team).await.unwrap(),
            vec![domain.clone()]
        );

        // Another team can't prove the same domain.
        sqlx::query(
            "INSERT INTO team_domains (organization_id, domain, verify_code, verified_at) VALUES ($1, $2, $3, NOW())",
        )
        .bind(other_team)
        .bind(&domain)
        .bind(new_code())
        .execute(&db)
        .await
        .expect_err("a domain belongs to one team");

        // Not required: nothing is.
        sqlx::query("UPDATE team_sso SET required = FALSE WHERE organization_id = $1")
            .bind(team)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(required_for(&db, member, &ada).await, None);

        // Joining: once, with the role given.
        assert!(join_team(&db, team, member, "viewer").await.unwrap());
        assert!(!join_team(&db, team, member, "admin").await.unwrap());
        let role = member_role(&db, team, member).await.unwrap();
        assert_eq!(role.as_deref(), Some("viewer"));

        for t in [team, other_team] {
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(t)
                .execute(&db)
                .await
                .unwrap();
        }
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_domains WHERE domain = $1")
            .bind(&domain)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(left, 0, "deleting the team removes its domains");
    }

    #[test]
    fn failure_codes_are_fixed() {
        let r = back_to_login(Failure::WrongDomain);
        assert_eq!(
            r.headers().get(header::LOCATION).unwrap(),
            "/login?sso_error=wrong_domain"
        );
    }
}
