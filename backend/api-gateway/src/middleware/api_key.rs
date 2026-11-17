//! API keys: how they look, how they're stored, and what they may do.
//!
//! A key is `vdx_` followed by 64 hex characters (256 random bits). Only its
//! SHA-256 is stored: the key is random and long, so a fast hash is safe and
//! lets a request find its key with one indexed lookup (a salted password
//! hash can't be looked up, which is why keys made before this never worked).
//!
//! A request may send the key as `X-API-Key: vdx_…` or
//! `Authorization: Bearer vdx_…`. Keys act as their owner, never as an
//! admin, and only within their scopes:
//!
//! - `read`: GET requests.
//! - `scan`: submit files and URLs and start analyses.
//! - `write`: other changes (webhooks, bounties, votes).
//!
//! Whatever the scopes, a key can't sign in, create or revoke keys, change or
//! delete the account, manage teams, or move money: those need the owner's
//! own session.
//!
//! A **team key** (one with an `organization_id`) acts for its team: it may
//! only use scans and engine status, its scans are saved to the team, and it
//! reads only the team's scans. It works while the admin who made it is still
//! an owner or admin of that team.

use axum::http::{HeaderMap, Method};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::auth::Claims;
use crate::AppState;

pub const KEY_PREFIX: &str = "vdx_";
/// Prefix of keys from before the rename. Accepted, never issued.
pub const LEGACY_KEY_PREFIX: &str = "nxs_";
/// Characters of the key kept in the clear so the owner can tell keys apart.
pub const DISPLAY_PREFIX_LEN: usize = 12;

pub const SCOPES: [&str; 3] = ["read", "scan", "write"];
pub const DEFAULT_SCOPES: [&str; 2] = ["read", "scan"];
/// Active keys one account may hold.
pub const MAX_ACTIVE_KEYS: i64 = 10;

/// What the middleware attaches to a request authenticated by a key.
#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    pub key_id: Uuid,
    pub scopes: Vec<String>,
    /// The team, for a team key.
    pub org_id: Option<Uuid>,
}

/// A new random key.
pub fn generate() -> String {
    format!(
        "{KEY_PREFIX}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

/// What is stored for a key.
pub fn hash(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

pub fn display_prefix(key: &str) -> String {
    key.chars().take(DISPLAY_PREFIX_LEN).collect()
}

fn looks_like_key(value: &str) -> bool {
    (value.starts_with(KEY_PREFIX) || value.starts_with(LEGACY_KEY_PREFIX))
        && value.len() >= 20
        && value.len() <= 128
}

/// The API key a request carries, if any: `X-API-Key`, or a Bearer value that
/// is a key rather than a session token.
pub fn from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-api-key").and_then(|h| h.to_str().ok()) {
        return Some(v.trim().to_string());
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;
    if let Some(basic) = auth.strip_prefix("Basic ") {
        // TAXII clients send keys as HTTP Basic: either half may be the key.
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(basic.trim())
            .ok()?;
        let text = String::from_utf8(decoded).ok()?;
        let (user, rest) = text.split_once(':').unwrap_or((text.as_str(), ""));
        return [rest, user]
            .into_iter()
            .map(str::trim)
            .find(|t| looks_like_key(t))
            .map(str::to_string);
    }
    auth.strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| looks_like_key(t))
        .map(str::to_string)
}

/// Scopes from a request body: known ones only, deduplicated, defaulting to
/// [`DEFAULT_SCOPES`]. `Err` names an unknown scope.
pub fn parse_scopes(requested: Option<&serde_json::Value>) -> Result<Vec<String>, String> {
    let Some(list) = requested.and_then(|v| v.as_array()) else {
        return Ok(DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect());
    };
    let mut scopes = Vec::new();
    for item in list {
        let s = item.as_str().unwrap_or_default();
        if !SCOPES.contains(&s) {
            return Err(format!("unknown scope {s:?}; use read, scan or write"));
        }
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_string());
        }
    }
    if scopes.is_empty() {
        return Err("choose at least one scope".to_string());
    }
    Ok(scopes)
}

/// Whether a key with `scopes` may make this request. `Err` says why not.
/// `path` is the full request path (`/api/v1/...` or `/api/...`).
pub fn allows(
    method: &Method,
    path: &str,
    scopes: &[String],
    team_key: bool,
) -> Result<(), &'static str> {
    let p = path
        .strip_prefix("/api/v1")
        .or_else(|| path.strip_prefix("/api"))
        .unwrap_or(path);
    let reading = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let has = |s: &str| scopes.iter().any(|x| x == s);

    if p.starts_with("/auth/") || p.starts_with("/users/me/api-keys") {
        return Err("API keys can't sign in or manage keys; use your account");
    }
    if p == "/users/me/export" {
        return Err("API keys can't export the account; use your account");
    }
    if p.starts_with("/orgs") || p.starts_with("/invitations") {
        return Err("API keys can't manage teams; use your account");
    }
    if team_key
        && !(p.starts_with("/submissions")
            || p.starts_with("/engines")
            || p.starts_with("/health")
            || (reading && p.starts_with("/taxii2")))
    {
        return Err("team keys can only scan, read the team's scans and check engines");
    }
    if !reading && (p == "/users/me" || p.starts_with("/users/me/")) {
        return Err("API keys can't change or delete the account");
    }
    if !reading && p.starts_with("/wallet") {
        return Err("API keys can't move funds");
    }
    if reading {
        return if has("read") {
            Ok(())
        } else {
            Err("this key lacks the read scope")
        };
    }
    // Deleting a scan is a change, not a scan.
    // A retrohunt is a scan over past uploads.
    let is_scan = (p.starts_with("/submissions")
        || p.starts_with("/analysis")
        || p.starts_with("/retrohunts"))
        && *method != Method::DELETE;
    if is_scan && (has("scan") || has("write")) {
        return Ok(());
    }
    if has("write") {
        return Ok(());
    }
    Err(if is_scan {
        "this key lacks the scan scope"
    } else {
        "this key lacks the write scope"
    })
}

/// Look up a key. `None` if it doesn't exist, was revoked or has expired.
pub async fn authenticate(
    state: &AppState,
    key: &str,
) -> Result<Option<(Claims, ApiKeyAuth)>, sqlx::Error> {
    if !looks_like_key(key) {
        return Ok(None);
    }
    let key_hash = hash(key);
    #[allow(clippy::type_complexity)]
    let row: Option<(
        Uuid,
        Uuid,
        String,
        String,
        Option<Vec<String>>,
        Option<Uuid>,
    )> = sqlx::query_as(
        r#"SELECT ak.id, u.id, u.email, u.username, ak.permissions, ak.organization_id
           FROM api_keys ak
           JOIN users u ON u.id = ak.user_id
           WHERE ak.key_hash = $1
             AND ak.is_active = TRUE
             AND u.is_active IS NOT FALSE
             AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
             AND (ak.organization_id IS NULL OR EXISTS (
                    SELECT 1 FROM organization_members m
                    WHERE m.organization_id = ak.organization_id
                      AND m.user_id = ak.user_id
                      AND m.role IN ('owner', 'admin')))"#,
    )
    .bind(&key_hash)
    .fetch_optional(state.db.pool())
    .await?;
    let Some((key_id, user_id, email, username, scopes, org_id)) = row else {
        return Ok(None);
    };

    // Recorded at most once a minute, off the request path.
    let pool = state.db.pool().clone();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "UPDATE api_keys SET last_used_at = NOW()
             WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')",
        )
        .bind(key_id)
        .execute(&pool)
        .await;
    });

    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        email,
        role: "user".to_string(),
        exp: (now + Duration::hours(1)).timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: key_id.to_string(),
        is_admin: false,
        username,
        token_type: "api_key".to_string(),
        org_id,
    };
    let scopes = scopes.unwrap_or_else(|| vec!["read".to_string()]);
    Ok(Some((
        claims,
        ApiKeyAuth {
            key_id,
            scopes,
            org_id,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn keys_look_right_and_hash_stably() {
        let k = generate();
        assert!(k.starts_with("vdx_"));
        assert_eq!(k.len(), 4 + 64);
        assert_ne!(k, generate());
        assert_eq!(hash(&k), hash(&k));
        assert_eq!(hash(&k).len(), 64);
        assert_eq!(display_prefix(&k).len(), 12);
    }

    #[test]
    fn keys_are_read_from_either_header() {
        let k = generate();
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&k).unwrap());
        assert_eq!(from_headers(&h).as_deref(), Some(k.as_str()));

        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {k}")).unwrap(),
        );
        assert_eq!(from_headers(&h).as_deref(), Some(k.as_str()));

        // A session token in the Bearer header isn't a key.
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            HeaderValue::from_static("Bearer eyJhbGciOi.x.y"),
        );
        assert!(from_headers(&h).is_none());
    }

    #[test]
    fn keys_are_read_from_basic_auth_for_taxii_clients() {
        use base64::Engine;
        let k = generate();
        for pair in [format!("taxii:{k}"), format!("{k}:"), format!("{k}:x")] {
            let mut h = HeaderMap::new();
            let v = base64::engine::general_purpose::STANDARD.encode(pair.as_bytes());
            h.insert(
                "authorization",
                HeaderValue::from_str(&format!("Basic {v}")).unwrap(),
            );
            assert_eq!(from_headers(&h).as_deref(), Some(k.as_str()), "{pair}");
        }
        // A real username and login aren't a key.
        let mut h = HeaderMap::new();
        let v = base64::engine::general_purpose::STANDARD.encode(b"ana:hunter2");
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Basic {v}")).unwrap(),
        );
        assert!(from_headers(&h).is_none());
    }

    #[test]
    fn team_keys_read_their_feed() {
        let r = scopes(&["read"]);
        assert!(allows(&Method::GET, "/taxii2/api/collections/", &r, true).is_ok());
        assert!(allows(
            &Method::POST,
            "/taxii2/api/collections/x/objects/",
            &r,
            true
        )
        .is_err());
    }

    #[test]
    fn scopes_are_validated() {
        assert_eq!(parse_scopes(None).unwrap(), scopes(&["read", "scan"]));
        let req = serde_json::json!(["read", "read", "write"]);
        assert_eq!(
            parse_scopes(Some(&req)).unwrap(),
            scopes(&["read", "write"])
        );
        assert!(parse_scopes(Some(&serde_json::json!(["admin"]))).is_err());
        assert!(parse_scopes(Some(&serde_json::json!([]))).is_err());
    }

    #[test]
    fn scopes_gate_requests() {
        let rs = scopes(&["read", "scan"]);
        assert!(allows(&Method::GET, "/api/v1/submissions/abc", &rs, false).is_ok());
        assert!(allows(&Method::POST, "/api/v1/submissions/file", &rs, false).is_ok());
        assert!(allows(&Method::POST, "/api/analysis/submit", &rs, false).is_ok());
        assert!(allows(&Method::POST, "/api/v1/retrohunts", &rs, false).is_ok());
        assert!(allows(
            &Method::POST,
            "/api/v1/retrohunts",
            &scopes(&["read"]),
            false
        )
        .is_err());
        assert!(
            allows(&Method::POST, "/api/v1/retrohunts", &rs, true).is_err(),
            "not team keys"
        );
        assert!(allows(&Method::POST, "/api/v1/webhooks", &rs, false).is_err());
        assert!(
            allows(&Method::DELETE, "/api/v1/submissions/abc", &rs, false).is_err(),
            "deleting needs write"
        );
        assert!(allows(
            &Method::DELETE,
            "/api/v1/submissions/abc",
            &scopes(&["write"]),
            false
        )
        .is_ok());
        assert!(allows(
            &Method::POST,
            "/api/v1/webhooks",
            &scopes(&["write"]),
            false
        )
        .is_ok());

        let read_only = scopes(&["read"]);
        assert!(allows(&Method::GET, "/api/v1/engines/status", &read_only, false).is_ok());
        assert!(allows(&Method::POST, "/api/v1/submissions/file", &read_only, false).is_err());
        assert!(allows(&Method::GET, "/api/v1/engines", &scopes(&["scan"]), false).is_err());
    }

    #[test]
    fn keys_never_manage_the_account() {
        let all = scopes(&["read", "scan", "write"]);
        for (m, p) in [
            (Method::POST, "/api/v1/auth/api-key"),
            (Method::GET, "/api/v1/users/me/api-keys"),
            (Method::DELETE, "/api/v1/users/me/api-keys/x"),
            (Method::DELETE, "/api/v1/users/me"),
            (Method::PUT, "/api/v1/users/me"),
            (Method::POST, "/api/v1/wallet/withdraw"),
            (Method::POST, "/api/auth/logout"),
        ] {
            assert!(allows(&m, p, &all, false).is_err(), "{m} {p}");
        }
        assert!(allows(&Method::GET, "/api/v1/users/me", &all, false).is_ok());
        assert!(allows(&Method::GET, "/api/v1/orgs", &all, false).is_err());
        assert!(allows(&Method::GET, "/api/v1/users/me/export", &all, false).is_err());
        assert!(allows(&Method::GET, "/api/v1/users/me/audit", &all, false).is_ok());
        assert!(allows(&Method::POST, "/api/v1/invitations/accept", &all, false).is_err());
    }

    #[test]
    fn team_keys_only_scan() {
        let all = scopes(&["read", "scan", "write"]);
        assert!(allows(&Method::POST, "/api/v1/submissions/file", &all, true).is_ok());
        assert!(allows(&Method::GET, "/api/v1/submissions/abc", &all, true).is_ok());
        assert!(allows(&Method::GET, "/api/v1/engines/status", &all, true).is_ok());
        for (m, p) in [
            (Method::GET, "/api/v1/users/me"),
            (Method::POST, "/api/v1/webhooks"),
            (Method::POST, "/api/v1/analysis/submit"),
            (Method::GET, "/api/v1/wallet/balance"),
            (Method::GET, "/api/v1/orgs/x"),
        ] {
            assert!(allows(&m, p, &all, true).is_err(), "{m} {p}");
        }
    }
}
