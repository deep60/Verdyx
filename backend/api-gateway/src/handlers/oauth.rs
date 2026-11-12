//! "Continue with Google / GitHub".
//!
//! The browser navigates (not fetches) through these, via the site's /api
//! proxy, so the session cookies set here land on the site's own origin:
//!
//! 1. `GET /auth/oauth/{provider}` stores a random `state` in a short-lived
//!    cookie and redirects to the provider.
//! 2. The provider redirects back to `GET /auth/oauth/{provider}/callback`
//!    with `code` and `state`. The state must match the cookie, which stops
//!    another site from logging a visitor into the attacker's account.
//! 3. user-service swaps the code for the provider's verified identity and
//!    returns tokens; the gateway sets the session cookies and redirects to
//!    the dashboard. Failures go back to /login with a short error code.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Json, Redirect, Response},
};
use serde::Deserialize;

use crate::handlers::auth::{sync_user_to_gateway_db, UsAuthResponse};
use crate::middleware::auth::{cookie, session_cookies};
use crate::{ApiResponse, AppState};

const STATE_COOKIE: &str = "verdyx_oauth_state";
const STATE_COOKIE_PATH: &str = "/api/v1/auth/oauth";
const STATE_TTL_SECS: u32 = 600;
const PROVIDERS: [&str; 2] = ["google", "github"];

/// Shown on /login after a failed attempt. Fixed codes, so a crafted link
/// can't put arbitrary text on the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Cancelled,
    Expired,
    TwoFactor,
    Suspended,
    NoEmail,
    Unavailable,
    Failed,
}

impl Failure {
    fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::TwoFactor => "two_factor",
            Self::Suspended => "suspended",
            Self::NoEmail => "no_email",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
        }
    }

    /// Classify a user-service error response.
    fn from_user_service(status: u16, message: &str) -> Self {
        match status {
            401 if message.contains("two-factor") => Self::TwoFactor,
            401 => Self::Expired,
            403 => Self::Suspended,
            400 if message.contains("verified email") => Self::NoEmail,
            404 => Self::Unavailable,
            _ => Self::Failed,
        }
    }
}

fn back_to_login(failure: Failure, extra: HeaderMap) -> Response {
    tracing::info!(reason = failure.code(), "OAuth sign-in did not complete");
    let mut headers = extra;
    append_cookie(&mut headers, &clear_state_cookie());
    (
        headers,
        Redirect::to(&format!("/login?oauth_error={}", failure.code())),
    )
        .into_response()
}

fn append_cookie(headers: &mut HeaderMap, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.append(header::SET_COOKIE, v);
    }
}

fn state_cookie(provider: &str, state: &str) -> String {
    format!(
        "{STATE_COOKIE}={provider}.{state}; Path={STATE_COOKIE_PATH}; Max-Age={STATE_TTL_SECS}; HttpOnly; Secure; SameSite=Lax"
    )
}

fn clear_state_cookie() -> String {
    format!("{STATE_COOKIE}=; Path={STATE_COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

/// 256 bits from the OS RNG (UUID v4 uses getrandom).
fn new_state() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Whether the callback's `state` is the one this browser was given.
fn state_matches(headers: &HeaderMap, provider: &str, state: Option<&str>) -> bool {
    let (Some(stored), Some(state)) = (cookie(headers, STATE_COOKIE), state) else {
        return false;
    };
    let expected = format!("{provider}.{state}");
    // Constant-time compare: the cookie is the secret here.
    stored.len() == expected.len()
        && stored
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// `GET /auth/oauth/providers`: which sign-in buttons to show.
pub async fn providers(State(state): State<AppState>) -> Json<ApiResponse<serde_json::Value>> {
    let enabled = match state
        .proxy
        .get("user-service", "/api/v1/auth/oauth/providers", None)
        .await
    {
        Ok(resp) if resp.status().is_success() => resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("providers").cloned())
            .unwrap_or_else(|| serde_json::json!([])),
        _ => serde_json::json!([]),
    };
    Json(ApiResponse::success(
        serde_json::json!({ "providers": enabled }),
    ))
}

/// `GET /auth/oauth/{provider}`: send the browser to the provider.
pub async fn start(State(state): State<AppState>, Path(provider): Path<String>) -> Response {
    if !PROVIDERS.contains(&provider.as_str()) {
        return back_to_login(Failure::Unavailable, HeaderMap::new());
    }
    let oauth_state = new_state();
    let url = state
        .proxy
        .post(
            "user-service",
            &format!("/api/v1/auth/oauth/{provider}/authorize"),
            serde_json::json!({ "state": oauth_state }),
            None,
        )
        .await;
    let url = match url {
        Ok(resp) if resp.status().is_success() => resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(str::to_string)),
        _ => None,
    };
    let Some(url) = url.filter(|u| u.starts_with("https://")) else {
        return back_to_login(Failure::Unavailable, HeaderMap::new());
    };
    let mut headers = HeaderMap::new();
    append_cookie(&mut headers, &state_cookie(&provider, &oauth_state));
    (headers, Redirect::to(&url)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/oauth/{provider}/callback`: finish signing in.
pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    if !PROVIDERS.contains(&provider.as_str()) {
        return back_to_login(Failure::Unavailable, HeaderMap::new());
    }
    if params.error.is_some() {
        return back_to_login(Failure::Cancelled, HeaderMap::new());
    }
    if !state_matches(&headers, &provider, params.state.as_deref()) {
        return back_to_login(Failure::Expired, HeaderMap::new());
    }
    let Some(code) = params.code.filter(|c| !c.is_empty() && c.len() <= 2048) else {
        return back_to_login(Failure::Failed, HeaderMap::new());
    };

    let resp = match state
        .proxy
        .post(
            "user-service",
            &format!("/api/v1/auth/oauth/{provider}/callback"),
            serde_json::json!({ "code": code }),
            None,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("user-service unreachable for OAuth callback: {}", e);
            return back_to_login(Failure::Failed, HeaderMap::new());
        }
    };

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        let message = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_default();
        return back_to_login(
            Failure::from_user_service(status, &message),
            HeaderMap::new(),
        );
    }
    let auth: UsAuthResponse = match resp.json().await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Invalid user-service OAuth response: {}", e);
            return back_to_login(Failure::Failed, HeaderMap::new());
        }
    };

    sync_user_to_gateway_db(&state, &auth.user).await;
    let expires_in = if auth.expires_in > 0 {
        auth.expires_in
    } else {
        3600
    };
    let mut out = session_cookies(&auth.access_token, &auth.refresh_token, expires_in);
    append_cookie(&mut out, &clear_state_cookie());
    (out, Redirect::to("/dashboard")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_cookie(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {STATE_COOKIE}={value}")).unwrap(),
        );
        h
    }

    #[test]
    fn state_must_match_the_cookie_and_provider() {
        let s = new_state();
        assert_eq!(s.len(), 64);
        let h = with_cookie(&format!("google.{s}"));
        assert!(state_matches(&h, "google", Some(&s)));
        assert!(!state_matches(&h, "github", Some(&s)));
        assert!(!state_matches(&h, "google", Some("forged")));
        assert!(!state_matches(&h, "google", None));
        assert!(!state_matches(&HeaderMap::new(), "google", Some(&s)));
    }

    #[test]
    fn user_service_errors_become_fixed_codes() {
        let two_fa =
            "This account uses two-factor authentication. Sign in with your password and code.";
        assert_eq!(Failure::from_user_service(401, two_fa), Failure::TwoFactor);
        assert_eq!(Failure::from_user_service(401, "expired"), Failure::Expired);
        assert_eq!(Failure::from_user_service(403, ""), Failure::Suspended);
        assert_eq!(
            Failure::from_user_service(400, "Your account there has no verified email address."),
            Failure::NoEmail
        );
        assert_eq!(Failure::from_user_service(404, ""), Failure::Unavailable);
        assert_eq!(Failure::from_user_service(500, ""), Failure::Failed);
    }

    #[test]
    fn failures_redirect_to_login_and_clear_the_state() {
        let r = back_to_login(Failure::Cancelled, HeaderMap::new());
        assert_eq!(
            r.headers().get(header::LOCATION).unwrap(),
            "/login?oauth_error=cancelled"
        );
        let set = r
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set.starts_with(&format!("{STATE_COOKIE}=;")) && set.contains("Max-Age=0"));
    }
}
