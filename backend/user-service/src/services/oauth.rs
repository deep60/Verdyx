//! Sign-in with Google and GitHub (OAuth 2.0 authorization-code flow).
//!
//! The gateway sends the browser to [`OAuthConfig::authorize_url`], checks the
//! `state` it gets back, and hands the `code` to [`OAuthConfig::fetch_identity`],
//! which swaps it for the provider's verified email and account id. A provider
//! is enabled only when both its client id and secret are set.

use serde::Deserialize;
use std::time::Duration;

use crate::models::{UserError, UserResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Github,
}

impl Provider {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "google" => Some(Self::Google),
            "github" => Some(Self::Github),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Github => "github",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthConfig {
    pub google: Option<OAuthClient>,
    pub github: Option<OAuthClient>,
    /// The site's public origin, e.g. https://verdyx.dev. Callbacks come back
    /// through the site's /api proxy so the session cookies land on it.
    pub public_url: String,
}

/// What a provider vouches for about the person signing in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub provider_user_id: String,
    /// Verified by the provider, lowercased.
    pub email: String,
    /// A username hint (GitHub login, or Google's name).
    pub name_hint: Option<String>,
}

fn env_client(prefix: &str) -> Option<OAuthClient> {
    let get = |key: &str| {
        std::env::var(format!("{prefix}_{key}"))
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    Some(OAuthClient {
        client_id: get("CLIENT_ID")?,
        client_secret: get("CLIENT_SECRET")?,
    })
}

impl OAuthConfig {
    pub fn from_env() -> Self {
        let public_url = std::env::var("OAUTH_PUBLIC_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| std::env::var("FRONTEND_URL").ok())
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        Self {
            google: env_client("GOOGLE"),
            github: env_client("GITHUB"),
            public_url,
        }
    }

    fn client(&self, provider: Provider) -> UserResult<&OAuthClient> {
        let client = match provider {
            Provider::Google => self.google.as_ref(),
            Provider::Github => self.github.as_ref(),
        };
        match client {
            Some(c) if !self.public_url.is_empty() => Ok(c),
            _ => Err(UserError::NotFound),
        }
    }

    /// Providers that are fully configured, in display order.
    pub fn enabled(&self) -> Vec<&'static str> {
        [Provider::Google, Provider::Github]
            .into_iter()
            .filter(|p| self.client(*p).is_ok())
            .map(Provider::as_str)
            .collect()
    }

    pub fn redirect_uri(&self, provider: Provider) -> String {
        format!(
            "{}/api/v1/auth/oauth/{}/callback",
            self.public_url,
            provider.as_str()
        )
    }

    pub fn authorize_url(&self, provider: Provider, state: &str) -> UserResult<String> {
        let client = self.client(provider)?;
        let redirect_uri = self.redirect_uri(provider);
        let (base, scope) = match provider {
            Provider::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth",
                "openid email profile",
            ),
            Provider::Github => (
                "https://github.com/login/oauth/authorize",
                "read:user user:email",
            ),
        };
        let mut params = vec![
            ("client_id", client.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", scope),
            ("state", state),
        ];
        if provider == Provider::Google {
            params.push(("response_type", "code"));
            params.push(("prompt", "select_account"));
        } else {
            params.push(("allow_signup", "true"));
        }
        reqwest::Url::parse_with_params(base, &params)
            .map(String::from)
            .map_err(|e| UserError::ValidationError(e.to_string()))
    }

    /// Swap an authorization code for the provider's verified identity.
    pub async fn fetch_identity(
        &self,
        provider: Provider,
        code: &str,
    ) -> UserResult<ProviderIdentity> {
        let client = self.client(provider)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Verdyx")
            .build()
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;
        match provider {
            Provider::Google => self.google_identity(&http, client, code).await,
            Provider::Github => self.github_identity(&http, client, code).await,
        }
    }

    async fn exchange_code(
        &self,
        http: &reqwest::Client,
        provider: Provider,
        client: &OAuthClient,
        token_url: &str,
        code: &str,
    ) -> UserResult<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: Option<String>,
            error: Option<String>,
        }
        let redirect_uri = self.redirect_uri(provider);
        let resp: TokenResponse = http
            .post(token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", client.client_id.as_str()),
                ("client_secret", client.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(provider_unreachable)?
            .json()
            .await
            .map_err(provider_unreachable)?;
        resp.access_token.ok_or_else(|| {
            tracing::warn!(
                provider = provider.as_str(),
                error = resp.error.as_deref().unwrap_or("none"),
                "OAuth code exchange refused"
            );
            UserError::AuthenticationError("The sign-in link expired. Try again.".to_string())
        })
    }

    async fn google_identity(
        &self,
        http: &reqwest::Client,
        client: &OAuthClient,
        code: &str,
    ) -> UserResult<ProviderIdentity> {
        #[derive(Deserialize)]
        struct UserInfo {
            sub: String,
            email: Option<String>,
            #[serde(default)]
            email_verified: bool,
            name: Option<String>,
        }
        let token = self
            .exchange_code(
                http,
                Provider::Google,
                client,
                "https://oauth2.googleapis.com/token",
                code,
            )
            .await?;
        let info: UserInfo = http
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(token)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(provider_unreachable)?
            .json()
            .await
            .map_err(provider_unreachable)?;
        let email = info
            .email
            .filter(|_| info.email_verified)
            .ok_or_else(no_verified_email)?;
        Ok(ProviderIdentity {
            provider_user_id: info.sub,
            email: email.trim().to_ascii_lowercase(),
            name_hint: info.name,
        })
    }

    async fn github_identity(
        &self,
        http: &reqwest::Client,
        client: &OAuthClient,
        code: &str,
    ) -> UserResult<ProviderIdentity> {
        #[derive(Deserialize)]
        struct GithubUser {
            id: u64,
            login: String,
        }
        let token = self
            .exchange_code(
                http,
                Provider::Github,
                client,
                "https://github.com/login/oauth/access_token",
                code,
            )
            .await?;
        let get = |url: &'static str| {
            http.get(url)
                .bearer_auth(&token)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        };
        let user: GithubUser = get("https://api.github.com/user")
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(provider_unreachable)?
            .json()
            .await
            .map_err(provider_unreachable)?;
        let emails: Vec<GithubEmail> = get("https://api.github.com/user/emails")
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(provider_unreachable)?
            .json()
            .await
            .map_err(provider_unreachable)?;
        Ok(ProviderIdentity {
            provider_user_id: user.id.to_string(),
            email: pick_github_email(&emails).ok_or_else(no_verified_email)?,
            name_hint: Some(user.login),
        })
    }
}

#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

/// The primary address if verified, else any verified one. GitHub's private
/// relay addresses (`…@users.noreply.github.com`) are skipped: mail to them
/// goes nowhere, so a reset link could never arrive.
fn pick_github_email(emails: &[GithubEmail]) -> Option<String> {
    let usable = |e: &&GithubEmail| e.verified && !e.email.ends_with("@users.noreply.github.com");
    emails
        .iter()
        .filter(usable)
        .find(|e| e.primary)
        .or_else(|| emails.iter().find(usable))
        .map(|e| e.email.trim().to_ascii_lowercase())
}

fn provider_unreachable(e: reqwest::Error) -> UserError {
    tracing::warn!("OAuth provider request failed: {}", e);
    UserError::AuthenticationError("Couldn't reach the sign-in provider. Try again.".to_string())
}

fn no_verified_email() -> UserError {
    UserError::ValidationError(
        "Your account there has no verified email address. Verify one and try again.".to_string(),
    )
}

/// A username from the provider's hint or the email's local part, reduced to
/// the characters usernames allow (letters, digits, underscore) and 3–24 long.
pub fn username_base(hint: Option<&str>, email: &str) -> String {
    let clean = |s: &str| -> String {
        let mut out = String::new();
        for c in s.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
            } else if !out.ends_with('_') && !out.is_empty() {
                out.push('_');
            }
        }
        out.trim_end_matches('_').chars().take(24).collect()
    };
    let from_hint = hint.map(clean).unwrap_or_default();
    let base = if from_hint.len() >= 3 {
        from_hint
    } else {
        clean(email.split('@').next().unwrap_or_default())
    };
    if base.len() >= 3 {
        base
    } else {
        format!("user_{base}").trim_end_matches('_').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuthConfig {
        let client = || {
            Some(OAuthClient {
                client_id: "id".into(),
                client_secret: "secret".into(),
            })
        };
        OAuthConfig {
            google: client(),
            github: client(),
            public_url: "https://verdyx.dev".into(),
        }
    }

    #[test]
    fn providers_need_an_id_a_secret_and_a_public_url() {
        assert_eq!(config().enabled(), vec!["google", "github"]);
        let mut c = config();
        c.github = None;
        assert_eq!(c.enabled(), vec!["google"]);
        c.public_url.clear();
        assert!(c.enabled().is_empty());
        assert!(c.authorize_url(Provider::Google, "s").is_err());
    }

    #[test]
    fn authorize_url_carries_state_and_the_site_callback() {
        let url = reqwest::Url::parse(&config().authorize_url(Provider::Github, "abc123").unwrap())
            .unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(url.host_str(), Some("github.com"));
        assert_eq!(q["state"], "abc123");
        assert_eq!(
            q["redirect_uri"],
            "https://verdyx.dev/api/v1/auth/oauth/github/callback"
        );
        let google = config().authorize_url(Provider::Google, "x").unwrap();
        assert!(google.contains("response_type=code"));
    }

    #[test]
    fn github_email_must_be_verified_and_real() {
        let e = |email: &str, primary, verified| GithubEmail {
            email: email.into(),
            primary,
            verified,
        };
        assert_eq!(
            pick_github_email(&[e("Me@Example.com", true, true)]).as_deref(),
            Some("me@example.com")
        );
        assert_eq!(
            pick_github_email(&[
                e("1+me@users.noreply.github.com", true, true),
                e("other@example.com", false, true),
            ])
            .as_deref(),
            Some("other@example.com")
        );
        assert_eq!(pick_github_email(&[e("me@example.com", true, false)]), None);
    }

    #[test]
    fn usernames_are_cleaned_up() {
        assert_eq!(username_base(Some("Octo-Cat"), "x@y.z"), "octo_cat");
        assert_eq!(username_base(Some("Jane Q. Doe"), "x@y.z"), "jane_q_doe");
        assert_eq!(username_base(Some("李"), "j.smith@ex.com"), "j_smith");
        assert_eq!(username_base(None, "ab@ex.com"), "user_ab");
        assert_eq!(username_base(None, "@ex.com"), "user");
        assert!(username_base(Some(&"a".repeat(60)), "x@y.z").len() <= 24);
    }
}
