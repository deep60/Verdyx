//! OpenID Connect, for signing in through a team's own identity provider
//! (Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak, ...).
//!
//! The authorization-code flow with PKCE and a nonce:
//!
//! 1. [`discover`] reads the provider's `/.well-known/openid-configuration`.
//! 2. The browser goes to [`authorize_url`].
//! 3. The provider sends it back with a `code`, which [`exchange`] swaps for
//!    an ID token.
//! 4. [`verify_id_token`] checks the token's signature against the
//!    provider's published keys, its issuer, audience, expiry and nonce.
//!
//! Every request goes through the webhook client, which only connects to
//! public addresses and doesn't follow redirects, since the issuer URL is
//! typed in by a team admin.

use base64::Engine;
use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Largest discovery document, key set or token response read.
const MAX_BODY: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// What the ID token says about the person.
#[derive(Debug, Clone, Deserialize)]
pub struct IdClaims {
    pub sub: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// Okta and Google send it. Entra doesn't, so it's only refused when it's
    /// present and false.
    #[serde(default, deserialize_with = "loose_bool")]
    pub email_verified: Option<bool>,
    /// Entra's sign-in name, usually the work address.
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub upn: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Some providers send `"true"` as a string.
fn loose_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        Some(serde_json::Value::Bool(b)) => Some(b),
        Some(serde_json::Value::String(s)) => Some(s.eq_ignore_ascii_case("true")),
        _ => None,
    })
}

/// The issuer as typed: https, no query or fragment, no trailing slash.
pub fn clean_issuer(raw: &str) -> Result<String, &'static str> {
    let raw = raw.trim();
    if raw.len() > 500 {
        return Err("the issuer URL is too long");
    }
    let url = crate::services::webhook_delivery::check_url(raw)?;
    if url.scheme() != "https" {
        return Err("the issuer URL must start with https://");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("the issuer URL can't have a query or a #fragment");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

fn https(raw: &str) -> Result<url::Url, String> {
    let url = crate::services::webhook_delivery::check_url(raw).map_err(str::to_string)?;
    if url.scheme() != "https" {
        return Err(format!("{raw} isn't https"));
    }
    Ok(url)
}

async fn read_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    what: &str,
) -> Result<T, String> {
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("couldn't read the {what}: {e}"))?;
    if bytes.len() > MAX_BODY {
        return Err(format!("the {what} is too large"));
    }
    if !status.is_success() {
        let detail = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| {
                let e = v.get("error")?.as_str()?.to_string();
                Some(match v.get("error_description").and_then(|d| d.as_str()) {
                    Some(d) => format!("{e}: {}", d.chars().take(200).collect::<String>()),
                    None => e,
                })
            })
            .unwrap_or_default();
        return Err(
            format!("the {what} answered HTTP {} {detail}", status.as_u16())
                .trim_end()
                .to_string(),
        );
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("the {what} isn't valid: {e}"))
}

/// Read the provider's configuration. Its `issuer` must be the one typed in,
/// and all its endpoints https.
pub async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Discovery, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    https(&url)?;
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("couldn't reach {url}: {e}"))?;
    let d: Discovery = read_json(resp, "provider's configuration").await?;
    if !same_issuer(&d.issuer, issuer) {
        return Err(format!(
            "the provider calls itself {}, not {issuer}",
            d.issuer
        ));
    }
    https(&d.authorization_endpoint)?;
    https(&d.token_endpoint)?;
    https(&d.jwks_uri)?;
    Ok(d)
}

/// A random value for `state`, `nonce` or the PKCE verifier: 256 bits as 64
/// hex characters (valid PKCE characters).
pub fn random() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// PKCE S256: base64url(SHA-256(verifier)), unpadded.
pub fn code_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn authorize_url(
    d: &Discovery,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
    login_hint: Option<&str>,
) -> Result<String, String> {
    let mut url = https(&d.authorization_endpoint)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &code_challenge(verifier))
            .append_pair("code_challenge_method", "S256");
        if let Some(hint) = login_hint {
            q.append_pair("login_hint", hint);
        }
    }
    Ok(url.into())
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// Swap the code for an ID token. The client authenticates with
/// `client_secret_post`, which Okta, Entra, Google, Auth0 and Keycloak all
/// accept.
pub async fn exchange(
    http: &reqwest::Client,
    d: &Discovery,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<String, String> {
    let resp = http
        .post(https(&d.token_endpoint)?)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(|e| format!("couldn't reach the token endpoint: {e}"))?;
    let t: TokenResponse = read_json(resp, "token endpoint").await?;
    t.id_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "the provider sent no ID token; is the openid scope allowed?".to_string())
}

pub async fn keys(http: &reqwest::Client, d: &Discovery) -> Result<JwkSet, String> {
    let resp = http
        .get(https(&d.jwks_uri)?)
        .send()
        .await
        .map_err(|e| format!("couldn't reach the provider's keys: {e}"))?;
    read_json(resp, "provider's key set").await
}

/// Algorithms accepted for ID tokens. Never `none` or a shared-secret HMAC.
const ALGORITHMS: [Algorithm; 7] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Check the ID token and return what it says.
pub fn verify_id_token(
    token: &str,
    keys: &JwkSet,
    issuer: &str,
    client_id: &str,
    nonce: &str,
) -> Result<IdClaims, String> {
    let header =
        jsonwebtoken::decode_header(token).map_err(|_| "the ID token isn't a JWT".to_string())?;
    if !ALGORITHMS.contains(&header.alg) {
        return Err(format!(
            "the ID token is signed with {:?}, which isn't accepted",
            header.alg
        ));
    }
    let jwk = match header.kid.as_deref() {
        Some(kid) => keys.find(kid),
        // No key id: only fine when there is exactly one key.
        None if keys.keys.len() == 1 => keys.keys.first(),
        None => None,
    }
    .ok_or_else(|| "the ID token's signing key isn't in the provider's key set".to_string())?;
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|_| "the provider's signing key can't be read".to_string())?;

    let mut validation = Validation::new(header.alg);
    // Entra's v2 issuer has no trailing slash and Okta's org issuer neither;
    // accept the issuer with and without one.
    let bare = issuer.trim_end_matches('/').to_string();
    validation.set_issuer(&[bare.clone(), format!("{bare}/")]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 60;
    let claims = jsonwebtoken::decode::<IdClaims>(token, &key, &validation)
        .map_err(|e| format!("the ID token was refused: {e}"))?
        .claims;

    let sent = nonce.as_bytes();
    let got = claims.nonce.as_deref().unwrap_or("").as_bytes();
    let same =
        sent.len() == got.len() && sent.iter().zip(got).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !same {
        return Err("the ID token's nonce doesn't match this sign-in".to_string());
    }
    if claims.sub.is_empty() || claims.sub.len() > 200 {
        return Err("the ID token has no usable subject".to_string());
    }
    Ok(claims)
}

/// The work address the token vouches for: `email`, else Entra's
/// `preferred_username` or `upn` when it is an address. Lowercased.
pub fn work_email(c: &IdClaims) -> Result<String, &'static str> {
    if c.email_verified == Some(false) {
        return Err("unverified_email");
    }
    [
        c.email.as_deref(),
        c.preferred_username.as_deref(),
        c.upn.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find_map(crate::handlers::organization::clean_email)
    .ok_or("no_email")
}

pub fn domain_of(email: &str) -> &str {
    email.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    /// A fresh P-256 key for each test run: (PKCS#8 DER, x, y).
    fn test_key() -> &'static (Vec<u8>, String, String) {
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        static KEY: std::sync::OnceLock<(Vec<u8>, String, String)> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap()
                .as_ref()
                .to_vec();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).unwrap();
            let public = pair.public_key().as_ref(); // 0x04 || x || y
            let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
            (pkcs8.clone(), b64(&public[1..33]), b64(&public[33..65]))
        })
    }

    fn key_set(kid: &str) -> JwkSet {
        let (_, x, y) = test_key();
        serde_json::from_value(serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "use": "sig", "alg": "ES256" }]
        }))
        .unwrap()
    }

    fn token(kid: Option<&str>, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = kid.map(str::to_string);
        encode(&header, &claims, &EncodingKey::from_ec_der(&test_key().0)).unwrap()
    }

    fn claims(nonce: &str) -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "iss": "https://acme.okta.com", "aud": "client-1", "sub": "00u1",
            "exp": now + 300, "iat": now, "nonce": nonce,
            "email": "Ada@Acme.com", "email_verified": true, "name": "Ada"
        })
    }

    #[test]
    fn a_good_id_token_is_accepted() {
        let t = token(Some("k1"), claims("n1"));
        let c = verify_id_token(
            &t,
            &key_set("k1"),
            "https://acme.okta.com",
            "client-1",
            "n1",
        )
        .unwrap();
        assert_eq!(c.sub, "00u1");
        assert_eq!(work_email(&c).unwrap(), "ada@acme.com");
        // The issuer with a trailing slash is the same issuer.
        assert!(verify_id_token(
            &t,
            &key_set("k1"),
            "https://acme.okta.com/",
            "client-1",
            "n1"
        )
        .is_ok());
        // No kid is fine when there's only one key.
        let t = token(None, claims("n1"));
        assert!(verify_id_token(
            &t,
            &key_set("k1"),
            "https://acme.okta.com",
            "client-1",
            "n1"
        )
        .is_ok());
    }

    #[test]
    fn a_wrong_id_token_is_refused() {
        let keys = key_set("k1");
        let ok = |t: &str, iss: &str, aud: &str, nonce: &str| {
            verify_id_token(t, &keys, iss, aud, nonce).is_ok()
        };
        let t = token(Some("k1"), claims("n1"));
        assert!(!ok(&t, "https://evil.okta.com", "client-1", "n1"), "issuer");
        assert!(
            !ok(&t, "https://acme.okta.com", "client-2", "n1"),
            "audience"
        );
        assert!(!ok(&t, "https://acme.okta.com", "client-1", "n2"), "nonce");
        assert!(
            !ok(
                &token(Some("k9"), claims("n1")),
                "https://acme.okta.com",
                "client-1",
                "n1"
            ),
            "unknown key"
        );

        let mut expired = claims("n1");
        expired["exp"] = serde_json::json!(chrono::Utc::now().timestamp() - 3600);
        assert!(
            !ok(
                &token(Some("k1"), expired),
                "https://acme.okta.com",
                "client-1",
                "n1"
            ),
            "expired"
        );

        // Signed with HMAC using the public key as the secret: the classic
        // algorithm-confusion attack.
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("k1".into());
        let forged = encode(
            &h,
            &claims("n1"),
            &EncodingKey::from_secret(test_key().1.as_bytes()),
        )
        .unwrap();
        assert!(
            !ok(&forged, "https://acme.okta.com", "client-1", "n1"),
            "HS256"
        );

        // Tampered payload.
        let parts: Vec<&str> = t.split('.').collect();
        let mut body = claims("n1");
        body["email"] = serde_json::json!("ceo@acme.com");
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&body).unwrap());
        let tampered = format!("{}.{}.{}", parts[0], body, parts[2]);
        assert!(
            !ok(&tampered, "https://acme.okta.com", "client-1", "n1"),
            "tampered"
        );
    }

    #[test]
    fn the_work_address_comes_from_email_or_entra_names() {
        let c = |v: serde_json::Value| serde_json::from_value::<IdClaims>(v).unwrap();
        assert_eq!(
            work_email(&c(
                serde_json::json!({"sub":"1","preferred_username":"Bob@Contoso.com"})
            )),
            Ok("bob@contoso.com".to_string())
        );
        assert_eq!(
            work_email(&c(
                serde_json::json!({"sub":"1","email":"a@x.com","email_verified":"false"})
            )),
            Err("unverified_email")
        );
        assert_eq!(
            work_email(&c(
                serde_json::json!({"sub":"1","preferred_username":"not-an-address"})
            )),
            Err("no_email")
        );
        assert_eq!(domain_of("a@b.example.com"), "b.example.com");
    }

    #[test]
    fn pkce_and_issuers() {
        // RFC 7636 appendix B.
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(random().len(), 64);
        assert_eq!(
            clean_issuer(" https://acme.okta.com/ ").unwrap(),
            "https://acme.okta.com"
        );
        assert_eq!(
            clean_issuer("https://login.microsoftonline.com/tid/v2.0").unwrap(),
            "https://login.microsoftonline.com/tid/v2.0"
        );
        assert!(clean_issuer("http://acme.okta.com").is_err());
        assert!(clean_issuer("https://127.0.0.1").is_err());
        assert!(clean_issuer("https://idp.internal").is_err());
        assert!(clean_issuer("https://acme.okta.com/?x=1").is_err());
    }

    #[test]
    fn the_authorize_url_carries_pkce_and_nonce() {
        let d = Discovery {
            issuer: "https://acme.okta.com".into(),
            authorization_endpoint: "https://acme.okta.com/oauth2/v1/authorize".into(),
            token_endpoint: "https://acme.okta.com/oauth2/v1/token".into(),
            jwks_uri: "https://acme.okta.com/oauth2/v1/keys".into(),
        };
        let u = authorize_url(
            &d,
            "c1",
            "https://verdyx.dev/cb",
            "s",
            "n",
            "v",
            Some("a@acme.com"),
        )
        .unwrap();
        let u = url::Url::parse(&u).unwrap();
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["nonce"], "n");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], code_challenge("v"));
        assert_eq!(q["login_hint"], "a@acme.com");
        assert!(q["scope"].contains("openid"));
    }
}
