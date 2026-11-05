use anyhow::{anyhow, Context, Result};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};

use crate::config::EmailConfig;

fn is_development() -> bool {
    std::env::var("ENVIRONMENT").as_deref() == Ok("development")
}

fn smtp_configured(config: &EmailConfig) -> bool {
    !config.smtp_host.trim().is_empty() && !config.smtp_username.trim().is_empty()
}

/// Everything that stops a reset email from being sent, in plain words.
///
/// Empty means email is set up. Logged at startup so a missing setting shows
/// up when the service boots, not only when someone is locked out. The reset
/// endpoint can't report it to the caller: it answers the same way whether or
/// not an account exists.
pub fn setup_problems(config: &EmailConfig, frontend_url: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    if config.smtp_host.trim().is_empty() {
        problems.push("SMTP_HOST is empty".to_string());
    }
    if config.smtp_username.trim().is_empty() {
        problems.push("SMTP_USERNAME (or SMTP_USER) is empty".to_string());
    }
    if config.smtp_password.is_empty() {
        problems.push("SMTP_PASSWORD is empty".to_string());
    }
    if config
        .from_address
        .parse::<lettre::message::Mailbox>()
        .is_err()
    {
        problems.push(format!(
            "EMAIL_FROM {:?} is not a valid address",
            config.from_address
        ));
    }
    if frontend_url.is_none_or(|u| u.trim().is_empty()) {
        problems.push("FRONTEND_URL is empty, so no reset link can be built".to_string());
    }
    problems
}

fn reset_link(frontend_url: &str, token: &str) -> String {
    format!(
        "{}/reset-password?token={token}",
        frontend_url.trim_end_matches('/')
    )
}

/// Email a password reset link. Without SMTP the link is logged in development
/// only, because anyone who can read a production log could use it.
pub async fn send_password_reset(config: &EmailConfig, to: &str, token: &str) -> Result<()> {
    let frontend_url = std::env::var("FRONTEND_URL").unwrap_or_default();
    if frontend_url.trim().is_empty() && !is_development() {
        return Err(anyhow!(
            "FRONTEND_URL is not set; cannot build a reset link"
        ));
    }
    let base = if frontend_url.trim().is_empty() {
        "http://localhost:5001"
    } else {
        frontend_url.as_str()
    };
    let link = reset_link(base, token);

    if !smtp_configured(config) {
        if is_development() {
            tracing::info!("SMTP not configured. Password reset link: {}", link);
            return Ok(());
        }
        return Err(anyhow!("SMTP is not configured; reset email was not sent"));
    }

    let message = Message::builder()
        .from(config.from_address.parse().context("invalid EMAIL_FROM")?)
        .to(to.parse().context("invalid recipient address")?)
        .subject("Reset your Verdyx password")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "We received a request to reset your Verdyx password.\n\n\
             Open this link within 1 hour to choose a new password:\n{link}\n\n\
             If you didn't ask for this, you can ignore this email."
        ))
        .context("could not build reset email")?;

    let builder = if config.smtp_port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
    }
    .context("invalid SMTP host")?;

    builder
        .port(config.smtp_port)
        .credentials(Credentials::new(
            config.smtp_username.clone(),
            config.smtp_password.clone(),
        ))
        .build()
        .send(message)
        .await
        .context("SMTP send failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(host: &str, user: &str) -> EmailConfig {
        EmailConfig {
            smtp_host: host.to_string(),
            smtp_port: 587,
            smtp_username: user.to_string(),
            smtp_password: "secret".to_string(),
            from_address: "noreply@example.com".to_string(),
        }
    }

    #[test]
    fn reset_link_has_no_double_slash() {
        assert_eq!(
            reset_link("https://verdyx.pages.dev/", "abc"),
            "https://verdyx.pages.dev/reset-password?token=abc"
        );
    }

    #[test]
    fn setup_problems_names_each_missing_setting() {
        let ok = config("smtp.example.com", "user");
        assert!(setup_problems(&ok, Some("https://verdyx.dev")).is_empty());

        let mut bad = config("", "");
        bad.smtp_password = String::new();
        bad.from_address = "not an address".to_string();
        let problems = setup_problems(&bad, None).join("; ");
        for needle in [
            "SMTP_HOST",
            "SMTP_USERNAME",
            "SMTP_PASSWORD",
            "EMAIL_FROM",
            "FRONTEND_URL",
        ] {
            assert!(
                problems.contains(needle),
                "{needle} missing from: {problems}"
            );
        }
        assert!(!setup_problems(&ok, Some(" ")).is_empty());
    }

    #[test]
    fn smtp_requires_host_and_username() {
        assert!(smtp_configured(&config("smtp.example.com", "user")));
        assert!(!smtp_configured(&config("", "user")));
        assert!(!smtp_configured(&config("smtp.example.com", " ")));
    }
}
