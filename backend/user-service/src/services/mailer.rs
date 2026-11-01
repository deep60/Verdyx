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
    fn smtp_requires_host_and_username() {
        assert!(smtp_configured(&config("smtp.example.com", "user")));
        assert!(!smtp_configured(&config("", "user")));
        assert!(!smtp_configured(&config("smtp.example.com", " ")));
    }
}
