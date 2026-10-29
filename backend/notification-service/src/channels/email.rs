use async_trait::async_trait;
use lettre::{
    message::{header, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info};

use crate::models::{NotificationChannel, NotificationError, NotificationResult};
use shared::messaging::event_types::{NotificationPayload, VerdyxEvent};

/// Email notification channel implementation
pub struct EmailChannel {
    smtp_transport: AsyncSmtpTransport<Tokio1Executor>,
    from_address: String,
    from_name: String,
    template_engine: handlebars::Handlebars<'static>,
}

impl EmailChannel {
    /// Create a new email channel
    pub fn new(config: EmailConfig) -> Result<Self, NotificationError> {
        // Build SMTP transport
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        let host = if config.smtp_host.trim().is_empty() {
            "localhost"
        } else {
            config.smtp_host.trim()
        };
        let smtp_transport = match AsyncSmtpTransport::<Tokio1Executor>::relay(host) {
            Ok(builder) => builder.port(config.smtp_port).credentials(creds).build(),
            Err(_) => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
                .port(config.smtp_port)
                .credentials(creds)
                .build(),
        };

        // Initialize template engine
        let mut template_engine = handlebars::Handlebars::new();

        // Register built-in templates
        Self::register_templates(&mut template_engine)?;

        Ok(Self {
            smtp_transport,
            from_address: config.from_address,
            from_name: config.from_name,
            template_engine,
        })
    }

    /// Register email templates
    fn register_templates(engine: &mut handlebars::Handlebars) -> Result<(), NotificationError> {
        // Welcome email template
        engine
            .register_template_string(
                "user_registered",
                include_str!("../templates/email/user_registered.hbs"),
            )
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to register template: {e}"))
            })?;

        // Bounty created template
        engine
            .register_template_string(
                "bounty_created",
                include_str!("../templates/email/bounty_created.hbs"),
            )
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to register template: {e}"))
            })?;

        // Submission received template
        engine
            .register_template_string(
                "submission_received",
                include_str!("../templates/email/submission_received.hbs"),
            )
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to register template: {e}"))
            })?;

        // Payment processed template
        engine
            .register_template_string(
                "payment_processed",
                include_str!("../templates/email/payment_processed.hbs"),
            )
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to register template: {e}"))
            })?;

        // Reputation updated template
        engine
            .register_template_string(
                "reputation_updated",
                include_str!("../templates/email/reputation_updated.hbs"),
            )
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to register template: {e}"))
            })?;

        // Generic notification template
        engine
            .register_template_string(
                "generic_notification",
                include_str!("../templates/email/generic_notification.hbs"),
            )
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to register template: {e}"))
            })?;

        Ok(())
    }

    /// Get template name for an event
    fn get_template_name(event: &VerdyxEvent) -> &'static str {
        match event {
            VerdyxEvent::UserRegistered(_) => "user_registered",
            VerdyxEvent::BountyCreated(_) => "bounty_created",
            VerdyxEvent::SubmissionReceived(_) => "submission_received",
            VerdyxEvent::PaymentProcessed(_) => "payment_processed",
            VerdyxEvent::ReputationUpdated(_) => "reputation_updated",
            _ => "generic_notification",
        }
    }

    /// Build email template data from event
    fn build_template_data(event: &VerdyxEvent) -> HashMap<String, serde_json::Value> {
        let mut data = HashMap::new();

        data.insert("title".to_string(), serde_json::json!(event.get_title()));
        data.insert(
            "description".to_string(),
            serde_json::json!(event.get_description()),
        );

        match event {
            VerdyxEvent::BountyCreated(e) => {
                data.insert(
                    "bounty_id".to_string(),
                    serde_json::json!(e.bounty_id.to_string()),
                );
                data.insert("bounty_title".to_string(), serde_json::json!(e.title));
                data.insert(
                    "reward_amount".to_string(),
                    serde_json::json!(e.reward_amount.to_string()),
                );
                data.insert(
                    "stake_requirement".to_string(),
                    serde_json::json!(e.stake_requirement.to_string()),
                );
                data.insert(
                    "expires_at".to_string(),
                    serde_json::json!(e.expires_at.to_rfc3339()),
                );
                data.insert("tags".to_string(), serde_json::json!(e.tags));
            }
            VerdyxEvent::SubmissionReceived(e) => {
                data.insert(
                    "submission_id".to_string(),
                    serde_json::json!(e.submission_id.to_string()),
                );
                data.insert(
                    "bounty_id".to_string(),
                    serde_json::json!(e.bounty_id.to_string()),
                );
                data.insert(
                    "verdict".to_string(),
                    serde_json::json!(format!("{:?}", e.verdict)),
                );
                data.insert(
                    "confidence_score".to_string(),
                    serde_json::json!(format!("{:.2}%", e.confidence_score * 100.0)),
                );
            }
            VerdyxEvent::PaymentProcessed(e) => {
                data.insert(
                    "amount".to_string(),
                    serde_json::json!(e.amount.to_string()),
                );
                data.insert("tx_hash".to_string(), serde_json::json!(e.tx_hash));
                data.insert(
                    "bounty_id".to_string(),
                    serde_json::json!(e.bounty_id.to_string()),
                );
            }
            VerdyxEvent::ReputationUpdated(e) => {
                data.insert("old_score".to_string(), serde_json::json!(e.old_score));
                data.insert("new_score".to_string(), serde_json::json!(e.new_score));
                data.insert(
                    "change_reason".to_string(),
                    serde_json::json!(e.change_reason),
                );
            }
            VerdyxEvent::UserRegistered(e) => {
                data.insert("username".to_string(), serde_json::json!(e.username));
            }
            _ => {}
        }

        data
    }

    /// Render email HTML content
    fn render_email_html(&self, event: &VerdyxEvent) -> Result<String, NotificationError> {
        let template_name = Self::get_template_name(event);
        let template_data = Self::build_template_data(event);

        self.template_engine
            .render(template_name, &template_data)
            .map_err(|e| {
                NotificationError::TemplateError(format!("Failed to render template: {e}"))
            })
    }

    /// Create plain text version from HTML
    fn html_to_text(html: &str) -> String {
        // Basic HTML to text conversion
        // In production, consider using a library like html2text
        html.replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("<br />", "\n")
            .replace("</p>", "\n\n")
            .replace("</div>", "\n")
            // Remove all HTML tags
            .split('<')
            .enumerate()
            .filter_map(|(i, s)| {
                if i == 0 {
                    Some(s.to_string())
                } else {
                    s.split_once('>').map(|(_, text)| text.to_string())
                }
            })
            .collect::<Vec<String>>()
            .join("")
            .trim()
            .to_string()
    }
}

#[async_trait]
impl NotificationChannel for EmailChannel {
    async fn send(&self, payload: &NotificationPayload, recipient: &str) -> NotificationResult<()> {
        info!(
            "Sending email notification to {} for event: {}",
            recipient,
            payload.event.get_title()
        );

        // Render email content
        let html_body = self.render_email_html(&payload.event)?;
        let text_body = Self::html_to_text(&html_body);

        // Build email message
        let email = Message::builder()
            .from(
                format!("{} <{}>", self.from_name, self.from_address)
                    .parse()
                    .map_err(|e| {
                        NotificationError::SendError(format!("Invalid from address: {e}"))
                    })?,
            )
            .to(recipient.parse().map_err(|e| {
                NotificationError::ValidationError(format!("Invalid recipient email: {e}"))
            })?)
            .subject(payload.event.get_title())
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|e| NotificationError::SendError(format!("Failed to build email: {e}")))?;

        // Send email
        match self.smtp_transport.send(email).await {
            Ok(_) => {
                info!("Email sent successfully to {}", recipient);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send email to {}: {}", recipient, e);
                Err(NotificationError::SendError(format!("SMTP error: {e}")))
            }
        }
    }

    fn channel_type(&self) -> &'static str {
        "email"
    }

    async fn validate_recipient(&self, recipient: &str) -> NotificationResult<bool> {
        // Basic email validation
        if recipient.contains('@') && recipient.contains('.') {
            Ok(true)
        } else {
            Err(NotificationError::ValidationError(
                "Invalid email format".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_address: String,
    pub from_name: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_address: "noreply@verdyx.io".to_string(),
            from_name: "Verdyx".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use shared::messaging::event_types::UserRegisteredEvent;
    use uuid::Uuid;

    #[test]
    fn test_html_to_text() {
        let html = "<p>Hello <strong>World</strong></p><br/><div>Test</div>";
        let text = EmailChannel::html_to_text(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(!text.contains("<p>"));
    }

    #[test]
    fn test_template_name_selection() {
        let event = VerdyxEvent::UserRegistered(UserRegisteredEvent {
            user_id: Uuid::new_v4(),
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            ethereum_address: "0x123".to_string(),
            registered_at: Utc::now(),
        });

        let template = EmailChannel::get_template_name(&event);
        assert_eq!(template, "user_registered");
    }
}
