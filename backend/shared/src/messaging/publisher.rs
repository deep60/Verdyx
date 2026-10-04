#[cfg(feature = "redis")]
use anyhow::{anyhow, Result};
#[cfg(feature = "redis")]
use redis::AsyncCommands;
use serde::Serialize;
use tracing::{error, info};

#[cfg(feature = "redis")]
use super::event_types::VerdyxEvent;

/// Redis Pub/Sub channel prefix for events
const EVENT_CHANNEL_PREFIX: &str = "events:";

/// Event publisher for Redis Pub/Sub
pub struct EventPublisher {
    redis_client: redis::Client,
}

impl EventPublisher {
    /// Create a new event publisher
    pub fn new(redis_client: redis::Client) -> Self {
        Self { redis_client }
    }

    /// Create from Redis URL
    pub fn from_url(redis_url: &str) -> Result<Self> {
        let redis_client = redis::Client::open(redis_url)
            .map_err(|e| anyhow!("Failed to create Redis client: {e}"))?;
        Ok(Self { redis_client })
    }

    /// Publish an event to the appropriate Redis Pub/Sub channel
    pub async fn publish(&self, event: &VerdyxEvent) -> Result<()> {
        let channel = self.get_channel_for_event(event);
        let payload =
            serde_json::to_string(event).map_err(|e| anyhow!("Failed to serialize event: {e}"))?;

        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;

        conn.publish::<_, _, ()>(&channel, payload)
            .await
            .map_err(|e| anyhow!("Failed to publish event to {channel}: {e}"))?;

        info!("Published event to channel: {}", channel);
        Ok(())
    }

    /// Publish multiple events in batch
    pub async fn publish_batch(&self, events: Vec<VerdyxEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let event_count = events.len();

        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;

        for event in events {
            let channel = self.get_channel_for_event(&event);
            let payload = serde_json::to_string(&event)
                .map_err(|e| anyhow!("Failed to serialize event: {e}"))?;

            if let Err(e) = conn.publish::<_, _, ()>(&channel, payload).await {
                error!("Failed to publish event to {}: {}", channel, e);
            }
        }

        info!("Published {} events in batch", event_count);
        Ok(())
    }

    /// Get the Redis channel name for a given event
    fn get_channel_for_event(&self, event: &VerdyxEvent) -> String {
        let event_name = match event {
            VerdyxEvent::BountyCreated(_) => "bounty_created",
            VerdyxEvent::BountyUpdated(_) => "bounty_updated",
            VerdyxEvent::BountyCompleted(_) => "bounty_completed",
            VerdyxEvent::BountyExpired(_) => "bounty_expired",
            VerdyxEvent::BountyCancelled(_) => "bounty_cancelled",

            VerdyxEvent::SubmissionReceived(_) => "submission_received",
            VerdyxEvent::SubmissionValidated(_) => "submission_validated",
            VerdyxEvent::SubmissionRejected(_) => "submission_rejected",

            VerdyxEvent::AnalysisStarted(_) => "analysis_started",
            VerdyxEvent::AnalysisCompleted(_) => "analysis_completed",
            VerdyxEvent::AnalysisFailed(_) => "analysis_failed",

            VerdyxEvent::ReputationUpdated(_) => "reputation_updated",

            VerdyxEvent::PaymentProcessed(_) => "payment_processed",
            VerdyxEvent::PaymentFailed(_) => "payment_failed",
            VerdyxEvent::StakeSlashed(_) => "stake_slashed",

            VerdyxEvent::UserRegistered(_) => "user_registered",
            VerdyxEvent::UserVerified(_) => "user_verified",
            VerdyxEvent::EngineRegistered(_) => "engine_registered",

            VerdyxEvent::DisputeCreated(_) => "dispute_created",
            VerdyxEvent::DisputeResolved(_) => "dispute_resolved",

            VerdyxEvent::SystemAlert(_) => "system_alert",
        };

        format!("{EVENT_CHANNEL_PREFIX}{event_name}")
    }
}

/// Publish a single event (convenience function)
pub async fn publish_event(redis_client: &redis::Client, event: &VerdyxEvent) -> Result<()> {
    let publisher = EventPublisher::new(redis_client.clone());
    publisher.publish(event).await
}

/// Publish a JSON payload to a specific channel (generic version)
pub async fn publish_to_channel<T: Serialize>(
    redis_client: &redis::Client,
    channel: &str,
    payload: &T,
) -> Result<()> {
    let message =
        serde_json::to_string(payload).map_err(|e| anyhow!("Failed to serialize payload: {e}"))?;

    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;

    conn.publish::<_, _, ()>(channel, message)
        .await
        .map_err(|e| anyhow!("Failed to publish to channel {channel}: {e}"))?;

    info!("Published message to channel: {}", channel);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::event_types::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_channel_mapping() {
        let redis_client = redis::Client::open("redis://localhost:6379").unwrap();
        let publisher = EventPublisher::new(redis_client);

        let event = VerdyxEvent::UserRegistered(UserRegisteredEvent {
            user_id: Uuid::new_v4(),
            username: "test_user".to_string(),
            email: "test@example.com".to_string(),
            ethereum_address: "0x0000000000000000000000000000000000000000".to_string(),
            registered_at: Utc::now(),
        });

        let channel = publisher.get_channel_for_event(&event);
        assert_eq!(channel, "events:user_registered");
    }

    #[test]
    fn test_payment_event_channel() {
        let redis_client = redis::Client::open("redis://localhost:6379").unwrap();
        let publisher = EventPublisher::new(redis_client);

        let event = VerdyxEvent::PaymentProcessed(PaymentProcessedEvent {
            bounty_id: Uuid::new_v4(),
            recipient_id: Uuid::new_v4(),
            amount: 1000,
            tx_hash: "0x1234567890abcdef".to_string(),
            payment_type: PaymentType::BountyReward,
            processed_at: Utc::now(),
        });

        let channel = publisher.get_channel_for_event(&event);
        assert_eq!(channel, "events:payment_processed");
    }
}
