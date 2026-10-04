/// Messaging and event handling utilities
pub mod event_types;

#[cfg(feature = "redis")]
pub mod publisher;

// Kafka client module - currently stubbed for future implementation
// pub mod kafka_client;

pub use event_types::*;

#[cfg(feature = "redis")]
pub use publisher::*;

/// Message queue trait for abstracting different messaging backends
#[async_trait::async_trait]
pub trait MessageQueue: Send + Sync {
    /// Publish a message to a topic
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<(), MessageError>;

    /// Subscribe to a topic
    async fn subscribe(&self, topic: &str) -> Result<MessageSubscription, MessageError>;

    /// Unsubscribe from a topic
    async fn unsubscribe(&self, subscription: MessageSubscription) -> Result<(), MessageError>;
}

/// Message subscription handle
pub struct MessageSubscription {
    pub topic: String,
    pub subscription_id: String,
}

/// Message queue errors
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Topic error: {0}")]
    Topic(String),

    #[error("Subscription error: {0}")]
    Subscription(String),
}

pub type MessageResult<T> = Result<T, MessageError>;
