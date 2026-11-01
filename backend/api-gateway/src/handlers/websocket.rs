use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use tracing::{debug, info, warn};

use crate::AppState;

pub async fn ws_proxy(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let redis_url = state.config.redis.url.clone();
    ws.on_upgrade(move |socket| handle_ws_client(socket, redis_url))
}

async fn handle_ws_client(socket: WebSocket, redis_url: String) {
    let (mut client_tx, mut client_rx) = socket.split();

    let welcome = serde_json::json!({
        "type": "connected",
        "status": "live",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    if client_tx
        .send(Message::Text(welcome.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    let pubsub_task = async move {
        let Ok(client) = redis::Client::open(redis_url.as_str()) else {
            warn!("WebSocket Redis client creation failed");
            futures_util::future::pending::<()>().await;
            return;
        };

        let Ok(conn) = client.get_async_connection().await else {
            warn!("WebSocket Redis connection failed; keeping socket alive via heartbeat");
            futures_util::future::pending::<()>().await;
            return;
        };

        let mut pubsub = conn.into_pubsub();
        let _ = pubsub.subscribe("events:analysis_updated").await;
        let _ = pubsub.subscribe("events:analysis_completed").await;
        info!("WebSocket subscribed to Redis analysis event channels");

        let mut stream = pubsub.on_message();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(25));

        loop {
            tokio::select! {
                Some(msg) = stream.next() => {
                    let channel = msg.get_channel_name().to_string();
                    let payload_str: String = msg.get_payload().unwrap_or_else(|_| "{}".to_string());
                    let parsed: serde_json::Value = serde_json::from_str(&payload_str)
                        .unwrap_or_else(|_| serde_json::json!({}));

                    let event_type = if channel.ends_with("analysis_completed") {
                        "analysis_completed"
                    } else {
                        "analysis_updated"
                    };

                    let envelope = serde_json::json!({
                        "type": event_type,
                        "data": {
                            "submissionId": parsed.get("submission_id").cloned().unwrap_or(serde_json::Value::Null),
                            "status": parsed.get("status").cloned().unwrap_or(serde_json::Value::Null),
                            "isMalicious": parsed.get("is_malicious").cloned().unwrap_or(serde_json::Value::Null),
                            "confidenceScore": parsed.get("confidence_score").cloned().unwrap_or(serde_json::Value::Null),
                        }
                    });

                    if client_tx.send(Message::Text(envelope.to_string().into())).await.is_err() {
                        break;
                    }
                }
                _ = heartbeat.tick() => {
                    if client_tx.send(Message::Ping(axum::body::Bytes::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let client_recv_task = async move {
        while let Some(Ok(msg)) = client_rx.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    };

    tokio::select! {
        _ = pubsub_task => {},
        _ = client_recv_task => {},
    }

    debug!("WebSocket client disconnected");
}
