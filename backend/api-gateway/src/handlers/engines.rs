use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

/// Query parameters for listing engines
#[derive(Debug, Deserialize)]
pub struct ListEnginesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub engine_type: Option<String>,
}

/// Request payload for registering a security engine
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterEngineRequest {
    pub name: String,
    #[serde(alias = "type")]
    pub engine_type: String,
    pub description: Option<String>,
    pub api_endpoint: Option<String>,
    pub stake_amount: Option<String>,
}

/// Raw database row for engines
#[derive(Debug, Clone, sqlx::FromRow)]
struct EngineDbRow {
    pub id: Uuid,
    pub name: String,
    pub engine_type: String,
    pub description: Option<String>,
    pub accuracy_rate: Option<f64>,
    pub total_analyses: Option<i64>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Security engine summary returned to clients (matches both Marketplace.tsx and EngineCard.tsx).
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EngineSummary {
    pub id: Uuid,
    pub name: String,
    pub engine_type: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub description: Option<String>,
    /// None until accuracy has been measured; never estimated.
    pub accuracy_rate: Option<String>,
    pub accuracy: Option<String>,
    pub total_analyses: Option<i64>,
    pub stake_amount: Option<String>,
    pub is_active: bool,
    /// Live state reported by the analysis engine, such as "online" or "unavailable".
    pub status: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<EngineDbRow> for EngineSummary {
    fn from(row: EngineDbRow) -> Self {
        let accuracy = row.accuracy_rate.map(|raw| {
            let pct = if raw <= 1.0 && raw > 0.0 {
                raw * 100.0
            } else {
                raw
            };
            format!("{:.2}", pct)
        });
        Self {
            id: row.id,
            name: row.name,
            r#type: row.engine_type.clone(),
            engine_type: row.engine_type,
            description: row.description,
            accuracy_rate: accuracy.clone(),
            accuracy,
            total_analyses: row.total_analyses,
            stake_amount: None,
            is_active: row.is_active,
            status: None,
            created_at: row.created_at,
        }
    }
}

/// One analyzer as reported by the analysis engine's `/engines/status`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnalyzerStatus {
    id: String,
    name: String,
    engine_type: String,
    status: String,
    details: String,
}

#[derive(Debug, Deserialize)]
struct AnalyzerReport {
    engines: Vec<AnalyzerStatus>,
}

/// Stable id for a built-in analyzer, derived from its name so links keep working.
fn builtin_engine_id(analyzer_id: &str) -> Uuid {
    let mut bytes = [0u8; 16];
    for (i, b) in analyzer_id.bytes().enumerate() {
        bytes[i % 16] = bytes[i % 16].wrapping_mul(31).wrapping_add(b);
    }
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

impl From<AnalyzerStatus> for EngineSummary {
    fn from(a: AnalyzerStatus) -> Self {
        Self {
            id: builtin_engine_id(&a.id),
            name: a.name,
            r#type: a.engine_type.clone(),
            engine_type: a.engine_type,
            description: Some(a.details),
            accuracy_rate: None,
            accuracy: None,
            total_analyses: None,
            stake_amount: None,
            is_active: a.status == "online",
            status: Some(a.status),
            created_at: Utc::now(),
        }
    }
}

/// The analyzers built into the analysis engine, with their live status.
async fn builtin_engines(state: &AppState) -> Result<Vec<EngineSummary>, StatusCode> {
    let resp = state
        .proxy
        .get("analysis-engine", "/engines/status", None)
        .await
        .map_err(|e| {
            tracing::warn!("Analysis engine status unavailable: {}", e);
            StatusCode::SERVICE_UNAVAILABLE
        })?;
    if !resp.status().is_success() {
        tracing::warn!("Analysis engine status returned {}", resp.status());
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let report: AnalyzerReport = resp.json().await.map_err(|e| {
        tracing::warn!("Unreadable analysis engine status: {}", e);
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    Ok(report
        .engines
        .into_iter()
        .map(EngineSummary::from)
        .collect())
}

/// List all security engines
///
/// GET /api/v1/engines
pub async fn list_engines(
    State(state): State<AppState>,
    Query(params): Query<ListEnginesQuery>,
) -> Result<Json<Vec<EngineSummary>>, StatusCode> {
    let limit = params.limit.unwrap_or(50).min(100) as i64;
    let offset = ((params.page.unwrap_or(1).saturating_sub(1)) * limit as u32) as i64;

    let rows = sqlx::query_as::<_, EngineDbRow>(
        r#"SELECT id, name, engine_type, description,
                  accuracy_rate::FLOAT8 as accuracy_rate,
                  total_analyses::BIGINT as total_analyses,
                  COALESCE(is_active, true) as is_active,
                  created_at
           FROM engines
           WHERE is_active = true
           ORDER BY created_at DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return builtin_engines(&state).await.map(Json);
    }

    Ok(Json(rows.into_iter().map(EngineSummary::from).collect()))
}

/// Get engine by ID
///
/// GET /api/v1/engines/:engine_id
pub async fn get_engine(
    State(state): State<AppState>,
    Path(engine_id): Path<Uuid>,
) -> Result<Json<EngineSummary>, StatusCode> {
    let row = sqlx::query_as::<_, EngineDbRow>(
        r#"SELECT id, name, engine_type, description,
                  accuracy_rate::FLOAT8 as accuracy_rate,
                  total_analyses::BIGINT as total_analyses,
                  COALESCE(is_active, true) as is_active,
                  created_at
           FROM engines
           WHERE id = $1"#,
    )
    .bind(engine_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error fetching engine: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(r) = row {
        return Ok(Json(EngineSummary::from(r)));
    }

    builtin_engines(&state)
        .await?
        .into_iter()
        .find(|e| e.id == engine_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Register a new security engine
///
/// POST /api/v1/engines
pub async fn register_engine(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(payload): Json<RegisterEngineRequest>,
) -> Result<Json<EngineSummary>, StatusCode> {
    if payload.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let engine_id = Uuid::new_v4();
    let now = Utc::now();

    let row = sqlx::query_as::<_, EngineDbRow>(
        r#"
        INSERT INTO engines (id, name, engine_type, description, owner_id, api_endpoint, is_active, accuracy_rate, total_analyses, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, true, NULL, 0, $7, $7)
        RETURNING id, name, engine_type, description,
                  accuracy_rate::FLOAT8 as accuracy_rate,
                  total_analyses::BIGINT as total_analyses,
                  COALESCE(is_active, true) as is_active,
                  created_at
        "#,
    )
    .bind(engine_id)
    .bind(payload.name.trim())
    .bind(payload.engine_type.trim())
    .bind(&payload.description)
    .bind(claims.sub)
    .bind(&payload.api_endpoint)
    .bind(now)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("DB error registering engine: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut summary = EngineSummary::from(row);
    if let Some(stake) = payload.stake_amount {
        summary.stake_amount = Some(stake);
    }
    Ok(Json(summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_engines_report_live_status_and_no_invented_numbers() {
        let report: AnalyzerReport = serde_json::from_value(serde_json::json!({
            "engines": [
                {"id": "yara", "name": "YARA Engine", "engineType": "yara", "isOptional": true,
                 "status": "online", "version": "4.5", "details": "Rules loaded", "error": null},
                {"id": "clamav", "name": "ClamAV Scanner", "engineType": "clamav", "isOptional": true,
                 "status": "unavailable", "version": "clamd", "details": "No daemon", "error": "refused"}
            ],
            "totalEngines": 2
        }))
        .unwrap();
        let engines: Vec<EngineSummary> = report
            .engines
            .into_iter()
            .map(EngineSummary::from)
            .collect();

        assert!(engines[0].is_active);
        assert!(!engines[1].is_active);
        assert_eq!(engines[1].status.as_deref(), Some("unavailable"));
        for e in &engines {
            assert!(e.accuracy.is_none() && e.total_analyses.is_none() && e.stake_amount.is_none());
        }
        assert_eq!(builtin_engine_id("yara"), builtin_engine_id("yara"));
        assert_ne!(builtin_engine_id("yara"), builtin_engine_id("clamav"));
    }
}
