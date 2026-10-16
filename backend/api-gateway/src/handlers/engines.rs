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

/// Security engine summary returned to clients.
#[derive(Debug, Serialize, Clone, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct EngineSummary {
    pub id: Uuid,
    pub name: String,
    pub engine_type: String,
    pub description: Option<String>,
    pub accuracy_rate: Option<f64>,
    pub total_analyses: Option<i64>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
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

    // Simple query – if the table doesn't exist yet this returns an empty vec via unwrap_or_default
    let engines = sqlx::query_as::<_, EngineSummary>(
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

    Ok(Json(engines))
}

/// Get engine by ID
///
/// GET /api/v1/engines/:engine_id
pub async fn get_engine(
    State(state): State<AppState>,
    Path(engine_id): Path<Uuid>,
) -> Result<Json<EngineSummary>, StatusCode> {
    let engine = sqlx::query_as::<_, EngineSummary>(
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
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(engine))
}
