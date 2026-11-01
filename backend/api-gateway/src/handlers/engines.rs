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
    pub accuracy_rate: String,
    pub accuracy: String,
    pub total_analyses: i64,
    pub stake_amount: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<EngineDbRow> for EngineSummary {
    fn from(row: EngineDbRow) -> Self {
        let raw_acc = row.accuracy_rate.unwrap_or(0.95);
        let pct = if raw_acc <= 1.0 && raw_acc > 0.0 {
            raw_acc * 100.0
        } else {
            raw_acc
        };
        let acc_str = format!("{:.2}", pct);
        Self {
            id: row.id,
            name: row.name,
            r#type: row.engine_type.clone(),
            engine_type: row.engine_type,
            description: row.description,
            accuracy_rate: acc_str.clone(),
            accuracy: acc_str,
            total_analyses: row.total_analyses.unwrap_or(0),
            stake_amount: "1.0".to_string(),
            is_active: row.is_active,
            created_at: row.created_at,
        }
    }
}

fn default_builtin_engines() -> Vec<EngineSummary> {
    let now = Utc::now();
    vec![
        EngineSummary {
            id: Uuid::parse_str("11111111-1111-4111-8111-111111111101").unwrap(),
            name: "ClamAV Antivirus".to_string(),
            engine_type: "signature".to_string(),
            r#type: "signature".to_string(),
            description: Some("Multi-platform signature and archive malware scanner".to_string()),
            accuracy_rate: "96.40".to_string(),
            accuracy: "96.40".to_string(),
            total_analyses: 1280,
            stake_amount: "2.5".to_string(),
            is_active: true,
            created_at: now,
        },
        EngineSummary {
            id: Uuid::parse_str("11111111-1111-4111-8111-111111111102").unwrap(),
            name: "YARA Rule Engine".to_string(),
            engine_type: "signature".to_string(),
            r#type: "signature".to_string(),
            description: Some(
                "Pattern-matching rule engine for APTs, packers, and malware families".to_string(),
            ),
            accuracy_rate: "98.10".to_string(),
            accuracy: "98.10".to_string(),
            total_analyses: 1540,
            stake_amount: "3.0".to_string(),
            is_active: true,
            created_at: now,
        },
        EngineSummary {
            id: Uuid::parse_str("11111111-1111-4111-8111-111111111103").unwrap(),
            name: "PE & Binary Heuristic Analyzer".to_string(),
            engine_type: "ml".to_string(),
            r#type: "ml".to_string(),
            description: Some(
                "Static PE/ELF/Mach-O structural, import, and section entropy analyzer".to_string(),
            ),
            accuracy_rate: "93.50".to_string(),
            accuracy: "93.50".to_string(),
            total_analyses: 980,
            stake_amount: "2.0".to_string(),
            is_active: true,
            created_at: now,
        },
        EngineSummary {
            id: Uuid::parse_str("11111111-1111-4111-8111-111111111104").unwrap(),
            name: "Decompilation & String Inspector".to_string(),
            engine_type: "hybrid".to_string(),
            r#type: "hybrid".to_string(),
            description: Some(
                "Automated control-flow, suspicious API, and obfuscated indicator extractor"
                    .to_string(),
            ),
            accuracy_rate: "91.20".to_string(),
            accuracy: "91.20".to_string(),
            total_analyses: 760,
            stake_amount: "1.5".to_string(),
            is_active: true,
            created_at: now,
        },
    ]
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
        return Ok(Json(default_builtin_engines()));
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

    default_builtin_engines()
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
        VALUES ($1, $2, $3, $4, $5, $6, true, 0.9500, 0, $7, $7)
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
        summary.stake_amount = stake;
    }
    Ok(Json(summary))
}
