use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::handlers::auth::{AppError, MessageResponse};
use crate::models::*;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub search: Option<String>,
    pub kyc_status: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UserListItem {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub ethereum_address: Option<String>,
    pub email_verified: bool,
    pub kyc_status: String,
    pub is_active: bool,
    pub is_admin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserListItem>,
    pub total: i64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
pub struct RejectKycRequest {
    pub reason: String,
}

/// List all users (admin only)
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    if !claims.is_admin {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20).min(100); // Max 100 per page
    let offset = (page - 1) * limit;

    // Build dynamic query
    let mut query_str = "SELECT * FROM users WHERE 1=1".to_string();
    let mut count_str = "SELECT COUNT(*) FROM users WHERE 1=1".to_string();

    if let Some(search) = &query.search {
        let search_clause =
            format!(" AND (username ILIKE '%{search}%' OR email ILIKE '%{search}%')");
        query_str.push_str(&search_clause);
        count_str.push_str(&search_clause);
    }

    if let Some(kyc_status) = &query.kyc_status {
        let kyc_clause = format!(" AND kyc_status = '{kyc_status}'");
        query_str.push_str(&kyc_clause);
        count_str.push_str(&kyc_clause);
    }

    if let Some(is_active) = query.is_active {
        let active_clause = format!(" AND is_active = {is_active}");
        query_str.push_str(&active_clause);
        count_str.push_str(&active_clause);
    }

    query_str.push_str(&format!(
        " ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}"
    ));

    // Execute queries
    let users: Vec<User> = sqlx::query_as(&query_str)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    let total: (i64,) = sqlx::query_as(&count_str)
        .fetch_one(&state.db_pool)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    let user_list: Vec<UserListItem> = users
        .into_iter()
        .map(|u| UserListItem {
            id: u.id,
            username: u.username,
            email: u.email,
            ethereum_address: u.ethereum_address,
            email_verified: u.email_verified,
            kyc_status: u.kyc_status,
            is_active: u.is_active,
            is_admin: u.is_admin,
            created_at: u.created_at,
            last_login: u.last_login,
        })
        .collect();

    Ok(Json(UserListResponse {
        users: user_list,
        total: total.0,
        page,
        limit,
    }))
}

/// Get user details (admin only)
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserPublic>, AppError> {
    if !claims.is_admin {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    let user = state.user_service.get_user_by_id(user_id).await?;
    // Never return password_hash, 2FA secrets, or other credential material.
    Ok(Json(user.into()))
}

/// Suspend user (admin only)
pub async fn suspend_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    if !claims.is_admin {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(Json(MessageResponse {
        message: "User suspended successfully".to_string(),
    }))
}

/// Activate user (admin only)
pub async fn activate_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    if !claims.is_admin {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    sqlx::query("UPDATE users SET is_active = true WHERE id = $1")
        .bind(user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(Json(MessageResponse {
        message: "User activated successfully".to_string(),
    }))
}

/// Approve KYC verification (admin only)
pub async fn approve_kyc(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    if !claims.is_admin {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    let admin_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    // Get latest KYC submission
    let kyc = state
        .user_service
        .get_kyc_status(user_id)
        .await?
        .ok_or(AppError::UserError(UserError::NotFound))?;

    // Update KYC status
    sqlx::query(
        r#"
        UPDATE kyc_verifications
        SET status = 'approved',
            verified_by = $1,
            verified_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(admin_id)
    .bind(kyc.id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    // Update user KYC status
    sqlx::query("UPDATE users SET kyc_status = 'approved' WHERE id = $1")
        .bind(user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(Json(MessageResponse {
        message: "KYC approved successfully".to_string(),
    }))
}

/// Reject KYC verification (admin only)
pub async fn reject_kyc(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<RejectKycRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    if !claims.is_admin {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    let admin_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    // Get latest KYC submission
    let kyc = state
        .user_service
        .get_kyc_status(user_id)
        .await?
        .ok_or(AppError::UserError(UserError::NotFound))?;

    // Update KYC status
    sqlx::query(
        r#"
        UPDATE kyc_verifications
        SET status = 'rejected',
            rejection_reason = $1,
            verified_by = $2,
            verified_at = NOW()
        WHERE id = $3
        "#,
    )
    .bind(&req.reason)
    .bind(admin_id)
    .bind(kyc.id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    // Update user KYC status
    sqlx::query("UPDATE users SET kyc_status = 'rejected' WHERE id = $1")
        .bind(user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(Json(MessageResponse {
        message: "KYC rejected successfully".to_string(),
    }))
}
