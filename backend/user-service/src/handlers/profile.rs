use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::handlers::auth::AppError;
use crate::models::*;
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct ProfileResponse {
    pub user: UserPublic,
    pub profile: UserProfile,
}

/// Get current user's profile
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ProfileResponse>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let user = state.user_service.get_user_by_id(user_id).await?;
    let profile = state.user_service.get_profile(user_id).await?;

    Ok(Json(ProfileResponse {
        user: user.into(),
        profile,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateAccountRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub bio: Option<String>,
}

/// Update username, email, and/or bio. Identity changes are validated and audited
/// in user-service. Other services must not write the users table for this.
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<UpdateAccountRequest>,
) -> Result<Json<UserPublic>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let user = state
        .user_service
        .update_identity(user_id, req.username, req.email)
        .await?;

    if req.bio.is_some() {
        let _ = state
            .user_service
            .update_profile(
                user_id,
                UpdateProfileRequest {
                    display_name: None,
                    bio: req.bio,
                    location: None,
                    website: None,
                    twitter: None,
                    github: None,
                    specializations: None,
                },
            )
            .await?;
    }

    Ok(Json(user.into()))
}

/// Soft-delete the current account. Requires the caller's own access token.
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<axum::http::StatusCode, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    state.user_service.delete_account(user_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Update current user's profile
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let profile = state.user_service.update_profile(user_id, req).await?;

    Ok(Json(profile))
}

/// Upload avatar (multipart form field "file"). Stores to S3/MinIO and
/// records the resulting URL on the user's profile.
pub async fn upload_avatar(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let storage = state
        .avatar_storage
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Avatar storage is not configured".to_string()))?;

    // Pull the first file field from the multipart body.
    let mut field_data: Option<(Vec<u8>, String)> = None;
    if let Some(field) = multipart.next_field().await.map_err(|e| {
        AppError::UserError(UserError::ValidationError(format!("invalid upload: {e}")))
    })? {
        let content_type = field
            .content_type()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let data = field
            .bytes()
            .await
            .map_err(|e| {
                AppError::UserError(UserError::ValidationError(format!("read failed: {e}")))
            })?
            .to_vec();
        field_data = Some((data, content_type));
    }

    let (data, content_type) = field_data.ok_or_else(|| {
        AppError::UserError(UserError::ValidationError("no file provided".to_string()))
    })?;

    // Basic validation: image content type and size cap (5 MB).
    if !content_type.starts_with("image/") {
        return Err(AppError::UserError(UserError::ValidationError(
            "avatar must be an image".to_string(),
        )));
    }
    if data.len() > 5 * 1024 * 1024 {
        return Err(AppError::UserError(UserError::ValidationError(
            "avatar exceeds 5MB limit".to_string(),
        )));
    }

    let ext = match content_type.as_str() {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "img",
    };
    let key = format!("avatars/{user_id}.{ext}");

    let url = storage
        .upload_avatar(&key, data, &content_type)
        .await
        .map_err(|e| AppError::InternalError(format!("upload failed: {e}")))?;

    let profile = state.user_service.update_avatar(user_id, &url).await?;

    Ok(Json(serde_json::json!({
        "message": "avatar updated",
        "avatar_url": profile.avatar_url,
    })))
}

/// Get public profile of any user
pub async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ProfileResponse>, AppError> {
    let user = state.user_service.get_user_by_id(user_id).await?;
    let profile = state.user_service.get_profile(user_id).await?;

    // Check privacy settings
    let settings = state.user_service.get_settings(user_id).await?;

    if !settings.privacy_public_profile {
        return Err(AppError::Unauthorized(
            "This profile is private".to_string(),
        ));
    }

    Ok(Json(ProfileResponse {
        user: user.into(),
        profile,
    }))
}
