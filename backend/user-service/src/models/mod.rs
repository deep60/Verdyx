use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use validator::Validate;

pub type UserResult<T> = Result<T, UserError>;

#[derive(Debug, Error)]
pub enum UserError {
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("User not found")]
    NotFound,

    #[error("User already exists")]
    AlreadyExists,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid token")]
    InvalidToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub ethereum_address: Option<String>,
    pub email_verified: bool,
    pub is_active: bool,
    pub is_admin: bool,
    pub two_factor_enabled: bool,
    pub two_factor_secret: Option<String>,
    pub kyc_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub location: Option<String>,
    pub website: Option<String>,
    pub twitter: Option<String>,
    pub github: Option<String>,
    pub specializations: Vec<String>,
    pub public_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserSettings {
    pub user_id: Uuid,
    pub email_notifications: bool,
    pub push_notifications: bool,
    pub webhook_notifications: bool,
    pub privacy_public_profile: bool,
    pub privacy_show_email: bool,
    pub privacy_show_stats: bool,
    pub language: String,
    pub timezone: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct KycVerification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub full_name: String,
    pub date_of_birth: Option<chrono::NaiveDate>,
    pub country: String,
    pub document_type: String,
    pub document_number: String,
    pub document_front_url: String,
    pub document_back_url: Option<String>,
    pub selfie_url: String,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub verified_by: Option<Uuid>,
    pub submitted_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KycStatus {
    NotSubmitted,
    Pending,
    UnderReview,
    Approved,
    Rejected,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,

    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8))]
    pub password: String,

    pub ethereum_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    /// Email address or username. Kept as `email` on the wire for existing
    /// clients; values without an `@` are looked up as a username.
    #[serde(alias = "identifier")]
    #[validate(length(min = 1, max = 255))]
    pub email: String,

    pub password: String,

    pub two_factor_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserPublic,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub ethereum_address: Option<String>,
    pub email_verified: bool,
    pub kyc_status: String,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub website: Option<String>,
    pub twitter: Option<String>,
    pub github: Option<String>,
    pub specializations: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitKycRequest {
    pub full_name: String,
    pub date_of_birth: String,
    pub country: String,
    pub document_type: String,
    pub document_number: String,
}

impl From<User> for UserPublic {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            ethereum_address: user.ethereum_address,
            email_verified: user.email_verified,
            kyc_status: user.kyc_status,
            is_admin: user.is_admin,
            created_at: user.created_at,
        }
    }
}
