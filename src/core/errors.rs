use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Authorization error: {0}")]
    AuthorizationError(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Role not found")]
    RoleNotFound,

    #[error("Policy not found")]
    PolicyNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::UserNotFound | AppError::RoleNotFound | AppError::PolicyNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": self.to_string()
                }))
            }
            AppError::InvalidCredentials | AppError::InvalidToken | AppError::AuthError(_) => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": self.to_string()
                }))
            }
            AppError::AuthorizationError(_) | AppError::PermissionDenied => {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": self.to_string()
                }))
            }
            AppError::BadRequest(_) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": self.to_string()
            })),
            _ => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })),
        }
    }
}
