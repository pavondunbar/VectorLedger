//! Unified error type for the license server.
//!
//! `ServerError` implements `axum::response::IntoResponse` so handlers can
//! return `Result<_, ServerError>` and Axum will convert failures into
//! appropriate HTTP responses automatically.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("License signing error: {0}")]
    Signing(String),

    #[error("Webhook signature verification failed: {0}")]
    WebhookSignature(String),

    #[error("Webhook payload parse error: {0}")]
    WebhookParse(String),

    #[error("Email delivery error: {0}")]
    Email(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Token expired or already used")]
    TokenExpired,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        // Log internal errors before converting to HTTP.
        // Webhook and signature errors are expected attack surface — log at
        // warn.  Everything else is unexpected — log at error.
        let (status, message) = match &self {
            ServerError::WebhookSignature(msg) => {
                tracing::warn!(error = %msg, "Webhook signature rejected");
                (StatusCode::BAD_REQUEST, "Invalid webhook signature".to_string())
            }
            ServerError::WebhookParse(msg) => {
                tracing::warn!(error = %msg, "Webhook parse error");
                (StatusCode::BAD_REQUEST, "Malformed webhook payload".to_string())
            }
            ServerError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, msg.clone())
            }
            ServerError::TokenExpired => {
                (StatusCode::GONE, "Token expired or already used".to_string())
            }
            other => {
                error!(error = %other, "Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

// Allow converting rusqlite errors directly.
impl From<rusqlite::Error> for ServerError {
    fn from(e: rusqlite::Error) -> Self {
        ServerError::Database(e.to_string())
    }
}
