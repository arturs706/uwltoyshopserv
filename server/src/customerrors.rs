

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

#[derive(Debug)]

pub enum CustomErrors {
    MissingCreds,
    InvalidToken,
    NotLoggedIn,
    InvalidKey,
    NotAuthorized
}

impl IntoResponse for CustomErrors {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::MissingCreds => (StatusCode::BAD_REQUEST,"Missing credentials"),
            Self::NotLoggedIn => (StatusCode::UNAUTHORIZED,"User is not logged in"),
            Self::InvalidToken => (StatusCode::UNAUTHORIZED,"Invalid token"),
            Self::InvalidKey => (StatusCode::UNAUTHORIZED,"Invalid key"),
            Self::NotAuthorized => (StatusCode::UNAUTHORIZED,"Not authorized")
            };
            (status, Json(json!({ "error": err_msg}))).into_response()
            
    }
}
