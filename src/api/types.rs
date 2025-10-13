use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use crate::context::{GatewayAuthService, NamespacedKv};
use std::sync::{Arc, RwLock};

pub(crate) const ENDPOINT_REGISTRATION_PREFIX: &str = "endpoints/registry";
pub(crate) const ENDPOINT_TOKEN_PREFIX: &str = "endpoints/tokens";
pub(crate) const AUTH_HEADER: &str = "x-ht-auth";
pub(crate) const SESSION_NAMESPACE: &[u8] = b"sessions";
pub(crate) const SESSION_COOKIE: &str = "ht_session";

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) kv: Arc<RwLock<NamespacedKv>>,
    pub(crate) auth: Arc<GatewayAuthService>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct EndpointRegistrationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) endpoint_id: Option<String>,
    pub(crate) public_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) assigned_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) local_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) local_port: Option<u16>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct EndpointRegistrationResponse {
    pub(crate) endpoint_id: String,
    pub(crate) token: String,
    pub(crate) gateway_public_key_hex: String,
    pub(crate) assigned_ip: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub(crate) struct LoginTemplate;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub(crate) struct DashboardTemplate;

#[derive(Template)]
#[template(path = "endpoints.html")]
pub(crate) struct EndpointsTemplate;

#[derive(Template)]
#[template(path = "settings.html")]
pub(crate) struct SettingsTemplate;

#[derive(Template)]
#[template(path = "login_alert.html")]
pub(crate) struct LoginAlertTemplate<'a> {
    pub(crate) kind: &'a str,
    pub(crate) message: &'a str,
}

#[derive(Template)]
#[template(path = "nodes_table.html")]
pub(crate) struct EndpointsTableTemplate<'a> {
    pub(crate) endpoints: &'a [EndpointRegistrationRequest],
}

#[derive(Template)]
#[template(path = "auth_keys_list.html")]
pub(crate) struct AuthKeysListTemplate<'a> {
    pub(crate) keys: &'a [crate::api::handlers::auth_keys::AuthKeyListItem],
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct SessionRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug)]
pub(crate) enum SessionApiError {
    Internal(String),
}

impl IntoResponse for SessionApiError {
    fn into_response(self) -> Response {
        match self {
            SessionApiError::Internal(message) => {
                tracing::error!(error = %message, "Session API error");
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum RootApiError {
    Unauthorized,
    InvalidPublicKey,
    Storage(String),
    Internal(String),
}

impl IntoResponse for RootApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            RootApiError::Unauthorized => {
                StatusCode::UNAUTHORIZED.into_response()
            }
            RootApiError::InvalidPublicKey => {
                (StatusCode::BAD_REQUEST, "invalid public key").into_response()
            }
            RootApiError::Storage(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            RootApiError::Internal(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}
