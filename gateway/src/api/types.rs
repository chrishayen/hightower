use crate::context::{GatewayAuthService, NamespacedKv};
use askama::Template;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::{Arc, RwLock};

pub(crate) const ENDPOINT_REGISTRATION_PREFIX: &str = "endpoints/registry";
pub(crate) const ENDPOINT_TOKEN_PREFIX: &str = "endpoints/tokens";
pub(crate) const AUTH_HEADER: &str = "x-ht-auth";
pub(crate) const SESSION_NAMESPACE: &[u8] = b"sessions";
pub(crate) const SESSION_COOKIE: &str = "ht_session";
pub(crate) const CONNECTION_INTENT_PREFIX: &str = "connections/intents";

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) kv: Arc<RwLock<NamespacedKv>>,
    pub(crate) auth: Arc<GatewayAuthService>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum CandidateKind {
    Local,
    StunPublic,
    HolePunch,
    Relay,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EndpointCandidate {
    pub(crate) kind: CandidateKind,
    pub(crate) addr: std::net::SocketAddr,
    pub(crate) priority: u32,
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
    pub(crate) candidates: Vec<EndpointCandidate>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionIntentRequest {
    pub(crate) target: String,
    pub(crate) port: u16,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionIntent {
    pub(crate) connection_id: String,
    pub(crate) initiator_endpoint_id: String,
    pub(crate) target_endpoint_id: String,
    pub(crate) port: u16,
    pub(crate) initiator: EndpointRegistrationRequest,
    pub(crate) target: EndpointRegistrationRequest,
    pub(crate) created_at_ms: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionIntentResponse {
    pub(crate) connection_id: String,
    pub(crate) port: u16,
    pub(crate) initiator: EndpointRegistrationRequest,
    pub(crate) target: EndpointRegistrationRequest,
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
    NotFound,
    Storage(String),
    Internal(String),
}

impl IntoResponse for RootApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            RootApiError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            RootApiError::InvalidPublicKey => {
                (StatusCode::BAD_REQUEST, "invalid public key").into_response()
            }
            RootApiError::NotFound => StatusCode::NOT_FOUND.into_response(),
            RootApiError::Storage(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
            RootApiError::Internal(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}

#[cfg(test)]
mod type_tests {
    use super::*;

    #[test]
    fn endpoint_candidate_round_trips_json() {
        let candidate = EndpointCandidate {
            kind: CandidateKind::Local,
            addr: "192.168.4.63:33565".parse().unwrap(),
            priority: 100,
        };

        let json = serde_json::to_string(&candidate).unwrap();
        assert!(json.contains("Local"));
        assert!(json.contains("192.168.4.63:33565"));

        let decoded: EndpointCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, CandidateKind::Local);
        assert_eq!(decoded.addr.to_string(), "192.168.4.63:33565");
        assert_eq!(decoded.priority, 100);
    }

    #[test]
    fn connection_intent_round_trips_json() {
        let request = ConnectionIntentRequest {
            target: "ht-unlimited-machine-6327".to_string(),
            port: 8080,
        };
        let json = serde_json::to_string(&request).unwrap();
        let decoded: ConnectionIntentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.target, "ht-unlimited-machine-6327");
        assert_eq!(decoded.port, 8080);
    }
}
