use axum::{
    extract::{Json, Path as AxumPath, State},
    http::{HeaderMap, HeaderName, StatusCode},
};
use hex::FromHex;
use rand::RngCore;
use tracing::debug;

use crate::context::NamespacedKv;
use crate::ip_allocator::IpAllocator;
use super::super::certificates::load_gateway_public_key;
use super::super::types::{
    ApiState, NodeRegistrationRequest, NodeRegistrationResponse, RootApiError,
    AUTH_HEADER, NODE_REGISTRATION_PREFIX, NODE_TOKEN_PREFIX,
};

pub(crate) async fn register_node(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<NodeRegistrationRequest>,
) -> Result<Json<NodeRegistrationResponse>, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    validate_auth(&kv, &headers)?;

    // Always generate node_id - nodes never provide their own name
    let node_id = generate_node_name();

    debug!(node_id = %node_id, "Gateway received node registration request");
    ensure_public_key_valid(&body.public_key_hex)?;

    // Allocate IP address for the node
    let assigned_ip = IpAllocator::allocate_ip(&kv, &node_id)
        .map_err(|err| RootApiError::Storage(format!("failed to allocate IP: {}", err)))?;
    debug!(node_id = %node_id, assigned_ip = %assigned_ip, "Assigned IP to node");

    let gateway_public_key_hex = load_gateway_public_key(&kv)?;
    let token = generate_registration_token();

    // Store the assigned IP in the registration
    let mut registration = body.clone();
    registration.node_id = Some(node_id.clone());
    registration.assigned_ip = Some(assigned_ip.clone());

    persist_registration(&kv, &registration, &token).map_err(|err| {
        RootApiError::Storage(format!("failed to persist node registration: {}", err))
    })?;

    // Add node as peer to transport layer
    if let Some(transport) = crate::wireguard_api::get_transport_server() {
        debug!(node_id = %node_id, "gateway: Adding node as WireGuard peer");
        let peer_public_key = hex::decode(&body.public_key_hex)
            .map_err(|_| RootApiError::InvalidPublicKey)?;
        if peer_public_key.len() != 32 {
            return Err(RootApiError::InvalidPublicKey);
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&peer_public_key);

        // We don't know the node's endpoint yet - they'll connect to us
        if let Err(e) = transport.add_peer(key_array, None).await {
            tracing::error!(
                error = ?e,
                node_id = %node_id,
                "gateway: Failed to add node as WireGuard peer"
            );
        } else {
            debug!(
                node_id = %node_id,
                public_key = &body.public_key_hex[..8],
                "gateway: Successfully added node as WireGuard peer"
            );
        }
    } else {
        debug!(node_id = %node_id, "gateway: WireGuard transport not initialized yet");
    }

    debug!(node_id = %node_id, assigned_ip = %assigned_ip, "Registered node");
    Ok(Json(NodeRegistrationResponse {
        node_id,
        token,
        gateway_public_key_hex,
        assigned_ip,
    }))
}

pub(crate) async fn deregister_node(
    State(state): State<ApiState>,
    AxumPath(token): AxumPath<String>,
) -> Result<StatusCode, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let token_key = token_storage_key(&token);
    let node_id = kv
        .get_bytes(&token_key)
        .map_err(|err| RootApiError::Storage(format!("failed to read token: {}", err)))?
        .ok_or(RootApiError::Unauthorized)?;

    let node_id = String::from_utf8(node_id)
        .map_err(|_| RootApiError::Internal("invalid node_id encoding".into()))?;

    debug!(node_id = %node_id, "Gateway received node deregistration request");

    let registration_key = registration_storage_key(&node_id);
    kv.put_bytes(&registration_key, b"__DELETED__")
        .map_err(|err| RootApiError::Storage(format!("failed to mark registration deleted: {}", err)))?;

    kv.put_bytes(&token_key, b"__DELETED__")
        .map_err(|err| RootApiError::Storage(format!("failed to mark token deleted: {}", err)))?;

    IpAllocator::release_ip(&kv, &node_id)
        .map_err(|err| RootApiError::Storage(format!("failed to release IP: {}", err)))?;

    debug!(node_id = %node_id, "Deregistered node");
    Ok(StatusCode::NO_CONTENT)
}

fn validate_auth(kv: &NamespacedKv, headers: &HeaderMap) -> Result<(), RootApiError> {
    let header_name = HeaderName::from_lowercase(AUTH_HEADER.as_bytes())
        .expect("static header name is valid lowercase");
    let provided = headers
        .get(&header_name)
        .and_then(|value| value.to_str().ok())
        .ok_or(RootApiError::Unauthorized)?;

    let is_valid_key = super::auth_keys::validate_auth_key(kv, provided)
        .map_err(|err| RootApiError::Internal(format!("failed to validate auth key: {}", err)))?;

    if is_valid_key {
        Ok(())
    } else {
        Err(RootApiError::Unauthorized)
    }
}

fn ensure_public_key_valid(public_key_hex: &str) -> Result<(), RootApiError> {
    let bytes = Vec::from_hex(public_key_hex).map_err(|_| RootApiError::InvalidPublicKey)?;
    if bytes.len() == 32 {
        Ok(())
    } else {
        Err(RootApiError::InvalidPublicKey)
    }
}

pub(crate) fn persist_registration(
    kv: &NamespacedKv,
    registration: &NodeRegistrationRequest,
    token: &str,
) -> Result<(), hightower_kv::Error> {
    let node_id = registration.node_id.as_ref().expect("node_id must be set before persist");
    let key = registration_storage_key(node_id);
    let serialized = serde_json::to_vec(registration)
        .expect("NodeRegistrationRequest serialization should not fail");
    kv.put_bytes(&key, &serialized)?;

    let token_key = token_storage_key(token);
    kv.put_bytes(&token_key, node_id.as_bytes())
}

pub(crate) fn registration_storage_key(node_id: &str) -> Vec<u8> {
    format!("{}/{}", NODE_REGISTRATION_PREFIX, node_id).into_bytes()
}

pub(crate) fn token_storage_key(token: &str) -> Vec<u8> {
    format!("{}/{}", NODE_TOKEN_PREFIX, token).into_bytes()
}

fn generate_registration_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_node_name() -> String {
    const PREFIX: &str = "ht";
    const SUFFIX_LEN: usize = 5;
    hightower_naming::generate_random_name_with_prefix(Some(PREFIX), Some(SUFFIX_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommonContext, initialize_kv};
    use crate::api::certificates::persist_certificate;
    use crate::api::handlers::auth_keys::store_legacy_key;
    use axum::http::HeaderValue;
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    #[tokio::test]
    async fn register_node_persists_entry_when_authenticated() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        store_legacy_key(&context.kv, "super-secret").expect("store auth key");

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase(AUTH_HEADER.as_bytes()).expect("static header"),
            HeaderValue::from_static("super-secret"),
        );

        let body = NodeRegistrationRequest {
            node_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_node(State(state), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        assert!(!response.0.node_id.is_empty());
        assert!(response.0.node_id.starts_with("ht-"));
        assert!(!response.0.token.is_empty());
        assert!(!response.0.gateway_public_key_hex.is_empty());
        assert_eq!(response.0.gateway_public_key_hex.len(), 64);
        assert!(!response.0.assigned_ip.is_empty());
        assert_eq!(response.0.assigned_ip, "100.64.0.1");

        let stored = context
            .kv
            .get_bytes(registration_storage_key(&response.0.node_id).as_ref())
            .expect("kv read")
            .expect("value present");
        let decoded: NodeRegistrationRequest =
            serde_json::from_slice(&stored).expect("deserialize");

        assert_eq!(decoded.node_id, Some(response.0.node_id));
        assert_eq!(decoded.public_key_hex, body.public_key_hex);
    }

    #[tokio::test]
    async fn register_node_rejects_missing_auth() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        store_legacy_key(&context.kv, "super-secret").expect("store auth key");

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };
        let headers = HeaderMap::new();
        let body = NodeRegistrationRequest {
            node_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_node(State(state), headers, Json(body)).await;
        assert!(matches!(response, Err(RootApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn deregister_node_removes_registration() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        store_legacy_key(&context.kv, "super-secret").expect("store auth key");

        let certificate = crate::startup::startup();
        persist_certificate(&context, &certificate);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase(AUTH_HEADER.as_bytes()).expect("static header"),
            HeaderValue::from_static("super-secret"),
        );

        let body = NodeRegistrationRequest {
            node_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_node(State(state.clone()), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        let node_id = response.0.node_id;
        let token = response.0.token;
        assert!(!node_id.is_empty());
        assert!(!token.is_empty());

        // Verify token was stored
        let token_before = context
            .kv
            .get_bytes(token_storage_key(&token).as_ref())
            .expect("kv read token before deregister")
            .expect("token should exist");
        assert_eq!(token_before, node_id.as_bytes());

        let status = deregister_node(State(state), AxumPath(token))
            .await
            .expect("deregistration succeeds");

        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}
