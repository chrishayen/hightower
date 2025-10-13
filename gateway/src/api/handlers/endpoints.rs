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
    ApiState, EndpointRegistrationRequest, EndpointRegistrationResponse, RootApiError,
    AUTH_HEADER, ENDPOINT_REGISTRATION_PREFIX, ENDPOINT_TOKEN_PREFIX,
};

pub(crate) async fn register_endpoint(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<EndpointRegistrationRequest>,
) -> Result<Json<EndpointRegistrationResponse>, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    validate_auth(&kv, &headers)?;

    // Always generate endpoint_id - endpoints never provide their own name
    let endpoint_id = generate_endpoint_name();

    debug!(endpoint_id = %endpoint_id, "Gateway received endpoint registration request");
    ensure_public_key_valid(&body.public_key_hex)?;

    // Allocate IP address for the endpoint
    let assigned_ip = IpAllocator::allocate_ip(&kv, &endpoint_id)
        .map_err(|err| RootApiError::Storage(format!("failed to allocate IP: {}", err)))?;
    debug!(endpoint_id = %endpoint_id, assigned_ip = %assigned_ip, "Assigned IP to endpoint");

    let gateway_public_key_hex = load_gateway_public_key(&kv)?;
    let token = generate_registration_token();

    // Store the assigned IP in the registration
    let mut registration = body.clone();
    registration.endpoint_id = Some(endpoint_id.clone());
    registration.assigned_ip = Some(assigned_ip.clone());

    persist_registration(&kv, &registration, &token).map_err(|err| {
        RootApiError::Storage(format!("failed to persist endpoint registration: {}", err))
    })?;

    // Add endpoint as peer to transport layer
    if let Some(transport) = crate::wireguard_api::get_transport_server() {
        debug!(endpoint_id = %endpoint_id, "gateway: Adding endpoint as WireGuard peer");
        let peer_public_key = hex::decode(&body.public_key_hex)
            .map_err(|_| RootApiError::InvalidPublicKey)?;
        if peer_public_key.len() != 32 {
            return Err(RootApiError::InvalidPublicKey);
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&peer_public_key);

        // We don't know the endpoint's network endpoint yet - they'll connect to us
        if let Err(e) = transport.add_peer(key_array, None).await {
            tracing::error!(
                error = ?e,
                endpoint_id = %endpoint_id,
                "gateway: Failed to add endpoint as WireGuard peer"
            );
        } else {
            debug!(
                endpoint_id = %endpoint_id,
                public_key = &body.public_key_hex[..8],
                "gateway: Successfully added endpoint as WireGuard peer"
            );
        }
    } else {
        debug!(endpoint_id = %endpoint_id, "gateway: WireGuard transport not initialized yet");
    }

    debug!(endpoint_id = %endpoint_id, assigned_ip = %assigned_ip, "Registered endpoint");
    Ok(Json(EndpointRegistrationResponse {
        endpoint_id,
        token,
        gateway_public_key_hex,
        assigned_ip,
    }))
}

pub(crate) async fn deregister_endpoint(
    State(state): State<ApiState>,
    AxumPath(token): AxumPath<String>,
) -> Result<StatusCode, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let token_key = token_storage_key(&token);
    let endpoint_id = kv
        .get_bytes(&token_key)
        .map_err(|err| RootApiError::Storage(format!("failed to read token: {}", err)))?
        .ok_or(RootApiError::Unauthorized)?;

    let endpoint_id = String::from_utf8(endpoint_id)
        .map_err(|_| RootApiError::Internal("invalid endpoint_id encoding".into()))?;

    debug!(endpoint_id = %endpoint_id, "Gateway received endpoint deregistration request");

    let registration_key = registration_storage_key(&endpoint_id);

    // Load registration to get public key for WireGuard cleanup
    let public_key_hex = kv
        .get_bytes(&registration_key)
        .ok()
        .flatten()
        .and_then(|data| {
            serde_json::from_slice::<EndpointRegistrationRequest>(&data)
                .ok()
                .map(|reg| reg.public_key_hex)
        });

    // Disconnect WireGuard peer if available
    if let Some(key_hex) = public_key_hex {
        disconnect_wireguard_peer(&endpoint_id, &key_hex).await;
    }

    kv.put_bytes(&registration_key, b"__DELETED__")
        .map_err(|err| RootApiError::Storage(format!("failed to mark registration deleted: {}", err)))?;

    kv.put_bytes(&token_key, b"__DELETED__")
        .map_err(|err| RootApiError::Storage(format!("failed to mark token deleted: {}", err)))?;

    IpAllocator::release_ip(&kv, &endpoint_id)
        .map_err(|err| RootApiError::Storage(format!("failed to release IP: {}", err)))?;

    debug!(endpoint_id = %endpoint_id, "Deregistered endpoint");
    Ok(StatusCode::NO_CONTENT)
}

async fn disconnect_wireguard_peer(endpoint_id: &str, key_hex: &str) {
    let Some(transport) = crate::wireguard_api::get_transport_server() else {
        return;
    };

    let Ok(peer_public_key) = hex::decode(key_hex) else {
        return;
    };

    if peer_public_key.len() != 32 {
        return;
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&peer_public_key);

    if let Err(e) = transport.disconnect(key_array).await {
        tracing::error!(
            error = ?e,
            endpoint_id = %endpoint_id,
            "gateway: Failed to disconnect WireGuard peer"
        );
        return;
    }

    debug!(
        endpoint_id = %endpoint_id,
        public_key = &key_hex[..8],
        "gateway: Successfully disconnected WireGuard peer"
    );
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
    registration: &EndpointRegistrationRequest,
    token: &str,
) -> Result<(), ::kv::Error> {
    let endpoint_id = registration.endpoint_id.as_ref().expect("endpoint_id must be set before persist");
    let key = registration_storage_key(endpoint_id);
    let serialized = serde_json::to_vec(registration)
        .expect("EndpointRegistrationRequest serialization should not fail");
    kv.put_bytes(&key, &serialized)?;

    let token_key = token_storage_key(token);
    kv.put_bytes(&token_key, endpoint_id.as_bytes())
}

pub(crate) fn registration_storage_key(endpoint_id: &str) -> Vec<u8> {
    format!("{}/{}", ENDPOINT_REGISTRATION_PREFIX, endpoint_id).into_bytes()
}

pub(crate) fn token_storage_key(token: &str) -> Vec<u8> {
    format!("{}/{}", ENDPOINT_TOKEN_PREFIX, token).into_bytes()
}

fn generate_registration_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_endpoint_name() -> String {
    const PREFIX: &str = "ht";
    const SUFFIX_LEN: usize = 4;
    naming::generate_random_name_with_prefix(Some(PREFIX), Some(SUFFIX_LEN))
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
    async fn register_endpoint_persists_entry_when_authenticated() {
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

        let body = EndpointRegistrationRequest {
            endpoint_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_endpoint(State(state), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        assert!(!response.0.endpoint_id.is_empty());
        assert!(response.0.endpoint_id.starts_with("ht-"));
        assert!(!response.0.token.is_empty());
        assert!(!response.0.gateway_public_key_hex.is_empty());
        assert_eq!(response.0.gateway_public_key_hex.len(), 64);
        assert!(!response.0.assigned_ip.is_empty());
        assert_eq!(response.0.assigned_ip, "100.64.0.1");

        let stored = context
            .kv
            .get_bytes(registration_storage_key(&response.0.endpoint_id).as_ref())
            .expect("kv read")
            .expect("value present");
        let decoded: EndpointRegistrationRequest =
            serde_json::from_slice(&stored).expect("deserialize");

        assert_eq!(decoded.endpoint_id, Some(response.0.endpoint_id));
        assert_eq!(decoded.public_key_hex, body.public_key_hex);
    }

    #[tokio::test]
    async fn register_endpoint_rejects_missing_auth() {
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
        let body = EndpointRegistrationRequest {
            endpoint_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_endpoint(State(state), headers, Json(body)).await;
        assert!(matches!(response, Err(RootApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn deregister_endpoint_removes_registration() {
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

        let body = EndpointRegistrationRequest {
            endpoint_id: None,
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let response = register_endpoint(State(state.clone()), headers, Json(body.clone()))
            .await
            .expect("registration succeeds");

        let endpoint_id = response.0.endpoint_id;
        let token = response.0.token;
        assert!(!endpoint_id.is_empty());
        assert!(!token.is_empty());

        // Verify token was stored
        let token_before = context
            .kv
            .get_bytes(token_storage_key(&token).as_ref())
            .expect("kv read token before deregister")
            .expect("token should exist");
        assert_eq!(token_before, endpoint_id.as_bytes());

        let status = deregister_endpoint(State(state), AxumPath(token))
            .await
            .expect("deregistration succeeds");

        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}
