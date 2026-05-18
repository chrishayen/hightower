use axum::{
    extract::{Json, Path as AxumPath, State},
    http::HeaderMap,
};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::types::{
    ApiState, ConnectionIntent, ConnectionIntentRequest, ConnectionIntentResponse, RootApiError,
    CONNECTION_INTENT_PREFIX,
};
use super::endpoints::{load_registration, resolve_registration_by_id_or_ip, validate_auth};

pub(crate) async fn create_connection_intent(
    State(state): State<ApiState>,
    AxumPath(initiator_endpoint_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<ConnectionIntentRequest>,
) -> Result<Json<ConnectionIntentResponse>, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    validate_auth(&kv, &headers)?;

    let initiator = load_registration(&kv, &initiator_endpoint_id)?;
    let target = resolve_registration_by_id_or_ip(&kv, &body.target)?;
    let target_endpoint_id = target.endpoint_id.clone().ok_or(RootApiError::NotFound)?;
    let connection_id = generate_connection_id();

    let intent = ConnectionIntent {
        connection_id: connection_id.clone(),
        initiator_endpoint_id,
        target_endpoint_id: target_endpoint_id.clone(),
        port: body.port,
        initiator: initiator.clone(),
        target: target.clone(),
        created_at_ms: current_time_ms(),
    };

    let serialized = serde_json::to_vec(&intent)
        .map_err(|err| RootApiError::Internal(format!("failed to serialize intent: {}", err)))?;
    kv.put_bytes(&intent_storage_key(&connection_id), &serialized)
        .map_err(|err| RootApiError::Storage(format!("failed to store intent: {}", err)))?;
    kv.put_bytes(
        &pending_target_key(&target_endpoint_id, &connection_id),
        connection_id.as_bytes(),
    )
    .map_err(|err| RootApiError::Storage(format!("failed to store pending intent: {}", err)))?;

    Ok(Json(ConnectionIntentResponse {
        connection_id,
        port: body.port,
        initiator,
        target,
    }))
}

pub(crate) async fn get_pending_connection_intents(
    State(state): State<ApiState>,
    AxumPath(endpoint_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConnectionIntent>>, RootApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    validate_auth(&kv, &headers)?;
    // Confirm endpoint exists so typoed IDs do not silently return an empty list.
    let _ = load_registration(&kv, &endpoint_id)?;

    let entries = kv
        .list_by_prefix(&pending_target_prefix(&endpoint_id))
        .map_err(|err| RootApiError::Storage(format!("failed to list pending intents: {}", err)))?;

    let mut intents = Vec::new();
    let mut consumed_keys = Vec::new();
    for (key, value) in entries {
        if value == b"__DELETED__" {
            continue;
        }
        let connection_id = String::from_utf8(value)
            .map_err(|_| RootApiError::Internal("invalid connection id encoding".into()))?;
        if kv
            .get_bytes(&consumed_target_key(&endpoint_id, &connection_id))
            .map_err(|err| {
                RootApiError::Storage(format!("failed to read consumed intent marker: {}", err))
            })?
            .is_some()
        {
            continue;
        }
        let data = kv
            .get_bytes(&intent_storage_key(&connection_id))
            .map_err(|err| RootApiError::Storage(format!("failed to read intent: {}", err)))?
            .ok_or(RootApiError::NotFound)?;
        let intent = serde_json::from_slice::<ConnectionIntent>(&data)
            .map_err(|err| RootApiError::Internal(format!("failed to decode intent: {}", err)))?;
        consumed_keys.push((key, connection_id));
        intents.push(intent);
    }

    for (_pending_key, connection_id) in consumed_keys {
        kv.delete(&pending_target_key(&endpoint_id, &connection_id))
            .map_err(|err| {
                RootApiError::Storage(format!("failed to consume pending intent: {}", err))
            })?;
        kv.put_bytes(&consumed_target_key(&endpoint_id, &connection_id), b"1")
            .map_err(|err| {
                RootApiError::Storage(format!("failed to mark consumed intent: {}", err))
            })?;
        kv.delete(&intent_storage_key(&connection_id))
            .map_err(|err| {
                RootApiError::Storage(format!("failed to delete consumed intent: {}", err))
            })?;
    }

    intents.sort_by_key(|intent| intent.created_at_ms);
    Ok(Json(intents))
}

fn intent_storage_key(connection_id: &str) -> Vec<u8> {
    format!("{}/{}", CONNECTION_INTENT_PREFIX, connection_id).into_bytes()
}

fn pending_target_prefix(target_endpoint_id: &str) -> Vec<u8> {
    format!(
        "{}/pending/{}/",
        CONNECTION_INTENT_PREFIX, target_endpoint_id
    )
    .into_bytes()
}

fn pending_target_key(target_endpoint_id: &str, connection_id: &str) -> Vec<u8> {
    format!(
        "{}/pending/{}/{}",
        CONNECTION_INTENT_PREFIX, target_endpoint_id, connection_id
    )
    .into_bytes()
}

fn consumed_target_key(target_endpoint_id: &str, connection_id: &str) -> Vec<u8> {
    format!(
        "{}/consumed/{}/{}",
        CONNECTION_INTENT_PREFIX, target_endpoint_id, connection_id
    )
    .into_bytes()
}

fn generate_connection_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("conn-{}", hex::encode(bytes))
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::certificates::persist_certificate;
    use crate::api::handlers::auth_keys::store_legacy_key;
    use crate::api::handlers::endpoints::register_endpoint;
    use crate::api::types::{EndpointRegistrationRequest, AUTH_HEADER};
    use crate::context::{initialize_kv, CommonContext};
    use axum::http::{HeaderName, HeaderValue};
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase(AUTH_HEADER.as_bytes()).expect("static header"),
            HeaderValue::from_static("super-secret"),
        );
        headers
    }

    fn body(hex_char: char) -> EndpointRegistrationRequest {
        EndpointRegistrationRequest {
            endpoint_id: None,
            public_key_hex: hex_char.to_string().repeat(64),
            token: None,
            assigned_ip: None,
            candidates: vec![],
        }
    }

    async fn setup() -> (ApiState, HeaderMap) {
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
        (state, headers())
    }

    #[tokio::test]
    async fn create_intent_and_pending_lookup_returns_initiator_to_target() {
        let (state, headers) = setup().await;
        let initiator = register_endpoint(State(state.clone()), headers.clone(), Json(body('a')))
            .await
            .expect("register initiator")
            .0;
        let target = register_endpoint(State(state.clone()), headers.clone(), Json(body('b')))
            .await
            .expect("register target")
            .0;

        let response = create_connection_intent(
            State(state.clone()),
            AxumPath(initiator.endpoint_id.clone()),
            headers.clone(),
            Json(ConnectionIntentRequest {
                target: target.endpoint_id.clone(),
                port: 8080,
            }),
        )
        .await
        .expect("intent created")
        .0;

        assert_eq!(
            response.initiator.endpoint_id.as_deref(),
            Some(initiator.endpoint_id.as_str())
        );
        assert_eq!(
            response.target.endpoint_id.as_deref(),
            Some(target.endpoint_id.as_str())
        );

        let pending = get_pending_connection_intents(
            State(state.clone()),
            AxumPath(target.endpoint_id.clone()),
            headers.clone(),
        )
        .await
        .expect("pending lookup")
        .0;

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].connection_id, response.connection_id);
        assert_eq!(pending[0].initiator_endpoint_id, initiator.endpoint_id);
        assert_eq!(pending[0].target_endpoint_id, target.endpoint_id);
        assert_eq!(pending[0].port, 8080);

        let pending_again = get_pending_connection_intents(
            State(state),
            AxumPath(target.endpoint_id.clone()),
            headers,
        )
        .await
        .expect("second pending lookup")
        .0;
        assert!(pending_again.is_empty());
    }
}
