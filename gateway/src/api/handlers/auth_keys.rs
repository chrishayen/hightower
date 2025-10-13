use askama::Template;
use axum::{
    extract::{Json, Path as AxumPath, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::context::NamespacedKv;
use super::super::types::{ApiState, AuthKeysListTemplate};

const AUTH_KEYS_PREFIX: &str = "auth/keys";

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthKey {
    pub key_id: String,
    pub key_hash: String,
    pub created_at: i64,
    pub last_chars: String,
}

#[derive(Debug, Serialize)]
pub struct GenerateKeyResponse {
    pub key: String,
    pub key_id: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthKeyListItem {
    pub key_id: String,
    pub created_at: i64,
    pub last_chars: String,
}

#[derive(Debug)]
pub enum AuthKeyError {
    Storage(String),
    NotFound,
}

impl IntoResponse for AuthKeyError {
    fn into_response(self) -> Response {
        match self {
            AuthKeyError::Storage(msg) => {
                error!("Auth key storage error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
            }
            AuthKeyError::NotFound => {
                (StatusCode::NOT_FOUND, "key not found").into_response()
            }
        }
    }
}

pub(crate) async fn generate_auth_key(
    State(state): State<ApiState>,
) -> Result<Json<GenerateKeyResponse>, AuthKeyError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let key = generate_key();
    let key_id = generate_key_id();
    let key_hash = hash_key(&key);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let last_chars = key.chars().rev().take(8).collect::<String>()
        .chars().rev().collect::<String>();

    let auth_key = AuthKey {
        key_id: key_id.clone(),
        key_hash,
        created_at,
        last_chars: last_chars.clone(),
    };

    store_auth_key(&kv, &auth_key)?;

    debug!(key_id = %key_id, "Generated new auth key");

    Ok(Json(GenerateKeyResponse {
        key,
        key_id,
        created_at,
    }))
}

pub(crate) async fn list_auth_keys(
    State(state): State<ApiState>,
) -> Result<Response, AuthKeyError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let prefix = AUTH_KEYS_PREFIX.as_bytes();
    let entries = kv
        .list_by_prefix(prefix)
        .map_err(|err| AuthKeyError::Storage(format!("failed to list keys: {}", err)))?;

    let mut keys = Vec::new();
    for (_, value) in entries {
        if value == b"__DELETED__" {
            continue;
        }

        match serde_json::from_slice::<AuthKey>(&value) {
            Ok(auth_key) => {
                keys.push(AuthKeyListItem {
                    key_id: auth_key.key_id,
                    created_at: auth_key.created_at,
                    last_chars: auth_key.last_chars,
                });
            }
            Err(err) => {
                error!(?err, "Failed to deserialize auth key");
            }
        }
    }

    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let template = AuthKeysListTemplate { keys: &keys };
    match template.render() {
        Ok(html) => Ok((StatusCode::OK, Html(html)).into_response()),
        Err(err) => {
            error!(?err, "Failed to render auth keys template");
            Err(AuthKeyError::Storage("failed to render template".into()))
        }
    }
}

pub(crate) async fn revoke_auth_key(
    State(state): State<ApiState>,
    AxumPath(key_id): AxumPath<String>,
) -> Result<Response, AuthKeyError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let key = storage_key(&key_id);

    // Check if key exists
    let exists = kv
        .get_bytes(&key)
        .map_err(|err| AuthKeyError::Storage(format!("failed to read key: {}", err)))?
        .is_some();

    if !exists {
        return Err(AuthKeyError::NotFound);
    }

    kv.put_bytes(&key, b"__DELETED__")
        .map_err(|err| AuthKeyError::Storage(format!("failed to revoke key: {}", err)))?;

    debug!(key_id = %key_id, "Revoked auth key");

    // Return updated list
    list_auth_keys(State(state)).await
}

pub(crate) fn validate_auth_key(kv: &NamespacedKv, provided_key: &str) -> Result<bool, ::kv::Error> {
    let prefix = AUTH_KEYS_PREFIX.as_bytes();
    let entries = kv.list_by_prefix(prefix)?;

    let provided_hash = hash_key(provided_key);

    for (_, value) in entries {
        if value == b"__DELETED__" {
            continue;
        }

        if let Ok(auth_key) = serde_json::from_slice::<AuthKey>(&value) {
            if constant_time_compare(&auth_key.key_hash, &provided_hash) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("ht_{}", hex::encode(bytes))
}

fn generate_key_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn hash_key(key: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }

    result == 0
}

fn storage_key(key_id: &str) -> Vec<u8> {
    format!("{}/{}", AUTH_KEYS_PREFIX, key_id).into_bytes()
}

pub(crate) fn store_auth_key(kv: &NamespacedKv, auth_key: &AuthKey) -> Result<(), AuthKeyError> {
    let key = storage_key(&auth_key.key_id);
    let serialized = serde_json::to_vec(auth_key)
        .map_err(|err| AuthKeyError::Storage(format!("failed to serialize: {}", err)))?;

    kv.put_bytes(&key, &serialized)
        .map_err(|err| AuthKeyError::Storage(format!("failed to store: {}", err)))
}

pub(crate) fn store_legacy_key(kv: &NamespacedKv, key: &str) -> Result<(), AuthKeyError> {
    let key_hash = hash_key(key);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let last_chars = key.chars().rev().take(8).collect::<String>()
        .chars().rev().collect::<String>();

    let auth_key = AuthKey {
        key_id: "default".to_string(),
        key_hash,
        created_at,
        last_chars,
    };

    store_auth_key(kv, &auth_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{initialize_kv, CommonContext};
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    #[tokio::test]
    async fn generate_key_creates_valid_key() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let response = generate_auth_key(State(state))
            .await
            .expect("generate succeeds");

        assert!(response.0.key.starts_with("ht_"));
        assert!(!response.0.key_id.is_empty());
        assert!(response.0.created_at > 0);
    }

    #[tokio::test]
    async fn list_keys_returns_generated_keys() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let _ = generate_auth_key(State(state.clone()))
            .await
            .expect("generate succeeds");

        let response = list_auth_keys(State(state))
            .await
            .expect("list succeeds");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn validate_auth_key_checks_stored_keys() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        let key = "ht_test1234567890abcdef";
        let key_hash = hash_key(key);

        let auth_key = AuthKey {
            key_id: "testid".into(),
            key_hash,
            created_at: 1000,
            last_chars: "90abcdef".into(),
        };

        store_auth_key(&context.kv, &auth_key).expect("store succeeds");

        let valid = validate_auth_key(&context.kv, key).expect("validate succeeds");
        assert!(valid);

        let invalid = validate_auth_key(&context.kv, "ht_wrongkey").expect("validate succeeds");
        assert!(!invalid);
    }
}
