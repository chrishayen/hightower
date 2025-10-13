use crate::auth_service::AuthService;
use crate::config::StoreConfig;
use crate::crypto::{AesGcmEncryptor, Argon2SecretHasher};
use crate::engine::{KvEngine, SingleNodeEngine};
use tempfile::tempdir;

#[test]
fn engine_round_trip_integration() {
    let temp = tempdir().unwrap();
    let mut cfg = StoreConfig::default();
    cfg.data_dir = temp
        .path()
        .join("engine-int")
        .to_string_lossy()
        .into_owned();
    let engine = SingleNodeEngine::with_config(cfg).unwrap();
    engine.put(b"alpha".to_vec(), b"beta".to_vec()).unwrap();
    assert_eq!(engine.get(b"alpha").unwrap(), Some(b"beta".to_vec()));
}

#[test]
fn auth_service_round_trip() {
    let temp = tempdir().unwrap();
    let mut cfg = StoreConfig::default();
    cfg.data_dir = temp.path().join("auth-int").to_string_lossy().into_owned();
    let engine = SingleNodeEngine::with_config(cfg).unwrap();
    let service = AuthService::new(
        engine,
        Argon2SecretHasher::default(),
        AesGcmEncryptor::new([0u8; 32]),
    );
    let user = service.create_user("alice", "password").unwrap();
    assert!(service.verify_password("alice", "password").unwrap());
    let (_, token) = service
        .create_api_key(&user.user_id, Some("default"))
        .unwrap();
    let authenticated = service.authenticate_api_key(&token).unwrap();
    assert!(authenticated.is_some());
}
