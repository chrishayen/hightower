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
fn auth_service_currently_unimplemented() {
    let temp = tempdir().unwrap();
    let mut cfg = StoreConfig::default();
    cfg.data_dir = temp.path().join("auth-int").to_string_lossy().into_owned();
    let engine = SingleNodeEngine::with_config(cfg).unwrap();
    let service = AuthService::new(
        engine,
        Argon2SecretHasher::default(),
        AesGcmEncryptor::new([0u8; 32]),
    );
    let err = service.create_user("alice", "password").unwrap_err();
    assert!(matches!(
        err,
        crate::error::Error::Unimplemented("auth_service::create_user")
    ));
}
