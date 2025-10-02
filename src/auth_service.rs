use crate::auth_types::{ApiKeyRecord, UserRecord};
use crate::crypto::{EnvelopeEncryptor, SecretHasher};
use crate::engine::KvEngine;
use crate::error::{Error, Result};
use crate::id_generator::IdGenerator;

pub struct AuthService<E, H, C>
where
    E: KvEngine,
    H: SecretHasher,
    C: EnvelopeEncryptor,
{
    engine: E,
    hasher: H,
    crypto: C,
    id_gen: IdGenerator,
}

impl<E, H, C> AuthService<E, H, C>
where
    E: KvEngine,
    H: SecretHasher,
    C: EnvelopeEncryptor,
{
    pub fn new(engine: E, hasher: H, crypto: C) -> Self {
        Self {
            engine,
            hasher,
            crypto,
            id_gen: IdGenerator::default(),
        }
    }

    pub fn create_user(&self, _username: &str, _password: &str) -> Result<UserRecord> {
        let _ = (&self.engine, &self.hasher, &self.crypto);
        let _ = self.id_gen.next();
        Err(Error::Unimplemented("auth_service::create_user"))
    }

    pub fn verify_password(&self, _username: &str, _password: &str) -> Result<bool> {
        let _ = (&self.engine, &self.hasher);
        Err(Error::Unimplemented("auth_service::verify_password"))
    }

    pub fn create_api_key(
        &self,
        _user_id: &str,
        _label: Option<&str>,
    ) -> Result<(ApiKeyRecord, String)> {
        let _ = (&self.engine, &self.crypto);
        let _ = self.id_gen.next();
        Err(Error::Unimplemented("auth_service::create_api_key"))
    }

    pub fn authenticate_api_key(&self, _token: &str) -> Result<Option<ApiKeyRecord>> {
        Err(Error::Unimplemented("auth_service::authenticate_api_key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AesGcmEncryptor, Argon2SecretHasher};
    use crate::engine::SingleNodeEngine;
    use tempfile::tempdir;

    #[test]
    fn new_service_instantiates() {
        let temp = tempdir().unwrap();
        let mut cfg = crate::config::StoreConfig::default();
        cfg.data_dir = temp.path().join("auth-data").to_string_lossy().into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        let service = AuthService::new(
            engine,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );
        let err = service.verify_password("user", "secret").unwrap_err();
        assert!(matches!(
            err,
            Error::Unimplemented("auth_service::verify_password")
        ));
    }

    #[test]
    fn create_user_unimplemented() {
        let temp = tempdir().unwrap();
        let mut cfg = crate::config::StoreConfig::default();
        cfg.data_dir = temp.path().join("auth-data").to_string_lossy().into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        let service = AuthService::new(
            engine,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );
        let err = service.create_user("user", "pass").unwrap_err();
        assert!(matches!(
            err,
            Error::Unimplemented("auth_service::create_user")
        ));
    }
}
