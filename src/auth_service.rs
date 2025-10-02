use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};

use crate::auth_types::{ApiKeyRecord, UserRecord};
use crate::command::Command;
use crate::crypto::{EnvelopeEncryptor, SecretHasher};
use crate::engine::KvEngine;
use crate::error::{Error, Result};
use crate::id_generator::IdGenerator;
use crate::state::ApplyOutcome;

const USER_PREFIX: &str = "auth/user/";
const USERNAME_INDEX_PREFIX: &str = "auth/user_by_name/";
const API_KEY_PREFIX: &str = "auth/apikey/";

pub struct AuthService<E, H, C>
where
    E: KvEngine,
    H: SecretHasher,
    C: EnvelopeEncryptor,
{
    engine: E,
    hasher: H,
    _crypto: C,
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
            _crypto: crypto,
            id_gen: IdGenerator::default(),
        }
    }

    pub fn create_user(&self, username: &str, password: &str) -> Result<UserRecord> {
        let normalized_username = normalize_username(username);
        if normalized_username.is_empty() {
            return Err(Error::Validation("username cannot be empty"));
        }

        if self.lookup_user_id(&normalized_username)?.is_some() {
            return Err(Error::Conflict("auth_service::username_exists"));
        }

        let user_id = format!("usr-{:016x}", self.id_gen.next());
        let password_hash = self.hasher.hash_secret(password.as_bytes())?;
        let record = UserRecord {
            user_id: user_id.clone(),
            username: username.trim().to_string(),
            password_hash,
            metadata: None,
            created_at: current_timestamp(),
            last_login: None,
            failed_attempts: 0,
        };
        record.validate()?;

        self.persist_user_record(&record)?;
        self.put_value(username_index_key(&normalized_username), user_id.into_bytes())?;

        Ok(record)
    }

    pub fn verify_password(&self, username: &str, password: &str) -> Result<bool> {
        let normalized_username = normalize_username(username);
        if normalized_username.is_empty() {
            return Ok(false);
        }

        let mut record = match self.load_user_by_username(&normalized_username)? {
            Some(record) => record,
            None => return Ok(false),
        };

        let verified = self
            .hasher
            .verify_secret(password.as_bytes(), &record.password_hash)?;
        if verified {
            record.last_login = Some(current_timestamp());
            record.failed_attempts = 0;
            self.persist_user_record(&record)?;
            return Ok(true);
        }

        record.failed_attempts = record.failed_attempts.saturating_add(1);
        self.persist_user_record(&record)?;
        Ok(false)
    }

    pub fn create_api_key(
        &self,
        user_id: &str,
        label: Option<&str>,
    ) -> Result<(ApiKeyRecord, String)> {
        let Some(_user) = self.load_user_by_id(user_id)? else {
            return Err(Error::NotFound("auth_service::user"));
        };

        let key_id = format!("key-{:016x}", self.id_gen.next());
        let secret = random_token();
        let token_hash = self.hasher.hash_secret(secret.as_bytes())?;
        let record = ApiKeyRecord {
            key_id: key_id.clone(),
            owner_id: user_id.to_string(),
            token_hash,
            label: label.map(|value| value.to_string()),
            metadata: None,
            created_at: current_timestamp(),
            last_used: None,
        };
        record.validate()?;

        self.persist_api_key_record(&record)?;
        let token = format!("{key_id}.{secret}");
        Ok((record, token))
    }

    pub fn authenticate_api_key(&self, token: &str) -> Result<Option<ApiKeyRecord>> {
        let (key_id, secret) = match token.split_once('.') {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let mut record = match self.load_api_key_record(key_id)? {
            Some(record) => record,
            None => return Ok(None),
        };

        if !self
            .hasher
            .verify_secret(secret.as_bytes(), &record.token_hash)?
        {
            return Ok(None);
        }

        record.last_used = Some(current_timestamp());
        self.persist_api_key_record(&record)?;
        Ok(Some(record))
    }

    fn persist_user_record(&self, record: &UserRecord) -> Result<()> {
        let key = user_key(&record.user_id);
        let bytes = serialize(record)?;
        self.put_value(key, bytes)
    }

    fn persist_api_key_record(&self, record: &ApiKeyRecord) -> Result<()> {
        let key = api_key_key(&record.key_id);
        let bytes = serialize(record)?;
        self.put_value(key, bytes)
    }

    fn load_user_by_username(&self, normalized_username: &str) -> Result<Option<UserRecord>> {
        let Some(user_id) = self.lookup_user_id(normalized_username)? else {
            return Ok(None);
        };
        self.load_user_by_id(&user_id)
    }

    fn load_user_by_id(&self, user_id: &str) -> Result<Option<UserRecord>> {
        self.fetch_record(user_key(user_id))
    }

    fn load_api_key_record(&self, key_id: &str) -> Result<Option<ApiKeyRecord>> {
        self.fetch_record(api_key_key(key_id))
    }

    fn fetch_record<T>(&self, key: Vec<u8>) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        match self.engine.get(key.as_slice())? {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    fn lookup_user_id(&self, normalized_username: &str) -> Result<Option<String>> {
        let key = username_index_key(normalized_username);
        match self.engine.get(key.as_slice())? {
            Some(bytes) => {
                let user_id = String::from_utf8(bytes)
                    .map_err(|_| Error::Serialization("invalid username index utf8".into()))?;
                Ok(Some(user_id))
            }
            None => Ok(None),
        }
    }

    fn put_value(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let command = Command::Set {
            key,
            value,
            version: self.id_gen.next(),
            timestamp: current_timestamp(),
        };
        match self.engine.submit(command)? {
            ApplyOutcome::Applied => Ok(()),
            ApplyOutcome::Removed => Err(Error::Invariant("auth_service::put_value_removed")),
            ApplyOutcome::IgnoredStale => Err(Error::Invariant("auth_service::put_value_stale")),
        }
    }
}

fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

fn username_index_key(username: &str) -> Vec<u8> {
    format!("{USERNAME_INDEX_PREFIX}{username}").into_bytes()
}

fn user_key(user_id: &str) -> Vec<u8> {
    format!("{USER_PREFIX}{user_id}").into_bytes()
}

fn api_key_key(key_id: &str) -> Vec<u8> {
    format!("{API_KEY_PREFIX}{key_id}").into_bytes()
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0)
}

fn serialize<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    serde_cbor::to_vec(value).map_err(|err| Error::Serialization(err.to_string()))
}

fn deserialize<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_cbor::from_slice(bytes).map_err(|err| Error::Serialization(err.to_string()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::crypto::{AesGcmEncryptor, Argon2SecretHasher};
    use crate::engine::SingleNodeEngine;
    use tempfile::tempdir;

    #[test]
    fn create_user_persists_record_and_index() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp
            .path()
            .join("create-user")
            .to_string_lossy()
            .into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        let svc = AuthService::new(
            engine,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );
        let record = svc.create_user("Alice", "secret").unwrap();
        assert_eq!(record.username, "Alice");
        assert!(svc.verify_password("alice", "secret").unwrap());
        assert!(!svc.verify_password("alice", "wrong").unwrap());
    }

    #[test]
    fn duplicate_usernames_are_rejected() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp
            .path()
            .join("duplicate-user")
            .to_string_lossy()
            .into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        let svc = AuthService::new(
            engine,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );
        svc.create_user("bob", "secret").unwrap();
        let err = svc.create_user("BOB", "secret").unwrap_err();
        assert!(matches!(err, Error::Conflict("auth_service::username_exists")));
    }

    #[test]
    fn create_api_key_returns_token_that_round_trips() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp
            .path()
            .join("create-key")
            .to_string_lossy()
            .into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        let svc = AuthService::new(
            engine,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );
        let user = svc.create_user("user", "pass").unwrap();
        let (key_record, token) = svc.create_api_key(&user.user_id, Some("primary")).unwrap();
        assert!(token.starts_with(&key_record.key_id));
        let fetched = svc.authenticate_api_key(&token).unwrap().unwrap();
        assert_eq!(fetched.key_id, key_record.key_id);
        assert_eq!(fetched.owner_id, user.user_id);
    }

    #[test]
    fn authenticate_api_key_rejects_invalid_tokens() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp
            .path()
            .join("invalid-token")
            .to_string_lossy()
            .into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        let svc = AuthService::new(
            engine,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );
        svc.create_user("user", "pass").unwrap();
        assert!(svc.authenticate_api_key("invalid").unwrap().is_none());
    }
}
