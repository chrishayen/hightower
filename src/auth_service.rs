use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Serialize, de::DeserializeOwned};

use crate::auth_types::{ApiKeyRecord, UserRecord};
use crate::command::Command;
use crate::crypto::{EncryptedBlob, EnvelopeEncryptor, SecretHasher};
use crate::engine::KvEngine;
use crate::error::{Error, Result};
use crate::id_generator::IdGenerator;
use crate::state::ApplyOutcome;

const USER_PREFIX: &str = "auth/user/";
const USERNAME_INDEX_PREFIX: &str = "auth/user_by_name/";
const API_KEY_PREFIX: &str = "auth/apikey/";

/// Service for managing user authentication and API key lifecycle
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
    /// Creates a new authentication service with the provided engine, hasher, and encryptor
    pub fn new(engine: E, hasher: H, crypto: C) -> Self {
        Self {
            engine,
            hasher,
            crypto,
            id_gen: IdGenerator::default(),
        }
    }

    /// Creates a new user with the given username and password
    pub fn create_user(&self, username: &str, password: &str) -> Result<UserRecord> {
        self.create_user_with_metadata(username, password, None)
    }

    /// Creates a new user with the given username, password, and optional encrypted metadata
    pub fn create_user_with_metadata(
        &self,
        username: &str,
        password: &str,
        metadata: Option<&[u8]>,
    ) -> Result<UserRecord> {
        let normalized_username = normalize_username(username);
        if normalized_username.is_empty() {
            return Err(Error::Validation("username cannot be empty"));
        }

        if self.lookup_user_id(&normalized_username)?.is_some() {
            return Err(Error::Conflict("auth_service::username_exists"));
        }

        let user_id = format!("usr-{:016x}", self.id_gen.next());
        let password_hash = self.hasher.hash_secret(password.as_bytes())?;
        let metadata = self.encrypt_optional(metadata)?;
        let record = UserRecord {
            user_id: user_id.clone(),
            username: username.trim().to_string(),
            password_hash,
            metadata,
            created_at: current_timestamp(),
            last_login: None,
            failed_attempts: 0,
        };
        record.validate()?;

        self.persist_user_record(&record)?;
        self.put_value(
            username_index_key(&normalized_username),
            user_id.into_bytes(),
        )?;

        Ok(record)
    }

    /// Verifies a username and password combination, updating last login and failed attempts
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

    /// Creates a new API key for the specified user and returns the record and token
    pub fn create_api_key(
        &self,
        user_id: &str,
        label: Option<&str>,
    ) -> Result<(ApiKeyRecord, String)> {
        self.create_api_key_with_metadata(user_id, label, None)
    }

    /// Creates a new API key with optional label and encrypted metadata
    pub fn create_api_key_with_metadata(
        &self,
        user_id: &str,
        label: Option<&str>,
        metadata: Option<&[u8]>,
    ) -> Result<(ApiKeyRecord, String)> {
        let Some(_user) = self.load_user_by_id(user_id)? else {
            return Err(Error::NotFound("auth_service::user"));
        };

        let key_id = format!("key-{:016x}", self.id_gen.next());
        let secret = random_token();
        let token_hash = self.hasher.hash_secret(secret.as_bytes())?;
        let metadata = self.encrypt_optional(metadata)?;
        let record = ApiKeyRecord {
            key_id: key_id.clone(),
            owner_id: user_id.to_string(),
            token_hash,
            label: label.map(|value| value.to_string()),
            metadata,
            created_at: current_timestamp(),
            last_used: None,
        };
        record.validate()?;

        self.persist_api_key_record(&record)?;
        let token = format!("{key_id}.{secret}");
        Ok((record, token))
    }

    /// Authenticates an API key token and returns the key record if valid
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

    /// Revokes an API key by deleting its record, returning true if the key existed
    pub fn revoke_api_key(&self, key_id: &str) -> Result<bool> {
        if self.load_api_key_record(key_id)?.is_none() {
            return Ok(false);
        }

        // Use microseconds since epoch for consistent versioning
        let version = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_micros() as u64)
            .unwrap_or_else(|_| self.id_gen.next());

        let command = Command::Delete {
            key: api_key_key(key_id),
            version,
            timestamp: current_timestamp(),
        };

        match self.engine.submit(command)? {
            ApplyOutcome::Removed => Ok(true),
            ApplyOutcome::IgnoredStale => Ok(false),
            ApplyOutcome::Applied => Ok(true),
        }
    }

    /// Decrypts and returns the user's metadata if present
    pub fn decrypt_user_metadata(&self, user: &UserRecord) -> Result<Option<Vec<u8>>> {
        self.decrypt_optional(user.metadata.as_ref())
    }

    /// Decrypts and returns the API key's metadata if present
    pub fn decrypt_api_key_metadata(&self, api_key: &ApiKeyRecord) -> Result<Option<Vec<u8>>> {
        self.decrypt_optional(api_key.metadata.as_ref())
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

    fn encrypt_optional(&self, payload: Option<&[u8]>) -> Result<Option<EncryptedBlob>> {
        match payload {
            Some(bytes) if !bytes.is_empty() => Ok(Some(self.crypto.encrypt(bytes)?)),
            Some(_) | None => Ok(None),
        }
    }

    fn decrypt_optional(&self, blob: Option<&EncryptedBlob>) -> Result<Option<Vec<u8>>> {
        match blob {
            Some(blob) => self.crypto.decrypt(blob).map(Some),
            None => Ok(None),
        }
    }

    fn put_value(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        // Use microseconds since epoch to ensure unique versions across instances
        // This provides monotonically increasing versions that won't conflict
        // between different AuthService instances
        let version = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_micros() as u64)
            .unwrap_or_else(|_| self.id_gen.next());

        let command = Command::Set {
            key,
            value,
            version,
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

    type TestService = AuthService<SingleNodeEngine, Argon2SecretHasher, AesGcmEncryptor>;

    fn build_service(suffix: &str, key: [u8; 32]) -> (TestService, tempfile::TempDir) {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp
            .path()
            .join(format!("auth-{suffix}"))
            .to_string_lossy()
            .into_owned();
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        (
            AuthService::new(
                engine,
                Argon2SecretHasher::default(),
                AesGcmEncryptor::new(key),
            ),
            temp,
        )
    }

    #[test]
    fn create_user_persists_record_and_index() {
        let (svc, _guard) = build_service("create-user", [0u8; 32]);
        let record = svc.create_user("Alice", "secret").unwrap();
        assert_eq!(record.username, "Alice");
        assert!(svc.verify_password("alice", "secret").unwrap());
        assert!(!svc.verify_password("alice", "wrong").unwrap());
    }

    #[test]
    fn duplicate_usernames_are_rejected() {
        let (svc, _guard) = build_service("duplicate-user", [1u8; 32]);
        svc.create_user("bob", "secret").unwrap();
        let err = svc.create_user("BOB", "secret").unwrap_err();
        assert!(matches!(
            err,
            Error::Conflict("auth_service::username_exists")
        ));
    }

    #[test]
    fn create_api_key_returns_token_that_round_trips() {
        let key_bytes = [2u8; 32];
        let (svc, _guard) = build_service("create-key", key_bytes);
        let user = svc.create_user("user", "pass").unwrap();
        let (key_record, token) = svc.create_api_key(&user.user_id, Some("primary")).unwrap();
        assert!(token.starts_with(&key_record.key_id));
        let fetched = svc.authenticate_api_key(&token).unwrap().unwrap();
        assert_eq!(fetched.key_id, key_record.key_id);
        assert_eq!(fetched.owner_id, user.user_id);
    }

    #[test]
    fn authenticate_api_key_rejects_invalid_tokens() {
        let (svc, _guard) = build_service("invalid-token", [3u8; 32]);
        svc.create_user("user", "pass").unwrap();
        assert!(svc.authenticate_api_key("invalid").unwrap().is_none());
    }

    #[test]
    fn revoke_api_key_removes_record() {
        let (svc, _guard) = build_service("revoke-key", [7u8; 32]);
        let user = svc.create_user("user", "secret").unwrap();
        let (record, token) = svc.create_api_key(&user.user_id, Some("session")).unwrap();
        assert!(svc.authenticate_api_key(&token).unwrap().is_some());
        assert!(svc.revoke_api_key(&record.key_id).unwrap());
        assert!(svc.authenticate_api_key(&token).unwrap().is_none());
        assert!(!svc.revoke_api_key(&record.key_id).unwrap());
    }

    #[test]
    fn user_metadata_is_encrypted() {
        let key_bytes = [4u8; 32];
        let (svc, _guard) = build_service("user-metadata", key_bytes);
        let record = svc
            .create_user_with_metadata("user", "secret", Some(b"payload"))
            .unwrap();
        let plaintext = svc.decrypt_user_metadata(&record).unwrap().unwrap();
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn api_key_metadata_is_encrypted() {
        let key_bytes = [5u8; 32];
        let (svc, _guard) = build_service("apikey-metadata", key_bytes);
        let user = svc.create_user("user", "secret").unwrap();
        let (record, _) = svc
            .create_api_key_with_metadata(&user.user_id, None, Some(b"api-metadata"))
            .unwrap();
        let plaintext = svc.decrypt_api_key_metadata(&record).unwrap().unwrap();
        assert_eq!(plaintext, b"api-metadata");
    }

    #[test]
    fn wrong_password_returns_false_without_panicking() {
        let (svc, _guard) = build_service("wrong-password", [6u8; 32]);
        svc.create_user("user", "secret").unwrap();
        assert!(!svc.verify_password("user", "nope").unwrap());
        assert!(!svc.verify_password("missing", "secret").unwrap());
    }

    #[test]
    fn decrypt_helpers_gracefully_handle_missing_metadata() {
        let (svc, _guard) = build_service("missing-metadata", [8u8; 32]);
        let user = svc.create_user("user", "secret").unwrap();
        assert!(svc.decrypt_user_metadata(&user).unwrap().is_none());
        let (api_key, _) = svc.create_api_key(&user.user_id, None).unwrap();
        assert!(svc.decrypt_api_key_metadata(&api_key).unwrap().is_none());
    }

    #[test]
    fn api_key_with_wrong_secret_is_rejected() {
        let (svc, _guard) = build_service("wrong-secret", [7u8; 32]);
        let user = svc.create_user("user", "secret").unwrap();
        let (record, token) = svc.create_api_key(&user.user_id, None).unwrap();
        let mut pieces = token.split('.');
        let key_id = pieces.next().unwrap();
        let bad_token = format!("{key_id}.bogus");
        assert!(svc.authenticate_api_key(&bad_token).unwrap().is_none());
        assert!(
            svc.authenticate_api_key(&format!("{}.{}", record.key_id, "notreal"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn multiple_auth_service_instances_should_not_conflict() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp
            .path()
            .join("multi-auth")
            .to_string_lossy()
            .into_owned();

        // Create the engine and first auth service
        let engine1 = SingleNodeEngine::with_config(cfg.clone()).unwrap();
        let auth1 = AuthService::new(
            engine1,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );

        // Create user with first auth service
        let user_record = auth1.create_user("testuser", "password123").unwrap();
        assert_eq!(user_record.username, "testuser");

        // Create a second auth service instance with a new engine pointing to the same data
        let engine2 = SingleNodeEngine::with_config(cfg).unwrap();
        let auth2 = AuthService::new(
            engine2,
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new([0u8; 32]),
        );

        // This should succeed but currently fails with stale version error
        // because auth2 has its own IdGenerator starting from 1
        let result = auth2.verify_password("testuser", "password123");

        // This test currently fails but should pass after the fix
        assert!(result.is_ok(), "Second auth service should be able to verify password");
        assert!(result.unwrap(), "Password should be verified successfully");
    }
}
