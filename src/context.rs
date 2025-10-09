use std::borrow::Cow;
use std::env::VarError;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

mod kv {
    use hightower_kv::{
        AuthService, Error as KvError, KvEngine, SingleNodeEngine, StoreConfig,
        command::Command,
        crypto::{AesGcmEncryptor, Argon2SecretHasher},
    };
    use rand::RngCore;
    use std::error::Error;
    use std::fmt;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::{Builder as TempDirBuilder, TempDir};
    use tracing::{debug, info, warn};

    const AUTH_MASTER_KEY: &[u8] = b"secrets/auth_master_key";

    type SharedEngine = Arc<SingleNodeEngine>;
    type SharedAuthService = AuthService<SharedEngine, Argon2SecretHasher, AesGcmEncryptor>;

    pub type GatewayAuthService = SharedAuthService;

    #[derive(Debug)]
    pub enum KvInitError {
        TempDir(std::io::Error),
        CreateDir(std::io::Error),
        Store(KvError),
    }

    impl fmt::Display for KvInitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                KvInitError::TempDir(err) => {
                    write!(f, "failed to create temporary directory: {}", err)
                }
                KvInitError::CreateDir(err) => {
                    write!(f, "failed to create data directory: {}", err)
                }
                KvInitError::Store(err) => {
                    write!(f, "failed to start key-value engine: {}", err)
                }
            }
        }
    }

    impl Error for KvInitError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                KvInitError::TempDir(err) | KvInitError::CreateDir(err) => Some(err),
                KvInitError::Store(err) => Some(err),
            }
        }
    }

    pub struct KvHandle {
        engine: SharedEngine,
        auth: Arc<SharedAuthService>,
        #[allow(dead_code)]
        data_dir: PathBuf,
        #[allow(dead_code)]
        temp_dir: Option<TempDir>,
    }

    impl fmt::Debug for KvHandle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("KvHandle")
                .field("data_dir", &self.data_dir)
                .field(
                    "temp_dir",
                    &self.temp_dir.as_ref().map(|dir| dir.path().to_path_buf()),
                )
                .finish()
        }
    }

    impl KvHandle {
        pub fn data_dir(&self) -> &Path {
            &self.data_dir
        }

        #[cfg(test)]
        pub fn temp_dir_path(&self) -> Option<&Path> {
            self.temp_dir.as_ref().map(|dir| dir.path())
        }

        pub fn put_bytes(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
            let (version, timestamp) = monotonic_version_timestamp();
            self.engine.submit(Command::Set {
                key: key.to_vec(),
                value: value.to_vec(),
                version,
                timestamp,
            })?;
            Ok(())
        }

        pub fn put_secret(&self, key: &[u8], value: &[u8]) {
            if let Err(err) = self.put_bytes(key, value) {
                warn!(?err, "Failed to persist secret to KV");
            }
        }

        pub fn get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
            self.engine.get(key)
        }

        pub fn auth(&self) -> Arc<SharedAuthService> {
            Arc::clone(&self.auth)
        }

        pub fn get_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
            self.engine.get_prefix(prefix)
        }
    }

    pub fn initialize(dir: Option<&Path>) -> Result<KvHandle, KvInitError> {
        let (data_dir, temp_dir) = match dir {
            Some(path) => {
                fs::create_dir_all(path).map_err(KvInitError::CreateDir)?;
                (path.to_path_buf(), None)
            }
            None => {
                let temp = TempDirBuilder::new()
                    .prefix("hightower-kv")
                    .tempdir()
                    .map_err(KvInitError::TempDir)?;
                (temp.path().to_path_buf(), Some(temp))
            }
        };

        let mut config = StoreConfig::default();
        config.data_dir = data_dir.to_string_lossy().into_owned();

        let engine = SingleNodeEngine::with_config(config).map_err(KvInitError::Store)?;
        let master_key = load_or_initialize_master_key(&engine).map_err(KvInitError::Store)?;
        let (engine, auth) = engine.into_argon2_hasher_aes_gcm_auth_service(master_key);
        let auth = Arc::new(auth);
        let temporary = temp_dir.is_some();
        debug!(path = %data_dir.display(), temporary, "Initialized key-value store");

        Ok(KvHandle {
            engine,
            auth,
            data_dir,
            temp_dir,
        })
    }

    fn load_or_initialize_master_key(engine: &SingleNodeEngine) -> Result<[u8; 32], KvError> {
        match engine.get(AUTH_MASTER_KEY)? {
            Some(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(key) => Ok(key),
                Err(_) => {
                    warn!(
                        stored_len = bytes.len(),
                        "Stored auth master key has unexpected length; generating a new key"
                    );
                    generate_and_persist_master_key(engine)
                }
            },
            None => generate_and_persist_master_key(engine),
        }
    }

    fn generate_and_persist_master_key(engine: &SingleNodeEngine) -> Result<[u8; 32], KvError> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let (version, timestamp) = monotonic_version_timestamp();
        engine.submit(Command::Set {
            key: AUTH_MASTER_KEY.to_vec(),
            value: key.to_vec(),
            version,
            timestamp,
        })?;
        info!("Provisioned new auth master key");
        Ok(key)
    }

    fn monotonic_version_timestamp() -> (u64, i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let millis = now.as_millis();
        let version = millis.min(u64::MAX as u128) as u64;
        let timestamp = millis.min(i64::MAX as u128) as i64;
        (version, timestamp)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn initialize_uses_provided_directory() {
            let temp_root = TempDirBuilder::new()
                .prefix("hightower-test")
                .tempdir()
                .unwrap();
            let target = temp_root.path().join("kv-store");

            let handle = initialize(Some(&target)).expect("kv init succeeds");

            assert_eq!(handle.data_dir(), target.as_path());
            assert!(target.exists());
            assert!(handle.temp_dir_path().is_none());
        }

        #[test]
        fn initialize_falls_back_to_temp_directory() {
            let handle = initialize(None).expect("kv init succeeds");

            let temp_dir = handle.temp_dir_path().expect("temp dir is retained");
            assert!(temp_dir.exists());
            assert!(handle.data_dir().starts_with(temp_dir));
        }

        #[test]
        fn put_bytes_persists_values() {
            let handle = initialize(None).expect("kv init succeeds");
            let key = b"kv-tests/cert";
            let value = b"payload";

            handle.put_bytes(key, value).expect("write succeeds");

            let stored = handle.get_bytes(key).expect("read succeeds");
            assert_eq!(stored, Some(value.to_vec()));
        }

        #[test]
        fn put_secret_does_not_panic_on_failure() {
            let handle = initialize(None).expect("kv init succeeds");
            let key = b"kv-tests/secret";

            handle.put_secret(key, b"secret");
            let stored = handle.get_bytes(key).expect("read succeeds");
            assert!(stored.is_some());
        }
    }
}

mod token {
    use std::env::VarError;
    use std::fmt;

    #[derive(Debug, PartialEq, Eq)]
    pub enum TokenError {
        Missing,
    }

    impl fmt::Display for TokenError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TokenError::Missing => {
                    write!(f, "HT_AUTH_KEY environment variable must be set.")
                }
            }
        }
    }

    impl std::error::Error for TokenError {}

    pub fn fetch<F>(mut lookup: F) -> Result<String, TokenError>
    where
        F: FnMut(&str) -> Result<String, VarError>,
    {
        lookup("HT_AUTH_KEY").map_err(|_| TokenError::Missing)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fetch_returns_token_when_present() {
            let token = fetch(|_| Ok(String::from("123"))).expect("token should be present");

            assert_eq!(token, "123");
        }

        #[test]
        fn fetch_reports_missing_token() {
            let error =
                fetch(|_| Err(VarError::NotPresent)).expect_err("token should be missing");

            assert_eq!(error, TokenError::Missing);
        }
    }
}

pub use kv::{GatewayAuthService, KvHandle, KvInitError, initialize as initialize_kv};
pub use token::{TokenError, fetch as fetch_token};

pub const NODE_NAME_KEY: &[u8] = b"nodes/name";
pub const NODE_CERTIFICATE_KEY: &[u8] = b"certificates/node";
pub const GATEWAY_CERTIFICATE_KEY: &[u8] = b"certificates/gateway";
pub const GATEWAY_PUBLIC_KEY: &[u8] = b"certificates/gateway_public_key";
pub const HT_AUTH_KEY: &[u8] = b"secrets/ht_auth_key";
const DEFAULT_AUTH_USERNAME_ENV: &str = "HT_DEFAULT_USER";
const DEFAULT_AUTH_PASSWORD_ENV: &str = "HT_DEFAULT_PASSWORD";
const DEFAULT_AUTH_USERNAME: &str = "admin";
const DEFAULT_AUTH_PASSWORD: &str = "admin";

#[derive(Clone)]
pub struct CommonContext {
    pub kv: NamespacedKv,
    pub auth: Arc<GatewayAuthService>,
}

impl CommonContext {
    pub fn new(kv: KvHandle) -> Self {
        let kv = NamespacedKv::from_handle(kv);
        let auth = kv.auth_service();
        Self { kv, auth }
    }

    pub fn namespaced(&self, prefix: &[u8]) -> Self {
        Self {
            kv: self.kv.clone_with_additional_prefix(prefix),
            auth: Arc::clone(&self.auth),
        }
    }
}

impl fmt::Debug for CommonContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonContext")
            .field("kv", &self.kv)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct NamespacedKv {
    inner: Arc<KvHandle>,
    prefix: Option<Vec<u8>>,
}

impl NamespacedKv {
    pub fn from_handle(kv: KvHandle) -> Self {
        Self {
            inner: Arc::new(kv),
            prefix: None,
        }
    }

    fn with_parts(inner: Arc<KvHandle>, prefix: Option<Vec<u8>>) -> Self {
        Self { inner, prefix }
    }

    pub fn clone_with_additional_prefix(&self, additional: &[u8]) -> Self {
        let prefix = match &self.prefix {
            Some(existing) => {
                let mut composed = existing.clone();
                if !existing.is_empty() {
                    composed.push(b'/');
                }
                composed.extend_from_slice(additional);
                composed
            }
            None => additional.to_vec(),
        };

        Self::with_parts(Arc::clone(&self.inner), Some(prefix))
    }

    pub fn put_bytes(&self, key: &[u8], value: &[u8]) -> Result<(), hightower_kv::Error> {
        let key = self.prefixed_key(key);
        self.inner.put_bytes(key.as_ref(), value)
    }

    pub fn put_secret(&self, key: &[u8], value: &[u8]) {
        let key = self.prefixed_key(key);
        self.inner.put_secret(key.as_ref(), value);
    }

    pub fn get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>, hightower_kv::Error> {
        let key = self.prefixed_key(key);
        self.inner.get_bytes(key.as_ref())
    }

    pub fn auth_service(&self) -> Arc<GatewayAuthService> {
        self.inner.auth()
    }

    pub fn list_by_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, hightower_kv::Error> {
        let full_prefix = match self.prefixed_key(prefix) {
            Cow::Borrowed(bytes) => bytes.to_vec(),
            Cow::Owned(bytes) => bytes,
        };

        let entries = self.inner.get_prefix(&full_prefix)?;

        let mut results = Vec::new();
        for (key, value) in entries {
            let mut remainder = &key[full_prefix.len()..];
            if remainder.first() == Some(&b'/') {
                remainder = &remainder[1..];
            }
            results.push((remainder.to_vec(), value));
        }

        Ok(results)
    }

    fn prefixed_key<'a>(&self, key: &'a [u8]) -> Cow<'a, [u8]> {
        match &self.prefix {
            Some(prefix) if !prefix.is_empty() => {
                let mut composed = Vec::with_capacity(prefix.len() + 1 + key.len());
                composed.extend_from_slice(prefix);
                composed.push(b'/');
                composed.extend_from_slice(key);
                Cow::Owned(composed)
            }
            _ => Cow::Borrowed(key),
        }
    }
}

#[derive(Debug)]
pub enum ContextError {
    Token(TokenError),
    Kv(KvInitError),
    Auth(hightower_kv::Error),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::Token(err) => write!(f, "failed to read HT_AUTH_KEY: {}", err),
            ContextError::Kv(err) => write!(f, "failed to initialize key-value store: {}", err),
            ContextError::Auth(err) => write!(f, "failed to bootstrap auth service: {}", err),
        }
    }
}

impl Error for ContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ContextError::Token(err) => Some(err),
            ContextError::Kv(err) => Some(err),
            ContextError::Auth(err) => Some(err),
        }
    }
}

pub fn initialize_with_token_source<F>(
    kv_path: Option<&Path>,
    mut lookup: F,
) -> Result<CommonContext, ContextError>
where
    F: FnMut(&str) -> Result<String, VarError>,
{
    let token = token::fetch(|key| lookup(key)).map_err(ContextError::Token)?;
    initialize_with_token(kv_path, token)
}

pub fn initialize_with_token(
    kv_path: Option<&Path>,
    token: String,
) -> Result<CommonContext, ContextError> {
    let kv = kv::initialize(kv_path).map_err(ContextError::Kv)?;
    let context = CommonContext::new(kv);
    context.kv.put_secret(HT_AUTH_KEY, token.as_bytes());
    bootstrap_default_user(&context).map_err(ContextError::Auth)?;
    Ok(context)
}

fn bootstrap_default_user(context: &CommonContext) -> Result<(), hightower_kv::Error> {
    let username = std::env::var(DEFAULT_AUTH_USERNAME_ENV)
        .unwrap_or_else(|_| DEFAULT_AUTH_USERNAME.to_string())
        .trim()
        .to_owned();

    if username.is_empty() {
        tracing::warn!("Skipping default auth bootstrap; username is empty");
        return Ok(());
    }

    let password = std::env::var(DEFAULT_AUTH_PASSWORD_ENV)
        .unwrap_or_else(|_| DEFAULT_AUTH_PASSWORD.to_string());

    if password.trim().is_empty() {
        tracing::warn!("Skipping default auth bootstrap; password is empty");
        return Ok(());
    }

    match context.auth.create_user(&username, &password) {
        Ok(_) => {
            tracing::info!(username = %username, "Bootstrapped default auth user");
            Ok(())
        }
        Err(hightower_kv::Error::Conflict(_)) => {
            tracing::debug!(username = %username, "Default auth user already exists");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub mod fixtures {
    use crate::context::{CommonContext, initialize_kv};
    use tempfile::TempDir;

    pub fn context() -> CommonContext {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        CommonContext::new(kv)
    }
}

pub mod env {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub const DISABLE_GATEWAY_REGISTRATION_ENV: &str = "HT_DISABLE_ROOT_REGISTRATION";

    fn registration_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    pub struct RegistrationGuard {
        lock: Option<MutexGuard<'static, ()>>,
    }

    impl RegistrationGuard {
        fn new(lock: MutexGuard<'static, ()>) -> Self {
            Self { lock: Some(lock) }
        }
    }

    impl Drop for RegistrationGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(DISABLE_GATEWAY_REGISTRATION_ENV);
            }
            drop(self.lock.take());
        }
    }

    pub fn disable_gateway_registration() -> RegistrationGuard {
        let guard = registration_lock().lock().expect("registration lock");
        unsafe {
            std::env::set_var(DISABLE_GATEWAY_REGISTRATION_ENV, "1");
        }
        RegistrationGuard::new(guard)
    }

    pub struct RegistrationEnableGuard {
        lock: Option<MutexGuard<'static, ()>>,
        previous: Option<String>,
    }

    impl RegistrationEnableGuard {
        fn new(lock: MutexGuard<'static, ()>, previous: Option<String>) -> Self {
            Self {
                lock: Some(lock),
                previous,
            }
        }
    }

    impl Drop for RegistrationEnableGuard {
        fn drop(&mut self) {
            unsafe {
                if let Some(value) = self.previous.take() {
                    std::env::set_var(DISABLE_GATEWAY_REGISTRATION_ENV, value);
                } else {
                    std::env::remove_var(DISABLE_GATEWAY_REGISTRATION_ENV);
                }
            }
            drop(self.lock.take());
        }
    }

    pub fn enable_gateway_registration() -> RegistrationEnableGuard {
        let guard = registration_lock().lock().expect("registration lock");
        let previous = std::env::var(DISABLE_GATEWAY_REGISTRATION_ENV).ok();
        unsafe {
            std::env::remove_var(DISABLE_GATEWAY_REGISTRATION_ENV);
        }
        RegistrationEnableGuard::new(guard, previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::VarError;
    use tempfile::TempDir;

    #[test]
    fn initialize_with_token_source_persists_token() {
        let temp = TempDir::new().expect("tempdir");
        let context =
            initialize_with_token_source(Some(temp.path()), |_| Ok("test-auth".into()))
                .expect("initialize");

        let stored = context
            .kv
            .get_bytes(HT_AUTH_KEY)
            .expect("kv read")
            .expect("value present");
        assert_eq!(stored, b"test-auth");
    }

    #[test]
    fn initialize_with_token_source_reports_missing_token() {
        let error = initialize_with_token_source(None, |_| Err(VarError::NotPresent))
            .expect_err("missing token");
        assert!(matches!(error, ContextError::Token(TokenError::Missing)));
    }

    #[test]
    fn initialize_with_token_bootstraps_default_user() {
        use std::sync::{Mutex, OnceLock};

        fn env_lock() -> &'static Mutex<()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
        }

        let _guard = env_lock().lock().expect("env lock");

        let previous_user = std::env::var(DEFAULT_AUTH_USERNAME_ENV).ok();
        let previous_password = std::env::var(DEFAULT_AUTH_PASSWORD_ENV).ok();
        unsafe {
            std::env::remove_var(DEFAULT_AUTH_USERNAME_ENV);
            std::env::remove_var(DEFAULT_AUTH_PASSWORD_ENV);
        }

        let temp = TempDir::new().expect("tempdir");
        let context = initialize_with_token(Some(temp.path()), "token".into())
            .expect("context initialized");

        assert!(
            context
                .auth
                .verify_password(DEFAULT_AUTH_USERNAME, DEFAULT_AUTH_PASSWORD)
                .expect("default password verification")
        );

        match previous_user {
            Some(value) => unsafe { std::env::set_var(DEFAULT_AUTH_USERNAME_ENV, value) },
            None => unsafe { std::env::remove_var(DEFAULT_AUTH_USERNAME_ENV) },
        }

        match previous_password {
            Some(value) => unsafe { std::env::set_var(DEFAULT_AUTH_PASSWORD_ENV, value) },
            None => unsafe { std::env::remove_var(DEFAULT_AUTH_PASSWORD_ENV) },
        }
    }

    #[test]
    fn context_creates_isolated_store() {
        let ctx_a = fixtures::context();
        let ctx_b = fixtures::context();

        ctx_a
            .kv
            .put_bytes(b"test/key", b"value-a")
            .expect("store a");

        let stored = ctx_b.kv.get_bytes(b"test/key").expect("read b");
        assert!(stored.is_none(), "unexpected shared state");
    }

    #[test]
    fn disable_gateway_registration_sets_env() {
        {
            let _guard = env::disable_gateway_registration();
            let value = std::env::var(env::DISABLE_GATEWAY_REGISTRATION_ENV).unwrap();
            assert_eq!(value, "1");
        }

        assert!(std::env::var(env::DISABLE_GATEWAY_REGISTRATION_ENV).is_err());
    }

    #[test]
    fn enable_gateway_registration_restores_previous_state() {
        use std::sync::{Mutex, OnceLock};

        fn test_env_lock() -> &'static Mutex<()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
        }

        let _test_lock = test_env_lock().lock().expect("test env lock");

        let previous = std::env::var(env::DISABLE_GATEWAY_REGISTRATION_ENV).ok();

        unsafe {
            std::env::set_var(env::DISABLE_GATEWAY_REGISTRATION_ENV, "1");
        }

        {
            let _guard = env::enable_gateway_registration();
            assert!(
                std::env::var(env::DISABLE_GATEWAY_REGISTRATION_ENV).is_err(),
                "env var should be cleared while guard is active"
            );
        }

        let restored =
            std::env::var(env::DISABLE_GATEWAY_REGISTRATION_ENV).expect("env var restored");
        assert_eq!(restored, "1");

        match previous {
            Some(value) => unsafe { std::env::set_var(env::DISABLE_GATEWAY_REGISTRATION_ENV, value) },
            None => unsafe { std::env::remove_var(env::DISABLE_GATEWAY_REGISTRATION_ENV) },
        }
    }
}
