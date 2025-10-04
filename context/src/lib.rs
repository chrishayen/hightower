use std::borrow::Cow;
use std::env::VarError;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

mod kv;
mod token;

pub use kv::{KvHandle, KvInitError, initialize as initialize_kv};
pub use token::{TokenError, fetch as fetch_token};

pub const NODE_NAME_KEY: &[u8] = b"nodes/name";
pub const NODE_CERTIFICATE_KEY: &[u8] = b"certificates/node";
pub const HT_AUTH_KEY: &[u8] = b"secrets/ht_auth_key";

#[derive(Clone, Debug)]
pub struct CommonContext {
    pub kv: NamespacedKv,
}

impl CommonContext {
    pub fn new(kv: KvHandle) -> Self {
        Self {
            kv: NamespacedKv::from_handle(kv),
        }
    }

    pub fn namespaced(&self, prefix: &[u8]) -> Self {
        Self {
            kv: self.kv.clone_with_additional_prefix(prefix),
        }
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

    fn prefixed_key<'a>(&self, key: &'a [u8]) -> Cow<'a, [u8]> {
        match &self.prefix {
            Some(prefix) if !prefix.is_empty() => {
                let mut composed = Vec::with_capacity(prefix.len() + 1 + key.len());
                composed.extend_from_slice(prefix);
                composed.push(b'/');
                composed.extend_from_slice(key);
                Cow::Owned(composed)
            }
            Some(_) => Cow::Borrowed(key),
            None => Cow::Borrowed(key),
        }
    }
}

#[derive(Debug)]
pub enum ContextError {
    Token(TokenError),
    Kv(KvInitError),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::Token(err) => write!(f, "failed to read HT_AUTH_KEY: {}", err),
            ContextError::Kv(err) => write!(f, "failed to initialize key-value store: {}", err),
        }
    }
}

impl Error for ContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ContextError::Token(err) => Some(err),
            ContextError::Kv(err) => Some(err),
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
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::VarError;
    use tempfile::TempDir;

    #[test]
    fn initialize_with_token_source_persists_token() {
        let temp = TempDir::new().expect("tempdir");
        let context = initialize_with_token_source(Some(temp.path()), |_| Ok("test-auth".into()))
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
}
