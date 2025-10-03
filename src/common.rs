use crate::cli::{Cli, ModeArg};
use crate::kv::{self, KvHandle};
use crate::token;
use std::borrow::Cow;
use std::env::VarError;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

pub const NODE_NAME_KEY: &[u8] = b"nodes/name";
pub const NODE_CERTIFICATE_KEY: &[u8] = b"certificates/node";
pub const HT_TOKEN_KEY: &[u8] = b"secrets/ht_token";

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
pub enum CommonError {
    Token(token::TokenError),
    Kv(kv::KvInitError),
}

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommonError::Token(err) => write!(f, "failed to read HT_TOKEN: {}", err),
            CommonError::Kv(err) => write!(f, "failed to initialize key-value store: {}", err),
        }
    }
}

impl Error for CommonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CommonError::Token(err) => Some(err),
            CommonError::Kv(err) => Some(err),
        }
    }
}

pub fn prepare(cli: &Cli) -> Result<CommonContext, CommonError> {
    prepare_with_token_source(cli, |key| std::env::var(key))
}

pub fn prepare_with_token_source<F>(cli: &Cli, mut lookup: F) -> Result<CommonContext, CommonError>
where
    F: FnMut(&str) -> Result<String, VarError>,
{
    let token = token::fetch(|key| lookup(key)).map_err(CommonError::Token)?;
    let kv = kv::initialize(cli.kv.as_deref()).map_err(CommonError::Kv)?;
    let context = CommonContext::new(kv);
    context.kv.put_secret(HT_TOKEN_KEY, token.as_bytes());
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prepare_returns_context_and_persists_token() {
        let temp = TempDir::new().expect("tempdir");
        let cli = Cli {
            mode: ModeArg::Node,
            kv: Some(temp.path().to_path_buf()),
        };

        let context =
            prepare_with_token_source(&cli, |_| Ok("test-token".into())).expect("prepare succeeds");
        let stored = context
            .kv
            .get_bytes(HT_TOKEN_KEY)
            .expect("kv read")
            .expect("value present");
        assert_eq!(stored, b"test-token");
    }
}
