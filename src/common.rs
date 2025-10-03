use crate::cli::Cli;
use crate::kv::{self, KvHandle};
use crate::token;
use std::env::VarError;
use std::error::Error;
use std::fmt;

pub const NODE_NAME_KEY: &[u8] = b"nodes/name";
pub const NODE_CERTIFICATE_KEY: &[u8] = b"certificates/node";
pub const HT_TOKEN_KEY: &[u8] = b"secrets/ht_token";

#[derive(Debug)]
pub struct CommonContext {
    pub kv: KvHandle,
}

impl CommonContext {
    pub fn new(kv: KvHandle) -> Self {
        Self { kv }
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
    kv.put_secret(HT_TOKEN_KEY, token.as_bytes());
    Ok(CommonContext::new(kv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prepare_returns_context_and_persists_token() {
        let temp = TempDir::new().expect("tempdir");
        let cli = Cli {
            node: true,
            root: false,
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
