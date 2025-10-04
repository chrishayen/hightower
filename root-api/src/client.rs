use hightower_context::{CommonContext, HT_AUTH_KEY, NamespacedKv};
use reqwest::blocking::Client;
use reqwest::StatusCode as HttpStatusCode;
use serde::Serialize;
use std::error::Error;
use std::fmt;
use std::time::Duration;
use tracing::debug;

const DEFAULT_ROOT_ENDPOINT: &str = "http://127.0.0.1:8008/nodes";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
pub const ROOT_ENDPOINT_KEY: &[u8] = b"config/root_api";

pub trait RootRegistrar {
    fn register(
        &self,
        context: &CommonContext,
        node_name: &str,
        public_key_hex: &str,
    ) -> Result<(), RootRegistrationError>;
}

#[derive(Debug)]
pub struct HttpRootRegistrar {
    client: Client,
}

#[derive(Debug)]
pub enum RootRegistrationError {
    MissingAuthToken,
    InvalidAuthToken,
    Kv(hightower_kv::Error),
    Request(reqwest::Error),
    UnexpectedStatus(HttpStatusCode),
    InvalidEndpoint,
}

#[derive(Serialize)]
struct NodeRegistrationPayload<'a> {
    node_id: &'a str,
    public_key_hex: &'a str,
}

impl Default for HttpRootRegistrar {
    fn default() -> Self {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("root registrar http client");

        Self { client }
    }
}

impl RootRegistrar for HttpRootRegistrar {
    fn register(
        &self,
        context: &CommonContext,
        node_name: &str,
        public_key_hex: &str,
    ) -> Result<(), RootRegistrationError> {
        if registration_disabled() {
            debug!(node = node_name, "Skipping root registration (disabled)");
            return Ok(());
        }

        let token = auth_token(&context.kv)?;
        let endpoint = endpoint(&context.kv)?;
        let payload = NodeRegistrationPayload {
            node_id: node_name,
            public_key_hex,
        };

        let response = self
            .client
            .post(endpoint)
            .header("X-HT-Auth", token)
            .json(&payload)
            .send()
            .map_err(RootRegistrationError::Request)?;

        if response.status().is_success() {
            debug!(node = node_name, "Node registration sent to root");
            Ok(())
        } else {
            Err(RootRegistrationError::UnexpectedStatus(response.status()))
        }
    }
}

pub fn default_registrar() -> HttpRootRegistrar {
    HttpRootRegistrar::default()
}

fn endpoint(kv: &NamespacedKv) -> Result<String, RootRegistrationError> {
    if let Some(bytes) = kv
        .get_bytes(ROOT_ENDPOINT_KEY)
        .map_err(RootRegistrationError::Kv)?
    {
        let value = String::from_utf8(bytes).map_err(|_| RootRegistrationError::InvalidEndpoint)?;
        if !value.is_empty() {
            return Ok(value);
        }
    }

    Ok(std::env::var("HT_ROOT_API").unwrap_or_else(|_| DEFAULT_ROOT_ENDPOINT.to_string()))
}

fn auth_token(kv: &NamespacedKv) -> Result<String, RootRegistrationError> {
    let bytes = kv
        .get_bytes(HT_AUTH_KEY)
        .map_err(RootRegistrationError::Kv)?
        .ok_or(RootRegistrationError::MissingAuthToken)?;

    String::from_utf8(bytes).map_err(|_| RootRegistrationError::InvalidAuthToken)
}

fn registration_disabled() -> bool {
    match std::env::var("HT_DISABLE_ROOT_REGISTRATION") {
        Ok(value) => matches!(value.as_bytes(), b"1" | b"true" | b"TRUE" | b"True"),
        Err(_) => false,
    }
}

impl fmt::Display for RootRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootRegistrationError::MissingAuthToken => write!(f, "root auth token missing"),
            RootRegistrationError::InvalidAuthToken => {
                write!(f, "stored root auth token is not valid UTF-8")
            }
            RootRegistrationError::Kv(err) => write!(f, "kv error: {err}"),
            RootRegistrationError::Request(err) => write!(f, "request error: {err}"),
            RootRegistrationError::UnexpectedStatus(status) => {
                write!(f, "unexpected root response: {status}")
            }
            RootRegistrationError::InvalidEndpoint => {
                write!(f, "configured root endpoint is not valid UTF-8")
            }
        }
    }
}

impl Error for RootRegistrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RootRegistrationError::Kv(err) => Some(err),
            RootRegistrationError::Request(err) => Some(err),
            RootRegistrationError::UnexpectedStatus(_) => None,
            RootRegistrationError::MissingAuthToken => None,
            RootRegistrationError::InvalidAuthToken => None,
            RootRegistrationError::InvalidEndpoint => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hightower_context::{initialize_kv, CommonContext};
    use std::sync::Mutex;
    use tempfile::TempDir;

    struct RecordingRegistrar {
        records: Mutex<Vec<(String, String)>>,
    }

    impl RecordingRegistrar {
        fn new() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
            }
        }
    }

    impl Default for RecordingRegistrar {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RootRegistrar for RecordingRegistrar {
        fn register(
            &self,
            _context: &CommonContext,
            node_name: &str,
            public_key_hex: &str,
        ) -> Result<(), RootRegistrationError> {
            self.records
                .lock()
                .expect("lock")
                .push((node_name.to_string(), public_key_hex.to_string()));
            Ok(())
        }
    }

    #[test]
    fn default_registrar_constructs_client() {
        let _registrar = default_registrar();
    }

    #[test]
    fn recording_registrar_captures_registration() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context.kv.put_secret(HT_AUTH_KEY, b"auth");

        let registrar = RecordingRegistrar::default();
        registrar
            .register(&context, "ht-test", "public-key")
            .expect("registration");

        let records = registrar.records.lock().expect("lock");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "ht-test");
        assert_eq!(records[0].1, "public-key");
    }
}
