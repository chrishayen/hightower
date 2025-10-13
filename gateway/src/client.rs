use crate::context::{CommonContext, HT_AUTH_KEY, NamespacedKv};
use reqwest::StatusCode as HttpStatusCode;
use reqwest::blocking::Client;
use serde::Serialize;
use std::error::Error;
use std::fmt;
use std::time::Duration;
use tracing::debug;

const DEFAULT_ROOT_ENDPOINT: &str = "http://127.0.0.1:8008/api/endpoints";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
pub const ROOT_ENDPOINT_KEY: &[u8] = b"config/root_api";

pub struct RegistrationResult {
    pub endpoint_id: String,
    pub token: String,
    pub gateway_public_key_hex: String,
    pub assigned_ip: String,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub public_ip: String,
    pub public_port: u16,
    pub local_ip: String,
    pub local_port: u16,
}

pub trait RootRegistrar {
    fn register(
        &self,
        context: &CommonContext,
        public_key_hex: &str,
        network_info: Option<&NetworkInfo>,
    ) -> Result<RegistrationResult, RootRegistrationError>;

    fn deregister(
        &self,
        context: &CommonContext,
        token: &str,
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
    Kv(::kv::Error),
    Request(reqwest::Error),
    UnexpectedStatus(HttpStatusCode),
    InvalidEndpoint,
}

#[derive(Serialize)]
struct NodeRegistrationPayload<'a> {
    public_key_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,
}

#[derive(Debug, serde::Deserialize)]
struct EndpointRegistrationResponse {
    endpoint_id: String,
    token: String,
    gateway_public_key_hex: String,
    assigned_ip: String,
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
        public_key_hex: &str,
        network_info: Option<&NetworkInfo>,
    ) -> Result<RegistrationResult, RootRegistrationError> {
        if registration_disabled() {
            debug!("Skipping root registration (disabled)");
            return Ok(RegistrationResult {
                endpoint_id: String::new(),
                token: String::new(),
                gateway_public_key_hex: String::new(),
                assigned_ip: String::new(),
            });
        }

        let token = auth_token(&context.kv)?;
        let endpoint = endpoint(&context.kv)?;
        let payload = NodeRegistrationPayload {
            public_key_hex,
            public_ip: network_info.map(|n| n.public_ip.as_str()),
            public_port: network_info.map(|n| n.public_port),
            local_ip: network_info.map(|n| n.local_ip.as_str()),
            local_port: network_info.map(|n| n.local_port),
        };

        let response = self
            .client
            .post(endpoint)
            .header("X-HT-Auth", token)
            .json(&payload)
            .send()
            .map_err(RootRegistrationError::Request)?;

        if response.status().is_success() {
            let registration_response: EndpointRegistrationResponse = response
                .json()
                .map_err(RootRegistrationError::Request)?;
            debug!("Endpoint registration sent to root");
            Ok(RegistrationResult {
                endpoint_id: registration_response.endpoint_id,
                token: registration_response.token,
                gateway_public_key_hex: registration_response.gateway_public_key_hex,
                assigned_ip: registration_response.assigned_ip,
            })
        } else {
            Err(RootRegistrationError::UnexpectedStatus(response.status()))
        }
    }

    fn deregister(
        &self,
        context: &CommonContext,
        token: &str,
    ) -> Result<(), RootRegistrationError> {
        if registration_disabled() {
            debug!("Skipping root deregistration (disabled)");
            return Ok(());
        }

        let base_endpoint = endpoint(&context.kv)?;
        let deregister_endpoint = format!("{}/{}", base_endpoint, token);

        let response = self
            .client
            .delete(&deregister_endpoint)
            .send()
            .map_err(RootRegistrationError::Request)?;

        if response.status().is_success() {
            debug!("Node deregistration sent to root");
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
    use crate::context::{CommonContext, initialize_kv};
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
            public_key_hex: &str,
            _network_info: Option<&NetworkInfo>,
        ) -> Result<RegistrationResult, RootRegistrationError> {
            let endpoint_name = "ht-test-endpoint".to_string();
            self.records
                .lock()
                .expect("lock")
                .push((endpoint_name.clone(), public_key_hex.to_string()));
            Ok(RegistrationResult {
                endpoint_id: endpoint_name,
                token: "test-token".to_string(),
                gateway_public_key_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                assigned_ip: "100.64.0.1".to_string(),
            })
        }

        fn deregister(
            &self,
            _context: &CommonContext,
            _token: &str,
        ) -> Result<(), RootRegistrationError> {
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
        let result = registrar
            .register(&context, "public-key", None)
            .expect("registration");

        assert_eq!(result.endpoint_id, "ht-test-endpoint");
        let records = registrar.records.lock().expect("lock");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "ht-test-endpoint");
        assert_eq!(records[0].1, "public-key");
    }
}
