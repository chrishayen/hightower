use crate::error::ClientError;
use crate::keys::Keypair;
use crate::types::{RegistrationRequest, RegistrationResponse, RegistrationResult};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::time::Duration;

const DEFAULT_GATEWAY: &str = "http://127.0.0.1:8008";
const API_PATH: &str = "/api/nodes";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

pub struct HightowerClient {
    endpoint: String,
    auth_token: String,
    client: Client,
}

impl HightowerClient {
    pub fn new(gateway_url: impl Into<String>, auth_token: impl Into<String>) -> Result<Self, ClientError> {
        let gateway_url = gateway_url.into();
        let auth_token = auth_token.into();

        if gateway_url.is_empty() {
            return Err(ClientError::Configuration("gateway_url cannot be empty".into()));
        }

        if auth_token.is_empty() {
            return Err(ClientError::Configuration("auth_token cannot be empty".into()));
        }

        let endpoint = build_endpoint(&gateway_url)?;

        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| ClientError::Configuration(format!("failed to build HTTP client: {}", e)))?;

        Ok(Self {
            endpoint,
            auth_token,
            client,
        })
    }

    pub fn with_auth_token(auth_token: impl Into<String>) -> Result<Self, ClientError> {
        Self::new(DEFAULT_GATEWAY, auth_token)
    }

    pub fn register(&self) -> Result<RegistrationResult, ClientError> {
        let keypair = Keypair::generate();
        let public_key_hex = keypair.public_key_hex();

        // Always auto-discover network info - fail if discovery fails
        let network_info = crate::ip_discovery::discover_network_info(None, None)
            .map_err(|e| ClientError::NetworkDiscovery(e.to_string()))?;

        let payload = RegistrationRequest {
            public_key_hex: &public_key_hex,
            public_ip: Some(network_info.public_ip.as_str()),
            public_port: Some(network_info.public_port),
            local_ip: Some(network_info.local_ip.as_str()),
            local_port: Some(network_info.local_port),
        };

        let response = self
            .client
            .post(&self.endpoint)
            .header("X-HT-Auth", &self.auth_token)
            .json(&payload)
            .send()?;

        let status = response.status();

        if status.is_success() {
            let registration_response: RegistrationResponse = response.json().map_err(|e| {
                ClientError::InvalidResponse(format!("failed to parse registration response: {}", e))
            })?;

            Ok(RegistrationResult {
                node_id: registration_response.node_id,
                token: registration_response.token,
                gateway_public_key_hex: registration_response.gateway_public_key_hex,
                assigned_ip: registration_response.assigned_ip,
                private_key_hex: keypair.private_key_hex(),
                public_key_hex: keypair.public_key_hex(),
            })
        } else {
            let message = response
                .text()
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(ClientError::GatewayError {
                status: status.as_u16(),
                message,
            })
        }
    }

    pub fn deregister(&self, token: &str) -> Result<(), ClientError> {
        let url = format!("{}/{}", self.endpoint, token);

        let response = self
            .client
            .delete(&url)
            .send()?;

        let status = response.status();

        if status.is_success() || status == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let message = response
                .text()
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(ClientError::GatewayError {
                status: status.as_u16(),
                message,
            })
        }
    }
}

fn build_endpoint(gateway_url: &str) -> Result<String, ClientError> {
    let gateway_url = gateway_url.trim();

    if !gateway_url.starts_with("http://") && !gateway_url.starts_with("https://") {
        return Err(ClientError::Configuration(
            "gateway_url must start with http:// or https://".into()
        ));
    }

    Ok(format!("{}{}", gateway_url.trim_end_matches('/'), API_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_validates_empty_gateway_url() {
        let result = HightowerClient::new("", "token");
        assert!(matches!(result, Err(ClientError::Configuration(_))));
    }

    #[test]
    fn new_validates_empty_token() {
        let result = HightowerClient::new("http://gateway.example.com:8008", "");
        assert!(matches!(result, Err(ClientError::Configuration(_))));
    }

    #[test]
    fn new_requires_scheme() {
        let result = HightowerClient::new("gateway.example.com:8008", "token");
        assert!(matches!(result, Err(ClientError::Configuration(_))));
    }

    #[test]
    fn with_auth_token_uses_default_gateway() {
        let client = HightowerClient::with_auth_token("test-token").unwrap();
        assert_eq!(client.endpoint, "http://127.0.0.1:8008/api/nodes");
        assert_eq!(client.auth_token, "test-token");
    }

    #[test]
    fn new_creates_client_with_http() {
        let client = HightowerClient::new("http://gateway.example.com:8008", "token").unwrap();
        assert_eq!(client.endpoint, "http://gateway.example.com:8008/api/nodes");
        assert_eq!(client.auth_token, "token");
    }

    #[test]
    fn new_creates_client_with_https() {
        let client = HightowerClient::new("https://gateway.example.com:8443", "token").unwrap();
        assert_eq!(client.endpoint, "https://gateway.example.com:8443/api/nodes");
    }

    #[test]
    fn build_endpoint_requires_scheme() {
        let result = build_endpoint("gateway.example.com:8008");
        assert!(matches!(result, Err(ClientError::Configuration(_))));
    }

    #[test]
    fn build_endpoint_accepts_http() {
        let endpoint = build_endpoint("http://gateway.example.com:8008").unwrap();
        assert_eq!(endpoint, "http://gateway.example.com:8008/api/nodes");
    }

    #[test]
    fn build_endpoint_accepts_https() {
        let endpoint = build_endpoint("https://gateway.example.com:8443").unwrap();
        assert_eq!(endpoint, "https://gateway.example.com:8443/api/nodes");
    }

    #[test]
    fn build_endpoint_strips_trailing_slash() {
        let endpoint = build_endpoint("http://gateway.example.com:8008/").unwrap();
        assert_eq!(endpoint, "http://gateway.example.com:8008/api/nodes");
    }
}
