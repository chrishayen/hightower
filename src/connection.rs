use crate::error::ClientError;
use crate::transport::TransportServer;
use crate::types::{RegistrationRequest, RegistrationResponse};
use hightower_wireguard::crypto::{dh_generate, PublicKey25519};
use hightower_wireguard::transport::Server;
use reqwest::StatusCode;
use std::net::SocketAddr;
use tracing::{debug, error};

const DEFAULT_GATEWAY: &str = "http://127.0.0.1:8008";
const API_PATH: &str = "/api/nodes";

/// Main connection to Hightower gateway with integrated WireGuard transport
pub struct HightowerConnection {
    transport: TransportServer,
    node_id: String,
    assigned_ip: String,
    token: String,
    endpoint: String,
}

impl HightowerConnection {
    /// Connect to a Hightower gateway
    ///
    /// This method handles everything:
    /// - Generates WireGuard keypair
    /// - Creates transport server on 0.0.0.0:0
    /// - Discovers network info via STUN using actual bound port
    /// - Registers with gateway
    /// - Adds gateway as peer
    ///
    /// Returns a ready-to-use connection with working transport
    pub async fn connect(
        gateway_url: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let gateway_url = gateway_url.into();
        let auth_token = auth_token.into();

        if gateway_url.is_empty() {
            return Err(ClientError::Configuration(
                "gateway_url cannot be empty".into(),
            ));
        }

        if auth_token.is_empty() {
            return Err(ClientError::Configuration(
                "auth_token cannot be empty".into(),
            ));
        }

        let endpoint = build_endpoint(&gateway_url)?;

        // 1. Generate WireGuard keypair
        let (private_key, public_key) = dh_generate();
        let public_key_hex = hex::encode(public_key);

        debug!("Generated WireGuard keypair");

        // 2. Create WireGuard transport server on 0.0.0.0:0
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e| {
            ClientError::Configuration(format!("invalid bind address: {}", e))
        })?;

        let server = Server::new(bind_addr, private_key)
            .await
            .map_err(|e| ClientError::Transport(format!("failed to create transport server: {}", e)))?;

        debug!("Created transport server");

        // Spawn background processor
        let server_clone = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_clone.run().await {
                error!(error = ?e, "Transport server error");
            }
        });

        // Spawn maintenance task
        let server_maintenance = server.clone();
        tokio::spawn(async move {
            server_maintenance.run_maintenance().await
        });

        // Wait for transport to be ready
        server
            .wait_until_ready()
            .await
            .map_err(|e| ClientError::Transport(format!("transport not ready: {}", e)))?;

        debug!("Transport server ready");

        // 3. Discover network info using actual bound port
        let local_addr = server
            .local_addr()
            .map_err(|e| ClientError::Transport(format!("failed to get local address: {}", e)))?;

        let network_info = crate::ip_discovery::discover_with_bound_address(local_addr, None)
            .map_err(|e| ClientError::NetworkDiscovery(e.to_string()))?;

        debug!(
            public_ip = %network_info.public_ip,
            public_port = network_info.public_port,
            local_ip = %network_info.local_ip,
            local_port = network_info.local_port,
            "Discovered network information"
        );

        // 4. Register with gateway
        let registration = register_with_gateway(
            &endpoint,
            &auth_token,
            &public_key_hex,
            &network_info,
        )
        .await?;

        debug!(
            node_id = %registration.node_id,
            assigned_ip = %registration.assigned_ip,
            "Registered with gateway"
        );

        // 5. Add gateway as peer
        let gateway_public_key_bytes = hex::decode(&registration.gateway_public_key_hex)
            .map_err(|e| {
                ClientError::InvalidResponse(format!("invalid gateway public key hex: {}", e))
            })?;

        let gateway_public_key: PublicKey25519 = gateway_public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|e| {
                ClientError::InvalidResponse(format!("invalid gateway public key format: {:?}", e))
            })?;

        server
            .add_peer(gateway_public_key, None)
            .await
            .map_err(|e| ClientError::Transport(format!("failed to add gateway as peer: {}", e)))?;

        debug!("Added gateway as peer");

        Ok(Self {
            transport: TransportServer::new(server),
            node_id: registration.node_id,
            assigned_ip: registration.assigned_ip,
            token: registration.token,
            endpoint,
        })
    }

    /// Connect using default gateway (http://127.0.0.1:8008)
    pub async fn connect_with_auth_token(auth_token: impl Into<String>) -> Result<Self, ClientError> {
        Self::connect(DEFAULT_GATEWAY, auth_token).await
    }

    /// Get the node ID assigned by the gateway
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get the IP address assigned by the gateway
    pub fn assigned_ip(&self) -> &str {
        &self.assigned_ip
    }

    /// Get the transport for sending/receiving data
    pub fn transport(&self) -> &TransportServer {
        &self.transport
    }

    /// Disconnect from the gateway and deregister
    pub async fn disconnect(self) -> Result<(), ClientError> {
        let url = format!("{}/{}", self.endpoint, self.token);

        let client = reqwest::Client::new();
        let response = client.delete(&url).send().await?;

        let status = response.status();

        if status.is_success() || status == StatusCode::NO_CONTENT {
            debug!("Successfully deregistered from gateway");
            Ok(())
        } else {
            let message = response
                .text()
                .await
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
            "gateway_url must start with http:// or https://".into(),
        ));
    }

    Ok(format!(
        "{}{}",
        gateway_url.trim_end_matches('/'),
        API_PATH
    ))
}

async fn register_with_gateway(
    endpoint: &str,
    auth_token: &str,
    public_key_hex: &str,
    network_info: &crate::types::NetworkInfo,
) -> Result<RegistrationResponse, ClientError> {
    let payload = RegistrationRequest {
        public_key_hex,
        public_ip: Some(network_info.public_ip.as_str()),
        public_port: Some(network_info.public_port),
        local_ip: Some(network_info.local_ip.as_str()),
        local_port: Some(network_info.local_port),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .header("X-HT-Auth", auth_token)
        .json(&payload)
        .send()
        .await?;

    let status = response.status();

    if status.is_success() {
        let registration_response: RegistrationResponse = response.json().await.map_err(|e| {
            ClientError::InvalidResponse(format!("failed to parse registration response: {}", e))
        })?;

        Ok(registration_response)
    } else {
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        Err(ClientError::GatewayError {
            status: status.as_u16(),
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
