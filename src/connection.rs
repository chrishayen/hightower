use crate::error::ClientError;
use crate::storage::{ConnectionStorage, StoredConnection, current_timestamp};
use crate::transport::TransportServer;
use crate::types::{RegistrationRequest, RegistrationResponse};
use hightower_wireguard::crypto::{dh_generate, PrivateKey, PublicKey25519};
use hightower_wireguard::transport::Server;
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

const DEFAULT_GATEWAY: &str = "http://127.0.0.1:8008";
const API_PATH: &str = "/api/nodes";

/// Main connection to Hightower gateway with integrated WireGuard transport
pub struct HightowerConnection {
    transport: TransportServer,
    node_id: String,
    assigned_ip: String,
    token: String,
    endpoint: String,
    gateway_url: String,
    storage: Option<ConnectionStorage>,
}

impl HightowerConnection {
    /// Connect to a Hightower gateway
    ///
    /// This method handles everything:
    /// - Checks for existing stored connection and restores if available
    /// - Otherwise: Generates WireGuard keypair, registers with gateway
    /// - Creates transport server on 0.0.0.0:0
    /// - Discovers network info via STUN using actual bound port
    /// - Adds gateway as peer
    /// - Persists connection info to storage (default: ~/.hightower-client/data)
    ///
    /// Returns a ready-to-use connection with working transport
    pub async fn connect(
        gateway_url: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, ClientError> {
        Self::connect_internal(gateway_url, auth_token, None, false).await
    }

    /// Connect without using persistent storage
    pub async fn connect_ephemeral(
        gateway_url: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, ClientError> {
        Self::connect_internal(gateway_url, auth_token, None, true).await
    }

    /// Connect with custom storage directory
    pub async fn connect_with_storage(
        gateway_url: impl Into<String>,
        auth_token: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Result<Self, ClientError> {
        Self::connect_internal(gateway_url, auth_token, Some(storage_dir.into()), false).await
    }

    /// Force a fresh registration even if stored connection exists
    pub async fn connect_fresh(
        gateway_url: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let gateway_url = gateway_url.into();
        let auth_token = auth_token.into();

        // Delete any stored connection first
        if let Ok(storage) = ConnectionStorage::for_gateway(&gateway_url) {
            let _ = storage.delete_connection();
        }

        Self::connect_internal(gateway_url, auth_token, None, false).await
    }

    async fn connect_internal(
        gateway_url: impl Into<String>,
        auth_token: impl Into<String>,
        storage_dir: Option<PathBuf>,
        ephemeral: bool,
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

        // Initialize storage if not ephemeral
        let storage = if ephemeral {
            None
        } else if let Some(dir) = storage_dir {
            // Use custom storage directory
            match ConnectionStorage::new(dir) {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(error = ?e, "Failed to initialize custom storage, continuing without persistence");
                    None
                }
            }
        } else {
            // Use default gateway-specific storage
            match ConnectionStorage::for_gateway(&gateway_url) {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(error = ?e, "Failed to initialize storage, continuing without persistence");
                    None
                }
            }
        };

        // Check for existing stored connection
        if let Some(ref storage) = storage {
            if let Ok(Some(stored)) = storage.get_connection() {
                info!(node_id = %stored.node_id, "Found stored connection, attempting to restore");

                match Self::restore_from_stored(stored, storage.clone()).await {
                    Ok(conn) => {
                        info!(node_id = %conn.node_id, "Successfully restored connection from storage");
                        return Ok(conn);
                    }
                    Err(e) => {
                        warn!(error = ?e, "Failed to restore stored connection, will create fresh connection");
                        // Continue to create fresh connection
                    }
                }
            }
        }

        // No stored connection or restore failed - create fresh connection
        info!("Creating fresh connection to gateway");

        // 1. Generate WireGuard keypair
        let (private_key, public_key) = dh_generate();
        let public_key_hex = hex::encode(public_key);
        let private_key_hex = hex::encode(private_key);

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

        // 6. Store connection info
        if let Some(ref storage) = storage {
            let now = current_timestamp();
            let stored = StoredConnection {
                node_id: registration.node_id.clone(),
                token: registration.token.clone(),
                gateway_url: gateway_url.clone(),
                assigned_ip: registration.assigned_ip.clone(),
                private_key_hex,
                public_key_hex,
                gateway_public_key_hex: registration.gateway_public_key_hex.clone(),
                created_at: now,
                last_connected_at: now,
            };

            if let Err(e) = storage.store_connection(&stored) {
                warn!(error = ?e, "Failed to persist connection to storage");
            } else {
                debug!("Persisted connection to storage");
            }
        }

        Ok(Self {
            transport: TransportServer::new(server),
            node_id: registration.node_id,
            assigned_ip: registration.assigned_ip,
            token: registration.token,
            endpoint,
            gateway_url,
            storage,
        })
    }

    /// Restore a connection from stored credentials
    async fn restore_from_stored(
        stored: StoredConnection,
        storage: ConnectionStorage,
    ) -> Result<Self, ClientError> {
        let endpoint = build_endpoint(&stored.gateway_url)?;

        // Parse stored keys
        let private_key_bytes = hex::decode(&stored.private_key_hex)
            .map_err(|e| ClientError::Storage(format!("invalid private key hex: {}", e)))?;
        let private_key: PrivateKey = private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|e| ClientError::Storage(format!("invalid private key format: {:?}", e)))?;

        let gateway_public_key_bytes = hex::decode(&stored.gateway_public_key_hex)
            .map_err(|e| ClientError::Storage(format!("invalid gateway public key hex: {}", e)))?;
        let gateway_public_key: PublicKey25519 = gateway_public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|e| ClientError::Storage(format!("invalid gateway public key format: {:?}", e)))?;

        // Create transport server with stored private key
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e| {
            ClientError::Configuration(format!("invalid bind address: {}", e))
        })?;

        let server = Server::new(bind_addr, private_key)
            .await
            .map_err(|e| ClientError::Transport(format!("failed to create transport server: {}", e)))?;

        debug!("Created transport server with stored keys");

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

        // Discover current network info (may have changed)
        let local_addr = server
            .local_addr()
            .map_err(|e| ClientError::Transport(format!("failed to get local address: {}", e)))?;

        let _network_info = crate::ip_discovery::discover_with_bound_address(local_addr, None)
            .map_err(|e| ClientError::NetworkDiscovery(e.to_string()))?;

        debug!("Rediscovered network information");

        // Add gateway as peer
        server
            .add_peer(gateway_public_key, None)
            .await
            .map_err(|e| ClientError::Transport(format!("failed to add gateway as peer: {}", e)))?;

        debug!("Added gateway as peer");

        // Update last_connected_at timestamp
        if let Err(e) = storage.update_last_connected() {
            warn!(error = ?e, "Failed to update last_connected timestamp");
        }

        Ok(Self {
            transport: TransportServer::new(server),
            node_id: stored.node_id,
            assigned_ip: stored.assigned_ip,
            token: stored.token,
            endpoint,
            gateway_url: stored.gateway_url,
            storage: Some(storage),
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

            // Remove stored connection
            if let Some(storage) = self.storage {
                if let Err(e) = storage.delete_connection() {
                    warn!(error = ?e, "Failed to delete stored connection");
                } else {
                    debug!("Deleted stored connection");
                }
            }

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
