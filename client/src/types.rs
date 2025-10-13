use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub public_ip: String,
    pub public_port: u16,
    pub local_ip: String,
    pub local_port: u16,
}

/// Information about a peer in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Endpoint ID (e.g., "ht-festive-penguin-abc123")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    /// WireGuard public key (hex encoded)
    pub public_key_hex: String,
    /// Registration token (optional, only included for own endpoint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Assigned IP on the WireGuard network (e.g., "100.64.0.5")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<String>,
    /// Public IP address (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    /// Public port (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// Local IP address (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    /// Local port (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
}

impl PeerInfo {
    /// Get the public internet endpoint (for NAT traversal)
    pub fn endpoint(&self) -> Option<SocketAddr> {
        match (&self.public_ip, self.public_port) {
            (Some(ip), Some(port)) => {
                format!("{}:{}", ip, port).parse().ok()
            }
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RegistrationRequest<'a> {
    pub public_key_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegistrationResponse {
    pub endpoint_id: String,
    pub token: String,
    pub gateway_public_key_hex: String,
    pub assigned_ip: String,
}
