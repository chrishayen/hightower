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
    pub endpoint_id: String,
    /// WireGuard public key (hex encoded)
    pub public_key_hex: String,
    /// Assigned IP on the WireGuard network (e.g., "100.64.0.5")
    pub assigned_ip: String,
    /// Public internet endpoint (optional, for NAT traversal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,
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
