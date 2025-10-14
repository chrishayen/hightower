use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Network information discovered via STUN for NAT traversal
///
/// This contains both the public (externally visible) and local (LAN) network
/// addresses for a client. The public information is used by peers to establish
/// direct connections through NAT, while local information can be used for
/// LAN-local optimizations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Public IP address as seen by the STUN server (external NAT address)
    pub public_ip: String,

    /// Public port as seen by the STUN server (external NAT port)
    pub public_port: u16,

    /// Local IP address on the LAN (e.g., 192.168.1.100)
    pub local_ip: String,

    /// Local port bound by the WireGuard transport
    pub local_port: u16,
}

/// Information about a peer in the Hightower network
///
/// Returned by the gateway when querying for peer information. Contains all
/// the necessary data to establish a WireGuard connection to the peer.
///
/// # Field Availability
/// - `public_key_hex` is always present (required for WireGuard)
/// - `endpoint_id` and `assigned_ip` are present for registered peers
/// - `token` is only present when querying your own endpoint info
/// - Network fields (`public_ip`, `public_port`, etc.) are optional and may
///   be absent if the peer hasn't reported them or is behind certain NAT types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Human-readable endpoint ID (e.g., "ht-festive-penguin-abc123")
    /// Present for all registered peers, absent only in edge cases
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    /// WireGuard public key in hexadecimal format (32 bytes = 64 hex chars)
    /// This is the peer's cryptographic identity
    pub public_key_hex: String,

    /// Registration token for deregistration (only present for own endpoint)
    /// Keep this secret - anyone with this token can deregister your endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Virtual IP assigned to the peer on the WireGuard network (e.g., "100.64.0.5")
    /// Use this IP when dialing the peer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<String>,

    /// Peer's public IP address as discovered via STUN (for NAT traversal)
    /// May be None if peer hasn't performed STUN discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,

    /// Peer's public port as discovered via STUN (for NAT traversal)
    /// May be None if peer hasn't performed STUN discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,

    /// Peer's local LAN IP address (if reported)
    /// Can be used for LAN-local connection optimization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,

    /// Peer's local LAN port (if reported)
    /// Can be used for LAN-local connection optimization
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
