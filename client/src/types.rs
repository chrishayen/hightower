use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateKind {
    Local,
    StunPublic,
    HolePunch,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCandidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
    pub priority: u32,
}

impl NetworkInfo {
    pub fn to_candidates(&self) -> Vec<EndpointCandidate> {
        let mut candidates = Vec::new();
        if let Ok(addr) = format!("{}:{}", self.local_ip, self.local_port).parse() {
            candidates.push(EndpointCandidate {
                kind: CandidateKind::Local,
                addr,
                priority: 100,
            });
        }
        if let Ok(addr) = format!("{}:{}", self.public_ip, self.public_port).parse() {
            candidates.push(EndpointCandidate {
                kind: CandidateKind::StunPublic,
                addr,
                priority: 50,
            });
        }
        candidates
    }
}

/// Information about a peer in the Hightower network
///
/// Returned by the gateway when querying for peer information. Contains the
/// cryptographic identity and concrete transport candidates required to
/// establish an app-level encrypted connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Human-readable endpoint ID (e.g., "ht-festive-penguin-abc123")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    /// WireGuard public key in hexadecimal format (32 bytes = 64 hex chars).
    pub public_key_hex: String,

    /// Registration token for deregistration (only present for own endpoint).
    /// Keep this secret - anyone with this token can deregister your endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Virtual app-network IP assigned to the peer (e.g., "100.64.0.5").
    /// This is a logical address, not a socket destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<String>,

    /// Real socket endpoints that can carry the encrypted app-level session.
    pub candidates: Vec<EndpointCandidate>,
}

impl PeerInfo {
    /// Return real transport endpoints ordered by priority.
    pub fn ordered_candidates(&self) -> Vec<EndpointCandidate> {
        let mut candidates = self.candidates.clone();
        candidates.sort_by_key(|candidate| Reverse(candidate.priority));
        candidates
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionIntentRequest {
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionIntentResponse {
    pub connection_id: String,
    pub initiator: PeerInfo,
    pub target: PeerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionIntent {
    pub connection_id: String,
    pub initiator_endpoint_id: String,
    pub target_endpoint_id: String,
    pub initiator: PeerInfo,
    pub target: PeerInfo,
    pub created_at_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegistrationRequest<'a> {
    pub public_key_hex: &'a str,
    pub candidates: Vec<EndpointCandidate>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegistrationResponse {
    pub endpoint_id: String,
    pub token: String,
    pub gateway_public_key_hex: String,
    pub assigned_ip: String,
}

#[cfg(test)]
mod candidate_tests {
    use super::*;

    #[test]
    fn endpoint_candidate_round_trips_json() {
        let candidate = EndpointCandidate {
            kind: CandidateKind::Local,
            addr: "192.168.4.63:33565".parse().unwrap(),
            priority: 100,
        };

        let json = serde_json::to_string(&candidate).unwrap();
        assert!(json.contains("Local"));
        assert!(json.contains("192.168.4.63:33565"));

        let decoded: EndpointCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, CandidateKind::Local);
        assert_eq!(decoded.addr.to_string(), "192.168.4.63:33565");
        assert_eq!(decoded.priority, 100);
    }

    #[test]
    fn network_info_builds_ordered_candidates() {
        let info = NetworkInfo {
            public_ip: "71.179.92.242".to_string(),
            public_port: 50963,
            local_ip: "192.168.4.63".to_string(),
            local_port: 33565,
        };

        let candidates = info.to_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].kind, CandidateKind::Local);
        assert_eq!(candidates[0].priority, 100);
        assert_eq!(candidates[1].kind, CandidateKind::StunPublic);
        assert_eq!(candidates[1].priority, 50);
    }

    #[test]
    fn peer_info_orders_candidates_by_priority() {
        let peer = PeerInfo {
            endpoint_id: Some("ht-peer".into()),
            public_key_hex: "00".repeat(32),
            token: None,
            assigned_ip: Some("100.64.0.13".into()),
            candidates: vec![
                EndpointCandidate {
                    kind: CandidateKind::StunPublic,
                    addr: "71.179.92.242:50963".parse().unwrap(),
                    priority: 50,
                },
                EndpointCandidate {
                    kind: CandidateKind::Local,
                    addr: "192.168.4.63:33565".parse().unwrap(),
                    priority: 100,
                },
            ],
        };

        let ordered = peer.ordered_candidates();
        assert_eq!(ordered[0].kind, CandidateKind::Local);
    }
}
