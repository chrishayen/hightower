use crate::crypto::{PrivateKey, PublicKey25519, dh_generate};
use crate::initiator::{InitiatorState, SessionKeys};
use crate::messages::{HandshakeInitiation, HandshakeResponse};
use crate::responder::ResponderState;
use crate::{Result, WireGuardError};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Information about a peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: PublicKey25519,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<(std::net::IpAddr, u8)>, // IP and prefix length
    pub persistent_keepalive: Option<u16>,
}

/// Active session with transport keys
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub keys: SessionKeys,
    pub peer_public_key: PublicKey25519,
    pub created_at: std::time::Instant,
    pub last_used: std::time::Instant,
}

/// Main WireGuard protocol handler
pub struct WireGuardProtocol {
    local_private_key: PrivateKey,
    local_public_key: PublicKey25519,
    peers: HashMap<PublicKey25519, PeerInfo>,
    active_sessions: HashMap<u32, ActiveSession>, // sender_id -> session
    pending_initiations: HashMap<u32, InitiatorState>, // sender_id -> state
    pending_responses: HashMap<u32, ResponderState>, // sender_id -> state
}

impl WireGuardProtocol {
    /// Create new WireGuard protocol instance
    pub fn new(private_key: Option<PrivateKey>) -> Self {
        let (private_key, public_key) = if let Some(key) = private_key {
            let public_key = {
                use x25519_dalek::{PublicKey, StaticSecret};
                let secret = StaticSecret::from(key);
                PublicKey::from(&secret).to_bytes()
            };
            (key, public_key)
        } else {
            dh_generate()
        };

        Self {
            local_private_key: private_key,
            local_public_key: public_key,
            peers: HashMap::new(),
            active_sessions: HashMap::new(),
            pending_initiations: HashMap::new(),
            pending_responses: HashMap::new(),
        }
    }

    /// Get our public key
    pub fn public_key(&self) -> PublicKey25519 {
        self.local_public_key
    }

    /// Add a peer to the protocol
    pub fn add_peer(&mut self, peer_info: PeerInfo) {
        self.peers.insert(peer_info.public_key, peer_info);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, public_key: &PublicKey25519) {
        self.peers.remove(public_key);

        // Clean up any sessions for this peer
        self.active_sessions
            .retain(|_, session| session.peer_public_key != *public_key);
    }

    /// Get peer info
    pub fn get_peer(&self, public_key: &PublicKey25519) -> Option<&PeerInfo> {
        self.peers.get(public_key)
    }

    /// Initiate handshake with a peer
    pub fn initiate_handshake(
        &mut self,
        peer_public_key: &PublicKey25519,
    ) -> Result<HandshakeInitiation> {
        let peer_info = self
            .peers
            .get(peer_public_key)
            .ok_or_else(|| WireGuardError::ProtocolError("Unknown peer".to_string()))?;

        let mut initiator = InitiatorState::new(
            self.local_private_key,
            *peer_public_key,
            peer_info.preshared_key,
        );

        let initiation = initiator.create_initiation()?;
        let sender_id = initiation.sender;

        // Store the initiator state for when we receive the response
        self.pending_initiations.insert(sender_id, initiator);

        Ok(initiation)
    }

    /// Process received handshake initiation
    pub fn process_initiation(&mut self, msg: &HandshakeInitiation) -> Result<HandshakeResponse> {
        // Create responder state
        let mut responder = ResponderState::new(self.local_private_key, None);

        // Process the initiation to discover the peer
        let peer_public_key = responder.process_initiation(msg)?;

        // Look up peer info to get PSK if available
        let peer_info = self
            .peers
            .get(&peer_public_key)
            .ok_or_else(|| WireGuardError::ProtocolError("Unknown peer".to_string()))?;

        // Create new responder with correct PSK
        let mut responder = ResponderState::new(self.local_private_key, peer_info.preshared_key);
        let _peer_key = responder.process_initiation(msg)?; // Process again with PSK

        // Create response
        let response = responder.create_response(msg.sender)?;
        let sender_id = response.sender;

        // Derive keys and create active session
        let keys = responder.derive_keys()?;
        let session = ActiveSession {
            keys,
            peer_public_key,
            created_at: std::time::Instant::now(),
            last_used: std::time::Instant::now(),
        };

        // Store the active session
        self.active_sessions.insert(sender_id, session);

        Ok(response)
    }

    /// Process received handshake response
    pub fn process_response(&mut self, msg: &HandshakeResponse) -> Result<PublicKey25519> {
        // Find the corresponding initiator state
        let mut initiator = self
            .pending_initiations
            .remove(&msg.receiver)
            .ok_or_else(|| {
                WireGuardError::ProtocolError("No pending initiation found".to_string())
            })?;

        // Process the response to get session keys
        let keys = initiator.process_response(msg)?;

        // Find the peer we were talking to
        let peer_public_key = self
            .peers
            .iter()
            .find_map(|(key, _)| {
                // We need to match this somehow - for now return the first peer
                // TODO: Better way to identify which peer this response is from
                Some(*key)
            })
            .ok_or_else(|| WireGuardError::ProtocolError("Cannot identify peer".to_string()))?;

        // Create active session
        let session = ActiveSession {
            keys,
            peer_public_key,
            created_at: std::time::Instant::now(),
            last_used: std::time::Instant::now(),
        };

        // Store the active session using the sender ID from the response
        self.active_sessions.insert(msg.sender, session);

        Ok(peer_public_key)
    }

    /// Get active session by sender ID
    pub fn get_session(&self, sender_id: u32) -> Option<&ActiveSession> {
        self.active_sessions.get(&sender_id)
    }

    /// Get all active sessions
    pub fn active_sessions(&self) -> &HashMap<u32, ActiveSession> {
        &self.active_sessions
    }

    /// Get all configured peers
    pub fn peers(&self) -> &HashMap<PublicKey25519, PeerInfo> {
        &self.peers
    }

    /// Clean up expired sessions and pending handshakes
    pub fn cleanup(&mut self) {
        let now = std::time::Instant::now();
        let session_timeout = std::time::Duration::from_secs(180); // 3 minutes
        let _handshake_timeout = std::time::Duration::from_secs(30); // 30 seconds

        // Remove expired sessions
        self.active_sessions
            .retain(|_, session| now.duration_since(session.last_used) < session_timeout);

        // Remove expired pending handshakes
        // Note: This is a simple cleanup - in reality we'd track creation time
        if self.pending_initiations.len() > 100 {
            self.pending_initiations.clear();
        }
        if self.pending_responses.len() > 100 {
            self.pending_responses.clear();
        }
    }
}
