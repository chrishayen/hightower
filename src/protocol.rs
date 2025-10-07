use crate::crypto::{PrivateKey, PublicKey25519, dh_generate};
use crate::initiator::{InitiatorState, SessionKeys};
use crate::messages::{HandshakeInitiation, HandshakeResponse};
use crate::replay::ReplayWindow;
use crate::responder::ResponderState;
use crate::{Result, WireGuardError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Time after which to initiate a new handshake (RFC: REKEY-AFTER-TIME)
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Time after which to reject packets and require new handshake (RFC: REJECT-AFTER-TIME)
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Time to wait before sending keep-alive if no data has been sent
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration and metadata for a WireGuard peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's public key for authentication and key derivation
    pub public_key: PublicKey25519,
    /// Optional preshared key for additional security
    pub preshared_key: Option<[u8; 32]>,
    /// Network endpoint (IP address and port) for the peer
    pub endpoint: Option<SocketAddr>,
    /// IP ranges allowed for this peer (IP address and prefix length)
    pub allowed_ips: Vec<(std::net::IpAddr, u8)>, // IP and prefix length
    /// Interval in seconds for keepalive packets
    pub persistent_keepalive: Option<u16>,
}

/// Active cryptographic session with established transport keys
#[derive(Debug, Clone)]
pub struct ActiveSession {
    /// Transport keys for encrypting/decrypting data
    pub keys: SessionKeys,
    /// Public key of the peer this session is with
    pub peer_public_key: PublicKey25519,
    /// Timestamp when this session was created (handshake completed)
    pub created_at: std::time::Instant,
    /// Timestamp of last activity on this session
    pub last_used: std::time::Instant,
    /// Timestamp of last data sent on this session
    pub last_send: std::time::Instant,
    /// Current endpoint address for this peer (updated on packet receipt)
    pub endpoint: Option<SocketAddr>,
    /// Replay protection window for received packets
    pub replay_window: ReplayWindow,
}

/// Main WireGuard protocol handler managing peers and sessions
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
        let now = std::time::Instant::now();
        let session = ActiveSession {
            keys,
            peer_public_key,
            created_at: now,
            last_used: now,
            last_send: now,
            endpoint: None,
            replay_window: ReplayWindow::new(),
        };

        // Store the active session
        self.active_sessions.insert(sender_id, session);

        #[cfg(feature = "transport")]
        {
            use tracing::info;
            let peer_key_hex = hex::encode(peer_public_key);
            info!(
                session_id = sender_id,
                peer_public_key = &peer_key_hex[..8],
                "SESSION: New session created (responder)"
            );
        }

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
        let now = std::time::Instant::now();
        let session = ActiveSession {
            keys,
            peer_public_key,
            created_at: now,
            last_used: now,
            last_send: now,
            endpoint: None,
            replay_window: ReplayWindow::new(),
        };

        // Store the active session using the sender ID from the response
        self.active_sessions.insert(msg.sender, session);

        #[cfg(feature = "transport")]
        {
            use tracing::info;
            let peer_key_hex = hex::encode(peer_public_key);
            info!(
                session_id = msg.sender,
                peer_public_key = &peer_key_hex[..8],
                "SESSION: New session created (initiator)"
            );
        }

        Ok(peer_public_key)
    }

    /// Get active session by sender ID
    pub fn get_session(&self, sender_id: u32) -> Option<&ActiveSession> {
        self.active_sessions.get(&sender_id)
    }

    /// Get mutable active session by sender ID
    pub fn get_session_mut(&mut self, sender_id: u32) -> Option<&mut ActiveSession> {
        self.active_sessions.get_mut(&sender_id)
    }

    /// Check and update replay window for a received packet
    ///
    /// Returns Ok(()) if the counter is valid and not a replay, Err otherwise
    pub fn check_replay(&mut self, sender_id: u32, counter: u64) -> Result<()> {
        let session = self
            .get_session_mut(sender_id)
            .ok_or_else(|| WireGuardError::ProtocolError("No active session".to_string()))?;

        if session.replay_window.check_and_update(counter) {
            session.last_used = std::time::Instant::now();
            Ok(())
        } else {
            Err(WireGuardError::ProtocolError("Replay detected".to_string()))
        }
    }

    /// Get a reference to all active sessions
    ///
    /// Returns a map of session IDs to active sessions
    pub fn active_sessions(&self) -> &HashMap<u32, ActiveSession> {
        &self.active_sessions
    }

    /// Get a reference to all configured peers
    ///
    /// Returns a map of public keys to peer information
    pub fn peers(&self) -> &HashMap<PublicKey25519, PeerInfo> {
        &self.peers
    }

    /// Remove expired sessions and stale pending handshakes
    ///
    /// Should be called periodically to prevent resource leaks
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

    /// Update endpoint address for a session when receiving a packet
    ///
    /// Supports endpoint roaming (mobile devices changing networks)
    pub fn update_endpoint(&mut self, sender_id: u32, new_endpoint: SocketAddr) {
        if let Some(session) = self.active_sessions.get_mut(&sender_id) {
            let old_endpoint = session.endpoint;
            if old_endpoint != Some(new_endpoint) {
                #[cfg(feature = "transport")]
                {
                    use tracing::info;
                    let peer_key_hex = hex::encode(session.peer_public_key);
                    info!(
                        session_id = sender_id,
                        peer_public_key = &peer_key_hex[..8],
                        old_endpoint = ?old_endpoint,
                        new_endpoint = %new_endpoint,
                        "ROAMING: Endpoint updated for session"
                    );
                }
            }
            session.endpoint = Some(new_endpoint);
        }
    }

    /// Update last send time for a session
    pub fn update_last_send(&mut self, sender_id: u32) {
        if let Some(session) = self.active_sessions.get_mut(&sender_id) {
            session.last_send = std::time::Instant::now();
        }
    }

    /// Check if a session needs rekeying based on age
    ///
    /// Returns true if the session is older than REKEY_AFTER_TIME
    pub fn needs_rekey(&self, sender_id: u32) -> bool {
        if let Some(session) = self.active_sessions.get(&sender_id) {
            let age = std::time::Instant::now().duration_since(session.created_at);
            age >= REKEY_AFTER_TIME
        } else {
            false
        }
    }

    /// Check if a session should be rejected (too old)
    ///
    /// Returns true if the session is older than REJECT_AFTER_TIME
    pub fn should_reject(&self, sender_id: u32) -> bool {
        if let Some(session) = self.active_sessions.get(&sender_id) {
            let age = std::time::Instant::now().duration_since(session.created_at);
            age >= REJECT_AFTER_TIME
        } else {
            true
        }
    }

    /// Find session by peer public key
    pub fn find_session_by_peer(&self, peer_public_key: &PublicKey25519) -> Option<(u32, &ActiveSession)> {
        self.active_sessions
            .iter()
            .find(|(_, session)| session.peer_public_key == *peer_public_key)
            .map(|(id, session)| (*id, session))
    }

    /// Find mutable session by peer public key
    pub fn find_session_by_peer_mut(&mut self, peer_public_key: &PublicKey25519) -> Option<(u32, &mut ActiveSession)> {
        self.active_sessions
            .iter_mut()
            .find(|(_, session)| session.peer_public_key == *peer_public_key)
            .map(|(id, session)| (*id, session))
    }
}
