use crate::crypto::PublicKey25519;

/// Message type identifier for handshake initiation (first message)
pub const MESSAGE_HANDSHAKE_INITIATION: u8 = 1;
/// Message type identifier for handshake response (second message)
pub const MESSAGE_HANDSHAKE_RESPONSE: u8 = 2;
/// Message type identifier for cookie reply (DoS protection)
pub const MESSAGE_COOKIE_REPLY: u8 = 3;
/// Message type identifier for transport data (encrypted tunnel packets)
pub const MESSAGE_TRANSPORT_DATA: u8 = 4;

/// First message in the WireGuard handshake (initiator to responder)
///
/// Contains encrypted static key and timestamp for establishing a session
#[derive(Debug, Clone)]
pub struct HandshakeInitiation {
    /// Message type (always MESSAGE_HANDSHAKE_INITIATION)
    pub message_type: u8,             // 1 byte
    /// Reserved bytes for alignment
    pub reserved: [u8; 3],            // 3 bytes
    /// Sender's session identifier
    pub sender: u32,                  // 4 bytes
    /// Initiator's ephemeral public key
    pub ephemeral: PublicKey25519,    // 32 bytes
    /// Encrypted static public key (32 bytes + 16 byte auth tag)
    pub static_encrypted: Vec<u8>,    // 48 bytes (32 + 16 for auth tag)
    /// Encrypted timestamp for replay protection (12 bytes + 16 byte auth tag)
    pub timestamp_encrypted: Vec<u8>, // 28 bytes (12 + 16 for auth tag)
    /// Message authentication code for cookie mechanism
    pub mac1: [u8; 16],               // 16 bytes
    /// Optional MAC for DoS protection
    pub mac2: [u8; 16],               // 16 bytes
}

/// Second message in the WireGuard handshake (responder to initiator)
///
/// Completes the handshake and establishes transport keys
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    /// Message type (always MESSAGE_HANDSHAKE_RESPONSE)
    pub message_type: u8,          // 1 byte
    /// Reserved bytes for alignment
    pub reserved: [u8; 3],         // 3 bytes
    /// Sender's session identifier
    pub sender: u32,               // 4 bytes
    /// Receiver's session identifier (from initiation message)
    pub receiver: u32,             // 4 bytes
    /// Responder's ephemeral public key
    pub ephemeral: PublicKey25519, // 32 bytes
    /// Encrypted empty payload (0 bytes + 16 byte auth tag)
    pub empty_encrypted: Vec<u8>,  // 16 bytes (0 + 16 for auth tag)
    /// Message authentication code for cookie mechanism
    pub mac1: [u8; 16],            // 16 bytes
    /// Optional MAC for DoS protection
    pub mac2: [u8; 16],            // 16 bytes
}

/// Encrypted data packet sent through the tunnel
///
/// Used for transmitting encrypted IP packets after handshake completion
#[derive(Debug, Clone)]
pub struct TransportData {
    /// Message type (always MESSAGE_TRANSPORT_DATA)
    pub message_type: u8,  // 1 byte
    /// Reserved bytes for alignment
    pub reserved: [u8; 3], // 3 bytes
    /// Receiver's session identifier
    pub receiver: u32,     // 4 bytes
    /// Packet counter for replay protection
    pub counter: u64,      // 8 bytes
    /// Encrypted packet data
    pub packet: Vec<u8>,   // variable length
}

/// Cookie reply message for DoS protection
///
/// Sent in response to handshake initiation under load conditions
#[derive(Debug, Clone)]
pub struct CookieReply {
    /// Message type (always MESSAGE_COOKIE_REPLY)
    pub message_type: u8,  // 1 byte
    /// Reserved bytes for alignment
    pub reserved: [u8; 3], // 3 bytes
    /// Receiver's session identifier
    pub receiver: u32,     // 4 bytes
    /// Nonce for cookie encryption
    pub nonce: [u8; 24],   // 24 bytes
    /// Encrypted cookie (16 bytes + 16 byte auth tag)
    pub cookie: Vec<u8>,   // 32 bytes (16 + 16 for auth tag)
}

impl HandshakeInitiation {
    /// Create a new handshake initiation message with default values
    pub fn new() -> Self {
        Self {
            message_type: MESSAGE_HANDSHAKE_INITIATION,
            reserved: [0; 3],
            sender: 0,
            ephemeral: [0; 32],
            static_encrypted: Vec::new(),
            timestamp_encrypted: Vec::new(),
            mac1: [0; 16],
            mac2: [0; 16],
        }
    }
}

impl HandshakeResponse {
    /// Create a new handshake response message with default values
    pub fn new() -> Self {
        Self {
            message_type: MESSAGE_HANDSHAKE_RESPONSE,
            reserved: [0; 3],
            sender: 0,
            receiver: 0,
            ephemeral: [0; 32],
            empty_encrypted: Vec::new(),
            mac1: [0; 16],
            mac2: [0; 16],
        }
    }
}

impl TransportData {
    /// Create a new transport data message with default values
    pub fn new() -> Self {
        Self {
            message_type: MESSAGE_TRANSPORT_DATA,
            reserved: [0; 3],
            receiver: 0,
            counter: 0,
            packet: Vec::new(),
        }
    }
}

impl CookieReply {
    /// Create a new cookie reply message with default values
    pub fn new() -> Self {
        Self {
            message_type: MESSAGE_COOKIE_REPLY,
            reserved: [0; 3],
            receiver: 0,
            nonce: [0; 24],
            cookie: Vec::new(),
        }
    }
}
