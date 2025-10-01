use crate::crypto::PublicKey25519;

// Message type constants from WireGuard spec
pub const MESSAGE_HANDSHAKE_INITIATION: u8 = 1;
pub const MESSAGE_HANDSHAKE_RESPONSE: u8 = 2;
pub const MESSAGE_COOKIE_REPLY: u8 = 3;
pub const MESSAGE_TRANSPORT_DATA: u8 = 4;

#[derive(Debug, Clone)]
pub struct HandshakeInitiation {
    pub message_type: u8,             // 1 byte
    pub reserved: [u8; 3],            // 3 bytes
    pub sender: u32,                  // 4 bytes
    pub ephemeral: PublicKey25519,    // 32 bytes
    pub static_encrypted: Vec<u8>,    // 48 bytes (32 + 16 for auth tag)
    pub timestamp_encrypted: Vec<u8>, // 28 bytes (12 + 16 for auth tag)
    pub mac1: [u8; 16],               // 16 bytes
    pub mac2: [u8; 16],               // 16 bytes
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub message_type: u8,          // 1 byte
    pub reserved: [u8; 3],         // 3 bytes
    pub sender: u32,               // 4 bytes
    pub receiver: u32,             // 4 bytes
    pub ephemeral: PublicKey25519, // 32 bytes
    pub empty_encrypted: Vec<u8>,  // 16 bytes (0 + 16 for auth tag)
    pub mac1: [u8; 16],            // 16 bytes
    pub mac2: [u8; 16],            // 16 bytes
}

#[derive(Debug, Clone)]
pub struct TransportData {
    pub message_type: u8,  // 1 byte
    pub reserved: [u8; 3], // 3 bytes
    pub receiver: u32,     // 4 bytes
    pub counter: u64,      // 8 bytes
    pub packet: Vec<u8>,   // variable length
}

#[derive(Debug, Clone)]
pub struct CookieReply {
    pub message_type: u8,  // 1 byte
    pub reserved: [u8; 3], // 3 bytes
    pub receiver: u32,     // 4 bytes
    pub nonce: [u8; 24],   // 24 bytes
    pub cookie: Vec<u8>,   // 32 bytes (16 + 16 for auth tag)
}

impl HandshakeInitiation {
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
