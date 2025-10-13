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

    /// Serialize message to wire format (148 bytes)
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        if self.static_encrypted.len() != 48 {
            return Err(format!(
                "static_encrypted must be 48 bytes, got {}",
                self.static_encrypted.len()
            ));
        }
        if self.timestamp_encrypted.len() != 28 {
            return Err(format!(
                "timestamp_encrypted must be 28 bytes, got {}",
                self.timestamp_encrypted.len()
            ));
        }

        let mut bytes = Vec::with_capacity(148);
        bytes.push(self.message_type);
        bytes.extend_from_slice(&self.reserved);
        bytes.extend_from_slice(&self.sender.to_le_bytes());
        bytes.extend_from_slice(&self.ephemeral);
        bytes.extend_from_slice(&self.static_encrypted);
        bytes.extend_from_slice(&self.timestamp_encrypted);
        bytes.extend_from_slice(&self.mac1);
        bytes.extend_from_slice(&self.mac2);
        Ok(bytes)
    }

    /// Deserialize message from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 148 {
            return Err(format!("expected 148 bytes, got {}", data.len()));
        }
        if data[0] != MESSAGE_HANDSHAKE_INITIATION {
            return Err(format!("expected message type {}, got {}", MESSAGE_HANDSHAKE_INITIATION, data[0]));
        }

        let mut msg = Self::new();
        msg.message_type = data[0];
        msg.reserved.copy_from_slice(&data[1..4]);
        msg.sender = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        msg.ephemeral.copy_from_slice(&data[8..40]);
        msg.static_encrypted = data[40..88].to_vec();
        msg.timestamp_encrypted = data[88..116].to_vec();
        msg.mac1.copy_from_slice(&data[116..132]);
        msg.mac2.copy_from_slice(&data[132..148]);
        Ok(msg)
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

    /// Serialize message to wire format (92 bytes)
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        if self.empty_encrypted.len() != 16 {
            return Err(format!(
                "empty_encrypted must be 16 bytes, got {}",
                self.empty_encrypted.len()
            ));
        }

        let mut bytes = Vec::with_capacity(92);
        bytes.push(self.message_type);
        bytes.extend_from_slice(&self.reserved);
        bytes.extend_from_slice(&self.sender.to_le_bytes());
        bytes.extend_from_slice(&self.receiver.to_le_bytes());
        bytes.extend_from_slice(&self.ephemeral);
        bytes.extend_from_slice(&self.empty_encrypted);
        bytes.extend_from_slice(&self.mac1);
        bytes.extend_from_slice(&self.mac2);
        Ok(bytes)
    }

    /// Deserialize message from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 92 {
            return Err(format!("expected 92 bytes, got {}", data.len()));
        }
        if data[0] != MESSAGE_HANDSHAKE_RESPONSE {
            return Err(format!("expected message type {}, got {}", MESSAGE_HANDSHAKE_RESPONSE, data[0]));
        }

        let mut msg = Self::new();
        msg.message_type = data[0];
        msg.reserved.copy_from_slice(&data[1..4]);
        msg.sender = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        msg.receiver = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        msg.ephemeral.copy_from_slice(&data[12..44]);
        msg.empty_encrypted = data[44..60].to_vec();
        msg.mac1.copy_from_slice(&data[60..76]);
        msg.mac2.copy_from_slice(&data[76..92]);
        Ok(msg)
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

    /// Serialize message to wire format (16 bytes header + variable packet data)
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(16 + self.packet.len());
        bytes.push(self.message_type);
        bytes.extend_from_slice(&self.reserved);
        bytes.extend_from_slice(&self.receiver.to_le_bytes());
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&self.packet);
        Ok(bytes)
    }

    /// Deserialize message from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!("expected at least 16 bytes, got {}", data.len()));
        }
        if data[0] != MESSAGE_TRANSPORT_DATA {
            return Err(format!("expected message type {}, got {}", MESSAGE_TRANSPORT_DATA, data[0]));
        }

        let mut msg = Self::new();
        msg.message_type = data[0];
        msg.reserved.copy_from_slice(&data[1..4]);
        msg.receiver = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        msg.counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);
        msg.packet = data[16..].to_vec();
        Ok(msg)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_init_roundtrip() {
        let mut msg = HandshakeInitiation::new();
        msg.sender = 12345;
        msg.ephemeral = [1u8; 32];
        msg.static_encrypted = vec![2u8; 48];
        msg.timestamp_encrypted = vec![3u8; 28];
        msg.mac1 = [4u8; 16];
        msg.mac2 = [5u8; 16];

        let bytes = msg.to_bytes().unwrap();
        assert_eq!(bytes.len(), 148);

        let decoded = HandshakeInitiation::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender, 12345);
        assert_eq!(decoded.ephemeral, [1u8; 32]);
    }

    #[test]
    fn handshake_response_roundtrip() {
        let mut msg = HandshakeResponse::new();
        msg.sender = 54321;
        msg.receiver = 12345;
        msg.ephemeral = [6u8; 32];
        msg.empty_encrypted = vec![7u8; 16];
        msg.mac1 = [8u8; 16];
        msg.mac2 = [9u8; 16];

        let bytes = msg.to_bytes().unwrap();
        assert_eq!(bytes.len(), 92);

        let decoded = HandshakeResponse::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender, 54321);
        assert_eq!(decoded.receiver, 12345);
    }

    #[test]
    fn transport_data_roundtrip() {
        let mut msg = TransportData::new();
        msg.receiver = 99999;
        msg.counter = 42;
        msg.packet = vec![10u8; 100];

        let bytes = msg.to_bytes().unwrap();
        assert_eq!(bytes.len(), 116); // 16 + 100

        let decoded = TransportData::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.receiver, 99999);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.packet.len(), 100);
    }
}
