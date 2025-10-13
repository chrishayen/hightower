pub mod client;
pub mod server;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// STUN constants
pub const MAGIC_COOKIE: u32 = 0x2112A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;

// Attribute types
pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const MAPPED_ADDRESS: u16 = 0x0001;

// Address families
pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut bytes = [0u8; 12];

        // Simple transaction ID generation using time and process ID
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        bytes[0..8].copy_from_slice(&now.to_be_bytes());
        bytes[8..12].copy_from_slice(&std::process::id().to_be_bytes());

        TransactionId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct StunMessage {
    pub message_type: u16,
    pub length: u16,
    pub transaction_id: TransactionId,
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    pub fn new_binding_request() -> Self {
        StunMessage {
            message_type: BINDING_REQUEST,
            length: 0,
            transaction_id: TransactionId::new(),
            attributes: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(20 + self.length as usize);

        // Message type
        buffer.extend_from_slice(&self.message_type.to_be_bytes());

        // Message length
        buffer.extend_from_slice(&self.length.to_be_bytes());

        // Magic cookie
        buffer.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        buffer.extend_from_slice(self.transaction_id.as_bytes());

        // Attributes
        for attr in &self.attributes {
            buffer.extend_from_slice(&attr.encode());
        }

        buffer
    }

    pub fn decode(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < 20 {
            return Err(StunError::MessageTooShort);
        }

        // Check first two bits are 0
        if data[0] & 0xC0 != 0 {
            return Err(StunError::InvalidMessage);
        }

        let message_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]);
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if magic != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie);
        }

        let mut transaction_id_bytes = [0u8; 12];
        transaction_id_bytes.copy_from_slice(&data[8..20]);
        let transaction_id = TransactionId(transaction_id_bytes);

        if data.len() < 20 + length as usize {
            return Err(StunError::InvalidLength);
        }

        let mut attributes = Vec::new();
        let mut offset = 20;

        while offset < 20 + length as usize {
            let attr = Attribute::decode(&data[offset..])?;
            let attr_len = 4 + attr.length as usize;
            let padded_len = (attr_len + 3) & !3; // Round up to multiple of 4
            offset += padded_len;
            attributes.push(attr);
        }

        Ok(StunMessage {
            message_type,
            length,
            transaction_id,
            attributes,
        })
    }
}

#[derive(Debug)]
pub struct Attribute {
    pub attr_type: u16,
    pub length: u16,
    pub value: Vec<u8>,
}

impl Attribute {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.attr_type.to_be_bytes());
        buffer.extend_from_slice(&self.length.to_be_bytes());
        buffer.extend_from_slice(&self.value);

        // Pad to multiple of 4 bytes
        let padding = (4 - (self.length % 4)) % 4;
        buffer.resize(buffer.len() + padding as usize, 0);

        buffer
    }

    pub fn decode(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < 4 {
            return Err(StunError::AttributeTooShort);
        }

        let attr_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]);

        if data.len() < 4 + length as usize {
            return Err(StunError::InvalidLength);
        }

        let value = data[4..4 + length as usize].to_vec();

        Ok(Attribute {
            attr_type,
            length,
            value,
        })
    }

    pub fn decode_xor_mapped_address(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<SocketAddr, StunError> {
        if self.attr_type != XOR_MAPPED_ADDRESS {
            return Err(StunError::WrongAttributeType);
        }

        if self.value.len() < 4 {
            return Err(StunError::InvalidLength);
        }

        let family = self.value[1];
        let x_port = u16::from_be_bytes([self.value[2], self.value[3]]);

        // XOR port with most significant 16 bits of magic cookie
        let port = x_port ^ (MAGIC_COOKIE >> 16) as u16;

        match family {
            FAMILY_IPV4 => {
                if self.value.len() < 8 {
                    return Err(StunError::InvalidLength);
                }

                let x_addr = u32::from_be_bytes([
                    self.value[4],
                    self.value[5],
                    self.value[6],
                    self.value[7],
                ]);

                // XOR address with magic cookie
                let addr = x_addr ^ MAGIC_COOKIE;
                let ip = Ipv4Addr::from(addr);

                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            }
            FAMILY_IPV6 => {
                if self.value.len() < 20 {
                    return Err(StunError::InvalidLength);
                }

                // XOR address with magic cookie + transaction ID
                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id.as_bytes());

                let mut addr_bytes = [0u8; 16];
                for i in 0..16 {
                    addr_bytes[i] = self.value[4 + i] ^ xor_key[i];
                }

                let ip = Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => Err(StunError::UnsupportedAddressFamily),
        }
    }

    pub fn decode_mapped_address(&self) -> Result<SocketAddr, StunError> {
        if self.attr_type != MAPPED_ADDRESS {
            return Err(StunError::WrongAttributeType);
        }

        if self.value.len() < 4 {
            return Err(StunError::InvalidLength);
        }

        let family = self.value[1];
        let port = u16::from_be_bytes([self.value[2], self.value[3]]);

        match family {
            FAMILY_IPV4 => {
                if self.value.len() < 8 {
                    return Err(StunError::InvalidLength);
                }

                let addr = u32::from_be_bytes([
                    self.value[4],
                    self.value[5],
                    self.value[6],
                    self.value[7],
                ]);

                let ip = Ipv4Addr::from(addr);
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            }
            FAMILY_IPV6 => {
                if self.value.len() < 20 {
                    return Err(StunError::InvalidLength);
                }

                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&self.value[4..20]);

                let ip = Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => Err(StunError::UnsupportedAddressFamily),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum StunError {
    MessageTooShort,
    InvalidMessage,
    InvalidMagicCookie,
    InvalidLength,
    AttributeTooShort,
    WrongAttributeType,
    UnsupportedAddressFamily,
    NoMappedAddress,
    IoError(String),
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunError::MessageTooShort => write!(f, "STUN message too short"),
            StunError::InvalidMessage => write!(f, "Invalid STUN message"),
            StunError::InvalidMagicCookie => write!(f, "Invalid magic cookie"),
            StunError::InvalidLength => write!(f, "Invalid length"),
            StunError::AttributeTooShort => write!(f, "Attribute too short"),
            StunError::WrongAttributeType => write!(f, "Wrong attribute type"),
            StunError::UnsupportedAddressFamily => write!(f, "Unsupported address family"),
            StunError::NoMappedAddress => write!(f, "No mapped address in response"),
            StunError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for StunError {}

impl From<std::io::Error> for StunError {
    fn from(e: std::io::Error) -> Self {
        StunError::IoError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_request_encode() {
        let msg = StunMessage::new_binding_request();
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 20);
        assert_eq!(&encoded[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&encoded[2..4], &0u16.to_be_bytes());
        assert_eq!(&encoded[4..8], &MAGIC_COOKIE.to_be_bytes());
    }

    #[test]
    fn test_binding_request_decode() {
        let msg = StunMessage::new_binding_request();
        let encoded = msg.encode();
        let decoded = StunMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.message_type, BINDING_REQUEST);
        assert_eq!(decoded.length, 0);
        assert_eq!(decoded.transaction_id, msg.transaction_id);
    }

    #[test]
    fn test_xor_mapped_address_ipv4() {
        let transaction_id = TransactionId([0; 12]);

        // Encode a test IPv4 address 192.0.2.1:32768
        let test_ip = Ipv4Addr::new(192, 0, 2, 1);
        let test_port = 32768u16;

        // XOR the values
        let x_port = test_port ^ (MAGIC_COOKIE >> 16) as u16;
        let x_addr = u32::from(test_ip) ^ MAGIC_COOKIE;

        let mut value = vec![0u8, FAMILY_IPV4];
        value.extend_from_slice(&x_port.to_be_bytes());
        value.extend_from_slice(&x_addr.to_be_bytes());

        let attr = Attribute {
            attr_type: XOR_MAPPED_ADDRESS,
            length: value.len() as u16,
            value,
        };

        let addr = attr.decode_xor_mapped_address(&transaction_id).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(test_ip));
        assert_eq!(addr.port(), test_port);
    }
}
