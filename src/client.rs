use crate::{StunError, StunMessage, XOR_MAPPED_ADDRESS, MAPPED_ADDRESS};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub struct StunClient {
    socket: UdpSocket,
    timeout: Duration,
}

impl StunClient {
    pub fn new() -> Result<Self, StunError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(StunClient {
            socket,
            timeout: Duration::from_secs(5),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.socket.set_read_timeout(Some(timeout)).ok();
        self.socket.set_write_timeout(Some(timeout)).ok();
        self
    }

    pub fn get_public_address(&self, server: &str) -> Result<SocketAddr, StunError> {
        let server_addr: SocketAddr = server
            .parse()
            .map_err(|_| StunError::IoError("Invalid server address".to_string()))?;

        let request = StunMessage::new_binding_request();
        let request_bytes = request.encode();

        self.socket.send_to(&request_bytes, server_addr)?;

        let mut buffer = [0u8; 1024];
        let (len, _) = self.socket.recv_from(&mut buffer)?;

        let response = StunMessage::decode(&buffer[..len])?;

        if response.transaction_id != request.transaction_id {
            return Err(StunError::InvalidMessage);
        }

        for attr in &response.attributes {
            if attr.attr_type == XOR_MAPPED_ADDRESS {
                return attr.decode_xor_mapped_address(&response.transaction_id);
            }
            if attr.attr_type == MAPPED_ADDRESS {
                return attr.decode_mapped_address();
            }
        }

        Err(StunError::NoMappedAddress)
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new().expect("Failed to create STUN client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_client_creation() {
        let client = StunClient::new();
        assert!(client.is_ok());
    }

    #[test]
    #[ignore] // Requires network access
    fn test_get_public_address() {
        let client = StunClient::new().unwrap();
        // Google's public STUN server
        let result = client.get_public_address("stun.l.google.com:19302");
        println!("Result: {:?}", result);
        assert!(result.is_ok());
    }
}
