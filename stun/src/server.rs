use crate::{
    Attribute, StunError, StunMessage, TransactionId, BINDING_REQUEST, BINDING_RESPONSE,
    FAMILY_IPV4, FAMILY_IPV6, MAGIC_COOKIE, XOR_MAPPED_ADDRESS,
};
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub struct StunServer {
    socket: UdpSocket,
}

impl StunServer {
    pub fn bind(addr: &str) -> Result<Self, StunError> {
        let socket = UdpSocket::bind(addr)?;
        Ok(StunServer { socket })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn run(&self) -> Result<(), StunError> {
        let mut buffer = [0u8; 1024];

        loop {
            let (len, client_addr) = self.socket.recv_from(&mut buffer)?;

            if let Err(e) = self.handle_request(&buffer[..len], client_addr) {
                eprintln!("Error handling request from {}: {}", client_addr, e);
            }
        }
    }

    fn handle_request(&self, data: &[u8], client_addr: SocketAddr) -> Result<(), StunError> {
        let request = StunMessage::decode(data)?;

        if request.message_type != BINDING_REQUEST {
            return Ok(());
        }

        let response = self.create_binding_response(&request, client_addr)?;
        let response_bytes = response.encode();

        self.socket.send_to(&response_bytes, client_addr)?;

        Ok(())
    }

    fn create_binding_response(
        &self,
        request: &StunMessage,
        client_addr: SocketAddr,
    ) -> Result<StunMessage, StunError> {
        let xor_mapped_attr = create_xor_mapped_address(client_addr, &request.transaction_id)?;

        let attr_len = 4 + xor_mapped_attr.length as usize;
        let padded_len = (attr_len + 3) & !3;

        Ok(StunMessage {
            message_type: BINDING_RESPONSE,
            length: padded_len as u16,
            transaction_id: request.transaction_id,
            attributes: vec![xor_mapped_attr],
        })
    }
}

fn create_xor_mapped_address(
    addr: SocketAddr,
    transaction_id: &TransactionId,
) -> Result<Attribute, StunError> {
    let mut value = Vec::new();

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            value.push(0); // Reserved
            value.push(FAMILY_IPV4);

            // XOR port with most significant 16 bits of magic cookie
            let x_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
            value.extend_from_slice(&x_port.to_be_bytes());

            // XOR address with magic cookie
            let ip_u32 = u32::from(ipv4);
            let x_addr = ip_u32 ^ MAGIC_COOKIE;
            value.extend_from_slice(&x_addr.to_be_bytes());
        }
        IpAddr::V6(ipv6) => {
            value.push(0); // Reserved
            value.push(FAMILY_IPV6);

            // XOR port with most significant 16 bits of magic cookie
            let x_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
            value.extend_from_slice(&x_port.to_be_bytes());

            // XOR address with magic cookie + transaction ID
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(transaction_id.as_bytes());

            let ip_bytes = ipv6.octets();
            for i in 0..16 {
                value.push(ip_bytes[i] ^ xor_key[i]);
            }
        }
    }

    Ok(Attribute {
        attr_type: XOR_MAPPED_ADDRESS,
        length: value.len() as u16,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_create_xor_mapped_address_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32768);
        let transaction_id = TransactionId([0; 12]);

        let attr = create_xor_mapped_address(addr, &transaction_id).unwrap();

        assert_eq!(attr.attr_type, XOR_MAPPED_ADDRESS);
        assert_eq!(attr.value[1], FAMILY_IPV4);

        // Decode it back to verify
        let decoded = attr.decode_xor_mapped_address(&transaction_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_create_xor_mapped_address_ipv6() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let attr = create_xor_mapped_address(addr, &transaction_id).unwrap();

        assert_eq!(attr.attr_type, XOR_MAPPED_ADDRESS);
        assert_eq!(attr.value[1], FAMILY_IPV6);

        // Decode it back to verify
        let decoded = attr.decode_xor_mapped_address(&transaction_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_binding_response_creation() {
        let request = StunMessage::new_binding_request();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);

        let server = StunServer {
            socket: UdpSocket::bind("127.0.0.1:0").unwrap(),
        };

        let response = server
            .create_binding_response(&request, client_addr)
            .unwrap();

        assert_eq!(response.message_type, BINDING_RESPONSE);
        assert_eq!(response.transaction_id, request.transaction_id);
        assert_eq!(response.attributes.len(), 1);
        assert_eq!(response.attributes[0].attr_type, XOR_MAPPED_ADDRESS);

        // Verify the address can be decoded back
        let decoded_addr = response.attributes[0]
            .decode_xor_mapped_address(&response.transaction_id)
            .unwrap();
        assert_eq!(decoded_addr, client_addr);
    }
}
