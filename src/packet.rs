use std::net::Ipv4Addr;

/// Build a simple mDNS A record response packet
pub fn build_mdns_packet(name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut packet = Vec::new();

    // DNS Header (12 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    packet.extend_from_slice(&[0x84, 0x00]); // Flags: Response, Authoritative
    packet.extend_from_slice(&[0x00, 0x00]); // Questions: 0
    packet.extend_from_slice(&[0x00, 0x01]); // Answer RRs: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // QNAME: encode the hostname
    let full_name = format!("{}.local", name);
    for label in full_name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // End of QNAME

    // TYPE: A (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    // CLASS: IN with cache-flush bit (0x8001)
    packet.extend_from_slice(&[0x80, 0x01]);

    // TTL: 120 seconds
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);

    // RDLENGTH: 4 (for IPv4 address)
    packet.extend_from_slice(&[0x00, 0x04]);

    // RDATA: IP address
    packet.extend_from_slice(&ip.octets());

    packet
}

/// Build an mDNS query packet
pub fn build_mdns_query(name: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // DNS Header (12 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    packet.extend_from_slice(&[0x00, 0x00]); // Flags: Query
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // QNAME: encode the hostname
    let full_name = format!("{}.local", name);
    for label in full_name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // End of QNAME

    // QTYPE: A (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    // QCLASS: IN (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Parse an mDNS query packet and extract the queried name
pub fn parse_mdns_query(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }

    // Check if it's a query (QR bit should be 0)
    if packet[2] & 0x80 != 0 {
        return None;
    }

    // Get question count
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if question_count == 0 {
        return None;
    }

    // Parse the first question's QNAME
    let mut pos = 12;
    let mut name_parts = Vec::new();

    while pos < packet.len() {
        let len = packet[pos] as usize;
        if len == 0 {
            break;
        }

        pos += 1;
        if pos + len > packet.len() {
            return None;
        }

        if let Ok(label) = std::str::from_utf8(&packet[pos..pos + len]) {
            name_parts.push(label.to_string());
        } else {
            return None;
        }

        pos += len;
    }

    if name_parts.is_empty() {
        None
    } else {
        Some(name_parts.join("."))
    }
}

/// Parse an mDNS response/announcement packet and extract hostname
pub fn parse_mdns_response(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }

    // Check if it's a response (QR bit should be 1)
    if packet[2] & 0x80 == 0 {
        return None;
    }

    // Get answer count
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
    if answer_count == 0 {
        return None;
    }

    // Skip questions section
    let mut pos = 12;
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);

    for _ in 0..question_count {
        while pos < packet.len() && packet[pos] != 0 {
            let len = packet[pos] as usize;
            pos += 1 + len;
        }
        pos += 1;
        pos += 4; // Skip QTYPE and QCLASS
    }

    if pos >= packet.len() {
        return None;
    }

    // Parse hostname from first answer
    let mut name_parts = Vec::new();

    while pos < packet.len() {
        let len = packet[pos] as usize;

        // Handle DNS compression pointer
        if len >= 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let offset = (u16::from_be_bytes([packet[pos] & 0x3F, packet[pos + 1]])) as usize;
            let mut offset_pos = offset;
            while offset_pos < packet.len() {
                let offset_len = packet[offset_pos] as usize;
                if offset_len == 0 || offset_len >= 0xC0 {
                    break;
                }
                offset_pos += 1;
                if offset_pos + offset_len > packet.len() {
                    return None;
                }
                if let Ok(label) = std::str::from_utf8(&packet[offset_pos..offset_pos + offset_len]) {
                    name_parts.push(label.to_string());
                }
                offset_pos += offset_len;
            }
            break;
        }

        if len == 0 {
            break;
        }

        pos += 1;
        if pos + len > packet.len() {
            return None;
        }

        if let Ok(label) = std::str::from_utf8(&packet[pos..pos + len]) {
            name_parts.push(label.to_string());
        } else {
            return None;
        }

        pos += len;
    }

    if name_parts.is_empty() {
        None
    } else {
        Some(name_parts.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mdns_packet() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let packet = build_mdns_packet("testhost", ip);

        // Verify header
        assert_eq!(packet[2], 0x84); // Response flag
        assert_eq!(packet[7], 0x01); // 1 answer

        // Verify the name is encoded
        assert!(packet.len() > 12); // Header + data

        // Verify IP address is in the packet
        let ip_octets = ip.octets();
        let packet_len = packet.len();
        assert_eq!(&packet[packet_len - 4..], &ip_octets);
    }

    #[test]
    fn test_parse_mdns_query() {
        // Build a simple query packet for "testhost.local"
        let mut packet = vec![
            0x00, 0x00, // Transaction ID
            0x00, 0x00, // Flags: Query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];

        // QNAME: testhost.local
        packet.push(8); // length of "testhost"
        packet.extend_from_slice(b"testhost");
        packet.push(5); // length of "local"
        packet.extend_from_slice(b"local");
        packet.push(0); // End of QNAME

        let parsed = parse_mdns_query(&packet);
        assert_eq!(parsed, Some("testhost.local".to_string()));
    }

    #[test]
    fn test_parse_mdns_response() {
        // Response packets should return None
        let packet = vec![
            0x00, 0x00, // Transaction ID
            0x84, 0x00, // Flags: Response
            0x00, 0x00, // Questions: 0
            0x00, 0x01, // Answer RRs: 1
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];

        let parsed = parse_mdns_query(&packet);
        assert_eq!(parsed, None);
    }

    #[test]
    fn test_build_mdns_query() {
        let packet = build_mdns_query("testhost");

        // Verify header
        assert_eq!(packet[2], 0x00); // Query flag
        assert_eq!(packet[3], 0x00); // Query flag
        assert_eq!(packet[5], 0x01); // 1 question

        // Verify it contains the name
        assert!(packet.len() > 12);
    }
}