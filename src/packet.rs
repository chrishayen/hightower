use std::net::Ipv4Addr;

/// Build a simple mDNS A record response packet
///
/// Creates an mDNS response packet advertising the given hostname and IP address
/// with a default TTL of 120 seconds.
///
/// # Arguments
///
/// * `name` - The hostname (without domain suffix)
/// * `domain` - The domain to use
/// * `ip` - The IPv4 address to advertise
///
/// # Returns
///
/// A byte vector containing the complete mDNS response packet
pub fn build_mdns_packet(name: &str, domain: &str, ip: Ipv4Addr) -> Vec<u8> {
    build_mdns_packet_with_ttl(name, domain, ip, 120)
}

/// Build a goodbye packet (TTL = 0)
///
/// Creates an mDNS goodbye packet to announce that a service is shutting down.
/// This is the same as a regular response but with TTL set to 0.
///
/// # Arguments
///
/// * `name` - The hostname (without domain suffix)
/// * `domain` - The domain to use
/// * `ip` - The IPv4 address being removed
///
/// # Returns
///
/// A byte vector containing the complete mDNS goodbye packet
pub fn build_goodbye_packet(name: &str, domain: &str, ip: Ipv4Addr) -> Vec<u8> {
    build_mdns_packet_with_ttl(name, domain, ip, 0)
}

/// Build an mDNS A record response packet with custom TTL
fn build_mdns_packet_with_ttl(name: &str, domain: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut packet = Vec::new();

    // DNS Header (12 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    packet.extend_from_slice(&[0x84, 0x00]); // Flags: Response, Authoritative
    packet.extend_from_slice(&[0x00, 0x00]); // Questions: 0
    packet.extend_from_slice(&[0x00, 0x01]); // Answer RRs: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // QNAME: encode the hostname
    let full_name = format!("{}.{}", name, domain);
    for label in full_name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // End of QNAME

    // TYPE: A (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    // CLASS: IN with cache-flush bit (0x8001)
    packet.extend_from_slice(&[0x80, 0x01]);

    // TTL: specified seconds
    packet.extend_from_slice(&ttl.to_be_bytes());

    // RDLENGTH: 4 (for IPv4 address)
    packet.extend_from_slice(&[0x00, 0x04]);

    // RDATA: IP address
    packet.extend_from_slice(&ip.octets());

    packet
}

/// Build an mDNS query packet
///
/// Creates an mDNS query packet to search for a specific hostname on the network.
///
/// # Arguments
///
/// * `name` - The hostname to query (without domain suffix)
/// * `domain` - The domain to use
///
/// # Returns
///
/// A byte vector containing the complete mDNS query packet
pub fn build_mdns_query(name: &str, domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // DNS Header (12 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    packet.extend_from_slice(&[0x00, 0x00]); // Flags: Query
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // QNAME: encode the hostname
    let full_name = format!("{}.{}", name, domain);
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
///
/// Parses an incoming mDNS query packet and extracts the hostname being queried.
///
/// # Arguments
///
/// * `packet` - The raw mDNS packet data
///
/// # Returns
///
/// The queried hostname as a string, or `None` if the packet is invalid or not a query
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

/// Parse an mDNS response/announcement packet and extract hostname and IP address
///
/// Parses an incoming mDNS response or announcement packet and extracts the hostname
/// and IPv4 address from the first A record.
///
/// # Arguments
///
/// * `packet` - The raw mDNS packet data
///
/// # Returns
///
/// A tuple of (hostname, IP address), or `None` if the packet is invalid, not a response,
/// or doesn't contain a valid A record
pub fn parse_mdns_response(packet: &[u8]) -> Option<(String, Ipv4Addr)> {
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
            pos += 2; // Skip the compression pointer
            break;
        }

        if len == 0 {
            pos += 1; // Skip the null terminator
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
        return None;
    }

    // Now we're at the TYPE field
    if pos + 10 > packet.len() {
        return None;
    }

    // Read TYPE
    let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    pos += 2;

    // Read CLASS
    pos += 2;

    // Read TTL
    pos += 4;

    // Read RDLENGTH
    let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    pos += 2;

    // Check if it's an A record and has correct length
    if rtype != 1 || rdlength != 4 {
        return None;
    }

    // Read the IP address
    if pos + 4 > packet.len() {
        return None;
    }

    let ip = Ipv4Addr::new(packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]);

    Some((name_parts.join("."), ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mdns_packet() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let packet = build_mdns_packet("testhost", "local", ip);

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
        let packet = build_mdns_query("testhost", "local");

        // Verify header
        assert_eq!(packet[2], 0x00); // Query flag
        assert_eq!(packet[3], 0x00); // Query flag
        assert_eq!(packet[5], 0x01); // 1 question

        // Verify it contains the name
        assert!(packet.len() > 12);
    }

    #[test]
    fn test_build_goodbye_packet() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let packet = build_goodbye_packet("testhost", "local", ip);

        // Verify header
        assert_eq!(packet[2], 0x84); // Response flag
        assert_eq!(packet[7], 0x01); // 1 answer

        // Find TTL position (after name encoding)
        // Name is "testhost.local":
        //   1 byte length (8) + 8 bytes "testhost"
        //   1 byte length (5) + 5 bytes "local"
        //   1 byte null = 16 bytes total
        // After header (12 bytes) + name (16 bytes) + TYPE (2) + CLASS (2) = 32 bytes
        // TTL starts at position 32
        let ttl_pos = 32;
        let ttl = u32::from_be_bytes([
            packet[ttl_pos],
            packet[ttl_pos + 1],
            packet[ttl_pos + 2],
            packet[ttl_pos + 3],
        ]);
        assert_eq!(ttl, 0); // TTL should be 0 for goodbye packet

        // Verify IP address is still in the packet
        let ip_octets = ip.octets();
        let packet_len = packet.len();
        assert_eq!(&packet[packet_len - 4..], &ip_octets);
    }
}