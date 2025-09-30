use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time;

const MDNS_PORT: u16 = 5353;
const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS service for advertising a hostname on the local network
pub struct Mdns {
    name: String,
    broadcast_interval: Duration,
    send_socket: Socket,
    recv_socket: Socket,
    local_ip: Ipv4Addr,
}

impl Mdns {
    /// Create a new mDNS instance with the given name and IP address
    ///
    /// # Arguments
    ///
    /// * `name` - The mDNS name to advertise (without .local suffix)
    /// * `ip` - The local IPv4 address to advertise
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hightower_mdns::Mdns;
    /// use std::net::Ipv4Addr;
    ///
    /// let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100)).unwrap();
    /// ```
    pub fn new<S: Into<String>>(name: S, ip: Ipv4Addr) -> io::Result<Self> {
        Self::with_interval(name, ip, Duration::from_secs(120))
    }

    /// Create a new mDNS instance with a custom broadcast interval
    ///
    /// # Arguments
    ///
    /// * `name` - The mDNS name to advertise (without .local suffix)
    /// * `ip` - The local IPv4 address to advertise
    /// * `interval` - Time between broadcasts (default is 120 seconds per RFC 6762)
    pub fn with_interval<S: Into<String>>(name: S, ip: Ipv4Addr, interval: Duration) -> io::Result<Self> {
        let send_socket = create_send_socket()?;
        let recv_socket = create_recv_socket()?;

        Ok(Self {
            name: name.into(),
            broadcast_interval: interval,
            send_socket,
            recv_socket,
            local_ip: ip,
        })
    }

    /// Get the name being advertised
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the broadcast interval
    pub fn broadcast_interval(&self) -> Duration {
        self.broadcast_interval
    }

    /// Start the mDNS broadcast and listen loops
    ///
    /// This will continuously broadcast the mDNS name at the configured interval
    /// and listen for queries from other peers.
    /// The loop runs until cancelled.
    pub async fn run(&self) {
        tokio::join!(
            self.broadcast_loop(),
            self.listen()
        );
    }

    /// Continuously broadcast mDNS announcements
    async fn broadcast_loop(&self) {
        let mut interval = time::interval(self.broadcast_interval);

        loop {
            interval.tick().await;
            self.broadcast().await;
        }
    }

    /// Broadcast a single mDNS announcement
    async fn broadcast(&self) {
        let packet = build_mdns_packet(&self.name, self.local_ip);
        let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

        if let Err(e) = self.send_socket.send_to(&packet, &addr.into()) {
            eprintln!("Failed to send mDNS packet: {}", e);
        }
    }

    /// Listen for and respond to mDNS queries
    async fn listen(&self) {
        let mut buf: [MaybeUninit<u8>; 4096] = [MaybeUninit::uninit(); 4096];

        loop {
            match self.recv_socket.recv_from(&mut buf) {
                Ok((len, _addr)) => {
                    // Safety: recv_from initializes the bytes it reads
                    let data = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr() as *const u8, len)
                    };

                    if let Some(query_name) = parse_mdns_query(data) {
                        let expected_name = format!("{}.local", self.name);
                        if query_name == expected_name {
                            println!("Received query for {}.local, sending response", self.name);
                            self.respond_to_query().await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to receive mDNS query: {}", e);
                }
            }
        }
    }

    /// Send a response to an mDNS query
    async fn respond_to_query(&self) {
        let packet = build_mdns_packet(&self.name, self.local_ip);
        let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

        if let Err(e) = self.send_socket.send_to(&packet, &addr.into()) {
            eprintln!("Failed to send mDNS response: {}", e);
        }
    }

    /// Get the local IP address being advertised
    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    /// Send a query for a specific hostname
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname to query (without .local suffix)
    pub async fn query(&self, hostname: &str) {
        let packet = build_mdns_query(hostname);
        let addr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

        if let Err(e) = self.send_socket.send_to(&packet, &addr.into()) {
            eprintln!("Failed to send mDNS query: {}", e);
        }
    }
}

/// Create a UDP socket for sending mDNS packets
fn create_send_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_ttl_v4(255)?;

    Ok(socket)
}

/// Create a UDP socket for receiving mDNS packets
fn create_recv_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(false)?;

    // Bind to mDNS port
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT);
    socket.bind(&addr.into())?;

    // Join multicast group
    socket.join_multicast_v4(&MDNS_MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;

    Ok(socket)
}

/// Build a simple mDNS A record response packet
fn build_mdns_packet(name: &str, ip: Ipv4Addr) -> Vec<u8> {
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
fn build_mdns_query(name: &str) -> Vec<u8> {
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
fn parse_mdns_query(packet: &[u8]) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_name() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mdns = Mdns::new("myhost", ip).unwrap();
        assert_eq!(mdns.name(), "myhost");
        assert_eq!(mdns.local_ip(), ip);
        assert_eq!(mdns.broadcast_interval(), Duration::from_secs(120));
    }

    #[test]
    fn test_with_custom_interval() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let mdns = Mdns::with_interval("myhost", ip, Duration::from_secs(60)).unwrap();
        assert_eq!(mdns.name(), "myhost");
        assert_eq!(mdns.local_ip(), ip);
        assert_eq!(mdns.broadcast_interval(), Duration::from_secs(60));
    }

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