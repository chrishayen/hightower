use hightower_stun::client::StunClient;
use std::net::{IpAddr, UdpSocket};
use std::time::Duration;
use tracing::debug;

const DEFAULT_STUN_SERVER: &str = "gateway.shotgun.dev:3478";
const DEFAULT_WIREGUARD_PORT: u16 = 51820;

/// Discovers network information including public and local IPs and ports
///
/// # Arguments
/// * `local_port` - Optional local port. Defaults to 51820 (standard WireGuard port).
/// * `stun_server` - Optional STUN server address. Defaults to gateway.shotgun.dev:3478.
///
/// # Returns
/// Network information or an error
pub fn discover_network_info(
    local_port: Option<u16>,
    stun_server: Option<&str>,
) -> Result<crate::NetworkInfo, Box<dyn std::error::Error>> {
    let local_port = local_port.unwrap_or(DEFAULT_WIREGUARD_PORT);
    let stun_server = stun_server.unwrap_or(DEFAULT_STUN_SERVER);

    debug!("Starting network discovery");
    debug!("Using STUN server: {}", stun_server);

    // Discover public IP and port via STUN
    let client = StunClient::new()?.with_timeout(Duration::from_secs(5));
    let public_addr = client.get_public_address(stun_server)?;

    debug!(
        public_ip = %public_addr.ip(),
        public_port = public_addr.port(),
        "Discovered public address via STUN"
    );

    // Discover local IP (the interface IP used for outbound connections)
    let local_ip = discover_local_ip()?;
    debug!(local_ip = %local_ip, "Discovered local IP");

    Ok(crate::NetworkInfo {
        public_ip: public_addr.ip().to_string(),
        public_port: public_addr.port(),
        local_ip: local_ip.to_string(),
        local_port,
    })
}

/// Discovers the local IP address by determining which interface would be used
/// for outbound connections to the internet
///
/// This uses the trick of connecting a UDP socket to a public IP (8.8.8.8:53)
/// without actually sending data, then checking the socket's local address.
fn discover_local_ip() -> Result<IpAddr, Box<dyn std::error::Error>> {
    // Connect to a public DNS server (8.8.8.8:53)
    // This doesn't actually send any packets, but causes the OS to select
    // the appropriate interface and bind to its IP
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:53")?;

    let local_addr = socket.local_addr()?;
    Ok(local_addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_local_ip() {
        let ip = discover_local_ip().expect("should discover local IP");
        println!("Discovered local IP: {}", ip);

        // Should not be unspecified (0.0.0.0)
        assert!(!ip.is_unspecified());
    }

    #[test]
    #[ignore] // Requires network access and STUN server
    fn test_discover_network_info() {
        let info = discover_network_info(None, None).expect("should discover network info");

        println!("Network Info:");
        println!("  Public IP: {}", info.public_ip);
        println!("  Public Port: {}", info.public_port);
        println!("  Local IP: {}", info.local_ip);
        println!("  Local Port: {}", info.local_port);

        assert!(!info.public_ip.is_empty());
        assert!(info.public_port > 0);
        assert!(!info.local_ip.is_empty());
        assert_eq!(info.local_port, DEFAULT_WIREGUARD_PORT);
    }
}
