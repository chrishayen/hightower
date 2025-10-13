use stun::client::StunClient;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;
use tracing::{debug, warn};

const DEFAULT_STUN_SERVER: &str = "gateway.shotgun.dev:3478";

/// Discovers network information using a bound socket address
///
/// This is used when a transport server is already bound to a specific port.
/// Uses STUN to discover the public address and uses the actual bound port.
///
/// # Arguments
/// * `local_addr` - The bound socket address (from transport.local_addr())
/// * `stun_server` - Optional STUN server address. Defaults to gateway.shotgun.dev:3478.
///
/// # Returns
/// Network information or an error
pub fn discover_with_bound_address(
    local_addr: SocketAddr,
    stun_server: Option<&str>,
) -> Result<crate::NetworkInfo, Box<dyn std::error::Error>> {
    let stun_server = stun_server.unwrap_or(DEFAULT_STUN_SERVER);

    debug!("Discovering network info for bound address: {}", local_addr);

    // Use STUN to discover public address
    let client = StunClient::new()?.with_timeout(Duration::from_secs(5));
    let public_addr = client.get_public_address(stun_server)?;

    debug!(
        public_ip = %public_addr.ip(),
        public_port = public_addr.port(),
        "Discovered public address via STUN"
    );

    // Discover local IP
    let local_ip = discover_local_ip()?;

    // Warn if local IP from socket doesn't match discovered local IP
    if local_addr.ip() != local_ip && !local_addr.ip().is_unspecified() {
        warn!(
            bound_ip = %local_addr.ip(),
            discovered_ip = %local_ip,
            "Bound IP differs from discovered local IP"
        );
    }

    Ok(crate::NetworkInfo {
        public_ip: public_addr.ip().to_string(),
        public_port: public_addr.port(),
        local_ip: local_ip.to_string(),
        local_port: local_addr.port(),
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

}
