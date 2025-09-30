mod broadcast;
mod constants;
mod packet;
mod query;
mod socket;

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;
use socket2::Socket;

use socket::{create_send_socket, create_recv_socket};

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
            broadcast::broadcast_loop(&self.send_socket, &self.name, self.local_ip, self.broadcast_interval),
            query::listen(&self.recv_socket, &self.send_socket, &self.name, self.local_ip)
        );
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
        query::query(&self.send_socket, hostname).await;
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
}