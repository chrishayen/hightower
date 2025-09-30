mod broadcast;
mod constants;
mod packet;
mod query;
mod socket;

use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use socket2::Socket;
use tokio::sync::mpsc;

use socket::{create_send_socket, create_recv_socket};

/// Response from an mDNS query or discovery
#[derive(Debug, Clone, PartialEq)]
pub struct MdnsResponse {
    /// The hostname (e.g., "myhost.local")
    pub hostname: String,
    /// The IPv4 address
    pub ip: Ipv4Addr,
}

/// Handle for interacting with a running mDNS service
pub struct MdnsHandle {
    send_socket: Arc<Socket>,
    domain: String,
    /// Channel for receiving discovered host announcements
    pub discoveries: mpsc::Receiver<MdnsResponse>,
    /// Channel for receiving query responses
    pub responses: mpsc::Receiver<MdnsResponse>,
}

impl MdnsHandle {
    /// Send a query for a specific hostname
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname to query (without domain suffix)
    pub async fn query(&self, hostname: &str) {
        query::query(&self.send_socket, hostname, &self.domain).await;
    }
}

/// mDNS service for advertising a hostname on the local network
pub struct Mdns {
    name: String,
    domain: String,
    broadcast_interval: Duration,
    send_socket: Arc<Socket>,
    recv_socket: Arc<Socket>,
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
    /// * `name` - The mDNS name to advertise (without domain suffix)
    /// * `ip` - The local IPv4 address to advertise
    /// * `interval` - Time between broadcasts (default is 120 seconds per RFC 6762)
    pub fn with_interval<S: Into<String>>(name: S, ip: Ipv4Addr, interval: Duration) -> io::Result<Self> {
        let send_socket = create_send_socket()?;
        let recv_socket = create_recv_socket()?;

        Ok(Self {
            name: name.into(),
            domain: "local".to_string(),
            broadcast_interval: interval,
            send_socket: Arc::new(send_socket),
            recv_socket: Arc::new(recv_socket),
            local_ip: ip,
        })
    }

    /// Set a custom domain (default is "local")
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to use (without leading dot)
    pub fn with_domain<S: Into<String>>(mut self, domain: S) -> Self {
        self.domain = domain.into();
        self
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
    /// Returns an MdnsHandle for querying and receiving discovery notifications.
    pub fn run(self) -> MdnsHandle {
        let (disc_tx, disc_rx) = mpsc::channel(100);
        let (resp_tx, resp_rx) = mpsc::channel(100);

        let send_socket = self.send_socket.clone();
        let recv_socket = self.recv_socket.clone();
        let name = Arc::new(self.name);
        let domain = Arc::new(self.domain.clone());
        let local_ip = self.local_ip;
        let broadcast_interval = self.broadcast_interval;

        // Spawn broadcast task
        let send_socket_clone = send_socket.clone();
        let name_clone = name.clone();
        let domain_clone = domain.clone();
        tokio::spawn(async move {
            broadcast::broadcast_loop(&send_socket_clone, &name_clone, &domain_clone, local_ip, broadcast_interval).await;
        });

        // Spawn listen task
        let send_socket_clone = send_socket.clone();
        let name_clone = name.clone();
        let domain_clone = domain.clone();
        tokio::spawn(async move {
            query::listen(&recv_socket, &send_socket_clone, &name_clone, &domain_clone, local_ip, disc_tx, resp_tx).await;
        });

        MdnsHandle {
            send_socket,
            domain: self.domain,
            discoveries: disc_rx,
            responses: resp_rx,
        }
    }

    /// Get the local IP address being advertised
    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    /// Send a goodbye packet to notify others this host is leaving
    ///
    /// This sends a packet with TTL=0 to tell other hosts to remove this
    /// hostname from their cache.
    pub async fn goodbye(&self) {
        broadcast::send_goodbye(&self.send_socket, &self.name, &self.domain, self.local_ip).await;
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