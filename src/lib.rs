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

use socket::{create_send_socket, create_recv_socket};

/// Callback function type for host discovery notifications
pub type HostDiscoveryCallback = Arc<dyn Fn(String) + Send + Sync>;

/// mDNS service for advertising a hostname on the local network
pub struct Mdns {
    name: String,
    domain: String,
    broadcast_interval: Duration,
    send_socket: Socket,
    recv_socket: Socket,
    local_ip: Ipv4Addr,
    on_host_discovered: Option<HostDiscoveryCallback>,
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
            send_socket,
            recv_socket,
            local_ip: ip,
            on_host_discovered: None,
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

    /// Set a callback to be invoked when a new host is discovered
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call with the hostname when discovered
    pub fn on_host_discovered<F>(mut self, callback: F) -> Self
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        self.on_host_discovered = Some(Arc::new(callback));
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
    /// The loop runs until cancelled.
    pub async fn run(&self) {
        tokio::join!(
            broadcast::broadcast_loop(&self.send_socket, &self.name, &self.domain, self.local_ip, self.broadcast_interval),
            query::listen(&self.recv_socket, &self.send_socket, &self.name, &self.domain, self.local_ip, self.on_host_discovered.clone())
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
    /// * `hostname` - The hostname to query (without domain suffix)
    pub async fn query(&self, hostname: &str) {
        query::query(&self.send_socket, hostname, &self.domain).await;
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