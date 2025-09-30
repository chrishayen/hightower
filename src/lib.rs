use std::time::Duration;
use tokio::time;

/// mDNS service for advertising a hostname on the local network
pub struct Mdns {
    name: String,
    broadcast_interval: Duration,
}

impl Mdns {
    /// Create a new mDNS instance with the given name
    ///
    /// # Arguments
    ///
    /// * `name` - The mDNS name to advertise (without .local suffix)
    ///
    /// # Example
    ///
    /// ```
    /// use hightower_mdns::Mdns;
    ///
    /// let mdns = Mdns::new("myhost");
    /// ```
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self::with_interval(name, Duration::from_secs(120))
    }

    /// Create a new mDNS instance with a custom broadcast interval
    ///
    /// # Arguments
    ///
    /// * `name` - The mDNS name to advertise (without .local suffix)
    /// * `interval` - Time between broadcasts (default is 120 seconds per RFC 6762)
    pub fn with_interval<S: Into<String>>(name: S, interval: Duration) -> Self {
        Self {
            name: name.into(),
            broadcast_interval: interval,
        }
    }

    /// Get the name being advertised
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the broadcast interval
    pub fn broadcast_interval(&self) -> Duration {
        self.broadcast_interval
    }

    /// Start the mDNS broadcast loop
    ///
    /// This will continuously broadcast the mDNS name at the configured interval.
    /// The loop runs until the returned handle is dropped or cancelled.
    pub async fn run(&self) {
        let mut interval = time::interval(self.broadcast_interval);

        loop {
            interval.tick().await;
            self.broadcast().await;
        }
    }

    /// Broadcast a single mDNS announcement
    async fn broadcast(&self) {
        // TODO: Implement actual mDNS broadcast
        println!("Broadcasting mDNS name: {}.local", self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_name() {
        let mdns = Mdns::new("myhost");
        assert_eq!(mdns.name(), "myhost");
        assert_eq!(mdns.broadcast_interval(), Duration::from_secs(120));
    }

    #[test]
    fn test_with_custom_interval() {
        let mdns = Mdns::with_interval("myhost", Duration::from_secs(60));
        assert_eq!(mdns.name(), "myhost");
        assert_eq!(mdns.broadcast_interval(), Duration::from_secs(60));
    }
}