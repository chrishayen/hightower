use wireguard::connection::Connection;
use std::sync::Arc;

/// Wrapper around hightower-wireguard transport connection.
/// Provides access to the underlying transport for communication.
#[derive(Clone)]
pub struct TransportServer {
    connection: Arc<Connection>,
}

impl TransportServer {
    pub(crate) fn new(connection: Connection) -> Self {
        Self { connection: Arc::new(connection) }
    }

    /// Get a reference to the underlying transport connection
    ///
    /// Use this to access the full hightower-wireguard Connection API
    /// for sending and receiving data.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}
