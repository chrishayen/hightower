use hightower_wireguard::transport::Server;

/// Wrapper around hightower-wireguard transport server.
/// Provides access to the underlying transport for communication.
#[derive(Clone)]
pub struct TransportServer {
    server: Server,
}

impl TransportServer {
    pub(crate) fn new(server: Server) -> Self {
        Self { server }
    }

    /// Get a reference to the underlying transport server
    ///
    /// Use this to access the full hightower-wireguard Server API
    /// for sending and receiving data.
    pub fn server(&self) -> &Server {
        &self.server
    }
}
