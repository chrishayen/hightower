use crate::crypto::PublicKey25519;
use crate::transport::error::Error;
use crate::transport::server::Server;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct ConnId(pub u64);

#[derive(Clone)]
pub struct Conn {
    pub(crate) id: ConnId,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) peer_public_key: PublicKey25519,
    pub(crate) recv_channel: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    pub(crate) recv_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) closed: Arc<Mutex<bool>>,
    pub(crate) server: Option<Arc<Server>>,
    pub(crate) send_counter: Arc<Mutex<u64>>,
}

impl Conn {
    pub(crate) fn new(
        id: ConnId,
        peer_addr: SocketAddr,
        peer_public_key: PublicKey25519,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            peer_addr,
            peer_public_key,
            recv_channel: Arc::new(Mutex::new(rx)),
            recv_tx: tx,
            closed: Arc::new(Mutex::new(false)),
            server: None,
            send_counter: Arc::new(Mutex::new(0)),
        }
    }

    pub(crate) fn with_server(mut self, server: Arc<Server>) -> Self {
        self.server = Some(server);
        self
    }

    /// Send data over the connection
    pub async fn send(&self, data: &[u8]) -> Result<usize, Error> {
        if *self.closed.lock().await {
            return Err(Error::ConnectionClosed);
        }

        let server = self.server.as_ref().ok_or(Error::ConnectionClosed)?;

        // Get the active session from the protocol
        let protocol = server.protocol.lock().await;

        // Find session by matching peer public key
        let active_sessions = protocol.active_sessions();
        let session_entry = active_sessions
            .iter()
            .find(|(_, session)| session.peer_public_key == self.peer_public_key)
            .ok_or_else(|| Error::ProtocolError("No active session for this peer".to_string()))?;

        let (session_id, session) = session_entry;
        let session_id = *session_id;

        // Encrypt the data using AEAD
        let mut counter = self.send_counter.lock().await;
        let encrypted = crate::crypto::aead_encrypt(
            &session.keys.send_key,
            *counter,
            data,
            &[],
        ).map_err(|_| Error::EncryptionFailed)?;

        let current_counter = *counter;
        *counter += 1;
        drop(counter);
        drop(protocol);

        // Create TransportData message
        use crate::messages::TransportData;
        let mut transport_msg = TransportData::new();
        transport_msg.receiver = session_id;
        transport_msg.counter = current_counter;
        transport_msg.packet = encrypted;

        // Serialize and send
        let msg_bytes = transport_msg.to_bytes()
            .map_err(|e| Error::ProtocolError(format!("Failed to serialize transport data: {}", e)))?;

        server.udp_socket.send_to(&msg_bytes, self.peer_addr).await?;

        Ok(data.len())
    }

    /// Receive data from the connection
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        debug!(conn_id = self.id.0, "Waiting to receive data from channel");

        if *self.closed.lock().await {
            return Err(Error::ConnectionClosed);
        }

        // Block on channel receive instead of busy-waiting
        let mut rx = self.recv_channel.lock().await;
        match rx.recv().await {
            Some(data) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                debug!(
                    conn_id = self.id.0,
                    bytes_received = len,
                    "Received data from channel"
                );
                Ok(len)
            }
            None => {
                debug!(conn_id = self.id.0, "Channel closed, no more data");
                Err(Error::ConnectionClosed)
            }
        }
    }

    /// Close the connection
    pub async fn close(self) -> Result<(), Error> {
        *self.closed.lock().await = true;
        Ok(())
    }

    /// Get the remote peer's address
    pub fn peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }

    /// Get the remote peer's public key
    pub fn peer_public_key(&self) -> &PublicKey25519 {
        &self.peer_public_key
    }
}
