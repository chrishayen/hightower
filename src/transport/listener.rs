use crate::transport::conn::Conn;
use crate::transport::error::Error;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct ListenerId(pub(crate) u64);

#[derive(Clone)]
pub struct Listener {
    #[allow(dead_code)]
    pub(crate) id: ListenerId,
    #[allow(dead_code)]
    pub(crate) network: String,
    pub(crate) addr: String,
    pub(crate) accept_channel: Arc<Mutex<mpsc::UnboundedReceiver<Conn>>>,
    pub(crate) accept_tx: mpsc::UnboundedSender<Conn>,
    pub(crate) closed: Arc<Mutex<bool>>,
}

impl Listener {
    pub(crate) fn new(id: ListenerId, network: String, addr: String) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            network,
            addr,
            accept_channel: Arc::new(Mutex::new(rx)),
            accept_tx: tx,
            closed: Arc::new(Mutex::new(false)),
        }
    }

    /// Accept an incoming connection
    pub async fn accept(&self) -> Result<Conn, Error> {
        debug!(listener_id = self.id.0, "Waiting to accept connection from channel");

        if *self.closed.lock().await {
            return Err(Error::ListenerClosed);
        }

        // Block on channel receive instead of busy-waiting
        let mut rx = self.accept_channel.lock().await;
        match rx.recv().await {
            Some(conn) => {
                debug!(
                    listener_id = self.id.0,
                    conn_id = conn.id.0,
                    peer_addr = ?conn.peer_addr,
                    "Accepted connection from channel"
                );
                Ok(conn)
            }
            None => {
                debug!(listener_id = self.id.0, "Channel closed, no more connections");
                Err(Error::ListenerClosed)
            }
        }
    }

    /// Close the listener
    pub async fn close(self) -> Result<(), Error> {
        *self.closed.lock().await = true;
        Ok(())
    }

    /// Get the listener's local address
    pub fn local_addr(&self) -> &str {
        &self.addr
    }
}
