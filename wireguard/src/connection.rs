mod actor;
mod error;
mod logging;
mod session;
mod stream;

use crate::crypto::{PrivateKey, PublicKey25519};
use actor::ConnectionActor;
pub use error::Error;
pub use stream::Stream;
use stream::Command;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    pub rekey_after: Duration,
    pub reject_after: Duration,
    pub session_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            rekey_after: crate::protocol::REKEY_AFTER_TIME,
            reject_after: crate::protocol::REJECT_AFTER_TIME,
            session_timeout: Duration::from_secs(180),
        }
    }
}

pub struct Connection {
    cmd_tx: mpsc::UnboundedSender<Command>,
    local_addr: SocketAddr,
}

impl Connection {
    pub async fn new(bind_addr: SocketAddr, private_key: PrivateKey) -> Result<Self, Error> {
        Self::with_timeouts(bind_addr, private_key, TimeoutConfig::default()).await
    }

    pub async fn with_timeouts(
        bind_addr: SocketAddr,
        private_key: PrivateKey,
        timeouts: TimeoutConfig,
    ) -> Result<Self, Error> {
        let udp_socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = udp_socket.local_addr()?;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let actor = ConnectionActor::new(udp_socket, private_key, cmd_tx.clone(), timeouts);
        tokio::spawn(actor.run(cmd_rx));

        debug!(addr = %local_addr, "Created WireGuard connection");

        Ok(Self { cmd_tx, local_addr })
    }

    pub async fn connect(&self, addr: SocketAddr, peer_public_key: PublicKey25519) -> Result<Stream, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.send_command(Command::Connect {
            addr,
            peer_public_key,
            reply: reply_tx,
        })?;

        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    pub async fn listen(&self) -> Result<mpsc::UnboundedReceiver<Stream>, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.send_command(Command::Listen { reply: reply_tx })?;

        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    pub async fn add_peer(&self, peer_public_key: PublicKey25519, endpoint: Option<SocketAddr>) -> Result<(), Error> {
        self.add_peer_with_keepalive(peer_public_key, endpoint, None).await
    }

    pub async fn add_peer_with_keepalive(
        &self,
        peer_public_key: PublicKey25519,
        endpoint: Option<SocketAddr>,
        keepalive_seconds: Option<u16>,
    ) -> Result<(), Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.send_command(Command::AddPeer {
            peer_public_key,
            endpoint,
            persistent_keepalive: keepalive_seconds,
            reply: reply_tx,
        })?;

        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    pub async fn disconnect(&self, peer_public_key: PublicKey25519) -> Result<(), Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.send_command(Command::Disconnect {
            peer_public_key,
            reply: reply_tx,
        })?;

        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn send_command(&self, cmd: Command) -> Result<(), Error> {
        self.cmd_tx.send(cmd).map_err(|_| Error::ActorShutdown)
    }
}
