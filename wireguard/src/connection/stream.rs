use crate::crypto::PublicKey25519;
use super::error::Error;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub(super) struct StreamId(pub u64);

pub(super) enum Command {
    Connect {
        addr: SocketAddr,
        peer_public_key: PublicKey25519,
        reply: oneshot::Sender<Result<Stream, Error>>,
    },
    Listen {
        reply: oneshot::Sender<Result<mpsc::UnboundedReceiver<Stream>, Error>>,
    },
    AddPeer {
        peer_public_key: PublicKey25519,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: Option<u16>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SendData {
        stream_id: StreamId,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    CloseStream {
        stream_id: StreamId,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Disconnect {
        peer_public_key: PublicKey25519,
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

pub struct Stream {
    pub(super) id: StreamId,
    peer_public_key: PublicKey25519,
    peer_addr: SocketAddr,
    pub(super) cmd_tx: mpsc::UnboundedSender<Command>,
    pub(super) recv_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Stream {
    pub(super) fn new(
        id: StreamId,
        peer_public_key: PublicKey25519,
        peer_addr: SocketAddr,
        cmd_tx: mpsc::UnboundedSender<Command>,
        recv_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        Self {
            id,
            peer_public_key,
            peer_addr,
            cmd_tx,
            recv_rx,
        }
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        let cmd = Command::SendData {
            stream_id: self.id,
            data: data.to_vec(),
            reply: reply_tx,
        };

        self.cmd_tx.send(cmd).map_err(|_| Error::ActorShutdown)?;
        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    pub async fn close(&self) -> Result<(), Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        let cmd = Command::CloseStream {
            stream_id: self.id,
            reply: reply_tx,
        };

        self.cmd_tx.send(cmd).map_err(|_| Error::ActorShutdown)?;
        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.recv_rx.recv().await.ok_or(Error::ConnectionClosed)
    }

    pub fn peer_public_key(&self) -> &PublicKey25519 {
        &self.peer_public_key
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

pub(super) struct StreamState {
    pub peer_public_key: PublicKey25519,
    pub recv_tx: mpsc::UnboundedSender<Vec<u8>>,
}
