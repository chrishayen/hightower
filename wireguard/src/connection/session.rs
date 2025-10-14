use crate::crypto::PublicKey25519;
use crate::protocol::ActiveSession;
use super::error::Error;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub(super) struct SessionId(pub u32);

pub(super) struct SessionState {
    pub peer_public_key: PublicKey25519,
    pub endpoint: Option<SocketAddr>,
    pub state: SessionStateInner,
    pub last_send: Instant,
    pub last_recv: Instant,
    pub created_at: Instant,
    pub persistent_keepalive: Option<u16>,
    pub send_counter: u64,
    pub is_initiator: bool,
}

impl SessionState {
    pub fn new(peer_public_key: PublicKey25519, endpoint: Option<SocketAddr>, session: ActiveSession, is_initiator: bool) -> Self {
        let now = Instant::now();
        Self {
            peer_public_key,
            endpoint,
            state: SessionStateInner::Active { session },
            last_send: now,
            last_recv: now,
            created_at: now,
            persistent_keepalive: None,
            send_counter: 0,
            is_initiator,
        }
    }

    pub fn needs_keepalive(&self, now: Instant) -> bool {
        let time_since_send = now.duration_since(self.last_send);
        let keepalive_interval = self.persistent_keepalive
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(crate::protocol::KEEPALIVE_TIMEOUT);

        time_since_send >= keepalive_interval
    }

    pub fn needs_rekey(&self, now: Instant, rekey_after: Duration) -> bool {
        if !self.is_initiator {
            return false;
        }

        if !matches!(self.state, SessionStateInner::Active { .. }) {
            return false;
        }

        let session_age = now.duration_since(self.created_at);
        session_age >= rekey_after
    }

    pub fn get_active_session(&self) -> Option<&ActiveSession> {
        match &self.state {
            SessionStateInner::Active { session } => Some(session),
            SessionStateInner::Rekeying { old_session, .. } => Some(old_session),
        }
    }

    pub fn start_rekey(&mut self) -> Result<(), Error> {
        let session = match &self.state {
            SessionStateInner::Active { session } => session.clone(),
            _ => return Err(Error::AlreadyRekeying),
        };

        self.state = SessionStateInner::Rekeying {
            old_session: session,
            queue: Vec::new(),
        };

        Ok(())
    }

    pub fn complete_rekey(&mut self, new_session: ActiveSession) -> Vec<Vec<u8>> {
        let queued = match &mut self.state {
            SessionStateInner::Rekeying { queue, .. } => queue.drain(..).collect(),
            _ => Vec::new(),
        };

        self.state = SessionStateInner::Active { session: new_session };
        self.created_at = Instant::now();
        self.send_counter = 0;

        queued
    }

    pub fn queue_packet(&mut self, data: Vec<u8>) -> Result<(), Error> {
        match &mut self.state {
            SessionStateInner::Rekeying { queue, .. } => {
                queue.push(data);
                Ok(())
            }
            _ => Err(Error::NotRekeying),
        }
    }
}

pub(super) enum SessionStateInner {
    Active {
        session: ActiveSession,
    },
    Rekeying {
        old_session: ActiveSession,
        queue: Vec<Vec<u8>>,
    },
}

pub(super) struct PendingHandshake {
    pub peer_public_key: PublicKey25519,
    pub reply: HandshakeReply,
    pub created_at: Instant,
}

pub(super) enum HandshakeReply {
    Connect(oneshot::Sender<Result<super::Stream, Error>>),
    Rekey(SessionId),
}
