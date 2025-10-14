use crate::crypto::{PrivateKey, PublicKey25519};
use crate::messages::{
    HandshakeInitiation, HandshakeResponse, TransportData,
    MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE,
};
use crate::protocol::{PeerInfo, WireGuardProtocol};
use super::error::Error;
use super::logging::*;
use super::session::{HandshakeReply, PendingHandshake, SessionId, SessionState};
use super::stream::{Command, Stream, StreamId, StreamState};
use super::TimeoutConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tracing::{debug, error, info};

pub(super) struct ConnectionActor {
    udp_socket: UdpSocket,
    protocol: WireGuardProtocol,
    sessions: HashMap<SessionId, SessionState>,
    peer_to_session: HashMap<PublicKey25519, SessionId>,
    pending_handshakes: HashMap<u32, PendingHandshake>,
    streams: HashMap<StreamId, StreamState>,
    peer_to_stream: HashMap<PublicKey25519, StreamId>,
    next_stream_id: Arc<AtomicU64>,
    listeners: Vec<mpsc::UnboundedSender<Stream>>,
    handshake_completed: bool,
    cmd_tx: mpsc::UnboundedSender<Command>,
    timeouts: TimeoutConfig,
}

impl ConnectionActor {
    pub fn new(udp_socket: UdpSocket, private_key: PrivateKey, cmd_tx: mpsc::UnboundedSender<Command>, timeouts: TimeoutConfig) -> Self {
        let protocol = WireGuardProtocol::new(Some(private_key));

        Self {
            udp_socket,
            protocol,
            sessions: HashMap::new(),
            peer_to_session: HashMap::new(),
            pending_handshakes: HashMap::new(),
            streams: HashMap::new(),
            peer_to_stream: HashMap::new(),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            listeners: Vec::new(),
            handshake_completed: false,
            cmd_tx,
            timeouts,
        }
    }

    pub async fn run(mut self, mut cmd_rx: mpsc::UnboundedReceiver<Command>) {
        let mut buf = vec![0u8; 65536];
        let mut maintenance_interval = interval(Duration::from_secs(1));
        maintenance_interval.tick().await;

        debug!("Connection actor started");

        loop {
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    self.handle_command(cmd).await;
                }

                Ok((len, from)) = self.udp_socket.recv_from(&mut buf) => {
                    self.handle_packet(&buf[..len], from).await;
                }

                _ = maintenance_interval.tick(), if self.handshake_completed => {
                    self.run_maintenance().await;
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Connect { addr, peer_public_key, reply } => {
                self.handle_connect(addr, peer_public_key, reply).await;
            }
            Command::Listen { reply } => {
                self.handle_listen(reply);
            }
            Command::AddPeer { peer_public_key, endpoint, persistent_keepalive, reply } => {
                self.handle_add_peer(peer_public_key, endpoint, persistent_keepalive, reply);
            }
            Command::SendData { stream_id, data, reply } => {
                self.handle_send_data(stream_id, data, reply).await;
            }
            Command::CloseStream { stream_id, reply } => {
                self.handle_close_stream(stream_id, reply);
            }
            Command::Disconnect { peer_public_key, reply } => {
                self.handle_disconnect(peer_public_key, reply);
            }
        }
    }

    async fn handle_connect(&mut self, addr: SocketAddr, peer_public_key: PublicKey25519, reply: oneshot::Sender<Result<Stream, Error>>) {
        debug_init!("Handling connect command to peer {}", addr);

        match self.initiate_handshake(addr, peer_public_key).await {
            Ok(handshake_id) => {
                let pending = PendingHandshake {
                    peer_public_key,
                    reply: HandshakeReply::Connect(reply),
                    created_at: Instant::now(),
                };
                self.pending_handshakes.insert(handshake_id, pending);
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    fn handle_listen(&mut self, reply: oneshot::Sender<Result<mpsc::UnboundedReceiver<Stream>, Error>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        self.listeners.push(tx);
        let _ = reply.send(Ok(rx));
    }

    fn handle_add_peer(&mut self, peer_public_key: PublicKey25519, endpoint: Option<SocketAddr>, persistent_keepalive: Option<u16>, reply: oneshot::Sender<Result<(), Error>>) {
        let peer_info = PeerInfo {
            public_key: peer_public_key,
            endpoint,
            persistent_keepalive,
            preshared_key: None,
            allowed_ips: vec![],
        };
        self.protocol.add_peer(peer_info);
        let _ = reply.send(Ok(()));
    }

    async fn handle_send_data(&mut self, stream_id: StreamId, data: Vec<u8>, reply: oneshot::Sender<Result<(), Error>>) {
        let result = self.send_data(stream_id, data).await;
        let _ = reply.send(result);
    }

    fn handle_close_stream(&mut self, stream_id: StreamId, reply: oneshot::Sender<Result<(), Error>>) {
        let stream = match self.streams.get(&stream_id) {
            Some(s) => s,
            None => {
                let _ = reply.send(Err(Error::ConnectionClosed));
                return;
            }
        };

        let peer_public_key = stream.peer_public_key;
        self.disconnect_peer(&peer_public_key);
        let _ = reply.send(Ok(()));
    }

    fn handle_disconnect(&mut self, peer_public_key: PublicKey25519, reply: oneshot::Sender<Result<(), Error>>) {
        self.disconnect_peer(&peer_public_key);
        let _ = reply.send(Ok(()));
    }

    fn disconnect_peer(&mut self, peer_public_key: &PublicKey25519) {
        if let Some(stream_id) = self.peer_to_stream.remove(peer_public_key) {
            self.streams.remove(&stream_id);
        }

        if let Some(session_id) = self.peer_to_session.remove(peer_public_key) {
            self.sessions.remove(&session_id);
            debug!(
                session_id = session_id.0,
                peer = %hex::encode(&peer_public_key[..8]),
                "Disconnected peer and removed session"
            );
        }
    }

    async fn handle_packet(&mut self, data: &[u8], from: SocketAddr) {
        if data.is_empty() {
            return;
        }

        let msg_type = data[0];

        match msg_type {
            MESSAGE_HANDSHAKE_INITIATION => {
                self.handle_handshake_initiation(data, from).await;
            }
            MESSAGE_HANDSHAKE_RESPONSE => {
                self.handle_handshake_response(data, from).await;
            }
            4 => {
                self.handle_transport_data(data, from).await;
            }
            _ => {
                debug!(msg_type = msg_type, from = %from, "Unknown message type");
            }
        }
    }

    async fn handle_handshake_initiation(&mut self, data: &[u8], from: SocketAddr) {
        let initiation = match HandshakeInitiation::from_bytes(data) {
            Ok(init) => init,
            Err(e) => {
                error!(from = %from, error = %e, "Failed to parse handshake initiation");
                return;
            }
        };

        debug_resp!("Received handshake initiation from {}, sender={}", from, initiation.sender);

        let response = match self.protocol.process_initiation(&initiation) {
            Ok(resp) => resp,
            Err(e) => {
                error_resp!("Failed to process handshake initiation from {}: {:?}", from, e);
                return;
            }
        };

        let peer_public_key = match self.protocol.get_session(response.sender) {
            Some(session) => session.peer_public_key,
            None => {
                error_resp!("No session found after processing initiation from {}", from);
                return;
            }
        };

        if let Err(e) = self.send_handshake_response(&response, from).await {
            error_resp!("Failed to send handshake response to {}: {:?}", from, e);
            return;
        }

        debug_resp!("Sent handshake response to {}", from);

        if !self.create_session_from_response(response.sender, peer_public_key, from, false) {
            error_resp!("Failed to create session (possible ID collision) for {}", from);
            return;
        }

        if !self.peer_to_stream.contains_key(&peer_public_key) {
            self.create_incoming_stream(peer_public_key, from);
        }

        self.enable_maintenance_if_first();
    }

    async fn send_handshake_response(&self, response: &HandshakeResponse, to: SocketAddr) -> Result<(), Error> {
        let response_bytes = response.to_bytes()
            .map_err(|e| Error::ProtocolError(format!("Failed to serialize: {}", e)))?;

        self.udp_socket.send_to(&response_bytes, to).await?;
        Ok(())
    }

    fn create_session_from_response(&mut self, session_id: u32, peer_public_key: PublicKey25519, from: SocketAddr, is_initiator: bool) -> bool {
        let session = match self.protocol.get_session(session_id) {
            Some(s) => s.clone(),
            None => return false,
        };

        let sid = SessionId(session_id);

        if self.sessions.contains_key(&sid) {
            error_session!(is_initiator,
                "Session ID collision detected! Rejecting new session: session_id={}, peer={}",
                session_id, hex::encode(&peer_public_key[..8]));
            return false;
        }

        if let Some(old_session_id) = self.peer_to_session.get(&peer_public_key) {
            if *old_session_id != sid {
                debug_session!(is_initiator,
                    "Replacing old session for peer: old_session_id={}, new_session_id={}",
                    old_session_id.0, session_id);
                self.sessions.remove(old_session_id);
            }
        }

        let mut state = SessionState::new(peer_public_key, Some(from), session, is_initiator);

        if let Some(peer) = self.protocol.peers().get(&peer_public_key) {
            state.persistent_keepalive = peer.persistent_keepalive;
        }

        self.sessions.insert(sid, state);
        self.peer_to_session.insert(peer_public_key, sid);
        true
    }

    async fn handle_handshake_response(&mut self, data: &[u8], from: SocketAddr) {
        let response = match HandshakeResponse::from_bytes(data) {
            Ok(resp) => resp,
            Err(e) => {
                error!(from = %from, error = %e, "Failed to parse handshake response");
                return;
            }
        };

        debug_init!("Received handshake response from {}, sender={}, receiver={}",
            from, response.sender, response.receiver);

        let pending = match self.pending_handshakes.remove(&response.receiver) {
            Some(p) => p,
            None => {
                debug!("No pending handshake for receiver {} from {}", response.receiver, from);
                return;
            }
        };

        if let Err(e) = self.protocol.process_response(&response) {
            error_init!("Failed to process handshake response from {}: {:?}", from, e);
            if let HandshakeReply::Connect(reply) = pending.reply {
                let _ = reply.send(Err(Error::HandshakeFailed(e.to_string())));
            }
            return;
        }

        match pending.reply {
            HandshakeReply::Connect(reply) => {
                self.handle_connect_reply(&response, from, pending.peer_public_key, reply);
            }
            HandshakeReply::Rekey(old_session_id) => {
                self.handle_rekey_reply(&response, from, old_session_id, pending.peer_public_key).await;
            }
        }
    }

    fn handle_connect_reply(&mut self, response: &HandshakeResponse, from: SocketAddr, peer_public_key: PublicKey25519, reply: oneshot::Sender<Result<Stream, Error>>) {
        if !self.create_session_from_response(response.sender, peer_public_key, from, true) {
            let _ = reply.send(Err(Error::HandshakeFailed("Session ID collision".to_string())));
            return;
        }

        let stream = self.create_stream(peer_public_key, from);
        let _ = reply.send(Ok(stream));

        self.enable_maintenance_if_first();
    }

    async fn handle_rekey_reply(&mut self, response: &HandshakeResponse, from: SocketAddr, old_session_id: SessionId, peer_public_key: PublicKey25519) {
        info_init!("Rekey completed: old_session_id={}, new_session_id={}",
            old_session_id.0, response.sender);

        let queued_packets = match self.sessions.get_mut(&old_session_id) {
            Some(old_session) => {
                let session = match self.protocol.get_session(response.sender) {
                    Some(s) => s.clone(),
                    None => return,
                };
                old_session.complete_rekey(session)
            }
            None => return,
        };

        self.sessions.remove(&old_session_id);

        if !self.create_session_from_response(response.sender, peer_public_key, from, true) {
            error_init!(
                "Failed to create new session after rekey (possible ID collision): old_session_id={}, new_session_id={}",
                old_session_id.0, response.sender);
            return;
        }

        for packet_data in queued_packets {
            if let Some(stream_id) = self.peer_to_stream.get(&peer_public_key) {
                let _ = self.send_data(*stream_id, packet_data).await;
            }
        }
    }

    async fn handle_transport_data(&mut self, data: &[u8], from: SocketAddr) {
        let transport = match TransportData::from_bytes(data) {
            Ok(t) => t,
            Err(e) => {
                error!(from = %from, error = %e, "Failed to parse transport data");
                return;
            }
        };

        let session_id = SessionId(transport.receiver);
        let counter = transport.counter;
        let receiver_id = transport.receiver;

        let (peer_public_key, plaintext, should_queue) = {
            let session_state = match self.sessions.get_mut(&session_id) {
                Some(s) => s,
                None => {
                    error!(from = %from, session_id = session_id.0, "No session");
                    return;
                }
            };

            session_state.endpoint = Some(from);
            session_state.last_recv = Instant::now();

            let session = match session_state.get_active_session() {
                Some(s) => s,
                None => return,
            };

            let plaintext = match crate::crypto::aead_decrypt(
                &session.keys.recv_key,
                transport.counter,
                &transport.packet,
                &[],
            ) {
                Ok(p) => p,
                Err(e) => {
                    error!(from = %from, error = ?e, "Failed to decrypt");
                    return;
                }
            };

            let should_queue = matches!(session_state.state, super::session::SessionStateInner::Rekeying { .. });
            let peer_public_key = session_state.peer_public_key;

            (peer_public_key, plaintext, should_queue)
        };

        if let Err(e) = self.protocol.check_replay(receiver_id, counter) {
            error!(
                from = %from,
                session_id = receiver_id,
                counter = counter,
                "Replay protection rejected packet: {:?}",
                e
            );
            return;
        }

        if plaintext.is_empty() {
            if let Some(session_state) = self.sessions.get(&session_id) {
                debug_session!(session_state.is_initiator, "Received keepalive response from {}, session_id={}", from, session_id.0);
            } else {
                debug!("Received keepalive from {} (session already removed), session_id={}", from, session_id.0);
            }
            return;
        }

        if should_queue {
            if let Some(session_state) = self.sessions.get_mut(&session_id) {
                let _ = session_state.queue_packet(plaintext);
            }
        } else {
            self.route_to_stream(&peer_public_key, plaintext);
        }
    }

    fn route_to_stream(&self, peer_public_key: &PublicKey25519, data: Vec<u8>) {
        let stream_id = match self.peer_to_stream.get(peer_public_key) {
            Some(id) => id,
            None => return,
        };

        let stream = match self.streams.get(stream_id) {
            Some(s) => s,
            None => return,
        };

        if let Err(e) = stream.recv_tx.send(data) {
            debug!(error = ?e, "Failed to send to stream (closed)");
        }
    }

    async fn initiate_handshake(&mut self, addr: SocketAddr, peer_public_key: PublicKey25519) -> Result<u32, Error> {
        self.ensure_peer_exists(peer_public_key, addr);

        let handshake = self.protocol.initiate_handshake(&peer_public_key)
            .map_err(|e| Error::HandshakeFailed(e.to_string()))?;

        let handshake_id = handshake.sender;

        let handshake_bytes = handshake.to_bytes()
            .map_err(|e| Error::ProtocolError(format!("Serialize failed: {}", e)))?;

        self.udp_socket.send_to(&handshake_bytes, addr).await?;

        debug_init!("Sent handshake initiation to {}, handshake_id={}", addr, handshake_id);

        Ok(handshake_id)
    }

    fn ensure_peer_exists(&mut self, peer_public_key: PublicKey25519, addr: SocketAddr) {
        if self.protocol.peers().contains_key(&peer_public_key) {
            return;
        }

        let peer_info = PeerInfo {
            public_key: peer_public_key,
            endpoint: Some(addr),
            preshared_key: None,
            allowed_ips: vec![],
            persistent_keepalive: None,
        };
        self.protocol.add_peer(peer_info);
    }

    async fn send_data(&mut self, stream_id: StreamId, data: Vec<u8>) -> Result<(), Error> {
        let stream = self.streams.get(&stream_id)
            .ok_or(Error::ConnectionClosed)?;

        let peer_public_key = stream.peer_public_key;

        let session_id = *self.peer_to_session.get(&peer_public_key)
            .ok_or(Error::NoSession)?;

        let session_state = self.sessions.get_mut(&session_id)
            .ok_or(Error::NoSession)?;

        if matches!(session_state.state, super::session::SessionStateInner::Rekeying { .. }) {
            session_state.queue_packet(data)?;
            return Ok(());
        }

        let session = session_state.get_active_session()
            .ok_or(Error::NoSession)?;

        let encrypted = crate::crypto::aead_encrypt(
            &session.keys.send_key,
            session_state.send_counter,
            &data,
            &[],
        ).map_err(|_| Error::EncryptionFailed)?;

        let counter = session_state.send_counter;
        session_state.send_counter += 1;
        session_state.last_send = Instant::now();

        let endpoint = session_state.endpoint.ok_or(Error::NoEndpoint)?;

        self.send_transport(session_id.0, counter, encrypted, endpoint).await
    }

    async fn send_transport(&self, session_id: u32, counter: u64, encrypted: Vec<u8>, to: SocketAddr) -> Result<(), Error> {
        let mut transport = TransportData::new();
        transport.receiver = session_id;
        transport.counter = counter;
        transport.packet = encrypted;

        let transport_bytes = transport.to_bytes()
            .map_err(|e| Error::ProtocolError(format!("Serialize failed: {}", e)))?;

        self.udp_socket.send_to(&transport_bytes, to).await?;
        Ok(())
    }

    fn create_stream(&mut self, peer_public_key: PublicKey25519, peer_addr: SocketAddr) -> Stream {
        let stream_id = StreamId(self.next_stream_id.fetch_add(1, Ordering::SeqCst));

        let (recv_tx, recv_rx) = mpsc::unbounded_channel();

        self.streams.insert(stream_id, StreamState {
            peer_public_key,
            recv_tx,
        });

        self.peer_to_stream.insert(peer_public_key, stream_id);

        Stream::new(stream_id, peer_public_key, peer_addr, self.cmd_tx.clone(), recv_rx)
    }

    fn create_incoming_stream(&mut self, peer_public_key: PublicKey25519, peer_addr: SocketAddr) {
        let stream = self.create_stream(peer_public_key, peer_addr);

        if self.listeners.is_empty() {
            return;
        }

        if let Err(_) = self.listeners[0].send(stream) {
            self.listeners.remove(0);
        }
    }

    fn enable_maintenance_if_first(&mut self) {
        if self.handshake_completed {
            return;
        }

        self.handshake_completed = true;
        debug!("First handshake completed, maintenance enabled");
    }

    async fn run_maintenance(&mut self) {
        let now = Instant::now();

        self.send_keepalives(now).await;
        self.initiate_rekeys(now).await;
        self.cleanup_stale_connections(now);

        self.protocol.cleanup();
    }

    async fn send_keepalives(&mut self, now: Instant) {
        let mut keepalives = Vec::new();
        for (session_id, session_state) in &mut self.sessions {
            if !session_state.needs_keepalive(now) {
                continue;
            }

            let session = match session_state.get_active_session() {
                Some(s) => s.clone(),
                None => continue,
            };

            let encrypted = match crate::crypto::aead_encrypt(
                &session.keys.send_key,
                session_state.send_counter,
                &[],
                &[],
            ) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let counter = session_state.send_counter;
            session_state.send_counter += 1;
            session_state.last_send = Instant::now();

            if let Some(endpoint) = session_state.endpoint {
                keepalives.push((session_id.0, counter, encrypted, endpoint, session_state.is_initiator));
            }
        }

        for (session_id, counter, encrypted, endpoint, is_initiator) in keepalives {
            if let Err(e) = self.send_transport(session_id, counter, encrypted, endpoint).await {
                error_session!(is_initiator, "Failed to send keepalive to {}, session_id={}: {:?}", endpoint, session_id, e);
            } else {
                debug_session!(is_initiator, "Sent keepalive to {}, session_id={}", endpoint, session_id);
            }
        }
    }


    async fn initiate_rekeys(&mut self, now: Instant) {
        let mut rekeys = Vec::new();
        let rekey_after = self.timeouts.rekey_after;

        for (session_id, session_state) in &self.sessions {
            if !session_state.needs_rekey(now, rekey_after) {
                continue;
            }

            let endpoint = match session_state.endpoint {
                Some(e) => e,
                None => continue,
            };

            rekeys.push((*session_id, session_state.peer_public_key, endpoint));
        }

        for (old_session_id, peer_public_key, endpoint) in rekeys {
            self.initiate_single_rekey(old_session_id, peer_public_key, endpoint).await;
        }
    }

    async fn initiate_single_rekey(&mut self, old_session_id: SessionId, peer_public_key: PublicKey25519, endpoint: SocketAddr) {
        info_init!("Initiating rekey for session_id={}, peer={}",
            old_session_id.0, hex::encode(&peer_public_key[..8]));

        let handshake_id = match self.initiate_handshake(endpoint, peer_public_key).await {
            Ok(id) => id,
            Err(e) => {
                error!(error = ?e, "Failed to initiate rekey");
                return;
            }
        };

        let session_state = match self.sessions.get_mut(&old_session_id) {
            Some(s) => s,
            None => return,
        };

        if let Err(e) = session_state.start_rekey() {
            error!(error = ?e, "Failed to start rekey");
            return;
        }

        self.pending_handshakes.insert(handshake_id, PendingHandshake {
            peer_public_key,
            reply: HandshakeReply::Rekey(old_session_id),
            created_at: Instant::now(),
        });
    }

    fn cleanup_stale_connections(&mut self, now: Instant) {
        let session_timeout = self.timeouts.session_timeout;

        let mut stale_peers = Vec::new();
        self.sessions.retain(|session_id, session_state| {
            let age = now.duration_since(session_state.last_recv);

            if age > session_timeout {
                debug!(
                    session_id = session_id.0,
                    peer = %hex::encode(&session_state.peer_public_key[..8]),
                    age_secs = age.as_secs(),
                    "Removing stale session"
                );
                stale_peers.push(session_state.peer_public_key);
                false
            } else {
                true
            }
        });

        for peer_key in stale_peers {
            self.peer_to_session.remove(&peer_key);

            if let Some(stream_id) = self.peer_to_stream.remove(&peer_key) {
                self.streams.remove(&stream_id);
                debug!(
                    stream_id = stream_id.0,
                    peer = %hex::encode(&peer_key[..8]),
                    "Removed stream for stale peer"
                );
            }
        }

        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
        let initial_count = self.pending_handshakes.len();

        self.pending_handshakes.retain(|handshake_id, pending| {
            let age = now.duration_since(pending.created_at);
            if age > HANDSHAKE_TIMEOUT {
                debug!(
                    handshake_id = handshake_id,
                    age_secs = age.as_secs(),
                    "Removing expired pending handshake"
                );
                false
            } else {
                true
            }
        });

        if initial_count > 0 && self.pending_handshakes.len() < initial_count {
            debug!(
                removed = initial_count - self.pending_handshakes.len(),
                remaining = self.pending_handshakes.len(),
                "Cleaned up expired pending handshakes"
            );
        }
    }
}
