use crate::crypto::{PrivateKey, PublicKey25519};
use crate::messages::{
    HandshakeInitiation, HandshakeResponse, TransportData,
    MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE,
};
use crate::protocol::{ActiveSession, PeerInfo, WireGuardProtocol};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tracing::{debug, error, info};

/// A WireGuard transport connection manager.
///
/// This is the main entry point for the transport layer. It manages all
/// connections to peers and handles the WireGuard protocol.
pub struct Connection {
    cmd_tx: mpsc::UnboundedSender<Command>,
    local_addr: SocketAddr,
}

impl Connection {
    /// Create a new WireGuard transport connection.
    pub async fn new(bind_addr: SocketAddr, private_key: PrivateKey) -> Result<Self, Error> {
        let udp_socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = udp_socket.local_addr()?;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let actor = ConnectionActor::new(udp_socket, private_key, cmd_tx.clone());
        tokio::spawn(actor.run(cmd_rx));

        debug!(addr = %local_addr, "Created WireGuard connection");

        Ok(Self { cmd_tx, local_addr })
    }

    /// Connect to a remote peer.
    pub async fn connect(&self, addr: SocketAddr, peer_public_key: PublicKey25519) -> Result<Stream, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.send_command(Command::Connect {
            addr,
            peer_public_key,
            reply: reply_tx,
        })?;

        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    /// Listen for incoming connections.
    pub async fn listen(&self) -> Result<mpsc::UnboundedReceiver<Stream>, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.send_command(Command::Listen { reply: reply_tx })?;

        reply_rx.await.map_err(|_| Error::ActorShutdown)?
    }

    /// Add a peer that can connect to us.
    pub async fn add_peer(&self, peer_public_key: PublicKey25519, endpoint: Option<SocketAddr>) -> Result<(), Error> {
        self.add_peer_with_keepalive(peer_public_key, endpoint, None).await
    }

    /// Add a peer with persistent keepalive.
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

    /// Get the local address this connection is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn send_command(&self, cmd: Command) -> Result<(), Error> {
        self.cmd_tx.send(cmd).map_err(|_| Error::ActorShutdown)
    }
}

/// A bidirectional stream to a peer.
pub struct Stream {
    id: StreamId,
    peer_public_key: PublicKey25519,
    peer_addr: SocketAddr,
    cmd_tx: mpsc::UnboundedSender<Command>,
    recv_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Stream {
    /// Send data to the peer.
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

    /// Receive data from the peer.
    pub async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.recv_rx.recv().await.ok_or(Error::ConnectionClosed)
    }

    /// Get the peer's public key.
    pub fn peer_public_key(&self) -> &PublicKey25519 {
        &self.peer_public_key
    }

    /// Get the peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

// Internal types

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct StreamId(u64);

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct SessionId(u32);

enum Command {
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
}

struct ConnectionActor {
    udp_socket: UdpSocket,
    protocol: WireGuardProtocol,

    // Session management
    sessions: HashMap<SessionId, SessionState>,
    peer_to_session: HashMap<PublicKey25519, SessionId>,
    pending_handshakes: HashMap<u32, PendingHandshake>,

    // Stream management
    streams: HashMap<StreamId, StreamState>,
    peer_to_stream: HashMap<PublicKey25519, StreamId>,
    next_stream_id: Arc<AtomicU64>,

    // Listeners
    listeners: Vec<mpsc::UnboundedSender<Stream>>,

    // Maintenance
    handshake_completed: bool,

    // Command channel to pass to streams
    cmd_tx: mpsc::UnboundedSender<Command>,
}

struct SessionState {
    peer_public_key: PublicKey25519,
    endpoint: Option<SocketAddr>,
    state: SessionStateInner,
    last_send: Instant,
    last_recv: Instant,
    created_at: Instant,
    persistent_keepalive: Option<u16>,
    send_counter: u64,
    is_initiator: bool,  // Whether we initiated this session
}

impl SessionState {
    fn new(peer_public_key: PublicKey25519, endpoint: Option<SocketAddr>, session: ActiveSession, is_initiator: bool) -> Self {
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

    fn needs_keepalive(&self, now: Instant) -> bool {
        let time_since_send = now.duration_since(self.last_send);
        let keepalive_interval = self.persistent_keepalive
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(crate::protocol::KEEPALIVE_TIMEOUT);

        time_since_send >= keepalive_interval
    }

    fn needs_rekey(&self, now: Instant) -> bool {
        // Only the initiator is responsible for time-based rekeying (WireGuard spec)
        if !self.is_initiator {
            return false;
        }

        if !matches!(self.state, SessionStateInner::Active { .. }) {
            return false;
        }

        let session_age = now.duration_since(self.created_at);
        session_age >= crate::protocol::REKEY_AFTER_TIME
    }

    fn get_active_session(&self) -> Option<&ActiveSession> {
        match &self.state {
            SessionStateInner::Active { session } => Some(session),
            SessionStateInner::Rekeying { old_session, .. } => Some(old_session),
        }
    }

    fn start_rekey(&mut self) -> Result<(), Error> {
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

    fn complete_rekey(&mut self, new_session: ActiveSession) -> Vec<Vec<u8>> {
        let queued = match &mut self.state {
            SessionStateInner::Rekeying { queue, .. } => queue.drain(..).collect(),
            _ => Vec::new(),
        };

        self.state = SessionStateInner::Active { session: new_session };
        self.created_at = Instant::now();
        self.send_counter = 0;

        queued
    }

    fn queue_packet(&mut self, data: Vec<u8>) -> Result<(), Error> {
        match &mut self.state {
            SessionStateInner::Rekeying { queue, .. } => {
                queue.push(data);
                Ok(())
            }
            _ => Err(Error::NotRekeying),
        }
    }
}

enum SessionStateInner {
    Active {
        session: ActiveSession,
    },
    Rekeying {
        old_session: ActiveSession,
        queue: Vec<Vec<u8>>,
    },
}

struct PendingHandshake {
    peer_public_key: PublicKey25519,
    reply: HandshakeReply,
}

enum HandshakeReply {
    Connect(oneshot::Sender<Result<Stream, Error>>),
    Rekey(SessionId),
}

struct StreamState {
    peer_public_key: PublicKey25519,
    recv_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl ConnectionActor {
    fn new(udp_socket: UdpSocket, private_key: PrivateKey, cmd_tx: mpsc::UnboundedSender<Command>) -> Self {
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
        }
    }

    async fn run(mut self, mut cmd_rx: mpsc::UnboundedReceiver<Command>) {
        let mut buf = vec![0u8; 65536];
        let mut maintenance_interval = interval(Duration::from_secs(1));
        maintenance_interval.tick().await; // Skip first immediate tick

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
        }
    }

    async fn handle_connect(&mut self, addr: SocketAddr, peer_public_key: PublicKey25519, reply: oneshot::Sender<Result<Stream, Error>>) {
        debug!(peer = %addr, "Handling connect command");

        match self.initiate_handshake(addr, peer_public_key).await {
            Ok(handshake_id) => {
                let pending = PendingHandshake {
                    peer_public_key,
                    reply: HandshakeReply::Connect(reply),
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

        debug!(from = %from, sender = initiation.sender, "Received handshake initiation");

        let response = match self.protocol.process_initiation(&initiation) {
            Ok(resp) => resp,
            Err(e) => {
                error!(from = %from, error = ?e, "Failed to process handshake initiation");
                return;
            }
        };

        let peer_public_key = match self.protocol.get_session(response.sender) {
            Some(session) => session.peer_public_key,
            None => {
                error!(from = %from, "No session found after processing initiation");
                return;
            }
        };

        if let Err(e) = self.send_handshake_response(&response, from).await {
            error!(from = %from, error = ?e, "Failed to send handshake response");
            return;
        }

        debug!(from = %from, "Sent handshake response");

        // We're the responder (they initiated to us)
        self.create_session_from_response(response.sender, peer_public_key, from, false);
        self.create_incoming_stream(peer_public_key, from);
        self.enable_maintenance_if_first();
    }

    async fn send_handshake_response(&self, response: &HandshakeResponse, to: SocketAddr) -> Result<(), Error> {
        let response_bytes = response.to_bytes()
            .map_err(|e| Error::ProtocolError(format!("Failed to serialize: {}", e)))?;

        self.udp_socket.send_to(&response_bytes, to).await?;
        Ok(())
    }

    fn create_session_from_response(&mut self, session_id: u32, peer_public_key: PublicKey25519, from: SocketAddr, is_initiator: bool) {
        let session = match self.protocol.get_session(session_id) {
            Some(s) => s.clone(),
            None => return,
        };

        let mut state = SessionState::new(peer_public_key, Some(from), session, is_initiator);

        // Set keepalive if configured
        if let Some(peer) = self.protocol.peers().get(&peer_public_key) {
            state.persistent_keepalive = peer.persistent_keepalive;
        }

        let sid = SessionId(session_id);
        self.sessions.insert(sid, state);
        self.peer_to_session.insert(peer_public_key, sid);
    }

    async fn handle_handshake_response(&mut self, data: &[u8], from: SocketAddr) {
        let response = match HandshakeResponse::from_bytes(data) {
            Ok(resp) => resp,
            Err(e) => {
                error!(from = %from, error = %e, "Failed to parse handshake response");
                return;
            }
        };

        debug!(
            from = %from,
            sender = response.sender,
            receiver = response.receiver,
            "Received handshake response"
        );

        let pending = match self.pending_handshakes.remove(&response.receiver) {
            Some(p) => p,
            None => {
                debug!(from = %from, receiver = response.receiver, "No pending handshake");
                return;
            }
        };

        if let Err(e) = self.protocol.process_response(&response) {
            error!(from = %from, error = ?e, "Failed to process handshake response");
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
        // We're the initiator (we initiated the connection)
        self.create_session_from_response(response.sender, peer_public_key, from, true);

        let stream = self.create_stream(peer_public_key, from);
        let _ = reply.send(Ok(stream));

        self.enable_maintenance_if_first();
    }

    async fn handle_rekey_reply(&mut self, response: &HandshakeResponse, from: SocketAddr, old_session_id: SessionId, peer_public_key: PublicKey25519) {
        info!(
            session_id = old_session_id.0,
            new_session_id = response.sender,
            "Rekey completed"
        );

        // Get queued packets from old session
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

        // Remove old session
        self.sessions.remove(&old_session_id);

        // Create new session with new ID (we're the initiator of the rekey)
        self.create_session_from_response(response.sender, peer_public_key, from, true);

        // Send queued packets with new session
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

        // Process in a block to avoid borrow issues
        let (peer_public_key, plaintext, should_queue) = {
            let session_state = match self.sessions.get_mut(&session_id) {
                Some(s) => s,
                None => {
                    error!(from = %from, session_id = session_id.0, "No session");
                    return;
                }
            };

            // Update endpoint for roaming and last receive time
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

            if plaintext.is_empty() {
                debug!(from = %from, "Received keep-alive");
                return;
            }

            let should_queue = matches!(session_state.state, SessionStateInner::Rekeying { .. });
            let peer_public_key = session_state.peer_public_key;

            (peer_public_key, plaintext, should_queue)
        };

        // Queue or route after releasing the borrow
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

        debug!(addr = %addr, handshake_id = handshake_id, "Sent handshake initiation");

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

        // Look up session ID using our mapping
        let session_id = *self.peer_to_session.get(&peer_public_key)
            .ok_or(Error::NoSession)?;

        // Now work with the specific session
        let session_state = self.sessions.get_mut(&session_id)
            .ok_or(Error::NoSession)?;

        // Queue if rekeying
        if matches!(session_state.state, SessionStateInner::Rekeying { .. }) {
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

        Stream {
            id: stream_id,
            peer_public_key,
            peer_addr,
            cmd_tx: self.cmd_tx.clone(),
            recv_rx,
        }
    }

    fn create_incoming_stream(&mut self, peer_public_key: PublicKey25519, peer_addr: SocketAddr) {
        let stream = self.create_stream(peer_public_key, peer_addr);

        // Route to first available listener only
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
    }

    async fn send_keepalives(&mut self, now: Instant) {
        // Collect sessions that need keepalive
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
                keepalives.push((session_id.0, counter, encrypted, endpoint));
            }
        }

        // Send keepalives after releasing mutable borrows
        for (session_id, counter, encrypted, endpoint) in keepalives {
            if let Err(e) = self.send_transport(session_id, counter, encrypted, endpoint).await {
                error!(session_id = session_id, error = ?e, "Failed to send keepalive");
            } else {
                debug!(session_id = session_id, "Sent keepalive");
            }
        }
    }


    async fn initiate_rekeys(&mut self, now: Instant) {
        let mut rekeys = Vec::new();

        for (session_id, session_state) in &self.sessions {
            if !session_state.needs_rekey(now) {
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
        info!(
            session_id = old_session_id.0,
            peer = %hex::encode(&peer_public_key[..8]),
            "Initiating rekey"
        );

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
        });
    }

    fn cleanup_stale_connections(&mut self, now: Instant) {
        const SESSION_TIMEOUT: Duration = Duration::from_secs(180); // 3 minutes

        // Remove stale sessions
        let mut stale_peers = Vec::new();
        self.sessions.retain(|session_id, session_state| {
            let last_activity = session_state.last_recv.max(session_state.last_send);
            let age = now.duration_since(last_activity);

            if age > SESSION_TIMEOUT {
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

        // Clean up all mappings for stale peers
        for peer_key in stale_peers {
            // Remove session mapping
            self.peer_to_session.remove(&peer_key);

            // Remove stream and stream mapping
            if let Some(stream_id) = self.peer_to_stream.remove(&peer_key) {
                self.streams.remove(&stream_id);
                debug!(
                    stream_id = stream_id.0,
                    peer = %hex::encode(&peer_key[..8]),
                    "Removed stream for stale peer"
                );
            }
        }

        // Clean up old pending handshakes (simple count-based for now)
        if self.pending_handshakes.len() > 100 {
            debug!(
                count = self.pending_handshakes.len(),
                "Clearing excessive pending handshakes"
            );
            self.pending_handshakes.clear();
        }
    }
}

// Error types

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    HandshakeFailed(String),
    EncryptionFailed,
    DecryptionFailed,
    ConnectionClosed,
    NoSession,
    NoEndpoint,
    ActorShutdown,
    ProtocolError(String),
    AlreadyRekeying,
    NotRekeying,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::NoSession => write!(f, "No session found"),
            Error::NoEndpoint => write!(f, "No endpoint available"),
            Error::ActorShutdown => write!(f, "Actor has shut down"),
            Error::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            Error::AlreadyRekeying => write!(f, "Already rekeying"),
            Error::NotRekeying => write!(f, "Not in rekey state"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}