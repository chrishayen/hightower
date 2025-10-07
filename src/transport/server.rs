use crate::crypto::{PrivateKey, PublicKey25519};
use crate::messages::HandshakeResponse;
use crate::protocol::{PeerInfo, WireGuardProtocol};
use crate::transport::conn::{Conn, ConnId};
use crate::transport::error::Error;
use crate::transport::listener::{Listener, ListenerId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, oneshot, Mutex, RwLock};
use tokio::time::Duration;
use tracing::{debug, error};

pub struct Server {
    pub(crate) protocol: Arc<Mutex<WireGuardProtocol>>,
    pub(crate) udp_socket: Arc<UdpSocket>,
    pub(crate) connections: Arc<RwLock<HashMap<ConnId, Conn>>>,
    pub(crate) listeners: Arc<RwLock<HashMap<ListenerId, Listener>>>,
    pub(crate) pending_handshakes: Arc<RwLock<HashMap<u32, oneshot::Sender<HandshakeResponse>>>>,
    pub(crate) next_conn_id: Arc<AtomicU64>,
    pub(crate) next_listener_id: Arc<AtomicU64>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) ready_tx: Arc<Mutex<Option<broadcast::Sender<()>>>>,
    pub(crate) ready_rx: Arc<Mutex<Option<broadcast::Receiver<()>>>>,
}

impl Server {
    /// Create a new WireGuard transport server
    pub async fn new(bind_addr: SocketAddr, private_key: PrivateKey) -> Result<Self, Error> {
        let udp_socket = UdpSocket::bind(bind_addr).await?;
        let protocol = WireGuardProtocol::new(Some(private_key));

        debug!(
            bind_addr = %bind_addr,
            "Created WireGuard transport server"
        );

        let (ready_tx, ready_rx) = broadcast::channel(1);

        Ok(Self {
            protocol: Arc::new(Mutex::new(protocol)),
            udp_socket: Arc::new(udp_socket),
            connections: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(RwLock::new(HashMap::new())),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            next_listener_id: Arc::new(AtomicU64::new(1)),
            running: Arc::new(AtomicBool::new(false)),
            ready_tx: Arc::new(Mutex::new(Some(ready_tx))),
            ready_rx: Arc::new(Mutex::new(Some(ready_rx))),
        })
    }

    /// Wait until the server's run() loop is ready to process packets
    pub async fn wait_until_ready(&self) -> Result<(), Error> {
        let mut rx_guard = self.ready_rx.lock().await;
        if let Some(mut rx) = rx_guard.take() {
            debug!("Waiting for server to be ready");
            match rx.recv().await {
                Ok(_) => {
                    debug!("Server is ready");
                    Ok(())
                }
                Err(_) => {
                    debug!("Server ready signal already sent or closed");
                    Ok(())
                }
            }
        } else {
            // Already waited or already ready
            debug!("Server already ready");
            Ok(())
        }
    }

    /// Add a peer to the transport layer
    /// Must be called before the peer can establish connections
    pub async fn add_peer(
        &self,
        peer_public_key: PublicKey25519,
        endpoint: Option<SocketAddr>,
    ) -> Result<(), Error> {
        let peer_key_hex = hex::encode(peer_public_key);
        debug!(
            peer_public_key = &peer_key_hex[..8],
            endpoint = ?endpoint,
            "Adding peer to WireGuard transport layer"
        );

        let mut protocol = self.protocol.lock().await;
        let peer_info = PeerInfo {
            public_key: peer_public_key,
            preshared_key: None,
            endpoint,
            allowed_ips: vec![],
            persistent_keepalive: None,
        };
        protocol.add_peer(peer_info);

        debug!(
            peer_public_key = &peer_key_hex[..8],
            "Successfully added peer to transport layer"
        );
        Ok(())
    }

    /// Dial a connection to a remote peer
    pub async fn dial(
        &self,
        network: &str,
        addr: &str,
        peer_public_key: PublicKey25519,
    ) -> Result<Conn, Error> {
        // Validate network type
        if network != "tcp" && network != "udp" {
            return Err(Error::InvalidNetwork(network.to_string()));
        }

        // Parse the address to get the peer's UDP address
        // For now, we assume the addr is the peer's WireGuard endpoint
        let peer_addr: SocketAddr = addr
            .parse()
            .map_err(|_| Error::InvalidAddress(addr.to_string()))?;

        let peer_key_hex = hex::encode(peer_public_key);
        debug!(
            network = network,
            addr = %peer_addr,
            peer_public_key = &peer_key_hex[..8],
            "Dialing peer via WireGuard"
        );

        // Initiate WireGuard handshake
        debug!(peer_addr = %peer_addr, "Initiating WireGuard handshake");
        let mut protocol = self.protocol.lock().await;
        let handshake_init = protocol
            .initiate_handshake(&peer_public_key)
            .map_err(|e| Error::HandshakeFailed(e.to_string()))?;

        let sender_index = handshake_init.sender;
        debug!(
            peer_addr = %peer_addr,
            sender_index = sender_index,
            "Created handshake initiation"
        );

        // Serialize and send handshake initiation
        let init_bytes = handshake_init
            .to_bytes()
            .map_err(|e| Error::ProtocolError(format!("Failed to serialize handshake: {}", e)))?;

        debug!(
            peer_addr = %peer_addr,
            bytes = init_bytes.len(),
            sender_index = sender_index,
            "Sending WireGuard handshake initiation"
        );

        // Create oneshot channel for this handshake
        let (tx, rx) = oneshot::channel();

        // Register pending handshake before sending
        self.pending_handshakes.write().await.insert(sender_index, tx);
        debug!(
            sender_index = sender_index,
            "Registered pending handshake"
        );

        drop(protocol); // Release protocol lock before I/O

        self.udp_socket.send_to(&init_bytes, peer_addr).await?;

        debug!(
            peer_addr = %peer_addr,
            sender_index = sender_index,
            "Sent handshake initiation, waiting for response on oneshot channel"
        );

        // Wait for handshake response via oneshot channel (routed by run() loop)
        use tokio::time::timeout;

        let response_timeout = Duration::from_secs(5);
        let response = match timeout(response_timeout, rx).await {
            Ok(Ok(resp)) => {
                debug!(
                    peer_addr = %peer_addr,
                    sender_index = sender_index,
                    "Received handshake response via oneshot channel"
                );
                resp
            }
            Ok(Err(_)) => {
                debug!(
                    peer_addr = %peer_addr,
                    sender_index = sender_index,
                    "Oneshot channel closed (sender dropped)"
                );
                // Clean up pending handshake
                self.pending_handshakes.write().await.remove(&sender_index);
                return Err(Error::HandshakeFailed("Response channel closed".to_string()));
            }
            Err(_) => {
                debug!(
                    peer_addr = %peer_addr,
                    sender_index = sender_index,
                    "Handshake timeout"
                );
                // Clean up pending handshake
                self.pending_handshakes.write().await.remove(&sender_index);
                return Err(Error::HandshakeFailed("Handshake timeout".to_string()));
            }
        };

        debug!(
            peer_addr = %peer_addr,
            sender_index = sender_index,
            "Completing handshake"
        );

        // Process the handshake response
        let mut protocol = self.protocol.lock().await;
        protocol.process_response(&response)
            .map_err(|e| Error::HandshakeFailed(e.to_string()))?;
        drop(protocol);

        debug!(
            peer_addr = %peer_addr,
            "Handshake completed successfully"
        );

        // Create connection
        let conn_id = ConnId(self.next_conn_id.fetch_add(1, Ordering::SeqCst));
        let conn = Conn::new(conn_id, peer_addr, peer_public_key)
            .with_server(Arc::new(self.clone()));

        // Store connection
        self.connections
            .write()
            .await
            .insert(conn_id, conn.clone());

        debug!(conn_id = conn_id.0, "Created connection");

        Ok(conn)
    }

    /// Listen for incoming connections
    pub async fn listen(&self, network: &str, addr: &str) -> Result<Listener, Error> {
        // Validate network type
        if network != "tcp" && network != "udp" {
            return Err(Error::InvalidNetwork(network.to_string()));
        }

        debug!(
            network = network,
            addr = addr,
            "Creating listener"
        );

        let listener_id = ListenerId(self.next_listener_id.fetch_add(1, Ordering::SeqCst));
        let listener = Listener::new(listener_id, network.to_string(), addr.to_string());

        self.listeners
            .write()
            .await
            .insert(listener_id, listener.clone());

        debug!(listener_id = listener_id.0, "Created listener");

        Ok(listener)
    }

    /// Run the server's background packet processing loop
    pub async fn run(&self) -> Result<(), Error> {
        use crate::messages::{
            HandshakeInitiation, HandshakeResponse, MESSAGE_HANDSHAKE_INITIATION,
            MESSAGE_HANDSHAKE_RESPONSE,
        };

        self.running.store(true, Ordering::SeqCst);
        debug!("Starting transport server packet processor");

        // Signal that we're ready to process packets
        {
            let tx_guard = self.ready_tx.lock().await;
            if let Some(tx) = tx_guard.as_ref() {
                let _ = tx.send(());
                debug!("Signaled server ready");
            }
        }

        let mut buf = vec![0u8; 65536];

        while self.running.load(Ordering::SeqCst) {
            match self.udp_socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    debug!(from = %from, len = len, "Received UDP packet");

                    if len == 0 {
                        continue;
                    }

                    // Determine message type
                    let msg_type = buf[0];

                    match msg_type {
                        MESSAGE_HANDSHAKE_INITIATION => {
                            // Process handshake initiation (we're the responder)
                            match HandshakeInitiation::from_bytes(&buf[..len]) {
                                Ok(initiation) => {
                                    debug!(
                                        from = %from,
                                        sender = initiation.sender,
                                        "Received handshake initiation"
                                    );

                                    // Process the initiation and generate response
                                    let mut protocol = self.protocol.lock().await;
                                    match protocol.process_initiation(&initiation) {
                                        Ok(response) => {
                                            debug!(
                                                from = %from,
                                                "Generated handshake response"
                                            );

                                            // Get the peer public key from the active sessions
                                            // The protocol stores this when processing the initiation
                                            let peer_public_key = if let Some(session) = protocol.get_session(response.sender) {
                                                session.peer_public_key
                                            } else {
                                                error!(
                                                    from = %from,
                                                    "No session found after processing initiation"
                                                );
                                                continue;
                                            };

                                            // Serialize and send response
                                            match response.to_bytes() {
                                                Ok(response_bytes) => {
                                                    if let Err(e) = self.udp_socket.send_to(&response_bytes, from).await {
                                                        error!(
                                                            from = %from,
                                                            error = ?e,
                                                            "Failed to send handshake response"
                                                        );
                                                    } else {
                                                        debug!(
                                                            from = %from,
                                                            bytes = response_bytes.len(),
                                                            "Sent handshake response"
                                                        );

                                                        // Create connection for this peer
                                                        let conn_id = ConnId(self.next_conn_id.fetch_add(1, Ordering::SeqCst));
                                                        let conn = Conn::new(conn_id, from, peer_public_key)
                                                            .with_server(Arc::new(self.clone()));

                                                        self.connections
                                                            .write()
                                                            .await
                                                            .insert(conn_id, conn.clone());

                                                        debug!(
                                                            conn_id = conn_id.0,
                                                            from = %from,
                                                            "Created incoming connection"
                                                        );

                                                        // Send to all listener channels
                                                        let listeners = self.listeners.read().await;
                                                        for listener in listeners.values() {
                                                            if let Err(e) = listener.accept_tx.send(conn.clone()) {
                                                                debug!(
                                                                    conn_id = conn_id.0,
                                                                    listener_id = listener.id.0,
                                                                    error = ?e,
                                                                    "Failed to send connection to listener channel (receiver dropped)"
                                                                );
                                                            } else {
                                                                debug!(
                                                                    conn_id = conn_id.0,
                                                                    listener_id = listener.id.0,
                                                                    "Sent connection to listener channel"
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!(
                                                        from = %from,
                                                        error = %e,
                                                        "Failed to serialize handshake response"
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                from = %from,
                                                error = ?e,
                                                "Failed to process handshake initiation"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        from = %from,
                                        error = %e,
                                        "Failed to parse handshake initiation"
                                    );
                                }
                            }
                        }
                        MESSAGE_HANDSHAKE_RESPONSE => {
                            // Process handshake response and route to the correct pending dial
                            match HandshakeResponse::from_bytes(&buf[..len]) {
                                Ok(response) => {
                                    debug!(
                                        from = %from,
                                        sender = response.sender,
                                        receiver = response.receiver,
                                        "Received handshake response"
                                    );

                                    // Check if this is for a pending handshake
                                    let receiver_index = response.receiver;
                                    let mut pending = self.pending_handshakes.write().await;
                                    if let Some(tx) = pending.remove(&receiver_index) {
                                        debug!(
                                            from = %from,
                                            receiver = receiver_index,
                                            "Routing handshake response to pending dial()"
                                        );
                                        // Send response to waiting dial() via oneshot
                                        if let Err(_) = tx.send(response) {
                                            debug!(
                                                from = %from,
                                                receiver = receiver_index,
                                                "Failed to send response (dial() cancelled)"
                                            );
                                        }
                                    } else {
                                        debug!(
                                            from = %from,
                                            receiver = receiver_index,
                                            "No pending handshake found for response (may have timed out)"
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        from = %from,
                                        error = %e,
                                        "Failed to parse handshake response"
                                    );
                                }
                            }
                        }
                        msg_type => {
                            // Check if it's a transport data message (type 4)
                            if msg_type == 4 {
                                use crate::messages::TransportData;

                                match TransportData::from_bytes(&buf[..len]) {
                                    Ok(transport_data) => {
                                        debug!(
                                            from = %from,
                                            receiver = transport_data.receiver,
                                            counter = transport_data.counter,
                                            packet_len = transport_data.packet.len(),
                                            "Received transport data"
                                        );

                                        // Decrypt the packet
                                        let protocol = self.protocol.lock().await;

                                        // Get the session
                                        if let Some(session) = protocol.get_session(transport_data.receiver) {
                                            match crate::crypto::aead_decrypt(
                                                &session.keys.recv_key,
                                                transport_data.counter,
                                                &transport_data.packet,
                                                &[],
                                            ) {
                                                Ok(plaintext) => {
                                                    debug!(
                                                        from = %from,
                                                        plaintext_len = plaintext.len(),
                                                        "Decrypted transport data"
                                                    );

                                                    // Find connection by peer address and route data
                                                    let connections = self.connections.read().await;
                                                    if let Some(conn) = connections.values().find(|c| c.peer_addr == from) {
                                                        if let Err(e) = conn.recv_tx.send(plaintext) {
                                                            debug!(
                                                                from = %from,
                                                                conn_id = conn.id.0,
                                                                error = ?e,
                                                                "Failed to send data to connection channel (receiver dropped)"
                                                            );
                                                        } else {
                                                            debug!(
                                                                from = %from,
                                                                conn_id = conn.id.0,
                                                                "Routed data to connection channel"
                                                            );
                                                        }
                                                    } else {
                                                        debug!(
                                                            from = %from,
                                                            "No connection found for peer address"
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    error!(
                                                        from = %from,
                                                        error = ?e,
                                                        "Failed to decrypt transport data"
                                                    );
                                                }
                                            }
                                        } else {
                                            error!(
                                                from = %from,
                                                receiver = transport_data.receiver,
                                                "No session found for transport data"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            from = %from,
                                            error = %e,
                                            "Failed to parse transport data"
                                        );
                                    }
                                }
                            } else {
                                debug!(
                                    from = %from,
                                    msg_type = msg_type,
                                    "Received unhandled message type"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to receive UDP packet");
                }
            }
        }

        debug!("Transport server packet processor stopped");
        Ok(())
    }

    /// Shutdown the server
    pub async fn close(self) -> Result<(), Error> {
        self.running.store(false, Ordering::SeqCst);
        debug!("Closed transport server");
        Ok(())
    }

    /// Get the local bound address
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.udp_socket.local_addr().map_err(Error::from)
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            protocol: Arc::clone(&self.protocol),
            udp_socket: Arc::clone(&self.udp_socket),
            connections: Arc::clone(&self.connections),
            listeners: Arc::clone(&self.listeners),
            pending_handshakes: Arc::clone(&self.pending_handshakes),
            next_conn_id: Arc::clone(&self.next_conn_id),
            next_listener_id: Arc::clone(&self.next_listener_id),
            running: Arc::clone(&self.running),
            ready_tx: Arc::clone(&self.ready_tx),
            ready_rx: Arc::clone(&self.ready_rx),
        }
    }
}
