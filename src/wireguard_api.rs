use crate::certificates::NodeCertificate;
use crate::context::NamespacedKv;
use hightower_wireguard::transport::{Conn, Error, Server as TransportServer};
use std::sync::{Arc, OnceLock, RwLock};
use tracing::{debug, error};

static TRANSPORT_SERVER: OnceLock<TransportServer> = OnceLock::new();
static GATEWAY_KV: OnceLock<Arc<RwLock<NamespacedKv>>> = OnceLock::new();

/// Set the KV handle for the WireGuard API
pub fn set_kv(kv: Arc<RwLock<NamespacedKv>>) {
    GATEWAY_KV.set(kv).ok();
}

/// Initialize the WireGuard transport server
pub async fn initialize(certificate: &NodeCertificate) {
    debug!("gateway: Initializing WireGuard transport server");

    let bind_addr = "0.0.0.0:51820"
        .parse()
        .expect("valid WireGuard bind address");

    let private_key = *certificate.private_key();
    let public_key = certificate.public_key_hex();

    debug!(
        bind_addr = %bind_addr,
        public_key = &public_key[..8],
        "gateway: Creating WireGuard transport server"
    );

    match TransportServer::new(bind_addr, private_key).await {
        Ok(server) => {
            debug!(
                bind_addr = %bind_addr,
                public_key = &public_key[..8],
                "gateway: WireGuard transport server created successfully"
            );

            // Spawn background packet processor
            debug!("gateway: Spawning WireGuard packet processor");
            let server_clone = server.clone();
            tokio::spawn(async move {
                debug!("gateway: WireGuard packet processor starting");
                if let Err(e) = server_clone.run().await {
                    error!(error = ?e, "gateway: WireGuard transport server error");
                }
            });

            // Spawn maintenance task for keepalive and rekey
            debug!("gateway: Spawning WireGuard maintenance task");
            let server_maintenance = server.clone();
            tokio::spawn(async move {
                server_maintenance.run_maintenance().await
            });

            // Start WireGuard API listener
            debug!("gateway: Spawning WireGuard API listener");
            let server_clone = server.clone();
            tokio::spawn(async move {
                debug!("gateway: WireGuard API listener starting");
                if let Err(e) = start_api_listener(server_clone).await {
                    error!(error = ?e, "gateway: WireGuard API listener error");
                }
            });

            TRANSPORT_SERVER.set(server).ok();
            debug!("gateway: WireGuard transport server fully initialized");
        }
        Err(e) => {
            error!(error = ?e, "gateway: Failed to initialize WireGuard transport");
        }
    }
}

async fn start_api_listener(server: TransportServer) -> Result<(), Error> {
    // Listen for HTTP connections over WireGuard
    let listener = server.listen("tcp", ":8080").await?;
    debug!("gateway: WireGuard API listening on :8080");

    loop {
        match listener.accept().await {
            Ok(conn) => {
                debug!(peer_addr = ?conn.peer_addr(), "Accepted WireGuard connection");

                tokio::spawn(async move {
                    // Simple HTTP response handler
                    let mut buf = vec![0u8; 8192];
                    match conn.recv(&mut buf).await {
                        Ok(n) => {
                            let request = String::from_utf8_lossy(&buf[..n]);
                            let first_line = request.lines().next().unwrap_or("");
                            debug!(request = first_line, "gateway: Received WireGuard HTTP request");

                            if request.contains("GET /ping") {
                                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nPong!";
                                if let Err(e) = conn.send(response).await {
                                    error!(error = ?e, "Failed to send response");
                                }
                            } else if request.contains("GET /peers/") {
                                handle_peer_lookup(&request, &conn).await;
                            } else {
                                let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                                if let Err(e) = conn.send(response).await {
                                    error!(error = ?e, "Failed to send 404");
                                }
                            }
                        }
                        Err(e) => {
                            error!(error = ?e, "Failed to receive from WireGuard connection");
                        }
                    }
                });
            }
            Err(e) => {
                error!(error = ?e, "Failed to accept WireGuard connection");
            }
        }
    }
}

async fn handle_peer_lookup(request: &str, conn: &Conn) {
    debug!("gateway: Handling peer lookup request");

    // Extract node_id from request like "GET /peers/{node_id}"
    let node_id = if let Some(start) = request.find("GET /peers/") {
        let after_prefix = &request[start + 11..]; // Length of "GET /peers/"
        after_prefix.split_whitespace().next()
    } else {
        None
    };

    let Some(node_id) = node_id else {
        debug!("gateway: Bad peer lookup request - no node_id");
        let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        let _ = conn.send(response).await;
        return;
    };

    debug!(node_id = node_id, "gateway: Looking up peer public key");

    // Load the peer's public key from KV storage
    let Some(kv) = GATEWAY_KV.get() else {
        error!("Gateway KV not initialized");
        let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        let _ = conn.send(response).await;
        return;
    };

    // Extract data and drop lock before any awaits
    let registration_key = format!("nodes/registry/{}", node_id);
    let public_key_hex = {
        let kv = kv.read().expect("gateway kv lock");
        match kv.get_bytes(registration_key.as_bytes()) {
            Ok(Some(data)) => {
                match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(registration) => {
                        registration.get("public_key_hex")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    }
                    Err(e) => {
                        error!(error = ?e, "gateway: Failed to deserialize registration");
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                error!(error = ?e, "gateway: Failed to query KV for node");
                None
            }
        }
    }; // Lock dropped here

    // Now send response without holding the lock
    match public_key_hex {
        Some(key) => {
            let response_body = format!(r#"{{"public_key_hex":"{}"}}"#, key);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            if let Err(e) = conn.send(response.as_bytes()).await {
                error!(error = ?e, "gateway: Failed to send peer lookup response");
            } else {
                debug!(node_id = node_id, "gateway: Sent peer public key");
            }
        }
        None => {
            let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            let _ = conn.send(response).await;
        }
    }
}

pub fn get_transport_server() -> Option<&'static TransportServer> {
    TRANSPORT_SERVER.get()
}
