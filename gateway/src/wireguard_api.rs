use crate::certificates::NodeCertificate;
use crate::context::NamespacedKv;
use wireguard::connection::{Connection as TransportServer, Stream, Error};
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

            TRANSPORT_SERVER.set(server).ok();

            // Start WireGuard API listener
            debug!("gateway: Spawning WireGuard API listener");
            if let Some(server) = TRANSPORT_SERVER.get() {
                tokio::spawn(async move {
                    debug!("gateway: WireGuard API listener starting");
                    if let Err(e) = start_api_listener(server).await {
                        error!(error = ?e, "gateway: WireGuard API listener error");
                    }
                });
            }

            debug!("gateway: WireGuard transport server fully initialized");
        }
        Err(e) => {
            error!(error = ?e, "gateway: Failed to initialize WireGuard transport");
        }
    }
}

async fn start_api_listener(server: &TransportServer) -> Result<(), Error> {
    // Listen for HTTP connections over WireGuard
    let mut listener = server.listen().await?;
    debug!("gateway: WireGuard API listening for connections");

    loop {
        match listener.recv().await {
            Some(mut stream) => {
                debug!(peer_addr = ?stream.peer_addr(), "Accepted WireGuard connection");

                tokio::spawn(async move {
                    // Simple HTTP response handler
                    match stream.recv().await {
                        Ok(data) => {
                            let request = String::from_utf8_lossy(&data);
                            let first_line = request.lines().next().unwrap_or("");
                            debug!(request = first_line, "gateway: Received WireGuard HTTP request");

                            if request.contains("GET /ping") {
                                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nPong!";
                                if let Err(e) = stream.send(response).await {
                                    error!(error = ?e, "Failed to send response");
                                }
                            } else if request.contains("GET /endpoints/") {
                                handle_endpoint_lookup(&request, &stream).await;
                            } else {
                                let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                                if let Err(e) = stream.send(response).await {
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
            None => {
                debug!("gateway: WireGuard listener closed");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_endpoint_lookup(request: &str, stream: &Stream) {
    debug!("gateway: Handling endpoint lookup request");

    // Extract identifier from request like "GET /endpoints/{ip_or_endpoint_id}"
    let identifier = if let Some(start) = request.find("GET /endpoints/") {
        let after_prefix = &request[start + 15..]; // Length of "GET /endpoints/"
        after_prefix.split_whitespace().next()
    } else {
        None
    };

    let Some(identifier) = identifier else {
        debug!("gateway: Bad endpoint lookup request - no identifier");
        let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.send(response).await;
        return;
    };

    debug!(identifier = identifier, "gateway: Looking up endpoint");

    // Load the KV storage
    let Some(kv) = GATEWAY_KV.get() else {
        error!("Gateway KV not initialized");
        let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.send(response).await;
        return;
    };

    // Determine if identifier is an IP or endpoint_id, and look up the endpoint
    let endpoint_id = {
        let kv = kv.read().expect("gateway kv lock");

        // Try to look up by IP first (check if it looks like an IP)
        if identifier.contains('.') {
            // Looks like an IP - look up endpoint_id from IP allocator
            let ip_allocation_key = format!("ip_allocations/{}", identifier);
            match kv.get_bytes(ip_allocation_key.as_bytes()) {
                Ok(Some(data)) if data != b"__DELETED__" => {
                    String::from_utf8(data).ok()
                }
                _ => None
            }
        } else {
            // Assume it's an endpoint_id
            Some(identifier.to_string())
        }
    };

    let Some(endpoint_id) = endpoint_id else {
        debug!(identifier = identifier, "gateway: Endpoint not found");
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.send(response).await;
        return;
    };

    // Extract data and drop lock before any awaits
    let registration_key = format!("endpoints/registry/{}", endpoint_id);
    let endpoint_data = {
        let kv = kv.read().expect("gateway kv lock");
        match kv.get_bytes(registration_key.as_bytes()) {
            Ok(Some(data)) => {
                match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(registration) => {
                        let public_key_hex = registration.get("public_key_hex")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let assigned_ip = registration.get("assigned_ip")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let public_ip = registration.get("public_ip")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let public_port = registration.get("public_port")
                            .and_then(|v| v.as_u64());
                        let local_ip = registration.get("local_ip")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let local_port = registration.get("local_port")
                            .and_then(|v| v.as_u64());

                        Some((public_key_hex, assigned_ip, public_ip, public_port, local_ip, local_port))
                    }
                    Err(e) => {
                        error!(error = ?e, "gateway: Failed to deserialize registration");
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                error!(error = ?e, "gateway: Failed to query KV for endpoint");
                None
            }
        }
    }; // Lock dropped here

    // Now send response without holding the lock
    match endpoint_data {
        Some((Some(public_key_hex), assigned_ip, public_ip, public_port, local_ip, local_port)) => {
            let mut response_body = format!(r#"{{"endpoint_id":"{}","public_key_hex":"{}""#,
                endpoint_id, public_key_hex);

            if let Some(ip) = assigned_ip {
                response_body.push_str(&format!(r#","assigned_ip":"{}""#, ip));
            }
            if let Some(ip) = public_ip {
                response_body.push_str(&format!(r#","public_ip":"{}""#, ip));
            }
            if let Some(port) = public_port {
                response_body.push_str(&format!(r#","public_port":{}"#, port));
            }
            if let Some(ip) = local_ip {
                response_body.push_str(&format!(r#","local_ip":"{}""#, ip));
            }
            if let Some(port) = local_port {
                response_body.push_str(&format!(r#","local_port":{}"#, port));
            }

            response_body.push_str("}");

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            if let Err(e) = stream.send(response.as_bytes()).await {
                error!(error = ?e, "gateway: Failed to send endpoint lookup response");
            } else {
                debug!(endpoint_id = endpoint_id, "gateway: Sent endpoint information");
            }
        }
        _ => {
            let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.send(response).await;
        }
    }
}

pub fn get_transport_server() -> Option<&'static TransportServer> {
    TRANSPORT_SERVER.get()
}
