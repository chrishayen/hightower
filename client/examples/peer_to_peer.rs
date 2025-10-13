use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable logging to see what's happening
    tracing_subscriber::fmt::init();

    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");
    let gateway_url = std::env::var("HT_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());
    let peer_endpoint = std::env::var("PEER_ENDPOINT")
        .expect("PEER_ENDPOINT environment variable must be set (endpoint ID or IP)");

    println!("=== Peer-to-Peer Connection Demo ===\n");
    println!("Gateway: {}", gateway_url);
    println!("Target Peer: {}", peer_endpoint);

    // Connect to the gateway
    println!("\n1. Connecting to gateway...");
    let connection = HightowerConnection::connect(&gateway_url, &auth_token).await?;
    println!("   ✓ Connected!");
    println!("   Endpoint ID: {}", connection.endpoint_id());
    println!("   Assigned IP: {}", connection.assigned_ip());

    // Get peer information from the gateway
    println!("\n2. Querying gateway for peer information...");
    match connection.get_peer_info(&peer_endpoint).await {
        Ok(peer_info) => {
            println!("   ✓ Peer info retrieved:");
            println!("     Endpoint ID: {}", peer_info.endpoint_id.as_deref().unwrap_or("unknown"));
            println!("     Assigned IP: {}", peer_info.assigned_ip.as_deref().unwrap_or("unknown"));
            println!("     Public Key: {}...", &peer_info.public_key_hex[..16]);
            if let Some(endpoint) = peer_info.endpoint() {
                println!("     Public Endpoint: {}", endpoint);
            } else {
                println!("     Public Endpoint: None (may be behind NAT)");
            }
        }
        Err(e) => {
            println!("   ✗ Failed to get peer info: {}", e);
            println!("\n   Make sure:");
            println!("   - The peer endpoint exists on the gateway");
            println!("   - The peer is currently connected");
            println!("   - You have permission to access this peer");
            connection.disconnect().await?;
            return Err(e.into());
        }
    }

    // Dial the peer (this also fetches peer info internally)
    println!("\n3. Connecting to peer on port 8080...");
    match connection.dial(&peer_endpoint, 8080).await {
        Ok(mut stream) => {
            println!("   ✓ Connected to peer!");

            // Send a message to the peer
            println!("\n4. Sending message to peer...");
            let message = b"Hello from hightower-client!";
            stream.send(message).await?;
            println!("   ✓ Sent: {}", String::from_utf8_lossy(message));

            // Try to receive a response (with timeout)
            println!("\n5. Waiting for response from peer...");
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                stream.recv()
            ).await {
                Ok(Ok(response)) => {
                    println!("   ✓ Received: {}", String::from_utf8_lossy(&response));
                }
                Ok(Err(e)) => {
                    println!("   ✗ Error receiving response: {}", e);
                }
                Err(_) => {
                    println!("   ⏱ Timeout waiting for response (peer may not be listening)");
                }
            }

            println!("\n6. Connection to peer successful!");
        }
        Err(e) => {
            println!("   ✗ Failed to dial peer: {}", e);
            println!("\n   Possible reasons:");
            println!("   - Peer is not listening on port 8080");
            println!("   - Network connectivity issues");
            println!("   - Peer's firewall is blocking connections");
        }
    }

    // Disconnect from gateway
    println!("\n7. Disconnecting from gateway...");
    connection.disconnect().await?;
    println!("   ✓ Disconnected");

    println!("\n=== Demo Complete ===");
    println!("\nKey points:");
    println!("- get_peer_info() queries the gateway for endpoint details");
    println!("- dial() automatically resolves the peer and establishes a connection");
    println!("- Peer can be specified by endpoint ID or assigned IP");
    println!("- The gateway provides the real IP and public key for NAT traversal");

    Ok(())
}
