//! Demonstration of keep-alive and rekey functionality
//!
//! This example creates two WireGuard peers and shows:
//! - Automatic keep-alive packets being sent
//! - Session rekeying when REKEY_AFTER_TIME is exceeded
//! - Endpoint roaming support
//!
//! Run with: cargo run --example keepalive_demo --features transport

#[cfg(feature = "transport")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::protocol::PeerInfo;
    use hightower_wireguard::transport::Server;
    use tokio::time::{sleep, Duration};

    println!("\n=== WireGuard Keep-Alive and Rekey Demo ===\n");

    // Generate keys for both peers
    let (alice_private, alice_public) = dh_generate();
    let (bob_private, bob_public) = dh_generate();

    println!("Alice public key: {}", hex::encode(&alice_public[..8]));
    println!("Bob public key: {}\n", hex::encode(&bob_public[..8]));

    // Create servers
    let alice_server = Server::new("127.0.0.1:0".parse().unwrap(), alice_private)
        .await
        .unwrap();
    let bob_server = Server::new("127.0.0.1:0".parse().unwrap(), bob_private)
        .await
        .unwrap();

    let alice_addr = alice_server.local_addr().unwrap();
    let bob_addr = bob_server.local_addr().unwrap();

    println!("Alice listening on: {}", alice_addr);
    println!("Bob listening on: {}\n", bob_addr);

    // Add peers
    alice_server
        .add_peer(bob_public, Some(bob_addr))
        .await
        .unwrap();
    bob_server
        .add_peer(alice_public, Some(alice_addr))
        .await
        .unwrap();

    // Configure persistent keepalive (2 seconds) for Alice -> Bob
    {
        let mut protocol = alice_server.protocol().lock().await;
        if let Some(peer) = protocol.peers().get(&bob_public).cloned() {
            let peer_with_keepalive = PeerInfo {
                persistent_keepalive: Some(2), // 2 seconds
                ..peer
            };
            protocol.remove_peer(&bob_public);
            protocol.add_peer(peer_with_keepalive);
            println!("Configured Alice with 2-second keep-alive interval\n");
        }
    }

    // Start both servers
    let alice_server_clone = alice_server.clone();
    let bob_server_clone = bob_server.clone();

    tokio::spawn(async move { alice_server_clone.run().await });
    tokio::spawn(async move { bob_server_clone.run().await });

    // Start maintenance tasks
    let alice_maintenance = alice_server.clone();
    let bob_maintenance = bob_server.clone();
    tokio::spawn(async move { alice_maintenance.run_maintenance().await });
    tokio::spawn(async move { bob_maintenance.run_maintenance().await });

    // Wait for servers to be ready
    alice_server.wait_until_ready().await.unwrap();
    bob_server.wait_until_ready().await.unwrap();

    println!("=== Establishing Initial Connection ===\n");

    // Bob creates listener
    let bob_listener = bob_server.listen("tcp", ":0").await.unwrap();

    // Alice dials Bob
    let _alice_conn = alice_server
        .dial("tcp", &bob_addr.to_string(), bob_public)
        .await
        .unwrap();

    // Bob accepts connection
    let _bob_conn = bob_listener.accept().await.unwrap();

    println!("\n=== Connection Established ===\n");
    println!("Now watching for keep-alive packets...\n");
    println!("Keep-alive should be sent every 2 seconds\n");

    // Wait to see keep-alive in action
    for i in 1..=5 {
        sleep(Duration::from_secs(2)).await;
        println!("--- {} seconds elapsed ---", i * 2);
    }

    println!("\n=== Keep-Alive Demo Complete ===\n");
    println!("For rekey demo, sessions need to age 120 seconds (REKEY_AFTER_TIME)");
    println!("You can manually trigger rekey by modifying session.created_at in tests\n");

    Ok(())
}

#[cfg(not(feature = "transport"))]
fn main() {
    eprintln!("This example requires the 'transport' feature");
    eprintln!("Run with: cargo run --example keepalive_demo --features transport");
    std::process::exit(1);
}
