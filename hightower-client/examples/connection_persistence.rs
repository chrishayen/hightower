use hightower_client::HightowerConnection;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable logging to see what's happening
    tracing_subscriber::fmt::init();

    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");
    let gateway_url = std::env::var("HT_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());

    println!("=== Connection Persistence Demo ===\n");
    println!("Gateway: {}", gateway_url);
    println!("Storage: ~/.hightower/gateway/<gateway>/\n");

    // First connection - will register with gateway and store credentials
    println!("1. First connection (will register and store credentials):");
    let conn1 = HightowerConnection::connect(&gateway_url, &auth_token).await?;
    println!("   ✓ Connected!");
    println!("   Endpoint ID: {}", conn1.endpoint_id());
    println!("   Assigned IP: {}", conn1.assigned_ip());

    // Keep connection alive for a moment
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Simulate application closing (drop the connection without disconnecting)
    println!("\n2. Simulating application shutdown (connection dropped but not deregistered)...");
    drop(conn1);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Second connection - will restore from stored credentials (same endpoint_id!)
    println!("\n3. Second connection (will restore from stored credentials):");
    let conn2 = HightowerConnection::connect(&gateway_url, &auth_token).await?;
    println!("   ✓ Connected!");
    println!("   Endpoint ID: {}", conn2.endpoint_id());
    println!("   Assigned IP: {}", conn2.assigned_ip());
    println!("   (Notice the endpoint_id is the same - we reused the stored connection!)");

    // Keep connection alive
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Demonstrate explicit disconnect - this will deregister and clear storage
    println!("\n4. Explicitly disconnecting (will deregister and clear stored credentials)...");
    conn2.disconnect().await?;
    println!("   ✓ Disconnected and cleaned up storage");

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Third connection - will register again (new endpoint_id since we cleared storage)
    println!("\n5. Third connection (storage cleared, will register fresh):");
    let conn3 = HightowerConnection::connect(&gateway_url, &auth_token).await?;
    println!("   ✓ Connected!");
    println!("   Endpoint ID: {}", conn3.endpoint_id());
    println!("   Assigned IP: {}", conn3.assigned_ip());
    println!("   (New endpoint_id because we explicitly disconnected last time)");

    // Clean up
    conn3.disconnect().await?;

    println!("\n=== Demo Complete ===");
    println!("\nKey takeaways:");
    println!("- Connections persist across application restarts by default");
    println!("- Same WireGuard keys = same identity = same endpoint_id");
    println!("- Only disconnect() removes stored credentials");
    println!("- Use connect_ephemeral() if you don't want persistence");

    Ok(())
}
