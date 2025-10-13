use client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");
    let gateway_url = std::env::var("HT_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());

    println!("=== Storage Modes Demo ===\n");
    println!("Gateway: {}\n", gateway_url);

    // Mode 1: Default - uses ~/.hightower/gateway/<gateway>/
    println!("1. Default mode (persistent storage):");
    let conn1 = HightowerConnection::connect(&gateway_url, &auth_token).await?;
    println!("   Endpoint ID: {}", conn1.endpoint_id());
    println!("   Storage: ~/.hightower/gateway/<sanitized-gateway>/");
    conn1.disconnect().await?;

    // Mode 2: Ephemeral - no storage, always fresh
    println!("\n2. Ephemeral mode (no storage, always fresh):");
    let conn2 = HightowerConnection::connect_ephemeral(
        &gateway_url,
        &auth_token
    ).await?;
    println!("   Endpoint ID: {}", conn2.endpoint_id());
    println!("   Storage: none (ephemeral)");
    conn2.disconnect().await?;

    // Mode 3: Custom storage directory
    println!("\n3. Custom storage directory:");
    let custom_dir = std::env::temp_dir().join("my-app-connections");
    let conn3 = HightowerConnection::connect_with_storage(
        &gateway_url,
        &auth_token,
        &custom_dir
    ).await?;
    println!("   Endpoint ID: {}", conn3.endpoint_id());
    println!("   Storage: {}", custom_dir.display());
    conn3.disconnect().await?;

    // Mode 4: Force fresh - bypass any stored connection
    println!("\n4. Force fresh registration (ignores stored connection):");
    let conn4 = HightowerConnection::connect_fresh(
        &gateway_url,
        &auth_token
    ).await?;
    println!("   Endpoint ID: {}", conn4.endpoint_id());
    println!("   (This is a brand new registration even if one was stored)");
    conn4.disconnect().await?;

    println!("\n=== Demo Complete ===");

    Ok(())
}
