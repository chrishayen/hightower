use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    println!("Connecting to gateway...");
    println!("Network info will be auto-discovered via STUN");

    let connection = HightowerConnection::connect_with_auth_token(auth_token).await?;

    println!("\nConnection successful!");
    println!("  Node ID: {}", connection.node_id());
    println!("  Assigned IP: {}", connection.assigned_ip());

    println!("\nTransport ready for communication");

    // Disconnect when done
    connection.disconnect().await?;

    Ok(())
}
