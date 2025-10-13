// This example demonstrates that deregistration is now automatic.
// Simply call connection.disconnect() and the library handles deregistration internally.

use client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    println!("Connecting to gateway...");

    let connection = HightowerConnection::connect_with_auth_token(auth_token).await?;

    println!("Connected! Endpoint ID: {}", connection.endpoint_id());
    println!("\nNow disconnecting (this will automatically deregister)...");

    // Disconnect handles deregistration automatically using internal token
    connection.disconnect().await?;

    println!("Successfully deregistered!");

    Ok(())
}
