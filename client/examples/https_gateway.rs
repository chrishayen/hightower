use client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    println!("Connecting to HTTPS gateway: https://gateway.example.com:8443");

    let connection = HightowerConnection::connect(
        "https://gateway.example.com:8443",
        auth_token
    ).await?;

    println!("\nConnection successful!");
    println!("  Endpoint ID: {}", connection.endpoint_id());
    println!("  Assigned IP: {}", connection.assigned_ip());

    println!("\nTransport ready for communication");

    // Disconnect when done
    connection.disconnect().await?;

    Ok(())
}
