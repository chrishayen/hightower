use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    let gateway_url = std::env::var("HT_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());

    println!("Using gateway URL: {}", gateway_url);
    println!("Connecting to gateway...");

    let connection = HightowerConnection::connect(gateway_url, auth_token).await?;

    println!("\nConnection successful!");
    println!("  Endpoint ID: {}", connection.endpoint_id());
    println!("  Assigned IP: {}", connection.assigned_ip());

    println!("\nTransport ready for communication");

    // Disconnect when done
    connection.disconnect().await?;

    Ok(())
}
