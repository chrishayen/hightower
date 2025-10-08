use hightower_client_lib::HightowerClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    let gateway_url = std::env::var("HT_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());

    println!("Using gateway URL: {}", gateway_url);

    let client = HightowerClient::new(gateway_url, auth_token)?;

    println!("Registering with gateway...");

    let result = client.register()?;

    println!("\nRegistration successful!");
    println!("  Node ID: {}", result.node_id);
    println!("  Token: {}", result.token);
    println!("  Assigned IP: {}", result.assigned_ip);
    println!("  Public Key: {}", result.public_key_hex);
    println!("  Private Key: {}", result.private_key_hex);
    println!("  Gateway Public Key: {}", result.gateway_public_key_hex);

    Ok(())
}
