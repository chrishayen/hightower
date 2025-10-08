use hightower_client_lib::HightowerClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    let client = HightowerClient::with_auth_token(auth_token)?;

    println!("Registering with gateway...");
    println!("Network info will be auto-discovered via STUN");

    let result = client.register()?;

    println!("\nRegistration successful!");
    println!("  Node ID: {}", result.node_id);
    println!("  Token: {}", result.token);
    println!("  Assigned IP: {}", result.assigned_ip);
    println!("  Public Key: {}...", &result.public_key_hex[..16]);
    println!("  Private Key: {}...", &result.private_key_hex[..16]);
    println!("  Gateway Public Key: {}...", &result.gateway_public_key_hex[..16]);

    Ok(())
}
