use hightower_client_lib::HightowerClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    let client = HightowerClient::with_auth_token(auth_token)?;

    println!("Registering with gateway...");

    let result = client.register()?;

    println!("\nRegistration successful!");
    println!("  Node ID: {}", result.node_id);
    println!("  Token: {}", result.token);
    println!("  Assigned IP: {}", result.assigned_ip);
    println!("  Public Key: {}", result.public_key_hex);
    println!("  Private Key: {}", result.private_key_hex);
    println!("  Gateway Public Key: {}", result.gateway_public_key_hex);

    println!("\nTo deregister, run:");
    println!("  cargo run --example simple_deregister {}", result.token);

    Ok(())
}
