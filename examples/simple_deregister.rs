use hightower_client_lib::HightowerClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo run --example simple_deregister <token>");
        std::process::exit(1);
    }

    let token = &args[1];

    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .expect("HT_AUTH_TOKEN environment variable must be set");

    let client = HightowerClient::with_auth_token(auth_token)?;

    println!("Deregistering node with token: {}...", &token[..8]);

    client.deregister(token)?;

    println!("Successfully deregistered!");

    Ok(())
}
