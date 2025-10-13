use stun::client::StunClient;
use std::env;

const DEFAULT_STUN_PORT: u16 = 3478;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <server[:port]>", args[0]);
        eprintln!("  Default port is {} if not specified", DEFAULT_STUN_PORT);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} stun.l.google.com", args[0]);
        eprintln!("  {} gateway.shotgun.dev", args[0]);
        eprintln!("  {} 46.62.214.173:3478", args[0]);
        std::process::exit(1);
    }

    let server = if args[1].contains(':') {
        args[1].clone()
    } else {
        format!("{}:{}", args[1], DEFAULT_STUN_PORT)
    };

    let client = StunClient::new().expect("Failed to create STUN client");

    println!("Querying STUN server at {}...", server);

    match client.get_public_address(&server) {
        Ok(addr) => {
            println!("Your public IP address: {}", addr.ip());
            println!("Your public port: {}", addr.port());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
