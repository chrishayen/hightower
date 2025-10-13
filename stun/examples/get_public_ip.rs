use stun::client::StunClient;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let server = if args.len() > 1 {
        args[1].clone()
    } else {
        "stun.l.google.com:19302".to_string()
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
