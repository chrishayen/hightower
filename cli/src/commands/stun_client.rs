use anyhow::Result;
use stun::client::StunClient;

pub fn query(address: &str) -> Result<()> {
    let server_address = if address.contains(':') {
        address.to_string()
    } else {
        format!("{}:3478", address)
    };

    println!("Querying STUN server at {}...", server_address);
    let client = StunClient::new()?;

    match client.get_public_address(&server_address) {
        Ok(addr) => {
            println!("Public address: {}", addr);
            Ok(())
        }
        Err(e) => {
            eprintln!("Error querying STUN server: {}", e);
            std::process::exit(1);
        }
    }
}
