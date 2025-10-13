use stun::server::StunServer;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let addr = if args.len() > 1 {
        args[1].clone()
    } else {
        "0.0.0.0:3478".to_string()
    };

    let server = StunServer::bind(&addr).expect("Failed to bind STUN server");

    println!("STUN server listening on {}", server.local_addr().unwrap());
    println!("Press Ctrl+C to stop");

    if let Err(e) = server.run() {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}
