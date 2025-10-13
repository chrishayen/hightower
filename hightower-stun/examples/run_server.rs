use hightower_stun::server::StunServer;

fn main() {
    let addr = "0.0.0.0:3478";

    let server = StunServer::bind(addr).expect("Failed to bind STUN server");

    println!("STUN server listening on {}", server.local_addr().unwrap());
    println!("Press Ctrl+C to stop");

    if let Err(e) = server.run() {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}
