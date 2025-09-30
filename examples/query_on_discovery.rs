use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let local_ip = Ipv4Addr::new(0, 0, 0, 0);

    let mdns = Mdns::new("example-host", local_ip)?;

    println!("Starting mDNS service on {}", local_ip);
    println!("Listening for broadcasts and will query any discovered hosts...");

    let mut handle = mdns.run();

    loop {
        tokio::select! {
            Some(response) = handle.discoveries.recv() => {
                println!("Discovered host via broadcast: {} at {}", response.hostname, response.ip);

                // Extract hostname without domain for query
                let host = response.hostname.split('.').next().unwrap_or(&response.hostname);
                println!("Sending query to: {}", host);
                handle.query(host).await;
            }
            Some(response) = handle.responses.recv() => {
                println!("Got query response from: {} at {}", response.hostname, response.ip);
            }
        }
    }
}
