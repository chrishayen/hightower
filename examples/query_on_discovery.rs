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
            Some(hostname) = handle.discoveries.recv() => {
                println!("Discovered host via broadcast: {}", hostname);

                // Extract hostname without domain for query
                let host = hostname.split('.').next().unwrap_or(&hostname);
                println!("Sending query to: {}", host);
                handle.query(host).await;
            }
            Some(hostname) = handle.responses.recv() => {
                println!("Got query response from: {}", hostname);
            }
        }
    }
}
