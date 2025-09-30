use hightower_mdns::Mdns;
use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <name> <ip_address> [query_name]", args[0]);
        eprintln!("Example: {} peer1 192.168.1.100", args[0]);
        eprintln!("Example: {} peer1 192.168.1.100 peer2", args[0]);
        std::process::exit(1);
    }

    let name = &args[1];
    let ip: Ipv4Addr = args[2].parse().expect("Invalid IP address");
    let query_name = args.get(3).map(|s| s.to_string());

    let mdns = Mdns::with_interval(name, ip, Duration::from_secs(5))
        .expect("Failed to create mDNS instance");

    println!("Starting mDNS peer: {}.local -> {}", mdns.name(), mdns.local_ip());
    println!("Broadcasting and listening for queries...");

    if let Some(ref query) = query_name {
        println!("Will also query for: {}.local", query);
    }

    println!("Press Ctrl+C to stop.\n");

    // If a query name is provided, create a second mdns instance for querying
    if let Some(query) = query_name {
        let mdns2 = Mdns::with_interval(name, ip, Duration::from_secs(5))
            .expect("Failed to create second mDNS instance");

        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(3)).await;
                mdns2.query(&query).await;
                println!("Sent query for {}.local", query);
            }
        });
    }

    mdns.run().await;
}