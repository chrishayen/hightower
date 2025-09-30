# hightower-mdns

A Rust implementation of mDNS (Multicast DNS) for advertising and discovering hostnames on a local network, following RFC 6762.

## Features

- Advertise a hostname on the local network with automatic periodic broadcasting
- Listen for and respond to mDNS queries from other peers
- Query for specific hostnames
- Configurable broadcast intervals
- Async/await support with Tokio

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-mdns = "0.1.0"
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
```

## Usage

### Basic Example

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Create an mDNS instance with your hostname and local IP
    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?;

    // Run the mDNS service (broadcasts and listens for queries)
    mdns.run().await;

    Ok(())
}
```

### Custom Broadcast Interval

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;
use std::time::Duration;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Broadcast every 60 seconds instead of the default 120 seconds
    let mdns = Mdns::with_interval(
        "myhost",
        Ipv4Addr::new(192, 168, 1, 100),
        Duration::from_secs(60)
    )?;

    mdns.run().await;

    Ok(())
}
```

### Discovering Hosts

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?
        .on_host_discovered(|hostname| {
            println!("Discovered: {}", hostname);
            // Query for more information or handle discovery
        });

    // Run the service (will call callback when hosts broadcast)
    mdns.run().await;

    Ok(())
}
```

### Querying Discovered Hosts

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mdns = Arc::new(Mutex::new(
        Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?
    ));

    let mdns_clone = mdns.clone();
    let mdns_instance = mdns.lock().await;
    let mdns_with_callback = std::mem::replace(
        &mut *mdns.lock().await,
        mdns_instance
    ).on_host_discovered(move |hostname| {
        println!("Discovered: {}", hostname);

        // Query the discovered host for more information
        let mdns = mdns_clone.clone();
        tokio::spawn(async move {
            let mdns = mdns.lock().await;
            // Strip .local suffix if present
            let query_name = hostname.strip_suffix(".local").unwrap_or(&hostname);
            mdns.query(query_name).await;
        });
    });

    mdns_with_callback.run().await;

    Ok(())
}
```

## How It Works

1. **Broadcasting**: The service periodically broadcasts your hostname and IP address to the mDNS multicast group (224.0.0.251:5353)
2. **Listening**: Simultaneously listens for mDNS queries and announcements from other peers
3. **Responding**: When a query is received for your hostname, automatically responds with your IP address
4. **Discovery**: When broadcasts from other hosts are received, invokes the callback with their hostname
5. **Querying**: Can send queries to discover specific hosts on the network

## RFC 6762 Compliance

This implementation follows the mDNS specification defined in RFC 6762, including:
- Default broadcast interval of 120 seconds
- Multicast address 224.0.0.251 on port 5353
- Proper DNS packet formatting
- Query/response handling

## License

[Add your license here]