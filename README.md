# hightower-mdns

A naive Rust implementation of mDNS (Multicast DNS) for advertising and discovering hostnames on a local network. Implements basic functionality from RFC 6762.

## Features

- Advertise a hostname on the local network with automatic periodic broadcasting
- Listen for and respond to mDNS queries from other peers
- Query for specific hostnames
- Configurable broadcast intervals
- Configurable domain (defaults to `.local` per RFC 6762)
- Host discovery callbacks
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
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();

    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?
        .on_host_discovered(move |hostname| {
            println!("Discovered: {}", hostname);
            let _ = tx.send(hostname);
        });

    // Spawn a task to handle discovered hosts
    tokio::spawn(async move {
        while let Some(hostname) = rx.recv().await {
            // Process discovered host (query, store, etc.)
            println!("Processing: {}", hostname);
        }
    });

    mdns.run().await;

    Ok(())
}
```

### Custom Domain

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Use a custom domain instead of .local
    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?
        .with_domain("custom");

    mdns.run().await;

    Ok(())
}
```

### Goodbye Packets

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?;

    // Manually send goodbye packet before leaving
    mdns.goodbye().await;

    // Note: Goodbye packet is also automatically sent when Mdns is dropped

    Ok(())
}
```

## How It Works

1. **Broadcasting**: The service periodically broadcasts your hostname and IP address to the mDNS multicast group (224.0.0.251:5353)
2. **Listening**: Simultaneously listens for mDNS queries and announcements from other peers
3. **Responding**: When a query is received for your hostname, automatically responds with your IP address
4. **Discovery**: When broadcasts from other hosts are received, invokes the callback with their hostname
5. **Querying**: Can send queries to discover specific hosts on the network

## RFC 6762 Implementation Status

### Implemented
- Periodic announcements/broadcasts
- Query and response handling
- A record (IPv4) support
- DNS packet formatting
- Multicast address 224.0.0.251 on port 5353
- Default broadcast interval of 120 seconds
- Cache-flush bit in responses
- Goodbye packets (TTL=0) when leaving the network

### Not Implemented
- Probing (Section 8.1) - name conflict detection before claiming
- Conflict resolution
- Known-Answer Suppression
- Negative responses
- IPv6 support (AAAA records)
- TTL-based cache management
- Multiple questions/answers per packet
- Truncation handling
- DNS compression pointer handling in queries

## License

[Add your license here]