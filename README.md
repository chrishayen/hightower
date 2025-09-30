# hightower-mdns

A naive Rust implementation of mDNS (Multicast DNS) for advertising and discovering hostnames on a local network. Implements basic functionality from RFC 6762.

## Features

- Advertise a hostname on the local network with automatic periodic broadcasting
- Listen for and respond to mDNS queries from other peers
- Query for specific hostnames
- Configurable broadcast intervals
- Configurable domain (defaults to `.local` per RFC 6762)
- Channel-based API for receiving discoveries and query responses
- Async/await support with Tokio

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-mdns = { git = "https://github.com/chrishayen/hightower-mdns.git" }
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
    // Returns a handle for querying and receiving notifications
    let mut handle = mdns.run();

    // Handle incoming discoveries and responses
    loop {
        tokio::select! {
            Some(response) = handle.discoveries.recv() => {
                println!("Discovered: {} at {}", response.hostname, response.ip);
            }
            Some(response) = handle.responses.recv() => {
                println!("Query response: {} at {}", response.hostname, response.ip);
            }
        }
    }
}
```

### Querying for Hosts

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?;
    let mut handle = mdns.run();

    // Query for a specific host
    handle.query("otherhost").await;

    // Wait for response
    if let Some(response) = handle.responses.recv().await {
        println!("Found: {} at {}", response.hostname, response.ip);
    }

    Ok(())
}
```

### Query on Discovery

```rust
use hightower_mdns::Mdns;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mdns = Mdns::new("myhost", Ipv4Addr::new(192, 168, 1, 100))?;
    let mut handle = mdns.run();

    loop {
        tokio::select! {
            Some(response) = handle.discoveries.recv() => {
                println!("Discovered: {} at {}", response.hostname, response.ip);

                // Query the discovered host
                let host = response.hostname.split('.').next().unwrap_or(&response.hostname);
                handle.query(host).await;
            }
            Some(response) = handle.responses.recv() => {
                println!("Query response from: {} at {}", response.hostname, response.ip);
            }
        }
    }
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

    let _handle = mdns.run();

    // Service is now running in the background
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

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

    Ok(())
}
```

## How It Works

1. **Broadcasting**: The service periodically broadcasts your hostname and IP address to the mDNS multicast group (224.0.0.251:5353)
2. **Listening**: Simultaneously listens for mDNS queries and announcements from other peers
3. **Responding**: When a query is received for your hostname, automatically responds with your IP address
4. **Discovery**: When broadcasts from other hosts are received, sends them to the `discoveries` channel
5. **Querying**: Can send queries to discover specific hosts, responses arrive on the `responses` channel

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