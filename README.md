# hightower-stun

A lightweight, RFC 8489-compliant STUN (Session Traversal Utilities for NAT) server and client implementation in Rust.

## Features

- **RFC 8489 Compliant**: Full implementation of the STUN protocol
- **Client & Server**: Both client and server implementations included
- **XOR-MAPPED-ADDRESS**: Proper support for reflexive address discovery
- **IPv4 & IPv6**: Support for both address families
- **DNS Resolution**: Client supports domain names and IP addresses
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Zero Dependencies**: Pure Rust implementation with only standard library

## Usage

### As a Library

#### STUN Client

```rust
use hightower_stun::client::StunClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = StunClient::new()?;

    // Query a STUN server to discover your public IP
    let addr = client.get_public_address("stun.l.google.com:3478")?;

    println!("Your public IP: {}", addr.ip());
    println!("Your public port: {}", addr.port());

    Ok(())
}
```

#### STUN Server

```rust
use hightower_stun::server::StunServer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = StunServer::bind("0.0.0.0:3478")?;

    println!("STUN server listening on {}", server.local_addr()?);

    // Run the server (blocks indefinitely)
    server.run()?;

    Ok(())
}
```

### As Binaries

The crate includes two binaries:

#### Client: `ht-stun-client`

Query a STUN server to discover your public IP address:

```bash
# Port defaults to 3478
ht-stun-client stun.l.google.com
ht-stun-client gateway.shotgun.dev

# Or specify port explicitly
ht-stun-client 192.168.1.1:3478
```

#### Server: `ht-stun-server`

Run a STUN server:

```bash
# Listen on default port 3478
ht-stun-server

# Or specify custom address
ht-stun-server 0.0.0.0:3478
```

## Building from Source

```bash
# Build library and binaries
cargo build --release

# Run tests
cargo test

# Run client
cargo run --bin ht-stun-client -- stun.l.google.com

# Run server
cargo run --bin ht-stun-server
```

## Cross-Compilation for ARM64

To build for ARM64 (aarch64) servers:

```bash
# Install the target
rustup target add aarch64-unknown-linux-gnu

# Install the cross-compiler (Arch Linux)
sudo pacman -S aarch64-linux-gnu-gcc

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

The included `Makefile` provides a `deploy` target for building and deploying to a remote server.

## How STUN Works

STUN helps clients discover their public IP address when behind a NAT:

1. Client sends a **Binding Request** to a STUN server
2. The NAT modifies the source IP/port of the packet
3. Server receives the request with the public IP/port
4. Server responds with a **Binding Response** containing an **XOR-MAPPED-ADDRESS** attribute
5. Client extracts its public IP/port from the response

## Protocol Details

- **Default Port**: 3478 (UDP/TCP)
- **Magic Cookie**: `0x2112A442`
- **Message Types**: Binding Request (`0x0001`), Binding Response (`0x0101`)
- **Attributes**: XOR-MAPPED-ADDRESS (`0x0020`), MAPPED-ADDRESS (`0x0001`)

## Examples

See the `examples/` directory for more:

- `get_public_ip.rs` - Simple client example
- `run_server.rs` - Basic server example

## Testing

```bash
# Run all tests
cargo test

# Test against a public STUN server
cargo run --example get_public_ip stun.l.google.com

# Test client against your own server
cargo run --bin ht-stun-server &
cargo run --bin ht-stun-client localhost
```

## References

- [RFC 8489 - STUN](https://www.rfc-editor.org/rfc/rfc8489.txt)
- [RFC 5389 - STUN (obsoleted by RFC 8489)](https://www.rfc-editor.org/rfc/rfc5389.txt)
- [RFC 3489 - Classic STUN](https://www.rfc-editor.org/rfc/rfc3489.txt)

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.
