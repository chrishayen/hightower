# Hightower Client Library

A Rust library for building applications that connect to Hightower gateways with integrated WireGuard transport.

## Overview

This library provides a complete solution for connecting to Hightower gateways. It handles everything internally:

- WireGuard transport creation and management
- Certificate/keypair generation
- Network discovery via STUN using actual bound ports
- Gateway registration
- Peer configuration
- Automatic deregistration on disconnect

**You only provide:** gateway URL and auth token
**You get:** a working transport, node ID, and assigned IP

Everything else is handled automatically!

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-client-lib = "0.1.0"
```

## Usage

### Basic Connection

```rust
use hightower_client_lib::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect with default gateway (http://127.0.0.1:8008)
    let connection = HightowerConnection::connect_with_auth_token("your-auth-token").await?;

    // Access what you need
    println!("Node ID: {}", connection.node_id());
    println!("Assigned IP: {}", connection.assigned_ip());

    // Get transport for communication
    let transport = connection.transport();

    // Use the underlying server for send/receive operations
    // See hightower-wireguard documentation for full API
    // let server = transport.server();

    // Disconnect (automatically deregisters)
    connection.disconnect().await?;

    Ok(())
}
```

### Custom Gateway URL

```rust
use hightower_client_lib::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Must specify http:// or https://
    let connection = HightowerConnection::connect(
        "https://gateway.example.com:8443",
        "your-auth-token"
    ).await?;

    println!("Connected to {}", connection.node_id());

    connection.disconnect().await?;

    Ok(())
}
```

## Examples

The library includes several examples:

### Simple Connection
```bash
export HT_AUTH_TOKEN="your-token"
cargo run --example simple_register
```

### Custom Gateway URL
```bash
export HT_AUTH_TOKEN="your-token"
export HT_GATEWAY_URL="https://gateway.example.com:8443"
cargo run --example custom_endpoint
```

### HTTPS Gateway
```bash
export HT_AUTH_TOKEN="your-token"
cargo run --example https_gateway
```

### Auto Deregistration
```bash
export HT_AUTH_TOKEN="your-token"
cargo run --example simple_deregister
```

## API Documentation

### `HightowerConnection`

The main connection struct with integrated WireGuard transport.

#### Methods

- `async fn connect(gateway_url: impl Into<String>, auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Connects to a Hightower gateway with a custom URL. The URL must include the scheme (http:// or https://).

  Handles everything internally:
  - Generates WireGuard keypair
  - Creates transport server on 0.0.0.0:0
  - Discovers network info via STUN using actual bound port
  - Registers with gateway
  - Adds gateway as peer

  Returns a ready-to-use connection with working transport.

- `async fn connect_with_auth_token(auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Connects using the default gateway (`http://127.0.0.1:8008`).

- `fn node_id(&self) -> &str`

  Returns the node ID assigned by the gateway.

- `fn assigned_ip(&self) -> &str`

  Returns the IP address assigned by the gateway.

- `fn transport(&self) -> &TransportServer`

  Returns the transport for sending/receiving data.

- `async fn disconnect(self) -> Result<(), ClientError>`

  Disconnects from the gateway and automatically deregisters using the internal token.

### `TransportServer`

Wrapper around the WireGuard transport.

#### Methods

- `fn server(&self) -> &Server`

  Get a reference to the underlying hightower-wireguard `Server`.
  Use this to access the full transport API for sending/receiving data.


### `ClientError`

Error types returned by the library.

**Variants:**
- `Configuration(String)` - Invalid configuration (e.g., empty endpoint, invalid URL)
- `Request(reqwest::Error)` - HTTP request failed
- `GatewayError { status: u16, message: String }` - Gateway returned error
- `InvalidResponse(String)` - Unexpected response format
- `NetworkDiscovery(String)` - Failed to discover network info via STUN
- `Transport(String)` - Transport creation or operation failed

## Testing

Run the test suite:

```bash
cargo test
```

## License

MIT
