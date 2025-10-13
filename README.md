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
- **Connection persistence and automatic restoration**

**You only provide:** gateway URL and auth token
**You get:** a working transport, endpoint ID, and assigned IP

Everything else is handled automatically!

### Connection Persistence (New in 0.1.1)

By default, connections are automatically persisted to `~/.hightower/gateway/<gateway>/`. When you reconnect to the same gateway:
- The library reuses your stored WireGuard keys (same identity)
- No re-registration needed with the gateway
- Same endpoint ID across application restarts
- Only `disconnect()` removes the stored connection

This makes your application's network identity stable across restarts!

### Peer-to-Peer Connectivity

Connect to other endpoints on the Hightower network by their endpoint ID or assigned IP:

```rust
use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = HightowerConnection::connect(
        "https://gateway.example.com:8443",
        "your-auth-token"
    ).await?;

    // Connect to another endpoint by ID or IP
    let mut stream = connection.dial("ht-festive-penguin-abc123", 8080).await?;

    // Send data to the peer
    stream.send(b"Hello, peer!").await?;

    // Receive response
    let response = stream.recv().await?;
    println!("Received: {}", String::from_utf8_lossy(&response));

    connection.disconnect().await?;
    Ok(())
}
```

The `dial()` method automatically:
1. Queries the gateway for the peer's real IP and public key
2. Adds the peer to your WireGuard configuration
3. Establishes a secure connection

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-client = "0.1.4"
```

## Usage

### Basic Connection

```rust
use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect with default gateway (http://127.0.0.1:8008)
    let connection = HightowerConnection::connect_with_auth_token("your-auth-token").await?;

    // Access what you need
    println!("Endpoint ID: {}", connection.endpoint_id());
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
use hightower_client::HightowerConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Must specify http:// or https://
    let connection = HightowerConnection::connect(
        "https://gateway.example.com:8443",
        "your-auth-token"
    ).await?;

    println!("Connected to {}", connection.endpoint_id());

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

### Connection Persistence Demo
```bash
export HT_AUTH_TOKEN="your-token"
export HT_GATEWAY_URL="http://127.0.0.1:8008"  # optional
cargo run --example connection_persistence
```

Demonstrates how connections are automatically restored across application restarts.

### Storage Modes
```bash
export HT_AUTH_TOKEN="your-token"
export HT_GATEWAY_URL="http://127.0.0.1:8008"  # optional
cargo run --example storage_modes
```

Shows all available storage modes: default persistence, ephemeral, custom directory, and forced fresh registration.

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

### Peer-to-Peer Connection
```bash
export HT_AUTH_TOKEN="your-token"
export PEER_ENDPOINT="ht-festive-penguin-abc123"  # or use an IP like "100.64.0.5"
cargo run --example peer_to_peer
```

Demonstrates connecting to another endpoint on the network.

## API Documentation

### `HightowerConnection`

The main connection struct with integrated WireGuard transport.

#### Methods

- `async fn connect(gateway_url: impl Into<String>, auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Connects to a Hightower gateway with a custom URL. The URL must include the scheme (http:// or https://).

  **With persistence (default):**
  - Checks for existing connection in `~/.hightower/gateway/<gateway>/`
  - If found, restores using stored keys (same identity)
  - If not found, generates new keypair and registers

  Handles everything internally:
  - Generates or restores WireGuard keypair
  - Creates transport server on 0.0.0.0:0
  - Discovers network info via STUN using actual bound port
  - Registers with gateway (or reuses existing registration)
  - Adds gateway as peer
  - Persists connection for future use

  Returns a ready-to-use connection with working transport.

- `async fn connect_with_auth_token(auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Connects using the default gateway (`http://127.0.0.1:8008`). Includes automatic persistence.

- `async fn connect_ephemeral(gateway_url: impl Into<String>, auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Connects without persistence. Always creates fresh registration, nothing stored to disk.

- `async fn connect_with_storage(gateway_url: impl Into<String>, auth_token: impl Into<String>, storage_dir: impl Into<PathBuf>) -> Result<Self, ClientError>`

  Connects using a custom storage directory instead of the default location.

- `async fn connect_fresh(gateway_url: impl Into<String>, auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Forces a fresh registration even if a stored connection exists. Deletes any existing stored connection for this gateway.

- `fn endpoint_id(&self) -> &str`

  Returns the endpoint ID assigned by the gateway.

- `fn assigned_ip(&self) -> &str`

  Returns the IP address assigned by the gateway.

- `fn transport(&self) -> &TransportServer`

  Returns the transport for sending/receiving data.

- `async fn get_peer_info(&self, endpoint_id_or_ip: &str) -> Result<PeerInfo, ClientError>`

  Queries the gateway for information about another endpoint. Accepts either an endpoint ID (e.g., "ht-festive-penguin-abc123") or an assigned IP (e.g., "100.64.0.5").

  Returns `PeerInfo` containing:
  - `endpoint_id`: The endpoint's ID
  - `public_key_hex`: The endpoint's WireGuard public key
  - `assigned_ip`: The endpoint's virtual IP on the network
  - `endpoint`: The endpoint's real public address (optional, for NAT traversal)

- `async fn dial(&self, peer: &str, port: u16) -> Result<Stream, ClientError>`

  Establishes a connection to another endpoint on the Hightower network.

  **Parameters:**
  - `peer`: Endpoint ID (e.g., "ht-festive-penguin") or assigned IP (e.g., "100.64.0.5")
  - `port`: Port to connect to on the peer

  This method automatically:
  1. Fetches peer info from the gateway
  2. Adds the peer to WireGuard configuration
  3. Establishes a secure connection

  Returns a `Stream` for bidirectional communication with the peer.

- `async fn ping_gateway(&self) -> Result<(), ClientError>`

  Pings the gateway over the WireGuard connection to verify connectivity.

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
- `Storage(String)` - Storage operation failed (persistence)

## Testing

Run the test suite:

```bash
cargo test
```

## License

MIT
