# Hightower Client Library

A Rust library for registering and managing nodes with a Hightower gateway.

## Overview

This library provides a simple client interface for interacting with Hightower gateway APIs. It allows you to:

- Register nodes with the gateway
- Automatically discover network information (public/local IPs) via STUN
- Generate WireGuard keypairs automatically
- Deregister nodes
- Handle authentication and error responses

Everything is handled automatically - you only need to provide an auth token!

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-client-lib = "0.1.0"
```

## Usage

### Basic Registration

```rust
use hightower_client_lib::HightowerClient;

let client = HightowerClient::with_auth_token("your-auth-token")?;

// Everything is automatic:
// - Keys generated
// - Node name assigned by gateway
// - Network info (public/local IPs) discovered via STUN
let result = client.register()?;

println!("Node ID: {}", result.node_id);
println!("Assigned IP: {}", result.assigned_ip);
println!("Token: {}", result.token);
```


### Deregistration

```rust
use hightower_client_lib::HightowerClient;

let client = HightowerClient::with_auth_token("your-auth-token")?;
client.deregister("registration-token")?;
```

### Custom Gateway URL

```rust
use hightower_client_lib::HightowerClient;

// Must specify http:// or https://
let client = HightowerClient::new(
    "https://gateway.example.com:8443",
    "your-auth-token"
)?;

// Or with HTTP (for testing)
let client = HightowerClient::new(
    "http://localhost:8008",
    "your-auth-token"
)?;
```

## Examples

The library includes several examples:

### Simple Registration
```bash
export HT_AUTH_TOKEN="your-token"
cargo run --example simple_register
```

### Remote Gateway
```bash
export HT_AUTH_TOKEN="your-token"
cargo run --example remote_gateway
```

### Deregistration
```bash
export HT_AUTH_TOKEN="your-token"
cargo run --example simple_deregister <registration-token>
```

### Custom Endpoint
```bash
export HT_AUTH_TOKEN="your-token"
export HT_GATEWAY_ENDPOINT="https://gateway.example.com/api/nodes"
cargo run --example custom_endpoint
```

## API Documentation

### `HightowerClient`

The main client struct for interacting with the gateway.

#### Methods

- `new(gateway_url: impl Into<String>, auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Creates a new client with a custom gateway URL and auth token. The URL must include the scheme (http:// or https://).

- `with_auth_token(auth_token: impl Into<String>) -> Result<Self, ClientError>`

  Creates a new client with the default gateway (`http://127.0.0.1:8008`).

- `register() -> Result<RegistrationResult, ClientError>`

  Registers a node with the gateway. Automatically:
  - Generates a WireGuard keypair
  - Discovers network info (public/local IPs and ports) via STUN
  - Receives assigned node name from gateway

  Returns registration details including assigned node name, IP, token, and generated keys.

- `deregister(token: &str) -> Result<(), ClientError>`

  Deregisters a node using its registration token.

### `RegistrationResult`

Contains the result of a successful registration.

**Fields:**
- `node_id: String` - Node name assigned by the gateway
- `token: String` - Token for deregistration
- `gateway_public_key_hex: String` - Gateway's public key (hex-encoded)
- `assigned_ip: String` - IP address assigned to the node
- `public_key_hex: String` - Node's generated public key (hex-encoded)
- `private_key_hex: String` - Node's generated private key (hex-encoded)


### `ClientError`

Error types returned by the client.

**Variants:**
- `Configuration(String)` - Invalid configuration (e.g., empty endpoint)
- `Request(reqwest::Error)` - HTTP request failed
- `GatewayError { status: u16, message: String }` - Gateway returned error
- `InvalidResponse(String)` - Unexpected response format
- `NetworkDiscovery(String)` - Failed to discover network info via STUN

## Testing

Run the test suite:

```bash
cargo test
```

## License

MIT
