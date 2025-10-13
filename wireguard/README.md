# hightower-wireguard

A Rust implementation of the WireGuard cryptographic handshake protocol (Noise_IK).

## What is this?

This crate implements the core cryptographic handshake protocol used by WireGuard. It provides the building blocks for establishing secure sessions between peers using the Noise_IK pattern with pre-shared key support.

## What's Implemented

- **Noise_IK Handshake Protocol**: Full implementation of the WireGuard handshake
  - Handshake initiation (Message Type 1)
  - Handshake response (Message Type 2)
  - Session key derivation using HKDF
  - Pre-shared key (PSK) support for post-quantum security
- **Cryptographic Primitives**:
  - X25519 Diffie-Hellman key exchange
  - ChaCha20-Poly1305 AEAD encryption
  - BLAKE2s hashing
  - HKDF key derivation
- **Protocol State Management**:
  - Initiator state machine
  - Responder state machine
  - Session key management
  - Peer configuration
  - Replay protection (anti-replay window)
  - Automatic session rekeying (REKEY_AFTER_TIME)
  - Keep-alive packet support
  - Endpoint roaming for mobile devices

## What's NOT Implemented

This is **not** a complete VPN implementation. The following components are not included:

- **TUN/TAP Interface**: No virtual network interface creation or management
- **Routing**: No IP routing, forwarding, or allowed-IPs enforcement
- **Cookie Mechanism**: No DoS protection via cookies (Message Type 3)

This library is suitable for:
- Learning WireGuard's cryptographic protocol
- Building custom WireGuard-based protocols
- Testing and experimentation
- Integration into larger VPN implementations

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
# For handshake protocol only
hightower-wireguard = "0.2.1"

# For transport layer (UDP Connection and Stream)
hightower-wireguard = { version = "0.2.1", features = ["transport"] }
```

## Usage

```rust
use hightower_wireguard::protocol::{WireGuardProtocol, PeerInfo};
use hightower_wireguard::crypto::dh_generate;

// Generate keys for both peers
let (alice_private, alice_public) = dh_generate();
let (bob_private, bob_public) = dh_generate();

// Create protocol instances
let mut alice = WireGuardProtocol::new(Some(alice_private));
let mut bob = WireGuardProtocol::new(Some(bob_private));

// Configure peers
alice.add_peer(PeerInfo {
    public_key: bob_public,
    preshared_key: None,
    endpoint: None,
    allowed_ips: Vec::new(),
    persistent_keepalive: None,
});

bob.add_peer(PeerInfo {
    public_key: alice_public,
    preshared_key: None,
    endpoint: None,
    allowed_ips: Vec::new(),
    persistent_keepalive: None,
});

// Perform handshake
let initiation = alice.initiate_handshake(&bob_public)?;
let response = bob.process_initiation(&initiation)?;
let peer_key = alice.process_response(&response)?;

// Now both sides have active sessions with transport keys
let alice_session = alice.get_session(response.sender).unwrap();
let bob_session = bob.get_session(response.sender).unwrap();

// Use session keys for encryption/decryption
// alice_session.keys.send_key and alice_session.keys.recv_key
```

## Pre-Shared Key Support

```rust
let psk = [42u8; 32]; // Your pre-shared key

alice.add_peer(PeerInfo {
    public_key: bob_public,
    preshared_key: Some(psk),
    // ... other fields
});

bob.add_peer(PeerInfo {
    public_key: alice_public,
    preshared_key: Some(psk),
    // ... other fields
});

// Handshake will now use PSK for additional security
```

## Message Serialization

Messages can be serialized to and from wire format for network transmission:

```rust
use hightower_wireguard::messages::HandshakeInitiation;

// After creating a handshake initiation message
let initiation = alice.initiate_handshake(&bob_public)?;

// Serialize to wire format (148 bytes)
let bytes = initiation.to_bytes()?;

// Send over network...
// let socket.send_to(&bytes, peer_addr)?;

// On the receiving side, deserialize from bytes
let received = HandshakeInitiation::from_bytes(&bytes)?;
let response = bob.process_initiation(&received)?;

// Serialize the response (92 bytes)
let response_bytes = response.to_bytes()?;
```

The following message types support serialization:
- `HandshakeInitiation`: 148 bytes
- `HandshakeResponse`: 92 bytes
- `TransportData`: 16 bytes + variable packet length

## Transport Layer

With the `transport` feature enabled, you can use the high-level UDP-based transport layer:

```rust
use hightower_wireguard::crypto::dh_generate;
use hightower_wireguard::connection::Connection;

#[tokio::main]
async fn main() {
    // Generate keys
    let (alice_private, alice_public) = dh_generate();
    let (bob_private, bob_public) = dh_generate();

    // Create connections
    let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
        .await
        .unwrap();
    let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
        .await
        .unwrap();

    let alice_addr = alice.local_addr();
    let bob_addr = bob.local_addr();

    // Add peers
    alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
    bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

    // Bob listens for incoming connections
    let mut bob_incoming = bob.listen().await.unwrap();

    // Alice connects to Bob
    let mut alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();

    // Bob accepts the connection
    let mut bob_stream = bob_incoming.recv().await.unwrap();

    // Send and receive data
    alice_stream.send(b"Hello from Alice!").await.unwrap();

    let received = bob_stream.recv().await.unwrap();
    println!("Bob received: {}", String::from_utf8_lossy(&received));
}
```

### Keep-Alive Configuration

Configure persistent keep-alive to maintain NAT mappings and detect dead peers:

```rust
// Add peer with keep-alive packets sent every 25 seconds
alice.add_peer_with_keepalive(
    bob_public,
    Some(bob_addr),
    Some(25)  // send keep-alive every 25 seconds
).await.unwrap();
```

The transport layer provides:
- **Connection**: UDP socket management, packet routing, and session management
- **Stream**: Bidirectional encrypted communication channel to a peer
- Automatic handshake handling
- Message encryption/decryption using session keys
- Automatic keep-alive packets (configurable per-peer)
- Automatic session rekeying after 120 seconds (initiator only)
- Endpoint roaming support for mobile devices
- Session cleanup and timeout handling

## Testing

Run the test suite:

```bash
# Test handshake protocol only
cargo test

# Test with transport layer
cargo test --features transport
```

## References

- [WireGuard Paper](https://www.wireguard.com/papers/wireguard.pdf)
- [Noise Protocol Framework](https://noiseprotocol.org/)
