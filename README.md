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

## What's NOT Implemented

This is **not** a complete VPN implementation. The following components are not included:

- **Network Transport**: No UDP socket handling or packet I/O
- **TUN/TAP Interface**: No virtual network interface creation or management
- **Routing**: No IP routing, forwarding, or allowed-IPs enforcement
- **Cookie Mechanism**: No DoS protection via cookies (Message Type 3)
- **Transport Data Messages**: No actual data encryption/decryption (Message Type 4)
- **Key Rotation**: No automatic session key rekeying
- **Packet Serialization**: Handshake messages are not serialized to wire format
- **Production Features**: No timers, replay protection, or keepalives

This library is suitable for:
- Learning WireGuard's cryptographic protocol
- Building custom WireGuard-based protocols
- Testing and experimentation
- Integration into larger VPN implementations

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hightower-wireguard = "0.1.1"
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

## Testing

Run the test suite:

```bash
cargo test
```

## References

- [WireGuard Paper](https://www.wireguard.com/papers/wireguard.pdf)
- [Noise Protocol Framework](https://noiseprotocol.org/)
