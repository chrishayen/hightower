use thiserror::Error;

/// Cryptographic primitives for WireGuard protocol
pub mod crypto;
/// Handshake initiator implementation
pub mod initiator;
/// WireGuard message structures
pub mod messages;
/// High-level protocol implementation
pub mod protocol;
/// Handshake responder implementation
pub mod responder;
/// WireGuard transport layer (UDP-based Server, Listener, Conn)
#[cfg(feature = "transport")]
pub mod transport;

/// Errors that can occur during WireGuard protocol operations
#[derive(Error, Debug)]
pub enum WireGuardError {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Authentication failed")]
    AuthenticationFailed,
}

pub type Result<T> = std::result::Result<T, WireGuardError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{aead_decrypt, aead_encrypt, dh_generate};
    use protocol::{PeerInfo, WireGuardProtocol};

    #[test]
    fn test_full_handshake_and_message_exchange() {
        // Generate keys for both peers
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        // Create protocol instances
        let mut alice = WireGuardProtocol::new(Some(alice_private));
        let mut bob = WireGuardProtocol::new(Some(bob_private));

        // Add each other as peers
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

        // Alice initiates handshake
        let initiation = alice.initiate_handshake(&bob_public).unwrap();
        println!(
            "Alice created initiation with sender ID: {}",
            initiation.sender
        );

        // Bob processes initiation and creates response
        let response = bob.process_initiation(&initiation).unwrap();
        println!("Bob created response with sender ID: {}", response.sender);

        // Alice processes response to complete handshake
        let peer_key = alice.process_response(&response).unwrap();
        assert_eq!(peer_key, bob_public);

        // Both sides should now have active sessions
        let alice_session = alice.get_session(response.sender).unwrap();
        let bob_session = bob.get_session(response.sender).unwrap();

        println!("Handshake complete!");
        println!(
            "Alice session keys: send={:?}, recv={:?}",
            &alice_session.keys.send_key[..8],
            &alice_session.keys.recv_key[..8]
        );
        println!(
            "Bob session keys: send={:?}, recv={:?}",
            &bob_session.keys.send_key[..8],
            &bob_session.keys.recv_key[..8]
        );

        // Test message encryption/decryption
        let message = b"Hello from Alice to Bob!";
        let counter = 0u64;

        // Alice encrypts message with her send key
        let encrypted = aead_encrypt(&alice_session.keys.send_key, counter, message, &[]).unwrap();
        println!("Alice encrypted message: {} bytes", encrypted.len());

        // Bob decrypts with his receive key (should match Alice's send key)
        let decrypted = aead_decrypt(&bob_session.keys.recv_key, counter, &encrypted, &[]).unwrap();
        assert_eq!(decrypted, message);
        println!("Bob decrypted: {:?}", String::from_utf8_lossy(&decrypted));

        // Test reverse direction
        let reply = b"Hello back from Bob to Alice!";
        let reply_counter = 0u64;

        // Bob encrypts reply with his send key
        let encrypted_reply =
            aead_encrypt(&bob_session.keys.send_key, reply_counter, reply, &[]).unwrap();

        // Alice decrypts with her receive key
        let decrypted_reply = aead_decrypt(
            &alice_session.keys.recv_key,
            reply_counter,
            &encrypted_reply,
            &[],
        )
        .unwrap();
        assert_eq!(decrypted_reply, reply);
        println!(
            "Alice decrypted reply: {:?}",
            String::from_utf8_lossy(&decrypted_reply)
        );

        println!("Bidirectional message exchange successful!");
    }

    #[test]
    fn test_handshake_with_preshared_key() {
        let psk = [42u8; 32]; // Shared preshared key

        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        let mut alice = WireGuardProtocol::new(Some(alice_private));
        let mut bob = WireGuardProtocol::new(Some(bob_private));

        // Add peers with PSK
        alice.add_peer(PeerInfo {
            public_key: bob_public,
            preshared_key: Some(psk),
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: None,
        });

        bob.add_peer(PeerInfo {
            public_key: alice_public,
            preshared_key: Some(psk),
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: None,
        });

        // Perform handshake
        let initiation = alice.initiate_handshake(&bob_public).unwrap();
        let response = bob.process_initiation(&initiation).unwrap();
        let _peer_key = alice.process_response(&response).unwrap();

        // Verify sessions exist
        assert!(alice.get_session(response.sender).is_some());
        assert!(bob.get_session(response.sender).is_some());

        println!("PSK handshake successful!");
    }
}
