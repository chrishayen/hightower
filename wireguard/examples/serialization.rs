use wireguard::crypto::dh_generate;
use wireguard::protocol::{PeerInfo, WireGuardProtocol};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("WireGuard Message Serialization Example\n");

    // Generate keys for both peers
    let (alice_private, alice_public) = dh_generate();
    let (bob_private, bob_public) = dh_generate();

    println!("Generated keys for Alice and Bob");

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

    // Step 1: Alice initiates handshake
    println!("\n1. Alice initiates handshake");
    let initiation = alice.initiate_handshake(&bob_public)?;
    println!("   Created HandshakeInitiation message");
    println!("   Sender ID: {}", initiation.sender);

    // Serialize initiation to wire format
    let initiation_bytes = initiation.to_bytes()?;
    println!("   Serialized to {} bytes", initiation_bytes.len());
    println!("   First 16 bytes: {:02x?}", &initiation_bytes[..16]);

    // Simulate network transmission by deserializing
    println!("\n2. Transmitting over network...");
    let received_initiation = wireguard::messages::HandshakeInitiation::from_bytes(
        &initiation_bytes,
    )?;
    println!("   Bob received and deserialized initiation");
    println!("   Sender ID: {}", received_initiation.sender);

    // Step 2: Bob processes initiation and creates response
    println!("\n3. Bob processes initiation and responds");
    let response = bob.process_initiation(&received_initiation)?;
    println!("   Created HandshakeResponse message");
    println!("   Sender ID: {}", response.sender);
    println!("   Receiver ID: {}", response.receiver);

    // Serialize response to wire format
    let response_bytes = response.to_bytes()?;
    println!("   Serialized to {} bytes", response_bytes.len());
    println!("   First 16 bytes: {:02x?}", &response_bytes[..16]);

    // Simulate network transmission by deserializing
    println!("\n4. Transmitting response over network...");
    let received_response =
        wireguard::messages::HandshakeResponse::from_bytes(&response_bytes)?;
    println!("   Alice received and deserialized response");
    println!("   Sender ID: {}", received_response.sender);
    println!("   Receiver ID: {}", received_response.receiver);

    // Step 3: Alice processes response
    println!("\n5. Alice processes response");
    let peer_key = alice.process_response(&received_response)?;
    println!("   Handshake complete with peer: {:02x?}...", &peer_key[..8]);

    // Verify sessions are established
    let alice_session = alice.get_session(received_response.sender).unwrap();
    let bob_session = bob.get_session(received_response.sender).unwrap();

    println!("\n6. Sessions established successfully");
    println!(
        "   Alice send key: {:02x?}...",
        &alice_session.keys.send_key[..8]
    );
    println!(
        "   Alice recv key: {:02x?}...",
        &alice_session.keys.recv_key[..8]
    );
    println!(
        "   Bob send key:   {:02x?}...",
        &bob_session.keys.send_key[..8]
    );
    println!(
        "   Bob recv key:   {:02x?}...",
        &bob_session.keys.recv_key[..8]
    );

    println!("\nHandshake complete! Both peers can now encrypt/decrypt data.");

    Ok(())
}
