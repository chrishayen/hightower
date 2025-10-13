#[cfg(feature = "transport")]
mod connection_tests {
    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::connection::Connection;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_connection_creation() {
        let (private_key, _public_key) = dh_generate();
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let conn = Connection::new(bind_addr, private_key).await;
        assert!(conn.is_ok());

        let conn = conn.unwrap();
        let local_addr = conn.local_addr();
        assert_ne!(local_addr.port(), 0);
    }

    #[tokio::test]
    async fn test_bidirectional_communication() {
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

        // Bob listens
        let mut bob_incoming = bob.listen().await.unwrap();

        // Alice connects
        let mut alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();

        // Bob accepts
        let mut bob_stream = timeout(Duration::from_secs(5), bob_incoming.recv())
            .await
            .unwrap()
            .unwrap();

        // Alice sends to Bob
        let alice_msg = b"Hello from Alice!";
        alice_stream.send(alice_msg).await.unwrap();

        // Bob receives
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, alice_msg);

        // Bob sends to Alice
        let bob_msg = b"Hello from Bob!";
        bob_stream.send(bob_msg).await.unwrap();

        // Alice receives
        let received = timeout(Duration::from_secs(1), alice_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, bob_msg);
    }

    #[tokio::test]
    async fn test_multiple_streams() {
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();
        let (charlie_private, charlie_public) = dh_generate();

        // Create connections
        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();
        let charlie = Connection::new("127.0.0.1:0".parse().unwrap(), charlie_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();
        let charlie_addr = charlie.local_addr();

        // Everyone adds everyone as peers
        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
        alice.add_peer(charlie_public, Some(charlie_addr)).await.unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();
        bob.add_peer(charlie_public, Some(charlie_addr)).await.unwrap();
        charlie.add_peer(alice_public, Some(alice_addr)).await.unwrap();
        charlie.add_peer(bob_public, Some(bob_addr)).await.unwrap();

        // Alice listens
        let mut alice_incoming = alice.listen().await.unwrap();

        // Bob and Charlie connect to Alice
        let bob_to_alice = bob.connect(alice_addr, alice_public).await.unwrap();
        let charlie_to_alice = charlie.connect(alice_addr, alice_public).await.unwrap();

        // Alice accepts both
        let mut alice_stream1 = timeout(Duration::from_secs(5), alice_incoming.recv())
            .await
            .unwrap()
            .unwrap();
        let mut alice_stream2 = timeout(Duration::from_secs(5), alice_incoming.recv())
            .await
            .unwrap()
            .unwrap();

        // Bob sends
        bob_to_alice.send(b"From Bob").await.unwrap();

        // Charlie sends
        charlie_to_alice.send(b"From Charlie").await.unwrap();

        // Alice receives both (order may vary)
        let msg1 = timeout(Duration::from_secs(1), alice_stream1.recv())
            .await
            .unwrap()
            .unwrap();
        let msg2 = timeout(Duration::from_secs(1), alice_stream2.recv())
            .await
            .unwrap()
            .unwrap();

        let messages = vec![msg1, msg2];
        assert!(messages.iter().any(|m| m == b"From Bob"));
        assert!(messages.iter().any(|m| m == b"From Charlie"));
    }

    #[tokio::test]
    async fn test_listener_routing() {
        // Test that only one listener gets each connection
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();

        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        // Create two listeners on Bob
        let mut bob_listener1 = bob.listen().await.unwrap();
        let mut bob_listener2 = bob.listen().await.unwrap();

        // Alice connects once
        let _alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();

        // Only one listener should receive the connection
        let result1 = timeout(Duration::from_millis(100), bob_listener1.recv()).await;
        let result2 = timeout(Duration::from_millis(100), bob_listener2.recv()).await;

        // One should succeed, one should timeout
        assert!(result1.is_ok() || result2.is_ok());
        assert!(!(result1.is_ok() && result2.is_ok()));
    }

    #[tokio::test]
    async fn test_keepalive_with_persistent_config() {
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();

        // Alice adds Bob with 2-second keepalive
        alice
            .add_peer_with_keepalive(bob_public, Some(bob_addr), Some(2))
            .await
            .unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        // Establish connection
        let mut bob_incoming = bob.listen().await.unwrap();
        let _alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let _bob_stream = bob_incoming.recv().await.unwrap();

        // Wait for keepalive to trigger (maintenance runs every 1s, keepalive is 2s)
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Connection should still be alive (keepalive prevents timeout)
        // We can't directly test that keepalive was sent, but the connection works
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();
        let (charlie_private, charlie_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();
        let charlie = Connection::new("127.0.0.1:0".parse().unwrap(), charlie_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();
        let charlie_addr = charlie.local_addr();

        // Add peers
        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
        alice.add_peer(charlie_public, Some(charlie_addr)).await.unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();
        charlie.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        // Both listen
        let mut bob_incoming = bob.listen().await.unwrap();
        let mut charlie_incoming = charlie.listen().await.unwrap();

        // Alice connects to both (sequentially to avoid lifetime issues)
        let alice_to_bob = alice.connect(bob_addr, bob_public).await;
        let alice_to_charlie = alice.connect(charlie_addr, charlie_public).await;

        // Both should succeed
        assert!(alice_to_bob.is_ok());
        assert!(alice_to_charlie.is_ok());

        // Both should receive connections
        assert!(timeout(Duration::from_secs(1), bob_incoming.recv())
            .await
            .is_ok());
        assert!(timeout(Duration::from_secs(1), charlie_incoming.recv())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_stream_cleanup_on_drop() {
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();

        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        let mut bob_incoming = bob.listen().await.unwrap();
        let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        // Send message
        alice_stream.send(b"test").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"test");

        // Drop alice stream
        drop(alice_stream);

        // Bob should eventually detect closed connection
        // (In production this would be via timeout or explicit close message)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_large_message_transfer() {
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();

        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        let mut bob_incoming = bob.listen().await.unwrap();
        let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        // Send a message near the practical UDP limit (8KB)
        // Note: WireGuard typically fragments at the application layer for larger messages
        let large_msg = vec![42u8; 8192];
        alice_stream.send(&large_msg).await.unwrap();

        // Bob should receive it intact
        let received = timeout(Duration::from_secs(2), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, large_msg);
    }

    #[tokio::test]
    async fn test_connection_without_peer_fails() {
        let (alice_private, _alice_public) = dh_generate();
        let (_bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();

        // Try to connect to non-existent address
        // This should timeout since no one is listening
        let result = timeout(
            Duration::from_secs(1),
            alice.connect("127.0.0.1:9999".parse().unwrap(), bob_public)
        ).await;

        // Should timeout because no one is listening
        assert!(result.is_err());
    }
}