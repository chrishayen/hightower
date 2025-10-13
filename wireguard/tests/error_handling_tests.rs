#[cfg(feature = "transport")]
mod error_handling_tests {
    use wireguard::crypto::dh_generate;
    use wireguard::connection::Connection;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_connect_to_unknown_peer() {
        // Test connecting to a peer we haven't added
        let (alice_private, _alice_public) = dh_generate();
        let (_bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();

        // Try to connect to Bob without adding him as a peer first
        let result = timeout(
            Duration::from_secs(1),
            alice.connect("127.0.0.1:9999".parse().unwrap(), bob_public),
        )
        .await;

        // Should timeout because handshake can't complete
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_stream_persistence_after_drop() {
        // Test that streams continue to work even after one side drops
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

        // Exchange a message to establish the session
        alice_stream.send(b"hello").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"hello");

        // Drop Bob's stream handle (but connection still exists)
        drop(bob_stream);

        // Alice can still send (packets arrive but no one is reading)
        alice_stream.send(b"message 1").await.unwrap();
        alice_stream.send(b"message 2").await.unwrap();

        // The session remains active on both sides
        // This is expected behavior - dropping a stream handle doesn't close the session
    }

    #[tokio::test]
    async fn test_duplicate_peer_add() {
        // Test adding the same peer twice
        let (alice_private, _alice_public) = dh_generate();
        let (_bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();

        let bob_addr = "127.0.0.1:8888".parse().unwrap();

        // Add Bob as a peer
        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();

        // Add Bob again - should succeed (overwrites previous)
        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
    }

    #[tokio::test]
    async fn test_session_persistence() {
        // Test that sessions persist even after peer info changes
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

        // Exchange messages
        alice_stream.send(b"hello").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"hello");

        // Update peer info (e.g., different endpoint)
        alice.add_peer(bob_public, Some("127.0.0.1:9999".parse().unwrap())).await.unwrap();

        // Existing stream should still work (session persists with original endpoint)
        alice_stream.send(b"still works").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"still works");
    }

    #[tokio::test]
    async fn test_multiple_listeners_single_connection() {
        // Test that only one listener receives each connection
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

        // Create three listeners
        let mut listener1 = bob.listen().await.unwrap();
        let mut listener2 = bob.listen().await.unwrap();
        let mut listener3 = bob.listen().await.unwrap();

        // Alice connects once
        let _alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();

        // Check all three listeners
        let result1 = timeout(Duration::from_millis(100), listener1.recv()).await;
        let result2 = timeout(Duration::from_millis(100), listener2.recv()).await;
        let result3 = timeout(Duration::from_millis(100), listener3.recv()).await;

        // Exactly one should succeed
        let successes = vec![result1.is_ok(), result2.is_ok(), result3.is_ok()]
            .into_iter()
            .filter(|&x| x)
            .count();
        assert_eq!(successes, 1);
    }

    #[tokio::test]
    async fn test_invalid_message_handling() {
        // Test that invalid messages are handled gracefully
        let (alice_private, _alice_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();

        let alice_addr = alice.local_addr();

        // Send garbage data to the connection
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send various invalid messages
        let garbage = vec![0xFF; 100];
        sock.send_to(&garbage, alice_addr).await.unwrap();

        // Send too-short message
        let short = vec![0x01];
        sock.send_to(&short, alice_addr).await.unwrap();

        // Send message with invalid type
        let mut invalid_type = vec![0xFF, 0x00, 0x00, 0x00];
        invalid_type.extend(vec![0; 100]);
        sock.send_to(&invalid_type, alice_addr).await.unwrap();

        // Connection should continue to work
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Can still add peers
        let (_bob_private, bob_public) = dh_generate();
        alice.add_peer(bob_public, Some("127.0.0.1:9999".parse().unwrap()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_connects_to_same_peer() {
        // Test multiple simultaneous connect attempts to the same peer
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

        // Launch multiple connect attempts concurrently
        let connect1 = alice.connect(bob_addr, bob_public);
        let connect2 = alice.connect(bob_addr, bob_public);
        let connect3 = alice.connect(bob_addr, bob_public);

        let (r1, r2, r3) = tokio::join!(connect1, connect2, connect3);

        // All should succeed (our implementation allows multiple handshakes)
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());

        // Bob should receive multiple connections
        let mut count = 0;
        while timeout(Duration::from_millis(100), bob_incoming.recv())
            .await
            .is_ok()
        {
            count += 1;
        }
        assert!(count > 0);
    }

    #[tokio::test]
    async fn test_message_size_limits() {
        // Test sending messages at various size boundaries
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

        // Test various sizes
        // Note: 0-length messages are used internally for keepalive and won't be delivered to streams
        let sizes = vec![1, 100, 1024, 4096];

        for size in sizes {
            let msg = vec![42u8; size];
            alice_stream.send(&msg).await.unwrap();
            let received = timeout(Duration::from_secs(1), bob_stream.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, msg);
        }

        // Test that empty messages can be sent (used as keepalive internally)
        // They won't be delivered to the receiving stream
        let empty_msg = vec![];
        alice_stream.send(&empty_msg).await.unwrap();

        // Send a non-empty message after to verify connection still works
        alice_stream.send(b"after empty").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"after empty");

        // Test message at UDP practical limit (8KB)
        let large_msg = vec![42u8; 8192];
        let result = alice_stream.send(&large_msg).await;

        if result.is_ok() {
            // If send succeeds, verify we can receive it
            let recv_result = timeout(Duration::from_secs(1), bob_stream.recv()).await;
            assert!(recv_result.is_ok());
        }

        // Test message way too large (>64KB definitely should fail)
        let huge_msg = vec![42u8; 65536];
        let result = alice_stream.send(&huge_msg).await;
        // This should fail due to UDP size limitations
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_listen_without_peers() {
        // Test that we can listen even without any peers added
        let (alice_private, _alice_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();

        // Should be able to create a listener without peers
        let mut listener = alice.listen().await.unwrap();

        // Trying to receive should not panic, just timeout
        let result = timeout(Duration::from_millis(100), listener.recv()).await;
        assert!(result.is_err());
    }
}