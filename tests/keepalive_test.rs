#[cfg(feature = "transport")]
mod keepalive_test {
    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::transport::Connection;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn test_automatic_keepalive() {
        // Test that keepalive packets are automatically sent
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

        // Configure persistent keepalive on Alice (1 second interval)
        alice
            .add_peer_with_keepalive(bob_public, Some(bob_addr), Some(1))
            .await
            .unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        // Establish connection
        let mut bob_incoming = bob.listen().await.unwrap();
        let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        // Send initial message to establish session
        alice_stream.send(b"hello").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"hello");

        // Wait for multiple keepalive intervals (3 seconds)
        // During this time, Alice should send keepalive packets
        sleep(Duration::from_secs(3)).await;

        // Connection should still be alive - send a message to verify
        alice_stream.send(b"still alive").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"still alive");
    }

    #[tokio::test]
    async fn test_manual_keepalive() {
        // Test that sending empty messages works as keepalive
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

        // Send a regular message
        alice_stream.send(b"hello").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"hello");

        // Send multiple empty messages (keepalives)
        // These should be processed but not delivered to the stream
        for _ in 0..5 {
            alice_stream.send(&[]).await.unwrap();
        }

        // Send another regular message to verify connection is still good
        alice_stream.send(b"goodbye").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"goodbye");

        // Bob should only have received the two non-empty messages
        // Try to receive another message - should timeout since only 2 were sent
        let result = timeout(Duration::from_millis(100), bob_stream.recv()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_bidirectional_keepalive() {
        // Test keepalive with traffic in both directions
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

        // Both peers configured with keepalive
        alice
            .add_peer_with_keepalive(bob_public, Some(bob_addr), Some(1))
            .await
            .unwrap();
        bob
            .add_peer_with_keepalive(alice_public, Some(alice_addr), Some(1))
            .await
            .unwrap();

        let mut bob_incoming = bob.listen().await.unwrap();
        let mut alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        // Exchange initial messages
        alice_stream.send(b"ping").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"ping");

        bob_stream.send(b"pong").await.unwrap();
        assert_eq!(alice_stream.recv().await.unwrap(), b"pong");

        // Wait for keepalive exchanges
        sleep(Duration::from_secs(2)).await;

        // Both directions should still work
        alice_stream.send(b"still here").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"still here");

        bob_stream.send(b"me too").await.unwrap();
        assert_eq!(alice_stream.recv().await.unwrap(), b"me too");
    }
}