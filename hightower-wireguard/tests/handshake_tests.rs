#[cfg(feature = "transport")]
mod handshake_tests {
    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::connection::Connection;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_handshake_with_wrong_peer_key() {
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();
        let (charlie_private, _charlie_public) = dh_generate();

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

        alice_stream.send(b"hello").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"hello");

        let charlie = Connection::new("127.0.0.1:0".parse().unwrap(), charlie_private)
            .await
            .unwrap();

        let charlie_addr = charlie.local_addr();

        bob.add_peer(alice_public, Some(charlie_addr))
            .await
            .unwrap();

        let result = timeout(
            Duration::from_secs(1),
            charlie.connect(bob_addr, bob_public),
        )
        .await;

        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_handshake_both_peers_initiate_simultaneously() {
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

        let mut alice_incoming = alice.listen().await.unwrap();
        let mut bob_incoming = bob.listen().await.unwrap();

        let alice_connect = alice.connect(bob_addr, bob_public);
        let bob_connect = bob.connect(alice_addr, alice_public);

        let (alice_result, bob_result) = tokio::join!(alice_connect, bob_connect);

        assert!(alice_result.is_ok());
        assert!(bob_result.is_ok());

        let mut alice_stream = alice_result.unwrap();
        let mut bob_stream = bob_result.unwrap();

        let accept_alice = timeout(Duration::from_millis(500), alice_incoming.recv());
        let accept_bob = timeout(Duration::from_millis(500), bob_incoming.recv());

        let (accept_alice_result, accept_bob_result) = tokio::join!(accept_alice, accept_bob);

        let accept_count = [accept_alice_result.is_ok(), accept_bob_result.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();

        assert!(accept_count >= 1);

        alice_stream.send(b"from alice").await.unwrap();
        bob_stream.send(b"from bob").await.unwrap();

        let msg_alice = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        let msg_bob = timeout(Duration::from_secs(1), alice_stream.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg_alice, b"from alice");
        assert_eq!(msg_bob, b"from bob");
    }

    #[tokio::test]
    async fn test_handshake_responder_without_peer_config() {
        let (alice_private, _alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let _bob = Connection::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();

        let bob_addr = "127.0.0.1:9999".parse().unwrap();

        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();

        let result = timeout(
            Duration::from_secs(1),
            alice.connect(bob_addr, bob_public),
        )
        .await;

        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_multiple_handshake_attempts() {
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

        // First connect creates the stream on Bob's side
        let alice_stream1 = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = timeout(Duration::from_secs(1), bob_incoming.recv())
            .await
            .unwrap()
            .unwrap();

        alice_stream1.send(b"attempt 0").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"attempt 0");

        // Subsequent connects create new sessions but reuse the stream
        // Messages continue to flow through the same stream
        for i in 1..5 {
            let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();

            let msg = format!("attempt {}", i);
            alice_stream.send(msg.as_bytes()).await.unwrap();

            // Bob receives on the same stream (no new stream is created)
            let received = timeout(Duration::from_secs(1), bob_stream.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, msg.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_handshake_to_unreachable_endpoint() {
        let (alice_private, _alice_public) = dh_generate();
        let (_bob_private, bob_public) = dh_generate();

        let alice = Connection::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();

        alice
            .add_peer(bob_public, Some("127.0.0.1:9".parse().unwrap()))
            .await
            .unwrap();

        let result = timeout(
            Duration::from_secs(1),
            alice.connect("127.0.0.1:9".parse().unwrap(), bob_public),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_successful_handshake_basic() {
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

        let alice_stream = alice.connect(bob_addr, bob_public).await;
        assert!(alice_stream.is_ok());

        let bob_stream = timeout(Duration::from_secs(5), bob_incoming.recv()).await;
        assert!(bob_stream.is_ok());
        assert!(bob_stream.unwrap().is_some());
    }
}
