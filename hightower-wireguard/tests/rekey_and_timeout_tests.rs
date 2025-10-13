#[cfg(feature = "transport")]
mod rekey_and_timeout_tests {
    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::connection::Connection;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn test_connection_survives_short_idle_period() {
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

        alice_stream.send(b"message 1").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"message 1");

        sleep(Duration::from_secs(5)).await;

        alice_stream.send(b"message 2").await.unwrap();
        let result = timeout(Duration::from_secs(1), bob_stream.recv()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), b"message 2");
    }

    #[tokio::test]
    async fn test_keepalive_prevents_timeout() {
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

        alice
            .add_peer_with_keepalive(bob_public, Some(bob_addr), Some(1))
            .await
            .unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        let mut bob_incoming = bob.listen().await.unwrap();
        let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        alice_stream.send(b"start").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"start");

        sleep(Duration::from_secs(10)).await;

        alice_stream.send(b"after keepalive").await.unwrap();
        let result = timeout(Duration::from_secs(1), bob_stream.recv()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), b"after keepalive");
    }

    #[tokio::test]
    async fn test_connection_idle_without_keepalive() {
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

        alice_stream.send(b"hello").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"hello");

        sleep(Duration::from_secs(15)).await;

        alice_stream.send(b"after idle").await.unwrap();
        let result = timeout(Duration::from_secs(2), bob_stream.recv()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_messages_during_keepalive_period() {
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

        alice
            .add_peer_with_keepalive(bob_public, Some(bob_addr), Some(2))
            .await
            .unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        let mut bob_incoming = bob.listen().await.unwrap();
        let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        for i in 0..10 {
            sleep(Duration::from_millis(500)).await;
            let msg = format!("message {}", i);
            alice_stream.send(msg.as_bytes()).await.unwrap();
            let received = timeout(Duration::from_secs(1), bob_stream.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, msg.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_bidirectional_keepalive_interaction() {
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

        alice_stream.send(b"ping").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"ping");

        sleep(Duration::from_secs(5)).await;

        bob_stream.send(b"pong").await.unwrap();
        let received = timeout(Duration::from_secs(1), alice_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"pong");

        alice_stream.send(b"still alive").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"still alive");
    }
}
