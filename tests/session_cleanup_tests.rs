#[cfg(feature = "transport")]
mod session_cleanup_tests {
    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::connection::Connection;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn test_connection_cleanup_on_connection_drop() {
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

        alice_stream.send(b"before drop").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"before drop");

        drop(alice);

        sleep(Duration::from_millis(100)).await;

        let result = timeout(Duration::from_millis(500), bob_stream.recv()).await;
        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_listener_cleanup_on_drop() {
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

        let mut bob_incoming1 = bob.listen().await.unwrap();
        let mut bob_incoming2 = bob.listen().await.unwrap();

        let alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();

        let result1 = timeout(Duration::from_millis(500), bob_incoming1.recv()).await;
        let result2 = timeout(Duration::from_millis(500), bob_incoming2.recv()).await;

        assert!(result1.is_ok() || result2.is_ok());

        let mut bob_stream = if result1.is_ok() {
            result1.unwrap().unwrap()
        } else {
            result2.unwrap().unwrap()
        };

        alice_stream.send(b"with listener").await.unwrap();
        assert_eq!(bob_stream.recv().await.unwrap(), b"with listener");
    }

    #[tokio::test]
    async fn test_concurrent_connections_cleanup() {
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

        alice.add_peer(bob_public, Some(bob_addr)).await.unwrap();
        alice.add_peer(charlie_public, Some(charlie_addr)).await.unwrap();
        bob.add_peer(alice_public, Some(alice_addr)).await.unwrap();
        charlie.add_peer(alice_public, Some(alice_addr)).await.unwrap();

        let mut bob_incoming = bob.listen().await.unwrap();
        let mut charlie_incoming = charlie.listen().await.unwrap();

        let alice_to_bob = alice.connect(bob_addr, bob_public).await.unwrap();
        let alice_to_charlie = alice.connect(charlie_addr, charlie_public).await.unwrap();

        let mut bob_stream = bob_incoming.recv().await.unwrap();
        let mut charlie_stream = charlie_incoming.recv().await.unwrap();

        alice_to_bob.send(b"to bob").await.unwrap();
        alice_to_charlie.send(b"to charlie").await.unwrap();

        assert_eq!(bob_stream.recv().await.unwrap(), b"to bob");
        assert_eq!(charlie_stream.recv().await.unwrap(), b"to charlie");

        drop(alice_to_bob);
        drop(bob_stream);

        sleep(Duration::from_millis(100)).await;

        alice_to_charlie.send(b"charlie still works").await.unwrap();
        assert_eq!(
            charlie_stream.recv().await.unwrap(),
            b"charlie still works"
        );
    }

}
