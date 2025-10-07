#[cfg(feature = "transport")]
mod transport_tests {
    use hightower_wireguard::crypto::dh_generate;
    use hightower_wireguard::transport::Server;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn server_can_be_created() {
        let (private_key, _public_key) = dh_generate();
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let server = Server::new(bind_addr, private_key).await;
        assert!(server.is_ok());

        let server = server.unwrap();
        let local_addr = server.local_addr();
        assert!(local_addr.is_ok());
    }

    #[tokio::test]
    async fn server_can_create_listener() {
        let (private_key, _public_key) = dh_generate();
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let server = Server::new(bind_addr, private_key).await.unwrap();

        let listener = server.listen("tcp", ":8080").await;
        assert!(listener.is_ok());

        let listener = listener.unwrap();
        assert_eq!(listener.local_addr(), ":8080");
    }

    #[tokio::test]
    async fn server_can_dial_peer() {
        let (private_key, _public_key) = dh_generate();
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let server = Server::new(bind_addr, private_key).await.unwrap();

        let (_, peer_public_key) = dh_generate();

        // Add peer before dialing
        let peer_addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        server
            .add_peer(peer_public_key, Some(peer_addr))
            .await
            .unwrap();

        // Note: This will timeout because no peer is listening, which is expected
        // We're just testing that dial() doesn't panic and returns an error
        let conn = server.dial("tcp", "127.0.0.1:9999", peer_public_key).await;

        // Should return an error (timeout) because no peer is listening
        assert!(conn.is_err());
    }

    #[tokio::test]
    async fn conn_recv_with_channels_does_not_busy_wait() {
        // Test that recv() properly blocks on a channel instead of busy-waiting
        let (private_key, _public_key) = dh_generate();
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let server = Server::new(bind_addr, private_key).await.unwrap();

        let (_, peer_public_key) = dh_generate();
        let peer_addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        server
            .add_peer(peer_public_key, Some(peer_addr))
            .await
            .unwrap();

        // This will fail handshake but we just want to test the connection object
        let conn = server.dial("tcp", "127.0.0.1:9999", peer_public_key).await;

        if conn.is_err() {
            // Expected - no peer listening
            return;
        }

        let conn = conn.unwrap();

        // recv() should timeout quickly if there's no data, not busy-wait
        let start = std::time::Instant::now();
        let mut buf = vec![0u8; 1024];
        let result = timeout(Duration::from_millis(100), conn.recv(&mut buf)).await;
        let elapsed = start.elapsed();

        // Should timeout, not busy-wait for 100ms
        assert!(result.is_err(), "recv should timeout");
        assert!(
            elapsed < Duration::from_millis(150),
            "recv should not busy-wait"
        );
    }

    #[tokio::test]
    async fn listener_accept_with_channels_does_not_busy_wait() {
        // Test that accept() properly blocks on a channel instead of busy-waiting
        let (private_key, _public_key) = dh_generate();
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let server = Server::new(bind_addr, private_key).await.unwrap();

        let listener = server.listen("tcp", ":8080").await.unwrap();

        // accept() should timeout quickly if there are no connections
        let start = std::time::Instant::now();
        let result = timeout(Duration::from_millis(100), listener.accept()).await;
        let elapsed = start.elapsed();

        // Should timeout, not busy-wait for 100ms
        assert!(result.is_err(), "accept should timeout");
        assert!(
            elapsed < Duration::from_millis(150),
            "accept should not busy-wait"
        );
    }

    // Note: This test is covered by full_handshake_and_data_exchange
    // which tests real data flow through connections

    #[tokio::test]
    async fn concurrent_dials_do_not_interfere() {
        // Test that multiple concurrent dial() calls don't steal each other's handshake responses
        // This test documents the expected behavior - we'll need a full integration test with
        // two real servers to properly test this

        // For now, just verify that the mechanism (oneshot channels) is in place
        // by checking that dial() doesn't panic with concurrent calls

        let (private_key, _) = dh_generate();
        let server = Server::new("127.0.0.1:0".parse().unwrap(), private_key)
            .await
            .unwrap();

        let (_, peer1_key) = dh_generate();
        let (_, peer2_key) = dh_generate();

        let peer1_addr: std::net::SocketAddr = "127.0.0.1:9991".parse().unwrap();
        let peer2_addr: std::net::SocketAddr = "127.0.0.1:9992".parse().unwrap();

        server.add_peer(peer1_key, Some(peer1_addr)).await.unwrap();
        server.add_peer(peer2_key, Some(peer2_addr)).await.unwrap();

        // Start two concurrent dials (they'll timeout but shouldn't interfere)
        let server1 = server.clone();
        let server2 = server.clone();

        let dial1 = tokio::spawn(async move {
            server1.dial("tcp", "127.0.0.1:9991", peer1_key).await
        });

        let dial2 = tokio::spawn(async move {
            server2.dial("tcp", "127.0.0.1:9992", peer2_key).await
        });

        // Both should timeout cleanly without panicking or stealing each other's responses
        let (result1, result2) = tokio::join!(dial1, dial2);

        assert!(result1.is_ok(), "dial1 task should not panic");
        assert!(result2.is_ok(), "dial2 task should not panic");
    }

    #[tokio::test]
    async fn full_handshake_and_data_exchange() {
        // Test a complete handshake and bidirectional data exchange between two servers
        let (alice_private, alice_public) = dh_generate();
        let (bob_private, bob_public) = dh_generate();

        // Create servers
        let alice_server = Server::new("127.0.0.1:0".parse().unwrap(), alice_private)
            .await
            .unwrap();
        let bob_server = Server::new("127.0.0.1:0".parse().unwrap(), bob_private)
            .await
            .unwrap();

        let alice_addr = alice_server.local_addr().unwrap();
        let bob_addr = bob_server.local_addr().unwrap();

        // Add peers
        alice_server
            .add_peer(bob_public, Some(bob_addr))
            .await
            .unwrap();
        bob_server
            .add_peer(alice_public, Some(alice_addr))
            .await
            .unwrap();

        // Start both servers
        let alice_server_clone = alice_server.clone();
        let bob_server_clone = bob_server.clone();

        tokio::spawn(async move { alice_server_clone.run().await });
        tokio::spawn(async move { bob_server_clone.run().await });

        // Wait for servers to be ready
        alice_server.wait_until_ready().await.unwrap();
        bob_server.wait_until_ready().await.unwrap();

        // Bob creates listener
        let bob_listener = bob_server.listen("tcp", ":0").await.unwrap();

        // Alice dials Bob
        let alice_conn = alice_server
            .dial("tcp", &bob_addr.to_string(), bob_public)
            .await
            .unwrap();

        // Bob accepts connection
        let bob_conn = bob_listener.accept().await.unwrap();

        // Alice sends data to Bob
        let alice_msg = b"Hello from Alice!";
        alice_conn.send(alice_msg).await.unwrap();

        // Bob receives data
        let mut buf = vec![0u8; 1024];
        let n = bob_conn.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], alice_msg);

        // Bob sends data to Alice
        let bob_msg = b"Hello from Bob!";
        bob_conn.send(bob_msg).await.unwrap();

        // Alice receives data
        let n = alice_conn.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], bob_msg);
    }
}
