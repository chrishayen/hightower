#[cfg(feature = "transport")]
mod communication_edge_cases_tests {
    use wireguard::crypto::dh_generate;
    use wireguard::connection::Connection;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_empty_message_handling() {
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

        alice_stream.send(&[]).await.unwrap();

        alice_stream.send(b"after empty").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"after empty");
    }

    #[tokio::test]
    async fn test_rapid_message_burst() {
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

        for i in 0..100 {
            let msg = format!("burst {}", i);
            alice_stream.send(msg.as_bytes()).await.unwrap();
        }

        for i in 0..100 {
            let expected = format!("burst {}", i);
            let received = timeout(Duration::from_secs(5), bob_stream.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_message_after_receive_timeout() {
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

        let result = timeout(Duration::from_millis(100), bob_stream.recv()).await;
        assert!(result.is_err());

        alice_stream.send(b"late message").await.unwrap();
        let received = timeout(Duration::from_secs(1), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"late message");
    }

    #[tokio::test]
    async fn test_alternating_direction_messages() {
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
        let mut alice_stream = alice.connect(bob_addr, bob_public).await.unwrap();
        let mut bob_stream = bob_incoming.recv().await.unwrap();

        for i in 0..20 {
            if i % 2 == 0 {
                let msg = format!("alice {}", i);
                alice_stream.send(msg.as_bytes()).await.unwrap();
                let received = timeout(Duration::from_secs(1), bob_stream.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(received, msg.as_bytes());
            } else {
                let msg = format!("bob {}", i);
                bob_stream.send(msg.as_bytes()).await.unwrap();
                let received = timeout(Duration::from_secs(1), alice_stream.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(received, msg.as_bytes());
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_bidirectional_messages() {
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
        let bob_stream = bob_incoming.recv().await.unwrap();

        for i in 0..50 {
            let alice_msg = format!("from alice {}", i);
            let bob_msg = format!("from bob {}", i);

            alice_stream.send(alice_msg.as_bytes()).await.unwrap();
            bob_stream.send(bob_msg.as_bytes()).await.unwrap();

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn test_varying_message_sizes() {
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

        let sizes = vec![1, 10, 50, 100, 500, 1000, 2000, 4000, 8000];

        for size in sizes {
            let msg = vec![42u8; size];
            alice_stream.send(&msg).await.unwrap();
            let received = timeout(Duration::from_secs(2), bob_stream.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.len(), size);
            assert_eq!(received, msg);
        }
    }

    #[tokio::test]
    async fn test_send_after_failed_send() {
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

        let huge_msg = vec![0u8; 100000];
        let _ = alice_stream.send(&huge_msg).await;

        alice_stream.send(b"normal message").await.unwrap();
        let received = timeout(Duration::from_secs(2), bob_stream.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"normal message");
    }

    #[tokio::test]
    async fn test_receiving_from_multiple_streams() {
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

        for i in 0..20 {
            let bob_msg = format!("to bob {}", i);
            let charlie_msg = format!("to charlie {}", i);

            alice_to_bob.send(bob_msg.as_bytes()).await.unwrap();
            alice_to_charlie.send(charlie_msg.as_bytes()).await.unwrap();

            let bob_received = timeout(Duration::from_secs(1), bob_stream.recv())
                .await
                .unwrap()
                .unwrap();
            let charlie_received = timeout(Duration::from_secs(1), charlie_stream.recv())
                .await
                .unwrap()
                .unwrap();

            assert_eq!(bob_received, bob_msg.as_bytes());
            assert_eq!(charlie_received, charlie_msg.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_send_to_dropped_receiver() {
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
        let bob_stream = bob_incoming.recv().await.unwrap();

        alice_stream.send(b"first").await.unwrap();

        drop(bob_stream);

        tokio::time::sleep(Duration::from_millis(100)).await;

        alice_stream.send(b"second").await.unwrap();
        alice_stream.send(b"third").await.unwrap();
    }
}
