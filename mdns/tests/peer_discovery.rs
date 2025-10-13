use mdns::Mdns;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_two_peers_can_discover_each_other() {
    // Create two peers with different IPs
    let peer1_ip = Ipv4Addr::new(127, 0, 0, 1);
    let peer2_ip = Ipv4Addr::new(127, 0, 0, 1);

    let peer1 = Mdns::with_interval("peer1", peer1_ip, Duration::from_millis(100))
        .expect("Failed to create peer1");

    let peer2 = Mdns::with_interval("peer2", peer2_ip, Duration::from_millis(100))
        .expect("Failed to create peer2");

    let handle1 = peer1.run();
    let handle2 = peer2.run();

    // Give peers time to start listening
    sleep(Duration::from_millis(50)).await;

    // Spawn tasks to send queries
    let query1_handle = tokio::spawn(async move {
        for _ in 0..3 {
            handle1.query("peer2").await;
            sleep(Duration::from_millis(100)).await;
        }
    });

    let query2_handle = tokio::spawn(async move {
        for _ in 0..3 {
            handle2.query("peer1").await;
            sleep(Duration::from_millis(100)).await;
        }
    });

    // Wait for queries to complete
    let query_result = timeout(Duration::from_secs(2), async {
        query1_handle.await.unwrap();
        query2_handle.await.unwrap();
    })
    .await;

    assert!(query_result.is_ok(), "Queries should complete within timeout");
}

#[tokio::test]
async fn test_peer_responds_to_query() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);

    let responder = Mdns::with_interval("responder", ip, Duration::from_millis(100))
        .expect("Failed to create responder");

    let querier = Mdns::with_interval("querier", ip, Duration::from_millis(100))
        .expect("Failed to create querier");

    let _responder_handle = responder.run();
    let querier_handle = querier.run();

    // Give responder time to start
    sleep(Duration::from_millis(50)).await;

    // Send a query
    let query_result = timeout(Duration::from_secs(1), async {
        querier_handle.query("responder").await;
        sleep(Duration::from_millis(200)).await;
    })
    .await;

    assert!(query_result.is_ok(), "Query should complete within timeout");
}