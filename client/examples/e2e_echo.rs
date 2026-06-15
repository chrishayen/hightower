use hightower_client::HightowerConnection;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "listen".to_string());
    let auth_token = std::env::var("HT_AUTH_TOKEN")?;
    let gateway_url =
        std::env::var("HT_GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());

    match mode.as_str() {
        "listen" => listen(&gateway_url, &auth_token).await,
        "dial" => {
            let peer = std::env::var("PEER_ENDPOINT")?;
            dial(&gateway_url, &auth_token, &peer).await
        }
        other => Err(format!("unknown mode: {other}; use listen or dial").into()),
    }
}

async fn listen(gateway_url: &str, auth_token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let connection =
        Arc::new(HightowerConnection::connect_ephemeral(gateway_url, auth_token).await?);
    println!("E2E_ENDPOINT={}", connection.endpoint_id());
    println!("E2E_ASSIGNED_IP={}", connection.assigned_ip());

    let sync_connection = Arc::clone(&connection);
    tokio::spawn(async move {
        loop {
            match sync_connection.sync_pending_peers().await {
                Ok(count) if count > 0 => println!("E2E_SYNCED_PENDING={count}"),
                Ok(_) => {}
                Err(err) => eprintln!("E2E_SYNC_ERROR={err}"),
            }
            sleep(Duration::from_millis(100)).await;
        }
    });

    let mut incoming = connection.transport().connection().listen().await?;
    println!("E2E_LISTENING=1");

    let mut stream = timeout(Duration::from_secs(30), incoming.recv())
        .await?
        .ok_or("incoming stream channel closed")?;
    println!("E2E_ACCEPTED=1");

    let msg = timeout(Duration::from_secs(10), stream.recv()).await??;
    println!("E2E_RECEIVED={}", String::from_utf8_lossy(&msg));
    stream.send(b"pong-from-responder").await?;
    println!("E2E_SENT=pong-from-responder");

    sleep(Duration::from_millis(500)).await;
    println!("E2E_DONE=1");
    Ok(())
}

async fn dial(
    gateway_url: &str,
    auth_token: &str,
    peer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = HightowerConnection::connect_ephemeral(gateway_url, auth_token).await?;
    println!("E2E_ENDPOINT={}", connection.endpoint_id());
    println!("E2E_ASSIGNED_IP={}", connection.assigned_ip());

    let mut stream = timeout(Duration::from_secs(30), connection.dial(peer, 8080)).await??;
    println!("E2E_DIALED=1");
    stream.send(b"ping-from-initiator").await?;
    println!("E2E_SENT=ping-from-initiator");

    let response = timeout(Duration::from_secs(10), stream.recv()).await??;
    println!("E2E_RESPONSE={}", String::from_utf8_lossy(&response));

    connection.disconnect().await?;
    println!("E2E_DONE=1");
    Ok(())
}
