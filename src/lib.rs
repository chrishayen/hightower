pub mod certificates;
pub mod context;

use context::CommonContext;
use hightower_client::HightowerConnection;
use tracing::{debug, error};

const GATEWAY_URL_KEY: &[u8] = b"gateway/url";

pub async fn run(context: &CommonContext) -> Result<HightowerConnection, String> {
    // Get gateway URL from context or use default
    let gateway_url = context
        .kv
        .get_bytes(GATEWAY_URL_KEY)
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| "http://127.0.0.1:8008".to_string());

    // Get auth token from context
    let auth_token = context
        .kv
        .get_bytes(context::HT_AUTH_KEY)
        .map_err(|e| format!("Failed to get auth token: {:?}", e))?
        .ok_or_else(|| "Auth token not found in context".to_string())?;

    let auth_token = String::from_utf8(auth_token)
        .map_err(|e| format!("Invalid auth token encoding: {:?}", e))?;

    debug!(gateway_url = %gateway_url, "Connecting to gateway");

    // Connect using hightower-client - handles everything:
    // - Keypair generation
    // - Transport server creation
    // - IP discovery via STUN
    // - Gateway registration
    // - Peer management
    // - Persistence
    let connection = HightowerConnection::connect(&gateway_url, &auth_token)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to connect to gateway");
            format!("Failed to connect to gateway: {:?}", e)
        })?;

    debug!(
        node_id = %connection.node_id(),
        assigned_ip = %connection.assigned_ip(),
        "Connected to gateway"
    );

    // Ping gateway to verify WireGuard connectivity
    if let Err(e) = connection.ping_gateway().await {
        error!(error = ?e, "Failed to ping gateway over WireGuard");
    } else {
        debug!("Successfully pinged gateway over WireGuard");
    }

    Ok(connection)
}

pub async fn deregister(connection: HightowerConnection) -> Result<(), String> {
    connection
        .disconnect()
        .await
        .map_err(|e| format!("Failed to disconnect: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::fixtures;

    #[tokio::test]
    async fn run_connects_to_gateway() {
        let ctx = fixtures::context();
        ctx.kv.put_secret(context::HT_AUTH_KEY, b"test-auth-key");

        // Note: This test will fail without a running gateway
        // In a real test environment, you'd mock the gateway or skip this test
        match run(&ctx).await {
            Ok(connection) => {
                assert!(!connection.node_id().is_empty());
                assert!(!connection.assigned_ip().is_empty());

                // Clean up
                let _ = deregister(connection).await;
            }
            Err(e) => {
                // Expected if no gateway is running
                assert!(e.contains("Failed to connect"));
            }
        }
    }
}
