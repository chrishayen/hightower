pub mod context;

use context::CommonContext;
use client::HightowerConnection;
use tracing::{debug, error};

pub async fn run(context: &CommonContext) -> Result<HightowerConnection, String> {
    // Get gateway URL from context or use default
    let gateway_url = context
        .kv
        .get_bytes(context::GATEWAY_URL_KEY)
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
        node_id = %connection.endpoint_id(),
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
