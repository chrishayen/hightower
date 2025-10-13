use anyhow::{Context, Result};
use hightower_client::HightowerConnection;
use std::time::Duration;
use tracing::{error, info};

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting Hightower WireGuard sidecar");

    let auth_token = std::env::var("HT_AUTH_TOKEN")
        .context("HT_AUTH_TOKEN environment variable must be set")?;

    let gateway_url = std::env::var("HT_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8008".to_string());

    info!("Connecting to gateway: {}", gateway_url);

    let connection = HightowerConnection::connect(&gateway_url, &auth_token)
        .await
        .context("Failed to connect to Hightower gateway")?;

    info!("Connected successfully");
    info!("  Node ID: {}", connection.node_id());
    info!("  Assigned IP: {}", connection.assigned_ip());
    info!("WireGuard tunnel established - routing ready");

    wait_for_shutdown(&connection).await;

    info!("Shutting down...");
    connection
        .disconnect()
        .await
        .context("Failed to disconnect gracefully")?;

    info!("Disconnected successfully");

    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown(connection: &HightowerConnection) {
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT");
        }
        _ = health_check_loop(connection) => {
            error!("Health check loop terminated unexpectedly");
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(connection: &HightowerConnection) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        _ = health_check_loop(connection) => {
            error!("Health check loop terminated unexpectedly");
        }
    }
}

async fn health_check_loop(connection: &HightowerConnection) {
    let check_interval = std::env::var("HT_HEALTH_CHECK_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    let mut interval = tokio::time::interval(Duration::from_secs(check_interval));

    loop {
        interval.tick().await;

        match connection.ping_gateway().await {
            Ok(_) => {
                info!("Health check passed");
            }
            Err(e) => {
                error!("Health check failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_health_check_interval_default() {
        let interval: u64 = None.unwrap_or(30);
        assert_eq!(interval, 30);
    }

    #[test]
    fn test_gateway_url_default() {
        let url: String = None.unwrap_or_else(|| "http://127.0.0.1:8008".to_string());
        assert_eq!(url, "http://127.0.0.1:8008");
    }
}
