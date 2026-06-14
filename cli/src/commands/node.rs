use anyhow::{anyhow, Context, Result};
use std::path::Path;

pub async fn run_node(kv_path: Option<&Path>) -> Result<()> {
    let context = node::context::initialize_with_token_source(kv_path, |key| std::env::var(key))
        .context("Failed to initialize node context")?;

    let connection = node::run(&context)
        .await
        .map_err(|err| anyhow!(err))
        .context("Failed to start node")?;

    println!(
        "Node connected as {} ({})",
        connection.endpoint_id(),
        connection.assigned_ip()
    );

    tokio::signal::ctrl_c()
        .await
        .context("Failed to wait for Ctrl-C")?;

    node::deregister(connection)
        .await
        .map_err(|err| anyhow!(err))
        .context("Failed to deregister node")?;

    Ok(())
}
