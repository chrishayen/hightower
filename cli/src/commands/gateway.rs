use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

pub fn run_gateway(
    kv_path: Option<&Path>,
    email: Option<String>,
    http_host: IpAddr,
    http_port: u16,
    https: bool,
) -> Result<()> {
    let _logging_guard = gateway::logging::init();

    let context =
        gateway::context::initialize_with_token_source(kv_path, |key| std::env::var(key))?;

    let config = gateway::GatewayServerConfig {
        http_addr: SocketAddr::new(http_host, http_port),
        https_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443),
        https_disabled: !https,
        email,
    };

    gateway::start_with_config(&context, config.clone());

    // Wait for gateway to be ready
    if let Err(e) = gateway::wait_until_ready_at(config.readiness_addr(), Duration::from_secs(5)) {
        bail!("Failed to start gateway: {:?}", e);
    }
    println!("Gateway server ready at {}", config.http_url());

    wait_for_ctrl_c()?;

    Ok(())
}

fn wait_for_ctrl_c() -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;
    rx.recv().ok();
    Ok(())
}
