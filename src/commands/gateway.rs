use anyhow::{Result, bail};
use std::time::Duration;

pub fn run_gateway() -> Result<()> {
    let _logging_guard = gateway::logging::init();

    let context = gateway::context::initialize_with_token_source(
        None,
        |key| std::env::var(key)
    )?;

    gateway::start(&context);

    // Wait for gateway to be ready
    if let Err(e) = gateway::wait_until_ready(Duration::from_secs(5)) {
        bail!("Failed to start gateway: {:?}", e);
    }
    println!("Gateway server ready on 0.0.0.0:8008");

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
