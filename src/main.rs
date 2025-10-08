use clap::Parser;
use gateway::context::initialize_with_token_source;
use gateway::logging;
use std::path::PathBuf;
use tracing::error;

#[derive(Parser, Debug)]
#[command(author, version, about = "Hightower Gateway", long_about = None)]
struct Cli {
    #[arg(long = "kv", value_name = "DIR", help = "Path to key-value store directory")]
    kv: Option<PathBuf>,
}

fn main() {
    let logging_guard = logging::init();
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        error!(?err, "Gateway error");
        drop(logging_guard);
        std::process::exit(1);
    }

    drop(logging_guard);
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let context = initialize_with_token_source(cli.kv.as_deref(), |key| std::env::var(key))?;

    gateway::start(&context);

    wait_for_ctrl_c()?;

    Ok(())
}

fn wait_for_ctrl_c() -> Result<(), ctrlc::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;
    rx.recv().ok();
    Ok(())
}
