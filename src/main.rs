mod certificates;
mod cli;
mod logging;
mod mode;
mod node;
mod shutdown;
mod token;

use clap::Parser;
use tracing::{error, info};

use crate::cli::Cli;
use crate::mode::Mode;

fn main() {
    let _logging_guard = logging::init();

    let cli = Cli::parse();
    let mode = mode::resolve(&cli);

    token::fetch(|key| std::env::var(key)).unwrap_or_else(|err| {
        error!("{}", err);
        std::process::exit(1);
    });

    if let Mode::Node = mode {
        node::startup();
    }

    info!("Waiting for Ctrl-C to exit");
    match shutdown::wait_for_ctrl_c() {
        Ok(()) => info!("Shutdown signal received"),
        Err(err) => error!(?err, "Failed while waiting for shutdown signal"),
    }
}
