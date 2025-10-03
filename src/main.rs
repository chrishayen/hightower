mod certificates;
mod cli;
mod logging;
mod mode;
mod node;
mod token;

use clap::Parser;
use tracing::{error, info};

use crate::cli::Cli;
use crate::mode::Mode;

fn main() {
    let _logging_guard = logging::init();

    let cli = Cli::parse();
    let mode = mode::resolve(&cli);

    let token = token::fetch(|key| std::env::var(key)).unwrap_or_else(|err| {
        error!("{}", err);
        std::process::exit(1);
    });

    info!("HT token available");

    match mode {
        Mode::Root => info!("Running in root mode"),
        Mode::Node => {
            let certificate = node::startup();
            info!(
                public_key_length = certificate.public_key().len(),
                "Running in node mode"
            );
        }
    }

    drop(token);
}
