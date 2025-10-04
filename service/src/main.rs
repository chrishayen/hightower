use clap::Parser;
use hightower_service::{run, Cli};
use tracing::error;

fn main() {
    let logging_guard = hightower_logging::init();
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        error!(?err, "Application error");
        drop(logging_guard);
        std::process::exit(1);
    }

    drop(logging_guard);
}
