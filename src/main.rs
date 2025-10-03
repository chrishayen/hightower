mod certificates;
mod cli;
mod common;
mod kv;
mod logging;
mod mode;
mod node;
mod node_mode;
mod node_name;
mod root_mode;
mod shutdown;
mod token;

use clap::Parser;
use std::process;
use tracing::{error, info};

use crate::cli::Cli;
use crate::common::CommonContext;
use crate::mode::Mode;

fn main() {
    let _logging_guard = logging::init();

    let cli = Cli::parse();
    let mode = mode::resolve(&cli);

    let context = crate::common::prepare(&cli).unwrap_or_else(|err| {
        error!(?err, "Startup failed");
        process::exit(1);
    });

    route(mode, &context);

    info!("Waiting for Ctrl-C to exit");
    match shutdown::wait_for_ctrl_c() {
        Ok(()) => info!("Shutdown signal received"),
        Err(err) => error!(?err, "Failed while waiting for shutdown signal"),
    }
}

fn route(mode: Mode, context: &CommonContext) {
    match mode {
        Mode::Node => node_mode::run(context),
        Mode::Root => root_mode::run(context),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn route_invokes_node_mode() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        route(Mode::Node, &context);
        let stored = context
            .kv
            .get_bytes(crate::common::NODE_NAME_KEY)
            .expect("kv read");
        assert!(stored.is_some());
    }

    #[test]
    fn route_invokes_root_mode() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        route(Mode::Root, &context);
        // No assertions; verifying it doesn't panic is sufficient.
    }
}
