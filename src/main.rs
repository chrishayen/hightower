mod certificates;
mod cli;
mod common;
mod kv;
mod logging;
mod mode;
mod node;
mod node_name;
mod node_startup;
mod root_startup;
mod shutdown;
mod token;

use clap::Parser;
use std::process;
use tracing::{error, info};

use crate::cli::Cli;
use crate::common::{CommonContext, HT_TOKEN_KEY};
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
        Mode::Node => node_startup::run(context),
        Mode::Root => root_startup::run(context),
        Mode::Dev => run_dev_mode(context),
    }
}

fn run_dev_mode(base_context: &CommonContext) {
    let node_context = base_context.namespaced(b"node");
    let root_context = base_context.namespaced(b"root");

    replicate_token(base_context, &node_context);
    replicate_token(base_context, &root_context);

    node_startup::run(&node_context);
    root_startup::run(&root_context);
}

fn replicate_token(source: &CommonContext, target: &CommonContext) {
    match source.kv.get_bytes(HT_TOKEN_KEY) {
        Ok(Some(token)) => target.kv.put_secret(HT_TOKEN_KEY, &token),
        Ok(None) => tracing::warn!("HT token missing; skipping namespace propagation"),
        Err(err) => tracing::error!(?err, "Failed to read HT token for namespace propagation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::NodeCertificate;
    use crate::common::NODE_CERTIFICATE_KEY;
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

    #[test]
    fn route_invokes_dev_mode_with_prefixed_keys() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        context.kv.put_secret(HT_TOKEN_KEY, b"test-token");

        route(Mode::Dev, &context);

        let name_bytes = context
            .kv
            .get_bytes(b"node/nodes/name")
            .expect("kv read")
            .expect("value present");
        let name = String::from_utf8(name_bytes).expect("utf-8");
        assert!(name.starts_with("ht-"));

        let unprefixed = context
            .kv
            .get_bytes(crate::common::NODE_NAME_KEY)
            .expect("kv read");
        assert!(unprefixed.is_none());

        let certificate_bytes = context
            .kv
            .get_bytes(b"node/certificates/node")
            .expect("kv read")
            .expect("value present");
        let certificate: NodeCertificate =
            serde_json::from_slice(&certificate_bytes).expect("certificate");
        assert_eq!(certificate.public_key().len(), 32);

        let unprefixed_certificate = context.kv.get_bytes(NODE_CERTIFICATE_KEY).expect("kv read");
        assert!(unprefixed_certificate.is_none());

        let node_token = context
            .kv
            .get_bytes(b"node/secrets/ht_token")
            .expect("kv read")
            .expect("node token present");
        assert_eq!(node_token, b"test-token");

        let root_token = context
            .kv
            .get_bytes(b"root/secrets/ht_token")
            .expect("kv read")
            .expect("root token present");
        assert_eq!(root_token, b"test-token");
    }
}
