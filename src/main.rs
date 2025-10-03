mod certificates;
mod cli;
mod kv;
mod logging;
mod mode;
mod node;
mod node_name;
mod shutdown;
mod token;

use clap::Parser;
use serde_json::to_vec;
use std::process;
use tracing::{error, info};

use crate::certificates::NodeCertificate;
use crate::cli::Cli;
use crate::mode::Mode;

const NODE_NAME_KEY: &[u8] = b"nodes/name";
const NODE_CERTIFICATE_KEY: &[u8] = b"certificates/node";
const HT_TOKEN_KEY: &[u8] = b"secrets/ht_token";

fn main() {
    let _logging_guard = logging::init();

    let cli = Cli::parse();
    let mode = mode::resolve(&cli);

    let token = token::fetch(|key| std::env::var(key)).unwrap_or_else(|err| {
        error!("{}", err);
        process::exit(1);
    });

    let kv = kv::initialize(cli.kv.as_deref()).unwrap_or_else(|err| {
        error!(?err, "Failed to initialize key-value store");
        process::exit(1);
    });

    persist_token(&kv, HT_TOKEN_KEY, &token);

    if let Mode::Node = mode {
        let node_name = node_name::generate();
        persist_node_name(&kv, NODE_NAME_KEY, &node_name);
        info!("Node identity established: {}", node_name);
        let certificate = node::startup();
        persist_certificate(&kv, NODE_CERTIFICATE_KEY, &certificate);
    } else {
        match kv.get_bytes(NODE_NAME_KEY) {
            Ok(Some(stored_name)) => match String::from_utf8(stored_name) {
                Ok(name) => info!("Node name available from KV: {}", name),
                Err(err) => info!(?err, "Node name in KV is not valid UTF-8"),
            },
            Ok(None) => info!("Node name not set"),
            Err(err) => info!(?err, "Failed to read node name from KV"),
        }
    }

    info!("Waiting for Ctrl-C to exit");
    match shutdown::wait_for_ctrl_c() {
        Ok(()) => info!("Shutdown signal received"),
        Err(err) => error!(?err, "Failed while waiting for shutdown signal"),
    }
}

fn persist_certificate(kv: &kv::KvHandle, key: &[u8], certificate: &NodeCertificate) {
    let payload = to_vec(certificate).unwrap_or_else(|err| {
        error!(?err, "Failed to serialize certificate");
        process::exit(1);
    });

    kv.put_bytes(key, &payload).unwrap_or_else(|err| {
        error!(?err, "Failed to store certificate");
        process::exit(1);
    });
}

fn persist_token(kv: &kv::KvHandle, key: &[u8], token: &str) {
    kv.put_secret(key, token.as_bytes());
}

fn persist_node_name(kv: &kv::KvHandle, key: &[u8], node_name: &str) {
    kv.put_bytes(key, node_name.as_bytes())
        .unwrap_or_else(|err| {
            error!(?err, "Failed to store node name");
            process::exit(1);
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn persist_certificate_writes_payload_to_kv() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let cert = NodeCertificate::from_keys([5u8; 32], [6u8; 32]);
        let key = b"certificates/test";

        persist_certificate(&kv, key, &cert);

        let stored = kv
            .get_bytes(key)
            .expect("kv read succeeded")
            .expect("value present");
        let decoded: NodeCertificate = serde_json::from_slice(&stored).expect("decode");
        assert_eq!(decoded, cert);
    }

    #[test]
    fn persist_token_writes_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let key = b"secrets/test_token";
        let token = "super-secret";

        persist_token(&kv, key, token);

        let stored = kv
            .get_bytes(key)
            .expect("kv read succeeded")
            .expect("value present");
        assert_eq!(stored, token.as_bytes());
    }

    #[test]
    fn persist_node_name_writes_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let key = b"nodes/test_name";
        let name = "ht-brave-tiger-abcde";

        persist_node_name(&kv, key, name);

        let stored = kv
            .get_bytes(key)
            .expect("kv read succeeded")
            .expect("value present");
        assert_eq!(stored, name.as_bytes());
    }
}
