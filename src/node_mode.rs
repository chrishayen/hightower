use crate::certificates::NodeCertificate;
use crate::common::{CommonContext, NODE_CERTIFICATE_KEY, NODE_NAME_KEY};
use crate::node;
use crate::node_name;
use tracing::info;

pub fn run(context: &CommonContext) {
    let node_name = node_name::generate();
    persist_node_name(context, &node_name);
    info!("Node identity established: {}", node_name);

    let certificate = node::startup();
    persist_certificate(context, &certificate);
}

fn persist_node_name(context: &CommonContext, name: &str) {
    context
        .kv
        .put_bytes(NODE_NAME_KEY, name.as_bytes())
        .unwrap_or_else(|err| {
            tracing::error!(?err, "Failed to store node name");
            std::process::exit(1);
        });
}

fn persist_certificate(context: &CommonContext, certificate: &NodeCertificate) {
    let payload = serde_json::to_vec(certificate).unwrap_or_else(|err| {
        tracing::error!(?err, "Failed to serialize certificate");
        std::process::exit(1);
    });

    context
        .kv
        .put_bytes(NODE_CERTIFICATE_KEY, &payload)
        .unwrap_or_else(|err| {
            tracing::error!(?err, "Failed to store certificate");
            std::process::exit(1);
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv;
    use tempfile::TempDir;

    fn context() -> CommonContext {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        CommonContext::new(kv)
    }

    #[test]
    fn run_persists_name_and_certificate() {
        let ctx = context();
        run(&ctx);

        let name = ctx
            .kv
            .get_bytes(NODE_NAME_KEY)
            .expect("kv read")
            .expect("value");
        let name = String::from_utf8(name).expect("utf-8");
        assert!(name.starts_with("ht-"));

        let cert_bytes = ctx
            .kv
            .get_bytes(NODE_CERTIFICATE_KEY)
            .expect("kv read")
            .expect("value");
        let certificate: NodeCertificate =
            serde_json::from_slice(&cert_bytes).expect("certificate deserializes");
        assert_eq!(certificate.public_key().len(), 32);
    }
}
