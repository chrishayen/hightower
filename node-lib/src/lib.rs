mod certificates;
mod node_impl;
mod node_name;

pub use certificates::NodeCertificate;

use hightower_context::{CommonContext, NODE_CERTIFICATE_KEY, NODE_NAME_KEY};
use hightower_root_web::{default_registrar, RootRegistrar};
use serde_json::to_vec;
use tracing::{debug, error};

pub fn run(context: &CommonContext) {
    let registrar = default_registrar();
    run_with_registrar(context, &registrar);
}

pub fn run_with_registrar<R>(context: &CommonContext, registrar: &R)
where
    R: RootRegistrar,
{
    let node_name = node_name::generate();
    persist_node_name(context, &node_name);
    debug!("Node running as {}", node_name);

    let certificate = node_impl::startup();
    persist_certificate(context, &certificate);

    if let Err(err) = registrar.register(context, &node_name, &certificate.public_key_hex()) {
        error!(?err, "Failed to register node with root");
        std::process::exit(1);
    }
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
    let payload = to_vec(certificate).unwrap_or_else(|err| {
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
    use hightower_context::{CommonContext, initialize_kv};
    use hightower_root_web::RootRegistrationError;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn context() -> CommonContext {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        CommonContext::new(kv)
    }

    #[test]
    fn run_persists_name_and_certificate() {
        let ctx = context();
        let registrar = RecordingRegistrar::default();
        run_with_registrar(&ctx, &registrar);

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

        let records = registrar.records.lock().expect("lock");
        assert_eq!(records.len(), 1);
        let (recorded_name, recorded_public_key) = &records[0];
        assert_eq!(recorded_name, &name);
        assert_eq!(recorded_public_key.len(), 64);
    }

    #[test]
    fn run_uses_namespace_prefix_when_present() {
        let base = context();
        let namespaced = base.namespaced(b"node");
        let registrar = RecordingRegistrar::default();

        run_with_registrar(&namespaced, &registrar);

        let stored = base
            .kv
            .get_bytes(b"node/nodes/name")
            .expect("kv read")
            .expect("value present");
        let stored = String::from_utf8(stored).expect("utf-8");
        assert!(stored.starts_with("ht-"));

        let unprefixed = base.kv.get_bytes(NODE_NAME_KEY).expect("kv read");
        assert!(unprefixed.is_none());

        let records = registrar.records.lock().expect("lock");
        assert_eq!(records.len(), 1);
        assert!(records[0].0.starts_with("ht-"));
    }

    #[derive(Default)]
    struct RecordingRegistrar {
        records: Mutex<Vec<(String, String)>>,
    }

    impl RootRegistrar for RecordingRegistrar {
        fn register(
            &self,
            _context: &CommonContext,
            node_name: &str,
            public_key_hex: &str,
        ) -> Result<(), RootRegistrationError> {
            self.records
                .lock()
                .expect("lock")
                .push((node_name.to_string(), public_key_hex.to_string()));
            Ok(())
        }
    }
}
