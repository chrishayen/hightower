use crate::certificates::NodeCertificate;
use crate::context::{CommonContext, NamespacedKv, GATEWAY_CERTIFICATE_KEY};
use super::types::RootApiError;

pub(crate) fn persist_certificate(context: &CommonContext, certificate: &NodeCertificate) {
    let payload = serde_json::to_vec(certificate).unwrap_or_else(|err| {
        tracing::error!(?err, "Failed to serialize gateway certificate");
        std::process::exit(1);
    });

    context
        .kv
        .put_bytes(GATEWAY_CERTIFICATE_KEY, &payload)
        .unwrap_or_else(|err| {
            tracing::error!(?err, "Failed to store gateway certificate");
            std::process::exit(1);
        });
}

pub(crate) fn load_gateway_public_key(kv: &NamespacedKv) -> Result<String, RootApiError> {
    let cert_bytes = kv
        .get_bytes(GATEWAY_CERTIFICATE_KEY)
        .map_err(|err| {
            RootApiError::Internal(format!("failed to read gateway certificate: {}", err))
        })?
        .ok_or_else(|| {
            RootApiError::Internal("gateway certificate not found in storage".to_string())
        })?;

    let certificate: NodeCertificate = serde_json::from_slice(&cert_bytes).map_err(|err| {
        RootApiError::Internal(format!("failed to deserialize gateway certificate: {}", err))
    })?;

    Ok(certificate.public_key_hex())
}
