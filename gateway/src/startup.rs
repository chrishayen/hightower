use crate::certificates::{self, NodeCertificate};
use tracing::debug;

pub fn startup() -> NodeCertificate {
    startup_with(certificates::generate)
}

fn startup_with<F>(generator: F) -> NodeCertificate
where
    F: Fn() -> NodeCertificate,
{
    let certificate = generator();
    let (public_summary, private_summary) = certificate_debug_fields(&certificate);
    debug!(public_key = %public_summary, "Generated gateway certificate public key");
    debug!(private_key = %private_summary, "Generated gateway certificate private key");
    certificate
}

fn certificate_debug_fields(certificate: &NodeCertificate) -> (String, String) {
    (
        summarize_hex(&certificate.public_key_hex()),
        summarize_hex(&certificate.private_key_hex()),
    )
}

fn summarize_hex(hex: &str) -> String {
    if hex.len() <= 12 {
        hex.to_string()
    } else {
        format!("{}..{}", &hex[..6], &hex[hex.len() - 6..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_certificate() -> NodeCertificate {
        NodeCertificate::from_keys([1u8; 32], [2u8; 32])
    }

    #[test]
    fn startup_returns_generated_certificate() {
        let cert = startup_with(fixed_certificate);

        assert_eq!(cert.public_key(), &[2u8; 32]);
    }

    #[test]
    fn startup_uses_default_generator() {
        let cert = startup();

        assert_eq!(cert.private_key().len(), 32);
    }

    #[test]
    fn certificate_debug_fields_returns_summary_strings() {
        let cert = fixed_certificate();
        let (public_summary, private_summary) = certificate_debug_fields(&cert);

        assert_eq!(public_summary, "020202..020202");
        assert_eq!(private_summary, "010101..010101");
    }

    #[test]
    fn summarize_hex_truncates_long_values() {
        let summary = summarize_hex("abcdef1234567890");

        assert_eq!(summary, "abcdef..567890");
    }

    #[test]
    fn summarize_hex_returns_short_values_untouched() {
        let summary = summarize_hex("abcdef");

        assert_eq!(summary, "abcdef");
    }
}
