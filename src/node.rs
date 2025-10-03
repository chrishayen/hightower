use crate::certificates::{self, NodeCertificate};

pub fn startup() -> NodeCertificate {
    startup_with(certificates::generate)
}

fn startup_with<F>(generator: F) -> NodeCertificate
where
    F: Fn() -> NodeCertificate,
{
    generator()
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
}
