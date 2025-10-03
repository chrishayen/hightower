use hightower_wireguard::crypto::{dh_generate, PrivateKey, PublicKey25519};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCertificate {
    private_key: PrivateKey,
    public_key: PublicKey25519,
}

impl NodeCertificate {
    pub fn from_keys(private_key: PrivateKey, public_key: PublicKey25519) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn public_key(&self) -> &PublicKey25519 {
        &self.public_key
    }
}

pub fn generate() -> NodeCertificate {
    let (private_key, public_key) = dh_generate();
    NodeCertificate::from_keys(private_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_keys_stores_values() {
        let private_key = [1u8; 32];
        let public_key = [2u8; 32];

        let cert = NodeCertificate::from_keys(private_key, public_key);

        assert_eq!(cert.private_key(), &private_key);
        assert_eq!(cert.public_key(), &public_key);
    }

    #[test]
    fn generate_returns_random_keys() {
        let cert = generate();

        assert_eq!(cert.private_key().len(), 32);
        assert_eq!(cert.public_key().len(), 32);
        assert!(cert.private_key().iter().any(|byte| *byte != 0));
        assert!(cert.public_key().iter().any(|byte| *byte != 0));
    }
}
