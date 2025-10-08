use hightower_wireguard::crypto::{PrivateKey, PublicKey25519, dh_generate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCertificate {
    #[serde(with = "serde_bytes")]
    private_key: PrivateKey,
    #[serde(with = "serde_bytes")]
    public_key: PublicKey25519,
}

impl NodeCertificate {
    pub fn from_keys(private_key: PrivateKey, public_key: PublicKey25519) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn public_key(&self) -> &PublicKey25519 {
        &self.public_key
    }

    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
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
    fn private_key_hex_encodes_key() {
        let private_key = [0xAAu8; 32];
        let public_key = [0u8; 32];
        let cert = NodeCertificate::from_keys(private_key, public_key);

        assert_eq!(
            cert.private_key_hex(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn public_key_hex_encodes_key() {
        let private_key = [0u8; 32];
        let public_key = [0xBBu8; 32];
        let cert = NodeCertificate::from_keys(private_key, public_key);

        assert_eq!(
            cert.public_key_hex(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn generate_returns_random_keys() {
        let cert = generate();

        assert_eq!(cert.private_key().len(), 32);
        assert_eq!(cert.public_key().len(), 32);
        assert_eq!(cert.private_key_hex().len(), 64);
        assert_eq!(cert.public_key_hex().len(), 64);
    }

    #[test]
    fn serde_round_trip_preserves_data() {
        let cert = NodeCertificate::from_keys([3u8; 32], [4u8; 32]);
        let bytes = serde_json::to_vec(&cert).expect("serialize");
        let decoded: NodeCertificate = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, cert);
    }
}
