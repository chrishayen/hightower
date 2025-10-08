use hightower_wireguard::crypto::{PrivateKey, PublicKey25519, dh_generate};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey25519,
}

impl Keypair {
    pub fn generate() -> Self {
        let (private_key, public_key) = dh_generate();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_creates_valid_keypair() {
        let keypair = Keypair::generate();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn generate_produces_different_keys() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn private_key_hex_encodes_correctly() {
        let keypair = Keypair::generate();
        let hex = keypair.private_key_hex();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn public_key_hex_encodes_correctly() {
        let keypair = Keypair::generate();
        let hex = keypair.public_key_hex();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn keypair_generates_32_byte_keys() {
        let keypair = Keypair::generate();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key_hex().len(), 64);
        assert_eq!(keypair.public_key_hex().len(), 64);
    }
}
