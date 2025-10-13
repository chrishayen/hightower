use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Trait for hashing and verifying secrets like passwords and API keys
pub trait SecretHasher: Send + Sync {
    /// Hashes a secret using a cryptographically secure algorithm
    fn hash_secret(&self, secret: &[u8]) -> Result<SecretHash>;
    /// Verifies a secret against a previously computed hash
    fn verify_secret(&self, secret: &[u8], hash: &SecretHash) -> Result<bool>;
}

/// A cryptographically secure hash of a secret
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHash(String);

impl SecretHash {
    /// Returns the hash as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretHash {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl AsRef<str> for SecretHash {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Secret hasher using the Argon2 algorithm
pub struct Argon2SecretHasher {
    argon2: Argon2<'static>,
}

impl Argon2SecretHasher {
    /// Creates a new Argon2 secret hasher with default settings
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }
}

impl Default for Argon2SecretHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretHasher for Argon2SecretHasher {
    fn hash_secret(&self, secret: &[u8]) -> Result<SecretHash> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .argon2
            .hash_password(secret, &salt)
            .map_err(|err| Error::Crypto(err.to_string()))?;
        Ok(SecretHash(hash.to_string()))
    }

    fn verify_secret(&self, secret: &[u8], hash: &SecretHash) -> Result<bool> {
        let parsed =
            PasswordHash::new(hash.as_str()).map_err(|err| Error::Crypto(err.to_string()))?;
        Ok(self.argon2.verify_password(secret, &parsed).is_ok())
    }
}

/// Trait for encrypting and decrypting data using envelope encryption
pub trait EnvelopeEncryptor: Send + Sync {
    /// Encrypts plaintext and returns an encrypted blob with nonce
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBlob>;
    /// Decrypts an encrypted blob and returns the plaintext
    fn decrypt(&self, blob: &EncryptedBlob) -> Result<Vec<u8>>;
}

/// An encrypted blob containing a nonce and ciphertext
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Random nonce used for encryption
    pub nonce: [u8; 12],
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
}

/// Encryptor using AES-256-GCM authenticated encryption
pub struct AesGcmEncryptor {
    cipher: Aes256Gcm,
}

impl AesGcmEncryptor {
    /// Creates a new AES-GCM encryptor with the provided 32-byte key
    pub fn new(key_bytes: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key_bytes)),
        }
    }

    /// Creates a new AES-GCM encryptor from a byte slice, returning an error if not exactly 32 bytes
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let key: [u8; 32] = slice
            .try_into()
            .map_err(|_| Error::Crypto("encryption key must be 32 bytes".into()))?;
        Ok(Self::new(key))
    }
}

impl EnvelopeEncryptor for AesGcmEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBlob> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|err| Error::Crypto(err.to_string()))?;
        Ok(EncryptedBlob {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    fn decrypt(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&blob.nonce);
        self.cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|err| Error::Crypto(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_round_trips() {
        let hasher = Argon2SecretHasher::default();
        let hash = hasher.hash_secret(b"secret").unwrap();
        assert!(hasher.verify_secret(b"secret", &hash).unwrap());
        assert!(!hasher.verify_secret(b"wrong", &hash).unwrap());
    }

    #[test]
    fn aes_gcm_encrypt_decrypt() {
        let encryptor = AesGcmEncryptor::new([42u8; 32]);
        let blob = encryptor.encrypt(b"payload").unwrap();
        let plaintext = encryptor.decrypt(&blob).unwrap();
        assert_eq!(plaintext, b"payload");
    }
}
