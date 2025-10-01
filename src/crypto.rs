use crate::{Result, WireGuardError};
use blake2::digest::{FixedOutput, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

// Noise IK constants from WireGuard spec
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

// Key types for Noise IK
pub type PrivateKey = [u8; 32];
pub type PublicKey25519 = [u8; 32];

// DH(private_key, public_key) -> 32 bytes
pub fn dh(private_key: &PrivateKey, public_key: &PublicKey25519) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*public_key);
    secret.diffie_hellman(&public).to_bytes()
}

// DH-Generate() -> (private, public)
pub fn dh_generate() -> (PrivateKey, PublicKey25519) {
    let mut rng = rand::thread_rng();
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

// Hash(input) -> 32 bytes
pub fn hash(input: &[u8]) -> [u8; 32] {
    Blake2s256::digest(input).into()
}

// HMAC-BLAKE2s for KDF (32 byte output)
fn hmac_blake2s(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Blake2sMac::new_from_slice(key).unwrap();
    mac.update(input);
    let mut output = [0u8; 32];
    mac.finalize_into((&mut output).into());
    output
}

// Kdf1(chaining_key, input) -> 32 bytes
// This implements HKDF-BLAKE2s as per WireGuard spec
pub fn kdf1(chaining_key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    // HKDF-Extract: PRK = HMAC(salt=chaining_key, input)
    let prk = hmac_blake2s(chaining_key, input);
    // HKDF-Expand: T(1) = HMAC(PRK, info || 0x01)
    hmac_blake2s(&prk, &[1u8])
}

// Kdf2(chaining_key, input) -> (32 bytes, 32 bytes)
pub fn kdf2(chaining_key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    // HKDF-Extract: PRK = HMAC(salt=chaining_key, input)
    let prk = hmac_blake2s(chaining_key, input);
    // HKDF-Expand: T(1) = HMAC(PRK, info || 0x01), T(2) = HMAC(PRK, info || 0x02)
    let output1 = hmac_blake2s(&prk, &[1u8]);
    let output2 = hmac_blake2s(&prk, &[2u8]);
    (output1, output2)
}

// Aead(key, counter, plaintext, authtext) -> ciphertext
pub fn aead_encrypt(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WireGuardError::CryptoError("Invalid ChaCha20Poly1305 key".to_string()))?;

    // Nonce is 12 bytes: 4 zero bytes + 8 bytes little-endian counter
    let mut nonce_bytes = [0u8; 12];
    (&mut nonce_bytes[4..])
        .write_u64::<LittleEndian>(counter)
        .unwrap();
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: auth_data,
            },
        )
        .map_err(|_| WireGuardError::CryptoError("AEAD encryption failed".to_string()))
}

// Aead decrypt
pub fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WireGuardError::CryptoError("Invalid ChaCha20Poly1305 key".to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    (&mut nonce_bytes[4..])
        .write_u64::<LittleEndian>(counter)
        .unwrap();
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: auth_data,
            },
        )
        .map_err(|_| WireGuardError::AuthenticationFailed)
}

// TAI64N timestamp for replay protection
pub fn timestamp() -> [u8; 12] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let secs = now.as_secs();
    let nanos = now.subsec_nanos();

    let mut timestamp = [0u8; 12];
    // TAI64N format: 8 bytes seconds (big-endian) + 4 bytes nanoseconds (big-endian)
    (&mut timestamp[0..8]).write_u64::<BigEndian>(secs).unwrap();
    (&mut timestamp[8..12])
        .write_u32::<BigEndian>(nanos)
        .unwrap();
    timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_generate() {
        let (private1, public1) = dh_generate();
        let (private2, public2) = dh_generate();

        // Keys should be different
        assert_ne!(private1, private2);
        assert_ne!(public1, public2);

        // Keys should be 32 bytes
        assert_eq!(private1.len(), 32);
        assert_eq!(public1.len(), 32);
    }

    #[test]
    fn test_dh_key_exchange() {
        let (private1, public1) = dh_generate();
        let (private2, public2) = dh_generate();

        // Both parties should compute the same shared secret
        let shared1 = dh(&private1, &public2);
        let shared2 = dh(&private2, &public1);

        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32);
    }

    #[test]
    fn test_hash_consistency() {
        let input = b"test data";
        let hash1 = hash(input);
        let hash2 = hash(input);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different input should produce different hash
        let hash3 = hash(b"different data");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_kdf1() {
        let chaining_key = [1u8; 32];
        let input = b"test input";

        let output1 = kdf1(&chaining_key, input);
        let output2 = kdf1(&chaining_key, input);

        // Same inputs should produce same output
        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 32);

        // Different input should produce different output
        let output3 = kdf1(&chaining_key, b"different input");
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_kdf2() {
        let chaining_key = [2u8; 32];
        let input = b"test input";

        let (output1a, output1b) = kdf2(&chaining_key, input);
        let (output2a, output2b) = kdf2(&chaining_key, input);

        // Same inputs should produce same outputs
        assert_eq!(output1a, output2a);
        assert_eq!(output1b, output2b);

        // Two outputs should be different from each other
        assert_ne!(output1a, output1b);

        // Different input should produce different outputs
        let (output3a, output3b) = kdf2(&chaining_key, b"different input");
        assert_ne!(output1a, output3a);
        assert_ne!(output1b, output3b);
    }

    #[test]
    fn test_aead_encrypt_decrypt() {
        let key = [3u8; 32];
        let counter = 42;
        let plaintext = b"Hello, WireGuard!";
        let auth_data = b"additional data";

        // Encrypt
        let ciphertext = aead_encrypt(&key, counter, plaintext, auth_data).unwrap();

        // Ciphertext should be longer than plaintext (includes auth tag)
        assert!(ciphertext.len() > plaintext.len());

        // Decrypt
        let decrypted = aead_decrypt(&key, counter, &ciphertext, auth_data).unwrap();

        // Decrypted should match original plaintext
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_auth_failure() {
        let key = [4u8; 32];
        let counter = 123;
        let plaintext = b"secret message";
        let auth_data = b"auth data";

        let ciphertext = aead_encrypt(&key, counter, plaintext, auth_data).unwrap();

        // Wrong auth data should fail
        let result = aead_decrypt(&key, counter, &ciphertext, b"wrong auth data");
        assert!(result.is_err());

        // Wrong counter should fail
        let result = aead_decrypt(&key, counter + 1, &ciphertext, auth_data);
        assert!(result.is_err());

        // Wrong key should fail
        let wrong_key = [5u8; 32];
        let result = aead_decrypt(&wrong_key, counter, &ciphertext, auth_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_different_counters() {
        let key = [6u8; 32];
        let plaintext = b"test message";
        let auth_data = b"";

        let ciphertext1 = aead_encrypt(&key, 0, plaintext, auth_data).unwrap();
        let ciphertext2 = aead_encrypt(&key, 1, plaintext, auth_data).unwrap();

        // Different counters should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly with their respective counters
        let decrypted1 = aead_decrypt(&key, 0, &ciphertext1, auth_data).unwrap();
        let decrypted2 = aead_decrypt(&key, 1, &ciphertext2, auth_data).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_timestamp() {
        let ts1 = timestamp();
        let ts2 = timestamp();

        // Timestamps should be 12 bytes
        assert_eq!(ts1.len(), 12);
        assert_eq!(ts2.len(), 12);

        // Should be different (unless called at exact same nanosecond)
        // We'll just test that they're both non-zero
        assert_ne!(ts1, [0u8; 12]);
        assert_ne!(ts2, [0u8; 12]);
    }

    #[test]
    fn test_constants() {
        assert_eq!(CONSTRUCTION, b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        assert_eq!(IDENTIFIER, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
        assert_eq!(CONSTRUCTION.len(), 37);
        assert_eq!(IDENTIFIER.len(), 34);
    }

    #[test]
    fn test_noise_ik_compatibility() {
        // Test that our crypto functions work together in a basic Noise IK pattern

        // Initialize hash chain
        let mut h = hash(CONSTRUCTION);
        h = hash(&[h.as_slice(), IDENTIFIER].concat());

        // Generate static keys for both parties
        let (s_priv_i, _) = dh_generate();
        let (_, s_pub_r) = dh_generate();

        // Responder's public key is mixed into hash
        h = hash(&[h.as_slice(), &s_pub_r].concat());

        // Generate ephemeral key for initiator
        let (e_priv_i, e_pub_i) = dh_generate();

        // Mix ephemeral public key
        h = hash(&[h.as_slice(), &e_pub_i].concat());

        // Perform DH operations
        let dh1 = dh(&e_priv_i, &s_pub_r);
        let dh2 = dh(&s_priv_i, &s_pub_r);

        // Derive keys using HKDF
        let (c1, k1) = kdf2(&[0u8; 32], &dh1);
        let (_c2, _k2) = kdf2(&c1, &dh2);

        // Test encryption/decryption with derived keys
        let plaintext = b"test payload";
        let ciphertext = aead_encrypt(&k1, 0, plaintext, &h).unwrap();
        let decrypted = aead_decrypt(&k1, 0, &ciphertext, &h).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
