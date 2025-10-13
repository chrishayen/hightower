use crate::crypto::{
    CONSTRUCTION, IDENTIFIER, PrivateKey, PublicKey25519, aead_decrypt, aead_encrypt, dh,
    dh_generate, hash, kdf1, kdf2, timestamp,
};
use crate::messages::{
    HandshakeInitiation, HandshakeResponse, MESSAGE_HANDSHAKE_INITIATION,
    MESSAGE_HANDSHAKE_RESPONSE,
};
use crate::{Result, WireGuardError};

/// Transport keys derived after successful handshake completion
///
/// Contains separate keys for sending and receiving encrypted data
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

/// Initiator state for Noise IK handshake
#[derive(Debug)]
pub struct InitiatorState {
    // Crypto state
    chaining_key: [u8; 32],
    hash: [u8; 32],

    // Keys
    local_static_private: PrivateKey,
    local_ephemeral_private: Option<PrivateKey>,
    remote_static_public: PublicKey25519,

    // Optional PSK
    preshared_key: Option<[u8; 32]>,

    // State tracking
    initiation_sent: bool,
}

impl InitiatorState {
    /// Create new initiator state
    pub fn new(
        local_static_private: PrivateKey,
        remote_static_public: PublicKey25519,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        // Initialize Noise IK hash chain
        let chaining_key = hash(CONSTRUCTION);
        let mut h = hash(&[chaining_key.as_slice(), IDENTIFIER].concat());
        h = hash(&[h.as_slice(), &remote_static_public].concat());

        Self {
            chaining_key,
            hash: h,
            local_static_private,
            local_ephemeral_private: None,
            remote_static_public,
            preshared_key,
            initiation_sent: false,
        }
    }

    /// Create handshake initiation message (first message of Noise IK)
    pub fn create_initiation(&mut self) -> Result<HandshakeInitiation> {
        if self.initiation_sent {
            return Err(WireGuardError::ProtocolError(
                "Initiation already sent".to_string(),
            ));
        }

        // Generate ephemeral key pair
        let (ephemeral_private, ephemeral_public) = dh_generate();
        self.local_ephemeral_private = Some(ephemeral_private);

        // Mix ephemeral public key into hash chain
        self.chaining_key = kdf1(&self.chaining_key, &ephemeral_public);
        self.hash = hash(&[self.hash.as_slice(), &ephemeral_public].concat());

        // Perform DH(ephemeral_private, remote_static_public) -> "es"
        let dh_es = dh(&ephemeral_private, &self.remote_static_public);
        let (chaining_key, temp_key1) = kdf2(&self.chaining_key, &dh_es);
        self.chaining_key = chaining_key;

        // Encrypt our static public key
        let local_static_public = self.derive_public_key()?;
        let static_encrypted = aead_encrypt(&temp_key1, 0, &local_static_public, &self.hash)?;
        self.hash = hash(&[self.hash.as_slice(), &static_encrypted].concat());

        // Perform DH(local_static_private, remote_static_public) -> "ss"
        let dh_ss = dh(&self.local_static_private, &self.remote_static_public);
        let (chaining_key, temp_key2) = kdf2(&self.chaining_key, &dh_ss);
        self.chaining_key = chaining_key;

        // Encrypt timestamp for replay protection
        let ts = timestamp();
        let timestamp_encrypted = aead_encrypt(&temp_key2, 0, &ts, &self.hash)?;
        self.hash = hash(&[self.hash.as_slice(), &timestamp_encrypted].concat());

        self.initiation_sent = true;

        Ok(HandshakeInitiation {
            message_type: MESSAGE_HANDSHAKE_INITIATION,
            reserved: [0; 3],
            sender: rand::random::<u32>(), // TODO: Should be managed by protocol layer
            ephemeral: ephemeral_public,
            static_encrypted,
            timestamp_encrypted,
            mac1: [0; 16], // TODO: Implement proper MAC calculation
            mac2: [0; 16], // TODO: Implement proper MAC calculation
        })
    }

    /// Process handshake response message (second message of Noise IK)
    pub fn process_response(&mut self, response: &HandshakeResponse) -> Result<SessionKeys> {
        if !self.initiation_sent {
            return Err(WireGuardError::ProtocolError(
                "No initiation sent yet".to_string(),
            ));
        }

        if response.message_type != MESSAGE_HANDSHAKE_RESPONSE {
            return Err(WireGuardError::ProtocolError(
                "Invalid message type".to_string(),
            ));
        }

        let local_ephemeral_private = self.local_ephemeral_private.ok_or_else(|| {
            WireGuardError::ProtocolError("Missing ephemeral private key".to_string())
        })?;

        // Mix responder's ephemeral public key
        self.chaining_key = kdf1(&self.chaining_key, &response.ephemeral);
        self.hash = hash(&[self.hash.as_slice(), &response.ephemeral].concat());

        // Perform DH(local_ephemeral_private, remote_ephemeral_public) -> "ee"
        let dh_ee = dh(&local_ephemeral_private, &response.ephemeral);
        self.chaining_key = kdf1(&self.chaining_key, &dh_ee);

        // Perform DH(local_static_private, remote_ephemeral_public) -> "se"
        let dh_se = dh(&self.local_static_private, &response.ephemeral);
        self.chaining_key = kdf1(&self.chaining_key, &dh_se);

        // Mix preshared key if present
        if let Some(psk) = self.preshared_key {
            // For PSK, we need a 3-output KDF. Since we only have KDF2, we'll do it manually
            // This follows the WireGuard spec for PSK integration
            let temp_key = kdf1(&self.chaining_key, &psk);
            let (chaining_key, temp_key2) = kdf2(&temp_key, &[]);
            self.chaining_key = chaining_key;
            self.hash = hash(&[self.hash.as_slice(), &temp_key2].concat());
        }

        // Derive key for decrypting the empty payload
        let (chaining_key, temp_key) = kdf2(&self.chaining_key, &[]);
        self.chaining_key = chaining_key;

        // Decrypt and verify empty payload
        let empty_decrypted = aead_decrypt(&temp_key, 0, &response.empty_encrypted, &self.hash)?;
        if !empty_decrypted.is_empty() {
            return Err(WireGuardError::ProtocolError(
                "Expected empty payload".to_string(),
            ));
        }
        self.hash = hash(&[self.hash.as_slice(), &response.empty_encrypted].concat());

        // Derive final transport keys
        let (send_key, recv_key) = kdf2(&self.chaining_key, &[]);

        Ok(SessionKeys { send_key, recv_key })
    }

    /// Get the remote peer's public key
    pub fn remote_static_public(&self) -> PublicKey25519 {
        self.remote_static_public
    }

    /// Derive public key from private key
    fn derive_public_key(&self) -> Result<PublicKey25519> {
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(self.local_static_private);
        let public = PublicKey::from(&secret);
        Ok(public.to_bytes())
    }
}
