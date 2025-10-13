use crate::crypto::{
    CONSTRUCTION, IDENTIFIER, PrivateKey, PublicKey25519, aead_decrypt, aead_encrypt, dh,
    dh_generate, hash, kdf1, kdf2,
};
use crate::initiator::SessionKeys;
use crate::messages::{
    HandshakeInitiation, HandshakeResponse, MESSAGE_HANDSHAKE_INITIATION,
    MESSAGE_HANDSHAKE_RESPONSE,
};
use crate::{Result, WireGuardError};

/// Responder state for Noise IK handshake
#[derive(Debug)]
pub struct ResponderState {
    // Crypto state
    chaining_key: [u8; 32],
    hash: [u8; 32],

    // Keys
    local_static_private: PrivateKey,
    local_ephemeral_private: Option<PrivateKey>,
    remote_static_public: Option<PublicKey25519>, // Discovered from initiation
    remote_ephemeral_public: Option<PublicKey25519>, // From initiation

    // Optional PSK
    preshared_key: Option<[u8; 32]>,

    // State tracking
    initiation_processed: bool,
}

impl ResponderState {
    /// Create new responder state
    pub fn new(local_static_private: PrivateKey, preshared_key: Option<[u8; 32]>) -> Self {
        // Initialize Noise IK hash chain (responder's perspective)
        // This should match what initiator does in new()
        let chaining_key = hash(CONSTRUCTION);
        let mut h = hash(&[chaining_key.as_slice(), IDENTIFIER].concat());

        // Mix responder's static public key (same as what initiator does with remote_static_public)
        let local_static_public = {
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(local_static_private);
            PublicKey::from(&secret).to_bytes()
        };
        h = hash(&[h.as_slice(), &local_static_public].concat());

        Self {
            chaining_key,
            hash: h,
            local_static_private,
            local_ephemeral_private: None,
            remote_static_public: None,
            remote_ephemeral_public: None,
            preshared_key,
            initiation_processed: false,
        }
    }

    /// Process handshake initiation message and return the peer's public key
    pub fn process_initiation(&mut self, msg: &HandshakeInitiation) -> Result<PublicKey25519> {
        if self.initiation_processed {
            return Err(WireGuardError::ProtocolError(
                "Initiation already processed".to_string(),
            ));
        }

        if msg.message_type != MESSAGE_HANDSHAKE_INITIATION {
            return Err(WireGuardError::ProtocolError(
                "Invalid message type".to_string(),
            ));
        }

        // Validate encrypted payload lengths
        if msg.static_encrypted.len() != 48 {
            // 32 + 16 auth tag
            return Err(WireGuardError::ProtocolError(
                "Invalid static encrypted length".to_string(),
            ));
        }
        if msg.timestamp_encrypted.len() != 28 {
            // 12 + 16 auth tag
            return Err(WireGuardError::ProtocolError(
                "Invalid timestamp encrypted length".to_string(),
            ));
        }

        // Store remote ephemeral key and mix into hash chain
        self.remote_ephemeral_public = Some(msg.ephemeral);
        self.chaining_key = kdf1(&self.chaining_key, &msg.ephemeral);
        self.hash = hash(&[self.hash.as_slice(), &msg.ephemeral].concat());

        // Perform DH(local_static_private, remote_ephemeral_public) -> "es"
        let dh_es = dh(&self.local_static_private, &msg.ephemeral);
        let (chaining_key, temp_key1) = kdf2(&self.chaining_key, &dh_es);
        self.chaining_key = chaining_key;

        // Decrypt remote static public key
        let remote_static_decrypted =
            aead_decrypt(&temp_key1, 0, &msg.static_encrypted, &self.hash)?;
        if remote_static_decrypted.len() != 32 {
            return Err(WireGuardError::ProtocolError(
                "Invalid decrypted static key length".to_string(),
            ));
        }

        let mut remote_static_public = [0u8; 32];
        remote_static_public.copy_from_slice(&remote_static_decrypted);
        self.remote_static_public = Some(remote_static_public);
        self.hash = hash(&[self.hash.as_slice(), &msg.static_encrypted].concat());

        // Perform DH(local_static_private, remote_static_public) -> "ss"
        let dh_ss = dh(&self.local_static_private, &remote_static_public);
        let (chaining_key, temp_key2) = kdf2(&self.chaining_key, &dh_ss);
        self.chaining_key = chaining_key;

        // Decrypt and verify timestamp
        let timestamp_decrypted =
            aead_decrypt(&temp_key2, 0, &msg.timestamp_encrypted, &self.hash)?;
        if timestamp_decrypted.len() != 12 {
            return Err(WireGuardError::ProtocolError(
                "Invalid decrypted timestamp length".to_string(),
            ));
        }
        self.hash = hash(&[self.hash.as_slice(), &msg.timestamp_encrypted].concat());

        // TODO: Verify timestamp for replay protection
        // For now, we just validate the format

        self.initiation_processed = true;
        Ok(remote_static_public)
    }

    /// Create handshake response message (second message of Noise IK)
    pub fn create_response(&mut self, initiation_sender: u32) -> Result<HandshakeResponse> {
        if !self.initiation_processed {
            return Err(WireGuardError::ProtocolError(
                "Must process initiation first".to_string(),
            ));
        }

        let remote_ephemeral = self.remote_ephemeral_public.ok_or_else(|| {
            WireGuardError::ProtocolError("Missing remote ephemeral key".to_string())
        })?;
        let remote_static = self.remote_static_public.ok_or_else(|| {
            WireGuardError::ProtocolError("Missing remote static key".to_string())
        })?;

        // Generate our ephemeral key pair
        let (ephemeral_private, ephemeral_public) = dh_generate();
        self.local_ephemeral_private = Some(ephemeral_private);

        // Mix our ephemeral public key into hash
        self.chaining_key = kdf1(&self.chaining_key, &ephemeral_public);
        self.hash = hash(&[self.hash.as_slice(), &ephemeral_public].concat());

        // Perform DH(local_ephemeral_private, remote_ephemeral_public) -> "ee"
        let dh_ee = dh(&ephemeral_private, &remote_ephemeral);
        self.chaining_key = kdf1(&self.chaining_key, &dh_ee);

        // Perform DH(local_ephemeral_private, remote_static_public) -> "se"
        let dh_se = dh(&ephemeral_private, &remote_static);
        self.chaining_key = kdf1(&self.chaining_key, &dh_se);

        // Mix preshared key if present
        if let Some(psk) = self.preshared_key {
            // For PSK, we need a 3-output KDF. Since we only have KDF2, we'll do it manually
            let temp_key = kdf1(&self.chaining_key, &psk);
            let (chaining_key, temp_key2) = kdf2(&temp_key, &[]);
            self.chaining_key = chaining_key;
            self.hash = hash(&[self.hash.as_slice(), &temp_key2].concat());
        }

        // Derive key for encrypting empty payload
        let (chaining_key, temp_key) = kdf2(&self.chaining_key, &[]);
        self.chaining_key = chaining_key;

        // Encrypt empty payload
        let empty_encrypted = aead_encrypt(&temp_key, 0, &[], &self.hash)?;
        self.hash = hash(&[self.hash.as_slice(), &empty_encrypted].concat());

        Ok(HandshakeResponse {
            message_type: MESSAGE_HANDSHAKE_RESPONSE,
            reserved: [0; 3],
            sender: rand::random::<u32>(), // TODO: Should be managed by protocol layer
            receiver: initiation_sender,
            ephemeral: ephemeral_public,
            empty_encrypted,
            mac1: [0; 16], // TODO: Implement proper MAC calculation
            mac2: [0; 16], // TODO: Implement proper MAC calculation
        })
    }

    /// Derive session keys after successful handshake
    pub fn derive_keys(&self) -> Result<SessionKeys> {
        if !self.initiation_processed {
            return Err(WireGuardError::ProtocolError(
                "Handshake not completed".to_string(),
            ));
        }

        // Derive final transport keys (responder has swapped keys)
        let (recv_key, send_key) = kdf2(&self.chaining_key, &[]);

        Ok(SessionKeys { send_key, recv_key })
    }
}
