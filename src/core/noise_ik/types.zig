//! Core types and constants for Noise_IK protocol implementation.
//!
//! The Noise_IK pattern provides mutual authentication with the initiator
//! knowing the responder's static public key in advance. Uses X25519 for
//! key agreement, ChaCha20-Poly1305 for encryption, and SHA256 for hashing.

const std = @import("std");
const mem = std.mem;

/// Length of X25519 keys in bytes (32 bytes)
pub const key_len = 32;

/// Length of ChaCha20-Poly1305 authentication tag in bytes (16 bytes)
pub const mac_len = 16;

/// Length of SHA256 hash output in bytes (32 bytes)
pub const hash_len = 32;

/// Long-term static keypair for identity authentication
pub const StaticKey = struct {
    public: [key_len]u8,
    secret: [key_len]u8,
};

/// Ephemeral keypair used for a single handshake session
pub const EphemeralKey = struct {
    public: [key_len]u8,
    secret: [key_len]u8,
};

/// State for ChaCha20-Poly1305 AEAD encryption
pub const CipherState = struct {
    key: [key_len]u8,
    nonce: u64,

    /// Initialize cipher state with a key and nonce set to 0
    pub fn init(key: [key_len]u8) CipherState {
        return .{
            .key = key,
            .nonce = 0,
        };
    }

    /// Check if this cipher has a non-zero key
    pub fn hasKey(self: CipherState) bool {
        const zero_key = [_]u8{0} ** key_len;
        return !mem.eql(u8, &self.key, &zero_key);
    }
};

/// Symmetric cryptographic state for the Noise protocol
pub const SymmetricState = struct {
    chaining_key: [hash_len]u8,
    hash: [hash_len]u8,
    cipher: CipherState,
};

/// Complete state for a Noise_IK handshake
pub const HandshakeState = struct {
    symmetric: SymmetricState,
    static_key: StaticKey,
    ephemeral_key: ?EphemeralKey,
    remote_static_key: ?[key_len]u8,
    remote_ephemeral_key: ?[key_len]u8,
    is_initiator: bool,
};
