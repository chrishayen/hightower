//! Symmetric state management for Noise_IK handshake protocol.
//!
//! Manages the cryptographic state during handshake including hash chains,
//! key derivation, and the transition from handshake to transport mode.

const std = @import("std");
const crypto = std.crypto;
const types = @import("types.zig");
const crypto_ops = @import("crypto.zig");

const key_len = types.key_len;
const hash_len = types.hash_len;
const StaticKey = types.StaticKey;
const CipherState = types.CipherState;
const SymmetricState = types.SymmetricState;
const HandshakeState = types.HandshakeState;

/// Initialize symmetric state with protocol name
///
/// Protocol name is hashed if longer than 32 bytes, otherwise zero-padded.
/// Both chaining_key and hash are initialized to this value.
pub fn initSymmetricState(protocol_name: []const u8) SymmetricState {
    var hash = [_]u8{0} ** hash_len;

    if (protocol_name.len <= hash_len) {
        @memcpy(hash[0..protocol_name.len], protocol_name);
    } else {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(protocol_name);
        hasher.final(&hash);
    }

    return .{
        .chaining_key = hash,
        .hash = hash,
        .cipher = CipherState.init([_]u8{0} ** key_len),
    };
}

/// Mix data into the handshake hash
///
/// Updates the running hash with new data from the handshake.
pub fn mixHash(state: *SymmetricState, data: []const u8) void {
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&state.hash);
    hasher.update(data);
    hasher.final(&state.hash);
}

/// Mix key material into the chaining key
///
/// Uses HKDF to derive a new chaining key and cipher key from input key material.
pub fn mixKey(state: *SymmetricState, input_key_material: []const u8) void {
    var temp_key: [hash_len]u8 = undefined;
    var output1: [hash_len]u8 = undefined;
    var output2: [hash_len]u8 = undefined;

    crypto_ops.hkdf2(&state.chaining_key, input_key_material, &output1, &output2);

    state.chaining_key = output1;
    temp_key = output2;
    state.cipher = CipherState.init(temp_key);
}

/// Encrypt plaintext and mix into handshake hash
///
/// If cipher has no key, data is copied in plaintext and mixed into hash.
/// Otherwise, data is encrypted with current hash as additional data.
pub fn encryptAndHash(
    state: *SymmetricState,
    plaintext: []const u8,
    out: []u8,
) !usize {
    if (!state.cipher.hasKey()) {
        @memcpy(out[0..plaintext.len], plaintext);
        mixHash(state, plaintext);
        return plaintext.len;
    }

    const ciphertext_len = try crypto_ops.encryptWithAd(&state.cipher, &state.hash, plaintext, out);
    state.cipher.nonce += 1;
    mixHash(state, out[0..ciphertext_len]);
    return ciphertext_len;
}

/// Decrypt ciphertext and mix into handshake hash
///
/// If cipher has no key, data is copied as-is and mixed into hash.
/// Otherwise, data is decrypted with current hash as additional data.
pub fn decryptAndHash(
    state: *SymmetricState,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (!state.cipher.hasKey()) {
        @memcpy(out[0..ciphertext.len], ciphertext);
        mixHash(state, ciphertext);
        return ciphertext.len;
    }

    const plaintext_len = try crypto_ops.decryptWithAd(&state.cipher, &state.hash, ciphertext, out);
    state.cipher.nonce += 1;
    mixHash(state, ciphertext);
    return plaintext_len;
}

/// Split into two transport cipher states for send and receive
///
/// Called after handshake completes to derive separate encryption keys
/// for bidirectional communication.
pub fn split(state: *SymmetricState) struct { CipherState, CipherState } {
    var output1: [hash_len]u8 = undefined;
    var output2: [hash_len]u8 = undefined;

    crypto_ops.hkdf2(&state.chaining_key, &[_]u8{}, &output1, &output2);

    return .{
        CipherState.init(output1),
        CipherState.init(output2),
    };
}

/// Initialize handshake state as initiator (client)
///
/// Initiator must know the responder's static public key in advance.
/// This key is mixed into the initial handshake hash.
pub fn initHandshakeInitiator(
    static_key: StaticKey,
    remote_static_key: [key_len]u8,
) HandshakeState {
    const protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256";
    var state = HandshakeState{
        .symmetric = initSymmetricState(protocol_name),
        .static_key = static_key,
        .ephemeral_key = null,
        .remote_static_key = remote_static_key,
        .remote_ephemeral_key = null,
        .is_initiator = true,
    };

    mixHash(&state.symmetric, &remote_static_key);

    return state;
}

/// Initialize handshake state as responder (server)
///
/// Responder's static public key is mixed into the initial handshake hash.
pub fn initHandshakeResponder(static_key: StaticKey) HandshakeState {
    const protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256";
    var state = HandshakeState{
        .symmetric = initSymmetricState(protocol_name),
        .static_key = static_key,
        .ephemeral_key = null,
        .remote_static_key = null,
        .remote_ephemeral_key = null,
        .is_initiator = false,
    };

    mixHash(&state.symmetric, &static_key.public);

    return state;
}

/// Split handshake state into transport cipher states
///
/// Wrapper around split() that operates on complete HandshakeState.
pub fn splitCiphers(state: *HandshakeState) struct { CipherState, CipherState } {
    return split(&state.symmetric);
}
