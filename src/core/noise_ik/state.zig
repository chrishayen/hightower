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

pub fn mixHash(state: *SymmetricState, data: []const u8) void {
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&state.hash);
    hasher.update(data);
    hasher.final(&state.hash);
}

pub fn mixKey(state: *SymmetricState, input_key_material: []const u8) void {
    var temp_key: [hash_len]u8 = undefined;
    var output1: [hash_len]u8 = undefined;
    var output2: [hash_len]u8 = undefined;

    crypto_ops.hkdf2(&state.chaining_key, input_key_material, &output1, &output2);

    state.chaining_key = output1;
    temp_key = output2;
    state.cipher = CipherState.init(temp_key);
}

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

pub fn split(state: *SymmetricState) struct { CipherState, CipherState } {
    var output1: [hash_len]u8 = undefined;
    var output2: [hash_len]u8 = undefined;

    crypto_ops.hkdf2(&state.chaining_key, &[_]u8{}, &output1, &output2);

    return .{
        CipherState.init(output1),
        CipherState.init(output2),
    };
}

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

pub fn splitCiphers(state: *HandshakeState) struct { CipherState, CipherState } {
    return split(&state.symmetric);
}
