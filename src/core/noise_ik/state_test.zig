const std = @import("std");
const state_ops = @import("state.zig");
const crypto_ops = @import("crypto.zig");
const types = @import("types.zig");

const crypto = std.crypto;
const mem = std.mem;

const initSymmetricState = state_ops.initSymmetricState;
const mixHash = state_ops.mixHash;
const mixKey = state_ops.mixKey;
const encryptAndHash = state_ops.encryptAndHash;
const decryptAndHash = state_ops.decryptAndHash;
const split = state_ops.split;
const initHandshakeInitiator = state_ops.initHandshakeInitiator;
const initHandshakeResponder = state_ops.initHandshakeResponder;
const generateKeyPair = crypto_ops.generateKeyPair;
const hash_len = types.hash_len;
const mac_len = types.mac_len;

test "symmetric state init with short protocol name" {
    const protocol_name = "Noise";
    const state_obj = initSymmetricState(protocol_name);

    var expected_hash = [_]u8{0} ** hash_len;
    @memcpy(expected_hash[0..protocol_name.len], protocol_name);

    try std.testing.expectEqualSlices(u8, &state_obj.hash, &expected_hash);
    try std.testing.expectEqualSlices(u8, &state_obj.chaining_key, &expected_hash);
}

test "symmetric state init with long protocol name" {
    const protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256_very_long_name_that_exceeds_hash_length";
    const state_obj = initSymmetricState(protocol_name);

    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(protocol_name);
    var expected_hash: [hash_len]u8 = undefined;
    hasher.final(&expected_hash);

    try std.testing.expectEqualSlices(u8, &state_obj.hash, &expected_hash);
}

test "symmetric state mixHash updates hash correctly" {
    const protocol_name = "Noise";
    var state_obj = initSymmetricState(protocol_name);

    const data = "test data";
    const original_hash = state_obj.hash;
    mixHash(&state_obj, data);

    try std.testing.expect(!mem.eql(u8, &state_obj.hash, &original_hash));
}

test "symmetric state mixKey updates chaining key and cipher" {
    const protocol_name = "Noise";
    var state_obj = initSymmetricState(protocol_name);

    const ikm = "input key material";
    const original_ck = state_obj.chaining_key;
    mixKey(&state_obj, ikm);

    try std.testing.expect(!mem.eql(u8, &state_obj.chaining_key, &original_ck));
    try std.testing.expect(state_obj.cipher.hasKey());
}

test "symmetric state encryptAndHash without key copies plaintext" {
    const protocol_name = "Noise";
    var state_obj = initSymmetricState(protocol_name);

    const plaintext = "hello world";
    var out: [100]u8 = undefined;

    const len = try encryptAndHash(&state_obj, plaintext, &out);

    try std.testing.expectEqual(plaintext.len, len);
    try std.testing.expectEqualSlices(u8, plaintext, out[0..len]);
}

test "symmetric state encryptAndHash with key encrypts data" {
    const protocol_name = "Noise";
    var state_obj = initSymmetricState(protocol_name);

    const ikm = "input key material";
    mixKey(&state_obj, ikm);

    const plaintext = "hello world";
    var out: [100]u8 = undefined;

    const len = try encryptAndHash(&state_obj, plaintext, &out);

    try std.testing.expect(len == plaintext.len + mac_len);
    try std.testing.expect(!mem.eql(u8, plaintext, out[0..plaintext.len]));
}

test "symmetric state decryptAndHash without key copies ciphertext" {
    const protocol_name = "Noise";
    var state_obj = initSymmetricState(protocol_name);

    const ciphertext = "hello world";
    var out: [100]u8 = undefined;

    const len = try decryptAndHash(&state_obj, ciphertext, &out);

    try std.testing.expectEqual(ciphertext.len, len);
    try std.testing.expectEqualSlices(u8, ciphertext, out[0..len]);
}

test "symmetric state encrypt and decrypt roundtrip" {
    const protocol_name = "Noise";
    var encrypt_state = initSymmetricState(protocol_name);
    var decrypt_state = initSymmetricState(protocol_name);

    const ikm = "input key material";
    mixKey(&encrypt_state, ikm);
    mixKey(&decrypt_state, ikm);

    const plaintext = "hello world";
    var encrypted: [100]u8 = undefined;
    var decrypted: [100]u8 = undefined;

    const enc_len = try encryptAndHash(&encrypt_state, plaintext, &encrypted);
    const dec_len = try decryptAndHash(&decrypt_state, encrypted[0..enc_len], &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..dec_len]);
}

test "symmetric state split produces two ciphers" {
    const protocol_name = "Noise";
    var state_obj = initSymmetricState(protocol_name);

    const ikm = "input key material";
    mixKey(&state_obj, ikm);

    const ciphers = split(&state_obj);

    try std.testing.expect(ciphers[0].hasKey());
    try std.testing.expect(ciphers[1].hasKey());
    try std.testing.expect(!mem.eql(u8, &ciphers[0].key, &ciphers[1].key));
}

test "handshake state init initiator sets up correctly" {
    const initiator_key = try generateKeyPair();
    const responder_key = try generateKeyPair();

    const state_obj = initHandshakeInitiator(initiator_key, responder_key.public);

    try std.testing.expect(state_obj.is_initiator);
    try std.testing.expectEqualSlices(u8, &state_obj.static_key.public, &initiator_key.public);
    try std.testing.expectEqualSlices(u8, &state_obj.remote_static_key.?, &responder_key.public);
    try std.testing.expect(state_obj.ephemeral_key == null);
}

test "handshake state init responder sets up correctly" {
    const responder_key = try generateKeyPair();

    const state_obj = initHandshakeResponder(responder_key);

    try std.testing.expect(!state_obj.is_initiator);
    try std.testing.expectEqualSlices(u8, &state_obj.static_key.public, &responder_key.public);
    try std.testing.expect(state_obj.remote_static_key == null);
    try std.testing.expect(state_obj.ephemeral_key == null);
}
