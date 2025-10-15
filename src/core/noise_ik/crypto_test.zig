const std = @import("std");
const crypto_ops = @import("crypto.zig");
const types = @import("types.zig");

const generateKeyPair = crypto_ops.generateKeyPair;
const generateEphemeralKey = crypto_ops.generateEphemeralKey;
const dh = crypto_ops.dh;
const key_len = types.key_len;

test "generate key pair produces valid keys" {
    const key = try generateKeyPair();
    try std.testing.expect(key.public.len == key_len);
    try std.testing.expect(key.secret.len == key_len);
}

test "generate ephemeral key produces valid keys" {
    const key = try generateEphemeralKey();
    try std.testing.expect(key.public.len == key_len);
    try std.testing.expect(key.secret.len == key_len);
}

test "diffie hellman produces shared secret" {
    const alice = try generateKeyPair();
    const bob = try generateKeyPair();

    const alice_shared = try dh(alice.secret, bob.public);
    const bob_shared = try dh(bob.secret, alice.public);

    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "diffie hellman rejects invalid public key" {
    const alice = try generateKeyPair();
    const invalid_public = [_]u8{0} ** key_len;

    const result = dh(alice.secret, invalid_public);
    try std.testing.expectError(error.IdentityElement, result);
}

test "encrypt rejects exhausted nonce" {
    const key = [_]u8{42} ** key_len;
    var cipher = types.CipherState.init(key);
    cipher.nonce = std.math.maxInt(u64);

    const plaintext = "test";
    const ad = "additional data";
    var out: [100]u8 = undefined;

    const result = crypto_ops.encryptWithAd(&cipher, ad, plaintext, &out);
    try std.testing.expectError(error.NonceExhausted, result);
}

test "decrypt rejects exhausted nonce" {
    const key = [_]u8{42} ** key_len;
    var cipher = types.CipherState.init(key);
    cipher.nonce = std.math.maxInt(u64);

    const ciphertext = [_]u8{0} ** 32;
    const ad = "additional data";
    var out: [100]u8 = undefined;

    const result = crypto_ops.decryptWithAd(&cipher, ad, &ciphertext, &out);
    try std.testing.expectError(error.NonceExhausted, result);
}
