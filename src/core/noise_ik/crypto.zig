const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const types = @import("types.zig");

const key_len = types.key_len;
const mac_len = types.mac_len;
const hash_len = types.hash_len;
const StaticKey = types.StaticKey;
const EphemeralKey = types.EphemeralKey;
const CipherState = types.CipherState;

pub fn generateKeyPair() !StaticKey {
    var seed: [32]u8 = undefined;
    crypto.random.bytes(&seed);

    const keypair = try crypto.dh.X25519.KeyPair.generateDeterministic(seed);

    return StaticKey{
        .public = keypair.public_key,
        .secret = keypair.secret_key,
    };
}

pub fn generateEphemeralKey() !EphemeralKey {
    var seed: [32]u8 = undefined;
    crypto.random.bytes(&seed);

    const keypair = try crypto.dh.X25519.KeyPair.generateDeterministic(seed);

    return EphemeralKey{
        .public = keypair.public_key,
        .secret = keypair.secret_key,
    };
}

pub fn dh(private_key: [key_len]u8, public_key: [key_len]u8) ![key_len]u8 {
    return try crypto.dh.X25519.scalarmult(private_key, public_key);
}

pub fn hkdf2(
    chaining_key: *const [hash_len]u8,
    input_key_material: []const u8,
    output1: *[hash_len]u8,
    output2: *[hash_len]u8,
) void {
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(chaining_key);
    hmac.update(input_key_material);
    var temp_key: [hash_len]u8 = undefined;
    hmac.final(&temp_key);

    var hmac1 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac1.update(&[_]u8{0x01});
    hmac1.final(output1);

    var hmac2 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac2.update(output1);
    hmac2.update(&[_]u8{0x02});
    hmac2.final(output2);
}

pub fn encryptWithAd(
    cipher: *const CipherState,
    ad: []const u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    if (cipher.nonce == std.math.maxInt(u64)) {
        return error.NonceExhausted;
    }

    if (plaintext.len + mac_len > out.len) {
        return error.BufferTooSmall;
    }

    var nonce_bytes: [12]u8 = [_]u8{0} ** 12;
    mem.writeInt(u64, nonce_bytes[4..12], cipher.nonce, .little);

    @memcpy(out[0..plaintext.len], plaintext);

    var tag: [mac_len]u8 = undefined;
    crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        out[0..plaintext.len],
        &tag,
        plaintext,
        ad,
        nonce_bytes,
        cipher.key,
    );

    @memcpy(out[plaintext.len..][0..mac_len], &tag);
    return plaintext.len + mac_len;
}

pub fn decryptWithAd(
    cipher: *const CipherState,
    ad: []const u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (cipher.nonce == std.math.maxInt(u64)) {
        return error.NonceExhausted;
    }

    if (ciphertext.len < mac_len) {
        return error.InvalidCiphertext;
    }

    const plaintext_len = ciphertext.len - mac_len;
    if (plaintext_len > out.len) {
        return error.BufferTooSmall;
    }

    var nonce_bytes: [12]u8 = [_]u8{0} ** 12;
    mem.writeInt(u64, nonce_bytes[4..12], cipher.nonce, .little);

    const ct = ciphertext[0..plaintext_len];
    const tag = ciphertext[plaintext_len..][0..mac_len];

    try crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        out[0..plaintext_len],
        ct,
        tag.*,
        ad,
        nonce_bytes,
        cipher.key,
    );

    return plaintext_len;
}
