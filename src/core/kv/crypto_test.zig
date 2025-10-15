const std = @import("std");
const testing = std.testing;
const crypto_mod = @import("crypto.zig");

test "PasswordHash - create and verify valid password" {
    const allocator = testing.allocator;
    const password = "my_secure_password_123";

    const hash = try crypto_mod.PasswordHash.fromPassword(allocator, password);
    try hash.verify(allocator, password);
}

test "PasswordHash - verify fails with wrong password" {
    const allocator = testing.allocator;
    const password = "my_secure_password_123";
    const wrong_password = "wrong_password";

    const hash = try crypto_mod.PasswordHash.fromPassword(allocator, password);

    const result = hash.verify(allocator, wrong_password);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "PasswordHash - toString and fromString roundtrip" {
    const allocator = testing.allocator;
    const password = "test_password";

    const hash = try crypto_mod.PasswordHash.fromPassword(allocator, password);
    const hash_str = try hash.toString(allocator);
    defer allocator.free(hash_str);

    const restored_hash = try crypto_mod.PasswordHash.fromString(hash_str);

    // Verify the restored hash works
    try restored_hash.verify(allocator, password);
}

test "PasswordHash - fromString fails with invalid length" {
    const invalid_str = "tooshort";
    const result = crypto_mod.PasswordHash.fromString(invalid_str);
    try testing.expectError(error.InvalidKey, result);
}

test "PasswordHash - different salts produce different hashes" {
    const allocator = testing.allocator;
    const password = "test_password";

    const hash1 = try crypto_mod.PasswordHash.fromPassword(allocator, password);
    const hash2 = try crypto_mod.PasswordHash.fromPassword(allocator, password);

    // Hashes should be different due to different salts
    try testing.expect(!std.mem.eql(u8, &hash1.hash, &hash2.hash));
    try testing.expect(!std.mem.eql(u8, &hash1.salt, &hash2.salt));

    // But both should verify with the same password
    try hash1.verify(allocator, password);
    try hash2.verify(allocator, password);
}

test "ApiKey - generate creates valid key" {
    const key = try crypto_mod.ApiKey.generate();
    try testing.expect(key.key.len == 32);
}

test "ApiKey - toString and fromString roundtrip" {
    const allocator = testing.allocator;

    const key = try crypto_mod.ApiKey.generate();
    const key_str = try key.toString(allocator);
    defer allocator.free(key_str);

    const restored_key = try crypto_mod.ApiKey.fromString(key_str);

    // Verify they're equal
    try testing.expectEqualSlices(u8, &key.key, &restored_key.key);
}

test "ApiKey - hash and verify" {
    const key = try crypto_mod.ApiKey.generate();
    const hash = key.hash();

    // Verify correct key
    try testing.expect(key.verifyHash(hash));

    // Verify wrong key fails
    const wrong_key = try crypto_mod.ApiKey.generate();
    try testing.expect(!wrong_key.verifyHash(hash));
}

test "ApiKey - different keys produce different hashes" {
    const key1 = try crypto_mod.ApiKey.generate();
    const key2 = try crypto_mod.ApiKey.generate();

    const hash1 = key1.hash();
    const hash2 = key2.hash();

    // Hashes should be different
    try testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "EncryptionKey - generate creates valid key" {
    const key = try crypto_mod.EncryptionKey.generate();
    try testing.expect(key.key.len == 32);
}

test "EncryptionKey - toString and fromString roundtrip" {
    const allocator = testing.allocator;

    const key = try crypto_mod.EncryptionKey.generate();
    const key_str = try key.toString(allocator);
    defer allocator.free(key_str);

    const restored_key = try crypto_mod.EncryptionKey.fromString(key_str);

    // Verify they're equal
    try testing.expectEqualSlices(u8, &key.key, &restored_key.key);
}

test "EncryptionKey - encrypt and decrypt roundtrip" {
    const allocator = testing.allocator;

    const key = try crypto_mod.EncryptionKey.generate();
    const plaintext = "This is my secret data!";

    const ciphertext = try key.encrypt(allocator, plaintext);
    defer allocator.free(ciphertext);

    const decrypted = try key.decrypt(allocator, ciphertext);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "EncryptionKey - decrypt with wrong key fails" {
    const allocator = testing.allocator;

    const key1 = try crypto_mod.EncryptionKey.generate();
    const key2 = try crypto_mod.EncryptionKey.generate();
    const plaintext = "This is my secret data!";

    const ciphertext = try key1.encrypt(allocator, plaintext);
    defer allocator.free(ciphertext);

    const result = key2.decrypt(allocator, ciphertext);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "EncryptionKey - encrypt produces different ciphertext each time" {
    const allocator = testing.allocator;

    const key = try crypto_mod.EncryptionKey.generate();
    const plaintext = "This is my secret data!";

    const ciphertext1 = try key.encrypt(allocator, plaintext);
    defer allocator.free(ciphertext1);

    const ciphertext2 = try key.encrypt(allocator, plaintext);
    defer allocator.free(ciphertext2);

    // Ciphertexts should be different due to random nonce
    try testing.expect(!std.mem.eql(u8, ciphertext1, ciphertext2));

    // But both should decrypt to the same plaintext
    const decrypted1 = try key.decrypt(allocator, ciphertext1);
    defer allocator.free(decrypted1);

    const decrypted2 = try key.decrypt(allocator, ciphertext2);
    defer allocator.free(decrypted2);

    try testing.expectEqualStrings(plaintext, decrypted1);
    try testing.expectEqualStrings(plaintext, decrypted2);
}

test "EncryptionKey - decrypt fails with truncated ciphertext" {
    const allocator = testing.allocator;

    const key = try crypto_mod.EncryptionKey.generate();
    const plaintext = "This is my secret data!";

    const ciphertext = try key.encrypt(allocator, plaintext);
    defer allocator.free(ciphertext);

    // Try to decrypt truncated ciphertext
    const truncated = ciphertext[0..10];
    const result = key.decrypt(allocator, truncated);
    try testing.expectError(error.DecryptionFailed, result);
}

test "EncryptionKey - encrypt and decrypt empty string" {
    const allocator = testing.allocator;

    const key = try crypto_mod.EncryptionKey.generate();
    const plaintext = "";

    const ciphertext = try key.encrypt(allocator, plaintext);
    defer allocator.free(ciphertext);

    const decrypted = try key.decrypt(allocator, ciphertext);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "generateUuid - creates valid UUID format" {
    const allocator = testing.allocator;

    const uuid = try crypto_mod.generateUuid(allocator);
    defer allocator.free(uuid);

    // UUID should be 36 characters (32 hex + 4 hyphens)
    try testing.expectEqual(@as(usize, 36), uuid.len);

    // Check hyphen positions
    try testing.expectEqual(@as(u8, '-'), uuid[8]);
    try testing.expectEqual(@as(u8, '-'), uuid[13]);
    try testing.expectEqual(@as(u8, '-'), uuid[18]);
    try testing.expectEqual(@as(u8, '-'), uuid[23]);
}

test "generateUuid - generates unique UUIDs" {
    const allocator = testing.allocator;

    const uuid1 = try crypto_mod.generateUuid(allocator);
    defer allocator.free(uuid1);

    const uuid2 = try crypto_mod.generateUuid(allocator);
    defer allocator.free(uuid2);

    // UUIDs should be different
    try testing.expect(!std.mem.eql(u8, uuid1, uuid2));
}
