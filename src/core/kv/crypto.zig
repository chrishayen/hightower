const std = @import("std");
const crypto = std.crypto;

pub const CryptoError = error{
    InvalidKey,
    InvalidNonce,
    DecryptionFailed,
    AuthenticationFailed,
};

// Timing-safe equality comparison
fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |a_byte, b_byte| {
        diff |= a_byte ^ b_byte;
    }
    return diff == 0;
}

// Password hashing using Argon2id
pub const PasswordHash = struct {
    hash: [128]u8,
    salt: [16]u8,

    pub fn fromPassword(allocator: std.mem.Allocator, password: []const u8) !PasswordHash {
        var hash: [128]u8 = undefined;

        // Generate a random salt
        var salt: [16]u8 = undefined;
        crypto.random.bytes(&salt);

        // Use Argon2id with recommended parameters
        // Time cost: 3, memory cost: 64MB, parallelism: 4
        try crypto.pwhash.argon2.kdf(
            allocator,
            &hash,
            password,
            &salt,
            .{ .t = 3, .m = 65536, .p = 4 },
            .argon2id,
        );

        return PasswordHash{ .hash = hash, .salt = salt };
    }

    pub fn verify(self: PasswordHash, allocator: std.mem.Allocator, password: []const u8) !void {
        // Derive hash with the stored salt
        var derived: [128]u8 = undefined;
        try crypto.pwhash.argon2.kdf(
            allocator,
            &derived,
            password,
            &self.salt,
            .{ .t = 3, .m = 65536, .p = 4 },
            .argon2id,
        );

        // Constant-time comparison
        if (!timingSafeEql(&self.hash, &derived)) {
            return error.AuthenticationFailed;
        }
    }

    pub fn toString(self: PasswordHash, allocator: std.mem.Allocator) ![]const u8 {
        // Format: hex(salt) + ":" + hex(hash)
        const salt_hex = std.fmt.bytesToHex(&self.salt, .lower);
        const hash_hex = std.fmt.bytesToHex(&self.hash, .lower);

        return try std.fmt.allocPrint(allocator, "{s}:{s}", .{ salt_hex, hash_hex });
    }

    pub fn fromString(str: []const u8) !PasswordHash {
        // Format: hex(salt) + ":" + hex(hash)
        // Salt is 16 bytes = 32 hex chars
        // Hash is 128 bytes = 256 hex chars
        // Total: 32 + 1 + 256 = 289 chars
        if (str.len != 289) return error.InvalidKey;

        const colon_pos = std.mem.indexOfScalar(u8, str, ':') orelse return error.InvalidKey;
        if (colon_pos != 32) return error.InvalidKey;

        var salt: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&salt, str[0..32]);

        var hash: [128]u8 = undefined;
        _ = try std.fmt.hexToBytes(&hash, str[33..]);

        return PasswordHash{ .hash = hash, .salt = salt };
    }
};

// API key generation and hashing
pub const ApiKey = struct {
    key: [32]u8,

    pub fn generate() !ApiKey {
        var key: [32]u8 = undefined;
        crypto.random.bytes(&key);
        return ApiKey{ .key = key };
    }

    pub fn toString(self: ApiKey, allocator: std.mem.Allocator) ![]const u8 {
        const hex = try allocator.alloc(u8, 64);
        errdefer allocator.free(hex);
        const result = std.fmt.bytesToHex(&self.key, .lower);
        @memcpy(hex, &result);
        return hex;
    }

    pub fn fromString(str: []const u8) !ApiKey {
        if (str.len != 64) return error.InvalidKey;

        var key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, str);

        return ApiKey{ .key = key };
    }

    // Hash the API key for storage
    pub fn hash(self: ApiKey) [32]u8 {
        var out: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&self.key, &out, .{});
        return out;
    }

    // Verify an API key against a hash in constant time
    pub fn verifyHash(self: ApiKey, expected_hash: [32]u8) bool {
        const actual_hash = self.hash();
        return timingSafeEql(&actual_hash, &expected_hash);
    }
};

// Encryption key for values
pub const EncryptionKey = struct {
    key: [32]u8,

    pub fn generate() !EncryptionKey {
        var key: [32]u8 = undefined;
        crypto.random.bytes(&key);
        return EncryptionKey{ .key = key };
    }

    pub fn fromBytes(bytes: [32]u8) EncryptionKey {
        return EncryptionKey{ .key = bytes };
    }

    pub fn toString(self: EncryptionKey, allocator: std.mem.Allocator) ![]const u8 {
        const hex = try allocator.alloc(u8, 64);
        errdefer allocator.free(hex);
        const result = std.fmt.bytesToHex(&self.key, .lower);
        @memcpy(hex, &result);
        return hex;
    }

    pub fn fromString(str: []const u8) !EncryptionKey {
        if (str.len != 64) return error.InvalidKey;

        var key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, str);

        return EncryptionKey{ .key = key };
    }

    // Encrypt data using ChaCha20-Poly1305
    pub fn encrypt(self: EncryptionKey, allocator: std.mem.Allocator, plaintext: []const u8) ![]const u8 {
        // Generate random nonce
        var nonce: [12]u8 = undefined;
        crypto.random.bytes(&nonce);

        // Allocate space for nonce + ciphertext + tag
        // Format: [nonce(12)][ciphertext][tag(16)]
        const output_len = 12 + plaintext.len + 16;
        const output = try allocator.alloc(u8, output_len);
        errdefer allocator.free(output);

        // Copy nonce to output
        @memcpy(output[0..12], &nonce);

        // Encrypt
        const ciphertext = output[12..12 + plaintext.len];
        const tag = output[12 + plaintext.len..];

        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext,
            tag[0..16],
            plaintext,
            "",  // no additional data
            nonce,
            self.key,
        );

        return output;
    }

    // Decrypt data using ChaCha20-Poly1305
    pub fn decrypt(self: EncryptionKey, allocator: std.mem.Allocator, ciphertext: []const u8) ![]const u8 {
        // Minimum size is nonce(12) + tag(16) = 28 bytes
        if (ciphertext.len < 28) return error.DecryptionFailed;

        // Extract components
        const nonce = ciphertext[0..12];
        const encrypted = ciphertext[12..ciphertext.len - 16];
        const tag = ciphertext[ciphertext.len - 16..];

        // Allocate space for plaintext
        const plaintext = try allocator.alloc(u8, encrypted.len);
        errdefer allocator.free(plaintext);

        // Decrypt and verify
        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            encrypted,
            tag[0..16].*,
            "",  // no additional data
            nonce[0..12].*,
            self.key,
        ) catch {
            allocator.free(plaintext);
            return error.AuthenticationFailed;
        };

        return plaintext;
    }
};

// Generate a UUID for API key IDs
pub fn generateUuid(allocator: std.mem.Allocator) ![]const u8 {
    var random_bytes: [16]u8 = undefined;
    crypto.random.bytes(&random_bytes);

    // Set version (4) and variant bits
    random_bytes[6] = (random_bytes[6] & 0x0f) | 0x40;
    random_bytes[8] = (random_bytes[8] & 0x3f) | 0x80;

    return try std.fmt.allocPrint(
        allocator,
        "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{
            random_bytes[0],  random_bytes[1],  random_bytes[2],  random_bytes[3],
            random_bytes[4],  random_bytes[5],  random_bytes[6],  random_bytes[7],
            random_bytes[8],  random_bytes[9],  random_bytes[10], random_bytes[11],
            random_bytes[12], random_bytes[13], random_bytes[14], random_bytes[15],
        },
    );
}
