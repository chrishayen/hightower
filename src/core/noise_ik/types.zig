const std = @import("std");
const mem = std.mem;

pub const key_len = 32;
pub const mac_len = 16;
pub const hash_len = 32;

pub const StaticKey = struct {
    public: [key_len]u8,
    secret: [key_len]u8,
};

pub const EphemeralKey = struct {
    public: [key_len]u8,
    secret: [key_len]u8,
};

pub const CipherState = struct {
    key: [key_len]u8,
    nonce: u64,

    pub fn init(key: [key_len]u8) CipherState {
        return .{
            .key = key,
            .nonce = 0,
        };
    }

    pub fn hasKey(self: CipherState) bool {
        const zero_key = [_]u8{0} ** key_len;
        return !mem.eql(u8, &self.key, &zero_key);
    }
};

pub const SymmetricState = struct {
    chaining_key: [hash_len]u8,
    hash: [hash_len]u8,
    cipher: CipherState,
};

pub const HandshakeState = struct {
    symmetric: SymmetricState,
    static_key: StaticKey,
    ephemeral_key: ?EphemeralKey,
    remote_static_key: ?[key_len]u8,
    remote_ephemeral_key: ?[key_len]u8,
    is_initiator: bool,
};
