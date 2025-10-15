const std = @import("std");
const types = @import("types.zig");

const CipherState = types.CipherState;
const key_len = types.key_len;

test "cipher state hasKey returns false for zero key" {
    const zero_key = [_]u8{0} ** key_len;
    const cipher = CipherState.init(zero_key);
    try std.testing.expect(!cipher.hasKey());
}

test "cipher state hasKey returns true for non-zero key" {
    const key = [_]u8{42} ** key_len;
    const cipher = CipherState.init(key);
    try std.testing.expect(cipher.hasKey());
}
