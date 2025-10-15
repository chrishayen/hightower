const std = @import("std");
const testing = std.testing;
const name_generator = @import("name_generator.zig");

test "generate returns error for empty prefix" {
    const allocator = testing.allocator;
    const result = name_generator.generate(allocator, "");
    try testing.expectError(name_generator.NameGeneratorError.EmptyPrefix, result);
}

test "generate creates valid name with prefix" {
    const allocator = testing.allocator;
    const prefix = "test";
    const name = try name_generator.generate(allocator, prefix);
    defer allocator.free(name);

    // Should start with prefix
    try testing.expect(std.mem.startsWith(u8, name, prefix));

    // Should contain exactly 3 hyphens (prefix-adjective-noun-xxxx)
    var hyphen_count: usize = 0;
    for (name) |c| {
        if (c == '-') hyphen_count += 1;
    }
    try testing.expectEqual(@as(usize, 3), hyphen_count);
}

test "generate creates name with correct suffix format" {
    const allocator = testing.allocator;
    const name = try name_generator.generate(allocator, "prefix");
    defer allocator.free(name);

    // Find the last hyphen
    var last_hyphen_idx: ?usize = null;
    var i: usize = name.len;
    while (i > 0) {
        i -= 1;
        if (name[i] == '-') {
            last_hyphen_idx = i;
            break;
        }
    }

    try testing.expect(last_hyphen_idx != null);

    // The suffix should be 4 hex characters
    const suffix = name[last_hyphen_idx.? + 1..];
    try testing.expectEqual(@as(usize, 4), suffix.len);

    // All characters should be valid hex
    for (suffix) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try testing.expect(is_hex);
    }
}

test "generate creates different names" {
    const allocator = testing.allocator;
    const prefix = "test";

    const name1 = try name_generator.generate(allocator, prefix);
    defer allocator.free(name1);

    const name2 = try name_generator.generate(allocator, prefix);
    defer allocator.free(name2);

    // Names should be different (highly likely with random generation)
    try testing.expect(!std.mem.eql(u8, name1, name2));
}

test "generate works with various prefixes" {
    const allocator = testing.allocator;
    const prefixes = [_][]const u8{ "wg", "vpn", "peer", "node" };

    for (prefixes) |prefix| {
        const name = try name_generator.generate(allocator, prefix);
        defer allocator.free(name);

        try testing.expect(std.mem.startsWith(u8, name, prefix));
        try testing.expect(name.len > prefix.len);
    }
}
