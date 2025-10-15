const std = @import("std");
const testing = std.testing;
const server = @import("gateway_core/server.zig");
const kv = @import("kv_store.zig");

test "Server.init with default config" {
    const allocator = testing.allocator;

    var kv_store = try kv.KVStore.init(allocator, 1);
    defer kv_store.deinit(allocator);
    try kv_store.bootstrap("localhost:0");

    const config = server.ServerConfig{};
    const s = server.Server.init(config, &kv_store);

    try testing.expectEqual(@as(u16, 8080), s.config.port);
    try testing.expectEqualStrings("127.0.0.1", s.config.address);
}

test "Server.init with custom config" {
    const allocator = testing.allocator;

    var kv_store = try kv.KVStore.init(allocator, 1);
    defer kv_store.deinit(allocator);
    try kv_store.bootstrap("localhost:0");

    const config = server.ServerConfig{
        .port = 9000,
        .address = "0.0.0.0",
    };
    const s = server.Server.init(config, &kv_store);

    try testing.expectEqual(@as(u16, 9000), s.config.port);
    try testing.expectEqualStrings("0.0.0.0", s.config.address);
}

test "Server.init with auth key" {
    const allocator = testing.allocator;

    var kv_store = try kv.KVStore.init(allocator, 1);
    defer kv_store.deinit(allocator);
    try kv_store.bootstrap("localhost:0");

    const config = server.ServerConfig{
        .auth_key = "test-key",
    };
    const s = server.Server.init(config, &kv_store);

    try testing.expect(s.config.auth_key != null);
    try testing.expectEqualStrings("test-key", s.config.auth_key.?);
}
