const std = @import("std");
const testing = std.testing;
const gateway_server = @import("gateway_server.zig");
const auth_mod = @import("auth_operations.zig");
const crypto_mod = @import("core/kv/crypto.zig");

test "bootstrapInitialAuthKey saves auth key as API key" {
    var temp_dir = testing.tmpDir(.{});
    defer temp_dir.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const temp_path = try temp_dir.dir.realpath(".", &path_buf);

    const api_key = try crypto_mod.ApiKey.generate();
    const api_key_str = try api_key.toString(testing.allocator);
    defer testing.allocator.free(api_key_str);

    {
        const config = gateway_server.ServerConfig{
            .auth_key = api_key_str,
            .kv_path = temp_path,
        };

        var server = try gateway_server.Server.init(testing.allocator, config);
        defer server.deinit();

        const marker_exists = server.kv_store.contains("__auth:initial_key_marker");
        try testing.expect(marker_exists);

        const username = try auth_mod.verifyApiKey(&server.kv_store, testing.allocator, api_key_str);
        defer testing.allocator.free(username);
        try testing.expectEqualStrings("admin", username);
    }
}

test "bootstrapInitialAuthKey does not duplicate on restart" {
    var temp_dir = testing.tmpDir(.{});
    defer temp_dir.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const temp_path = try temp_dir.dir.realpath(".", &path_buf);

    const api_key = try crypto_mod.ApiKey.generate();
    const api_key_str = try api_key.toString(testing.allocator);
    defer testing.allocator.free(api_key_str);

    {
        const config = gateway_server.ServerConfig{
            .auth_key = api_key_str,
            .kv_path = temp_path,
        };

        var server1 = try gateway_server.Server.init(testing.allocator, config);
        defer server1.deinit();

        const count1 = server1.kv_store.count();

        server1.kv_store.mutex.lock();
        var api_key_count1: usize = 0;
        var it1 = server1.kv_store.kv_state.map.iterator();
        while (it1.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, "__auth:apikey:")) {
                api_key_count1 += 1;
            }
        }
        server1.kv_store.mutex.unlock();

        try testing.expectEqual(@as(usize, 1), api_key_count1);

        var server2 = try gateway_server.Server.init(testing.allocator, config);
        defer server2.deinit();

        const count2 = server2.kv_store.count();
        try testing.expectEqual(count1, count2);

        server2.kv_store.mutex.lock();
        var api_key_count2: usize = 0;
        var it2 = server2.kv_store.kv_state.map.iterator();
        while (it2.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, "__auth:apikey:")) {
                api_key_count2 += 1;
            }
        }
        server2.kv_store.mutex.unlock();

        try testing.expectEqual(@as(usize, 1), api_key_count2);
    }
}

test "bootstrapInitialAuthKey skipped when no auth key provided" {
    var temp_dir = testing.tmpDir(.{});
    defer temp_dir.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const temp_path = try temp_dir.dir.realpath(".", &path_buf);

    const config = gateway_server.ServerConfig{
        .auth_key = null,
        .kv_path = temp_path,
    };

    var server = try gateway_server.Server.init(testing.allocator, config);
    defer server.deinit();

    const marker_exists = server.kv_store.contains("__auth:initial_key_marker");
    try testing.expect(!marker_exists);

    server.kv_store.mutex.lock();
    var api_key_count: usize = 0;
    var it = server.kv_store.kv_state.map.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "__auth:apikey:")) {
            api_key_count += 1;
        }
    }
    server.kv_store.mutex.unlock();

    try testing.expectEqual(@as(usize, 0), api_key_count);
}

test "admin user created on first run" {
    var temp_dir = testing.tmpDir(.{});
    defer temp_dir.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const temp_path = try temp_dir.dir.realpath(".", &path_buf);

    const config = gateway_server.ServerConfig{
        .auth_key = null,
        .kv_path = temp_path,
    };

    var server = try gateway_server.Server.init(testing.allocator, config);
    defer server.deinit();

    const user = try auth_mod.getUser(&server.kv_store, testing.allocator, "admin");
    defer user.deinit(testing.allocator);

    try testing.expectEqualStrings("admin", user.username);
}
