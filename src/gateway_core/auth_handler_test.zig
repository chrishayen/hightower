const std = @import("std");
const testing = std.testing;
const auth_handler = @import("auth_handler.zig");
const auth_ops = @import("../auth_operations.zig");
const kv = @import("../kv_store.zig");

test "handleAuth returns success for valid credentials" {
    var store = try kv.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);
    try store.bootstrap("localhost:0");

    // Create a test user
    try auth_ops.createUser(&store, testing.allocator, "testuser", "testpass123", "{}");

    const json =
        \\{"username":"testuser","password":"testpass123"}
    ;

    const response = try auth_handler.handleAuth(&store, testing.allocator, json);
    defer {
        if (response.api_key) |key| testing.allocator.free(key);
        if (response.key_id) |id| testing.allocator.free(id);
    }

    try testing.expect(response.success);
    try testing.expectEqualStrings("Authentication successful", response.message);
    try testing.expect(response.api_key != null);
    try testing.expect(response.key_id != null);
}

test "handleAuth returns failure for invalid password" {
    var store = try kv.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);
    try store.bootstrap("localhost:0");

    // Create a test user
    try auth_ops.createUser(&store, testing.allocator, "testuser", "correctpass", "{}");

    const json =
        \\{"username":"testuser","password":"wrongpass"}
    ;

    const response = try auth_handler.handleAuth(&store, testing.allocator, json);

    try testing.expect(!response.success);
    try testing.expectEqualStrings("Invalid username or password", response.message);
    try testing.expect(response.api_key == null);
}

test "handleAuth returns failure for non-existent user" {
    var store = try kv.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);
    try store.bootstrap("localhost:0");

    const json =
        \\{"username":"nonexistent","password":"anypass"}
    ;

    const response = try auth_handler.handleAuth(&store, testing.allocator, json);

    try testing.expect(!response.success);
    try testing.expectEqualStrings("Invalid username or password", response.message);
    try testing.expect(response.api_key == null);
}

test "handleAuth returns error for invalid JSON" {
    var store = try kv.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);
    try store.bootstrap("localhost:0");

    const json =
        \\{"username":"testuser"}
    ;

    const result = auth_handler.handleAuth(&store, testing.allocator, json);
    try testing.expectError(error.MissingField, result);
}
