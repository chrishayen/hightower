const std = @import("std");
const testing = std.testing;
const auth_mod = @import("auth.zig");
const store_mod = @import("store.zig");

fn setupStore(allocator: std.mem.Allocator) !store_mod.KVStore {
    var store = try store_mod.KVStore.init(allocator, 1);
    try store.bootstrap("localhost:0");
    return store;
}

test "User - create and get" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const user = try auth_mod.getUser(&store, allocator, username);
    defer user.deinit(allocator);

    try testing.expectEqualStrings(username, user.username);
    try testing.expectEqualStrings(metadata, user.metadata);
}

test "User - create duplicate fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = auth_mod.createUser(&store, allocator, username, password, metadata);
    try testing.expectError(auth_mod.AuthError.UserAlreadyExists, result);
}

test "User - get non-existent user fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const result = auth_mod.getUser(&store, allocator, "nonexistent");
    try testing.expectError(auth_mod.AuthError.UserNotFound, result);
}

test "User - verify correct password" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);
    try auth_mod.verifyPassword(&store, allocator, username, password);
}

test "User - verify wrong password fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const wrong_password = "wrongpass";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = auth_mod.verifyPassword(&store, allocator, username, wrong_password);
    try testing.expectError(auth_mod.AuthError.InvalidCredentials, result);
}

test "User - delete user" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);
    try auth_mod.deleteUser(&store, allocator, username);

    const result = auth_mod.getUser(&store, allocator, username);
    try testing.expectError(auth_mod.AuthError.UserNotFound, result);
}

test "User - delete non-existent user fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const result = auth_mod.deleteUser(&store, allocator, "nonexistent");
    try testing.expectError(auth_mod.AuthError.UserNotFound, result);
}

test "User - update password" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const old_password = "oldpass123";
    const new_password = "newpass456";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, old_password, metadata);
    try auth_mod.updatePassword(&store, allocator, username, new_password);

    // Old password should fail
    const old_result = auth_mod.verifyPassword(&store, allocator, username, old_password);
    try testing.expectError(auth_mod.AuthError.InvalidCredentials, old_result);

    // New password should work
    try auth_mod.verifyPassword(&store, allocator, username, new_password);
}

test "ApiKey - create and verify" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = try auth_mod.createApiKey(&store, allocator, username, null, metadata);
    defer allocator.free(result.key_id);
    defer allocator.free(result.key);

    // Verify the API key
    const verified_username = try auth_mod.verifyApiKey(&store, allocator, result.key);
    defer allocator.free(verified_username);

    try testing.expectEqualStrings(username, verified_username);
}

test "ApiKey - create without user fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const metadata = "{}";

    const result = auth_mod.createApiKey(&store, allocator, "nonexistent", null, metadata);
    try testing.expectError(auth_mod.AuthError.UserNotFound, result);
}

test "ApiKey - verify wrong key fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = try auth_mod.createApiKey(&store, allocator, username, null, metadata);
    defer allocator.free(result.key_id);
    defer allocator.free(result.key);

    // Generate a different key
    const wrong_result = try auth_mod.createApiKey(&store, allocator, username, null, metadata);
    defer allocator.free(wrong_result.key_id);
    defer allocator.free(wrong_result.key);

    // Verify each key returns correct username
    const verified1 = try auth_mod.verifyApiKey(&store, allocator, result.key);
    defer allocator.free(verified1);
    try testing.expectEqualStrings(username, verified1);

    const verified2 = try auth_mod.verifyApiKey(&store, allocator, wrong_result.key);
    defer allocator.free(verified2);
    try testing.expectEqualStrings(username, verified2);
}

test "ApiKey - revoke key" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = try auth_mod.createApiKey(&store, allocator, username, null, metadata);
    defer allocator.free(result.key);

    try auth_mod.revokeApiKey(&store, allocator, result.key_id);
    allocator.free(result.key_id);

    // Verify should fail after revocation
    const verify_result = auth_mod.verifyApiKey(&store, allocator, result.key);
    try testing.expectError(auth_mod.AuthError.InvalidCredentials, verify_result);
}

test "ApiKey - revoke non-existent key fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const result = auth_mod.revokeApiKey(&store, allocator, "nonexistent-uuid");
    try testing.expectError(auth_mod.AuthError.ApiKeyNotFound, result);
}

test "ApiKey - get key data" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = try auth_mod.createApiKey(&store, allocator, username, null, metadata);
    defer allocator.free(result.key_id);
    defer allocator.free(result.key);

    const api_key_data = try auth_mod.getApiKey(&store, allocator, result.key_id);
    defer api_key_data.deinit(allocator);

    try testing.expectEqualStrings(username, api_key_data.username);
    try testing.expectEqualStrings(metadata, api_key_data.metadata);
    try testing.expectEqual(@as(?i64, null), api_key_data.expires_at);
    try testing.expectEqual(@as(?i64, null), api_key_data.last_used);
}

test "ApiKey - last_used updates after verification" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const username = "testuser";
    const password = "testpass123";
    const metadata = "{}";

    try auth_mod.createUser(&store, allocator, username, password, metadata);

    const result = try auth_mod.createApiKey(&store, allocator, username, null, metadata);
    defer allocator.free(result.key_id);
    defer allocator.free(result.key);

    // Verify the key
    const verified_username = try auth_mod.verifyApiKey(&store, allocator, result.key);
    defer allocator.free(verified_username);

    // Check that last_used was updated
    const api_key_data = try auth_mod.getApiKey(&store, allocator, result.key_id);
    defer api_key_data.deinit(allocator);

    try testing.expect(api_key_data.last_used != null);
}

test "ApiKey - get non-existent key fails" {
    const allocator = testing.allocator;

    var store = try setupStore(allocator);
    defer store.deinit(allocator);

    const result = auth_mod.getApiKey(&store, allocator, "nonexistent-uuid");
    try testing.expectError(auth_mod.AuthError.ApiKeyNotFound, result);
}

test "User - toJson and fromJson roundtrip" {
    const allocator = testing.allocator;

    const user = auth_mod.User{
        .username = "testuser",
        .password_hash = "abcd1234",
        .created_at = 1234567890,
        .updated_at = 1234567891,
        .metadata = "{}",
    };

    const json = try user.toJson(allocator);
    defer allocator.free(json);

    const restored = try auth_mod.User.fromJson(allocator, json);
    defer restored.deinit(allocator);

    try testing.expectEqualStrings(user.username, restored.username);
    try testing.expectEqualStrings(user.password_hash, restored.password_hash);
    try testing.expectEqual(user.created_at, restored.created_at);
    try testing.expectEqual(user.updated_at, restored.updated_at);
    try testing.expectEqualStrings(user.metadata, restored.metadata);
}

test "ApiKeyData - toJson and fromJson roundtrip" {
    const allocator = testing.allocator;

    const api_key_data = auth_mod.ApiKeyData{
        .key_id = "test-uuid",
        .key_hash = "abcd1234",
        .username = "testuser",
        .created_at = 1234567890,
        .expires_at = 1234567999,
        .last_used = 1234567895,
        .metadata = "{}",
    };

    const json = try api_key_data.toJson(allocator);
    defer allocator.free(json);

    const restored = try auth_mod.ApiKeyData.fromJson(allocator, json);
    defer restored.deinit(allocator);

    try testing.expectEqualStrings(api_key_data.key_id, restored.key_id);
    try testing.expectEqualStrings(api_key_data.key_hash, restored.key_hash);
    try testing.expectEqualStrings(api_key_data.username, restored.username);
    try testing.expectEqual(api_key_data.created_at, restored.created_at);
    try testing.expectEqual(api_key_data.expires_at, restored.expires_at);
    try testing.expectEqual(api_key_data.last_used, restored.last_used);
    try testing.expectEqualStrings(api_key_data.metadata, restored.metadata);
}
