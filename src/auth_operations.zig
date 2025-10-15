const std = @import("std");
const kv_store_mod = @import("kv_store.zig");
const auth_core = @import("core/kv/auth.zig");
const crypto_mod = @import("core/kv/crypto.zig");

// Imperative shell for auth operations

pub const AuthError = auth_core.AuthError || kv_store_mod.KVError;
pub const User = auth_core.User;
pub const ApiKeyData = auth_core.ApiKeyData;

// User operations
pub fn createUser(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    metadata: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    if (store.contains(key)) {
        return AuthError.UserAlreadyExists;
    }

    const now = std.time.milliTimestamp();
    const user_data = try auth_core.createUserData(allocator, username, password, metadata, now);
    defer allocator.free(user_data.key);
    defer allocator.free(user_data.user_json);

    try store.put(user_data.key, user_data.user_json);
}

pub fn getUser(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
) !User {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    const user_json = store.get(allocator, key) catch |err| {
        if (err == kv_store_mod.KVError.KeyNotFound) {
            return AuthError.UserNotFound;
        }
        return err;
    };
    defer allocator.free(user_json);

    return try User.fromJson(allocator, user_json);
}

pub fn deleteUser(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    store.delete(key) catch |err| {
        if (err == kv_store_mod.KVError.KeyNotFound) {
            return AuthError.UserNotFound;
        }
        return err;
    };
}

pub fn verifyPassword(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
) !void {
    const user = try getUser(store, allocator, username);
    defer user.deinit(allocator);

    try auth_core.verifyPasswordHash(allocator, password, user.password_hash);
}

pub fn updatePassword(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    new_password: []const u8,
) !void {
    const user = try getUser(store, allocator, username);
    defer user.deinit(allocator);

    const now = std.time.milliTimestamp();
    const updated = try auth_core.updateUserPassword(allocator, user, new_password, now);
    defer allocator.free(updated.key);
    defer allocator.free(updated.user_json);

    try store.put(updated.key, updated.user_json);
}

// API Key operations
pub fn createApiKey(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    expires_in_days: ?u32,
    metadata: []const u8,
) !struct { key_id: []const u8, key: []const u8 } {
    const user = try getUser(store, allocator, username);
    defer user.deinit(allocator);

    const now = std.time.milliTimestamp();
    const api_key_data = try auth_core.createApiKeyData(allocator, username, expires_in_days, metadata, now);
    errdefer allocator.free(api_key_data.key_id);
    errdefer allocator.free(api_key_data.key_str);
    defer allocator.free(api_key_data.kv_key);
    defer allocator.free(api_key_data.api_key_json);

    try store.put(api_key_data.kv_key, api_key_data.api_key_json);

    return .{ .key_id = api_key_data.key_id, .key = api_key_data.key_str };
}

pub fn revokeApiKey(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    key_id: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "__auth:apikey:{s}", .{key_id});
    defer allocator.free(key);

    store.delete(key) catch |err| {
        if (err == kv_store_mod.KVError.KeyNotFound) {
            return AuthError.ApiKeyNotFound;
        }
        return err;
    };
}

pub fn verifyApiKey(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    key_str: []const u8,
) ![]const u8 {
    const api_key = try crypto_mod.ApiKey.fromString(key_str);

    store.mutex.lock();
    defer store.mutex.unlock();

    var it = store.kv_state.map.iterator();
    while (it.next()) |entry| {
        const kv_key = entry.key_ptr.*;

        if (!std.mem.startsWith(u8, kv_key, "__auth:apikey:")) {
            continue;
        }

        const api_key_data = ApiKeyData.fromJson(allocator, entry.value_ptr.*) catch continue;
        defer api_key_data.deinit(allocator);

        var stored_hash: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&stored_hash, api_key_data.key_hash) catch continue;

        if (!auth_core.verifyApiKeyHash(api_key, stored_hash)) {
            continue;
        }

        const now = std.time.milliTimestamp();
        if (auth_core.isApiKeyExpired(api_key_data, now)) {
            return AuthError.InvalidCredentials;
        }

        const kv_key_copy = try allocator.dupe(u8, kv_key);
        defer allocator.free(kv_key_copy);

        const username_copy = try allocator.dupe(u8, api_key_data.username);
        errdefer allocator.free(username_copy);

        const updated_json = try auth_core.updateApiKeyLastUsed(allocator, api_key_data, now);
        defer allocator.free(updated_json);

        store.mutex.unlock();
        store.put(kv_key_copy, updated_json) catch {
            allocator.free(username_copy);
            return AuthError.InvalidCredentials;
        };

        return username_copy;
    }

    return AuthError.InvalidCredentials;
}

pub fn getApiKey(
    store: *kv_store_mod.KVStore,
    allocator: std.mem.Allocator,
    key_id: []const u8,
) !ApiKeyData {
    const key = try std.fmt.allocPrint(allocator, "__auth:apikey:{s}", .{key_id});
    defer allocator.free(key);

    const api_key_json = store.get(allocator, key) catch |err| {
        if (err == kv_store_mod.KVError.KeyNotFound) {
            return AuthError.ApiKeyNotFound;
        }
        return err;
    };
    defer allocator.free(api_key_json);

    return try ApiKeyData.fromJson(allocator, api_key_json);
}
