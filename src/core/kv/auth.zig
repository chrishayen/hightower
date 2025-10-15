const std = @import("std");
const crypto_mod = @import("crypto.zig");
const store_mod = @import("store.zig");

pub const AuthError = error{
    UserNotFound,
    UserAlreadyExists,
    ApiKeyNotFound,
    InvalidCredentials,
} || std.mem.Allocator.Error || store_mod.KVError;

// User structure
pub const User = struct {
    username: []const u8,
    password_hash: []const u8,
    created_at: i64,
    updated_at: i64,
    metadata: []const u8, // JSON string

    pub fn toJson(self: User, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"username\":\"{s}\",\"password_hash\":\"{s}\",\"created_at\":{},\"updated_at\":{},\"metadata\":{s}}}",
            .{ self.username, self.password_hash, self.created_at, self.updated_at, self.metadata },
        );
    }

    pub fn fromJson(allocator: std.mem.Allocator, json: []const u8) !User {
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            json,
            .{},
        );
        defer parsed.deinit();

        const obj = parsed.value.object;

        const username = try allocator.dupe(u8, obj.get("username").?.string);
        errdefer allocator.free(username);

        const password_hash = try allocator.dupe(u8, obj.get("password_hash").?.string);
        errdefer allocator.free(password_hash);

        const metadata = try allocator.dupe(u8, obj.get("metadata").?.string);
        errdefer allocator.free(metadata);

        return User{
            .username = username,
            .password_hash = password_hash,
            .created_at = obj.get("created_at").?.integer,
            .updated_at = obj.get("updated_at").?.integer,
            .metadata = metadata,
        };
    }

    pub fn deinit(self: User, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.password_hash);
        allocator.free(self.metadata);
    }
};

// API Key structure
pub const ApiKeyData = struct {
    key_id: []const u8,
    key_hash: []const u8,
    username: []const u8,
    created_at: i64,
    expires_at: ?i64,
    last_used: ?i64,
    metadata: []const u8, // JSON string

    pub fn toJson(self: ApiKeyData, allocator: std.mem.Allocator) ![]const u8 {
        if (self.expires_at) |exp| {
            if (self.last_used) |last| {
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"key_id\":\"{s}\",\"key_hash\":\"{s}\",\"username\":\"{s}\",\"created_at\":{},\"expires_at\":{},\"last_used\":{},\"metadata\":{s}}}",
                    .{ self.key_id, self.key_hash, self.username, self.created_at, exp, last, self.metadata },
                );
            } else {
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"key_id\":\"{s}\",\"key_hash\":\"{s}\",\"username\":\"{s}\",\"created_at\":{},\"expires_at\":{},\"last_used\":null,\"metadata\":{s}}}",
                    .{ self.key_id, self.key_hash, self.username, self.created_at, exp, self.metadata },
                );
            }
        } else {
            if (self.last_used) |last| {
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"key_id\":\"{s}\",\"key_hash\":\"{s}\",\"username\":\"{s}\",\"created_at\":{},\"expires_at\":null,\"last_used\":{},\"metadata\":{s}}}",
                    .{ self.key_id, self.key_hash, self.username, self.created_at, last, self.metadata },
                );
            } else {
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"key_id\":\"{s}\",\"key_hash\":\"{s}\",\"username\":\"{s}\",\"created_at\":{},\"expires_at\":null,\"last_used\":null,\"metadata\":{s}}}",
                    .{ self.key_id, self.key_hash, self.username, self.created_at, self.metadata },
                );
            }
        }
    }

    pub fn fromJson(allocator: std.mem.Allocator, json: []const u8) !ApiKeyData {
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            json,
            .{},
        );
        defer parsed.deinit();

        const obj = parsed.value.object;

        const key_id = try allocator.dupe(u8, obj.get("key_id").?.string);
        errdefer allocator.free(key_id);

        const key_hash = try allocator.dupe(u8, obj.get("key_hash").?.string);
        errdefer allocator.free(key_hash);

        const username = try allocator.dupe(u8, obj.get("username").?.string);
        errdefer allocator.free(username);

        const metadata = try allocator.dupe(u8, obj.get("metadata").?.string);
        errdefer allocator.free(metadata);

        const expires_at = if (obj.get("expires_at")) |val| switch (val) {
            .null => null,
            .integer => |i| i,
            else => null,
        } else null;

        const last_used = if (obj.get("last_used")) |val| switch (val) {
            .null => null,
            .integer => |i| i,
            else => null,
        } else null;

        return ApiKeyData{
            .key_id = key_id,
            .key_hash = key_hash,
            .username = username,
            .created_at = obj.get("created_at").?.integer,
            .expires_at = expires_at,
            .last_used = last_used,
            .metadata = metadata,
        };
    }

    pub fn deinit(self: ApiKeyData, allocator: std.mem.Allocator) void {
        allocator.free(self.key_id);
        allocator.free(self.key_hash);
        allocator.free(self.username);
        allocator.free(self.metadata);
    }
};

// User operations
pub fn createUser(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    metadata: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    // Check if user already exists
    if (store.contains(key)) {
        return AuthError.UserAlreadyExists;
    }

    // Hash password
    const password_hash = try crypto_mod.PasswordHash.fromPassword(allocator, password);
    const password_hash_str = try password_hash.toString(allocator);
    defer allocator.free(password_hash_str);

    // Create user
    const now = std.time.milliTimestamp();
    const user = User{
        .username = username,
        .password_hash = password_hash_str,
        .created_at = now,
        .updated_at = now,
        .metadata = metadata,
    };

    const user_json = try user.toJson(allocator);
    defer allocator.free(user_json);

    try store.put(key, user_json);
}

pub fn getUser(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
) !User {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    const user_json = store.get(allocator, key) catch |err| {
        if (err == store_mod.KVError.KeyNotFound) {
            return AuthError.UserNotFound;
        }
        return err;
    };
    defer allocator.free(user_json);

    return try User.fromJson(allocator, user_json);
}

pub fn deleteUser(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    store.delete(key) catch |err| {
        if (err == store_mod.KVError.KeyNotFound) {
            return AuthError.UserNotFound;
        }
        return err;
    };
}

pub fn verifyPassword(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
) !void {
    const user = try getUser(store, allocator, username);
    defer user.deinit(allocator);

    const password_hash = try crypto_mod.PasswordHash.fromString(user.password_hash);
    password_hash.verify(allocator, password) catch {
        return AuthError.InvalidCredentials;
    };
}

pub fn updatePassword(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    new_password: []const u8,
) !void {
    const user = try getUser(store, allocator, username);
    defer user.deinit(allocator);

    // Hash new password
    const password_hash = try crypto_mod.PasswordHash.fromPassword(allocator, new_password);
    const password_hash_str = try password_hash.toString(allocator);
    defer allocator.free(password_hash_str);

    // Update user
    const updated_user = User{
        .username = user.username,
        .password_hash = password_hash_str,
        .created_at = user.created_at,
        .updated_at = std.time.milliTimestamp(),
        .metadata = user.metadata,
    };

    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    defer allocator.free(key);

    const user_json = try updated_user.toJson(allocator);
    defer allocator.free(user_json);

    try store.put(key, user_json);
}

// API Key operations
pub fn createApiKey(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    username: []const u8,
    expires_in_days: ?u32,
    metadata: []const u8,
) !struct { key_id: []const u8, key: []const u8 } {
    // Verify user exists
    const user = try getUser(store, allocator, username);
    defer user.deinit(allocator);

    // Generate API key and ID
    const api_key = try crypto_mod.ApiKey.generate();
    const key_id = try crypto_mod.generateUuid(allocator);
    errdefer allocator.free(key_id);

    const key_str = try api_key.toString(allocator);
    errdefer allocator.free(key_str);

    // Hash the key for storage
    const key_hash = api_key.hash();
    const key_hash_hex = std.fmt.bytesToHex(&key_hash, .lower);
    const key_hash_str = try allocator.dupe(u8, &key_hash_hex);
    defer allocator.free(key_hash_str);

    // Calculate expiration
    const now = std.time.milliTimestamp();
    const expires_at = if (expires_in_days) |days|
        now + (@as(i64, days) * 24 * 60 * 60 * 1000)
    else
        null;

    // Create API key data
    const api_key_data = ApiKeyData{
        .key_id = key_id,
        .key_hash = key_hash_str,
        .username = username,
        .created_at = now,
        .expires_at = expires_at,
        .last_used = null,
        .metadata = metadata,
    };

    const kv_key = try std.fmt.allocPrint(allocator, "__auth:apikey:{s}", .{key_id});
    defer allocator.free(kv_key);

    const api_key_json = try api_key_data.toJson(allocator);
    defer allocator.free(api_key_json);

    try store.put(kv_key, api_key_json);

    return .{ .key_id = key_id, .key = key_str };
}

pub fn revokeApiKey(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    key_id: []const u8,
) !void {
    const key = try std.fmt.allocPrint(allocator, "__auth:apikey:{s}", .{key_id});
    defer allocator.free(key);

    store.delete(key) catch |err| {
        if (err == store_mod.KVError.KeyNotFound) {
            return AuthError.ApiKeyNotFound;
        }
        return err;
    };
}

pub fn verifyApiKey(
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    key_str: []const u8,
) ![]const u8 {
    // Parse the key
    const api_key = try crypto_mod.ApiKey.fromString(key_str);

    store.mutex.lock();
    defer store.mutex.unlock();

    // Find the matching key by iterating through all API keys
    var it = store.kv_state.map.iterator();
    while (it.next()) |entry| {
        const kv_key = entry.key_ptr.*;

        // Check if this is an API key entry
        if (!std.mem.startsWith(u8, kv_key, "__auth:apikey:")) {
            continue;
        }

        // Parse the API key data
        const api_key_data = ApiKeyData.fromJson(allocator, entry.value_ptr.*) catch continue;
        defer api_key_data.deinit(allocator);

        // Parse stored hash
        var stored_hash: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&stored_hash, api_key_data.key_hash) catch continue;

        // Verify hash
        if (!api_key.verifyHash(stored_hash)) {
            continue;
        }

        // Check expiration
        if (api_key_data.expires_at) |exp| {
            if (std.time.milliTimestamp() > exp) {
                return AuthError.InvalidCredentials;
            }
        }

        // Update last_used - must unlock before calling put
        const kv_key_copy = try allocator.dupe(u8, kv_key);
        defer allocator.free(kv_key_copy);

        const username_copy = try allocator.dupe(u8, api_key_data.username);
        errdefer allocator.free(username_copy);

        const updated_data = ApiKeyData{
            .key_id = api_key_data.key_id,
            .key_hash = api_key_data.key_hash,
            .username = api_key_data.username,
            .created_at = api_key_data.created_at,
            .expires_at = api_key_data.expires_at,
            .last_used = std.time.milliTimestamp(),
            .metadata = api_key_data.metadata,
        };

        const updated_json = try updated_data.toJson(allocator);
        defer allocator.free(updated_json);

        // Unlock before calling put (which also locks)
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
    store: *store_mod.KVStore,
    allocator: std.mem.Allocator,
    key_id: []const u8,
) !ApiKeyData {
    const key = try std.fmt.allocPrint(allocator, "__auth:apikey:{s}", .{key_id});
    defer allocator.free(key);

    const api_key_json = store.get(allocator, key) catch |err| {
        if (err == store_mod.KVError.KeyNotFound) {
            return AuthError.ApiKeyNotFound;
        }
        return err;
    };
    defer allocator.free(api_key_json);

    return try ApiKeyData.fromJson(allocator, api_key_json);
}
