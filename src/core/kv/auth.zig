const std = @import("std");
const crypto_mod = @import("crypto.zig");

// Pure types and validation logic (Functional Core)

pub const AuthError = error{
    UserNotFound,
    UserAlreadyExists,
    ApiKeyNotFound,
    InvalidCredentials,
} || std.mem.Allocator.Error;

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

// Pure function: Create user data structure
pub fn createUserData(
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    metadata: []const u8,
    now: i64,
) !struct { key: []const u8, user_json: []const u8 } {
    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{username});
    errdefer allocator.free(key);

    const password_hash = try crypto_mod.PasswordHash.fromPassword(allocator, password);
    const password_hash_str = try password_hash.toString(allocator);
    defer allocator.free(password_hash_str);

    const user = User{
        .username = username,
        .password_hash = password_hash_str,
        .created_at = now,
        .updated_at = now,
        .metadata = metadata,
    };

    const user_json = try user.toJson(allocator);
    return .{ .key = key, .user_json = user_json };
}

// Pure function: Verify password against hash
pub fn verifyPasswordHash(
    allocator: std.mem.Allocator,
    password: []const u8,
    password_hash_str: []const u8,
) !void {
    const password_hash = try crypto_mod.PasswordHash.fromString(password_hash_str);
    password_hash.verify(allocator, password) catch {
        return AuthError.InvalidCredentials;
    };
}

// Pure function: Update user password
pub fn updateUserPassword(
    allocator: std.mem.Allocator,
    user: User,
    new_password: []const u8,
    now: i64,
) !struct { key: []const u8, user_json: []const u8 } {
    const password_hash = try crypto_mod.PasswordHash.fromPassword(allocator, new_password);
    const password_hash_str = try password_hash.toString(allocator);
    defer allocator.free(password_hash_str);

    const updated_user = User{
        .username = user.username,
        .password_hash = password_hash_str,
        .created_at = user.created_at,
        .updated_at = now,
        .metadata = user.metadata,
    };

    const key = try std.fmt.allocPrint(allocator, "__auth:user:{s}", .{user.username});
    errdefer allocator.free(key);

    const user_json = try updated_user.toJson(allocator);
    return .{ .key = key, .user_json = user_json };
}

// Pure function: Create API key data
pub fn createApiKeyData(
    allocator: std.mem.Allocator,
    username: []const u8,
    expires_in_days: ?u32,
    metadata: []const u8,
    now: i64,
) !struct { key_id: []const u8, key_str: []const u8, kv_key: []const u8, api_key_json: []const u8 } {
    const api_key = try crypto_mod.ApiKey.generate();
    const key_id = try crypto_mod.generateUuid(allocator);
    errdefer allocator.free(key_id);

    const key_str = try api_key.toString(allocator);
    errdefer allocator.free(key_str);

    const key_hash = api_key.hash();
    const key_hash_hex = std.fmt.bytesToHex(&key_hash, .lower);
    const key_hash_str = try allocator.dupe(u8, &key_hash_hex);
    defer allocator.free(key_hash_str);

    const expires_at = if (expires_in_days) |days|
        now + (@as(i64, days) * 24 * 60 * 60 * 1000)
    else
        null;

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
    errdefer allocator.free(kv_key);

    const api_key_json = try api_key_data.toJson(allocator);

    return .{
        .key_id = key_id,
        .key_str = key_str,
        .kv_key = kv_key,
        .api_key_json = api_key_json,
    };
}

// Pure function: Verify API key hash
pub fn verifyApiKeyHash(api_key: crypto_mod.ApiKey, stored_hash: [32]u8) bool {
    return api_key.verifyHash(stored_hash);
}

// Pure function: Check if API key is expired
pub fn isApiKeyExpired(api_key_data: ApiKeyData, now: i64) bool {
    if (api_key_data.expires_at) |exp| {
        return now > exp;
    }
    return false;
}

// Pure function: Update API key last used
pub fn updateApiKeyLastUsed(
    allocator: std.mem.Allocator,
    api_key_data: ApiKeyData,
    now: i64,
) ![]const u8 {
    const updated_data = ApiKeyData{
        .key_id = api_key_data.key_id,
        .key_hash = api_key_data.key_hash,
        .username = api_key_data.username,
        .created_at = api_key_data.created_at,
        .expires_at = api_key_data.expires_at,
        .last_used = now,
        .metadata = api_key_data.metadata,
    };

    return try updated_data.toJson(allocator);
}
