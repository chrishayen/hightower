const std = @import("std");
const gateway_core = @import("core/gateway/server.zig");
const kv = @import("core/kv/store.zig");
const auth_mod = @import("core/kv/auth.zig");
const crypto_mod = @import("core/kv/crypto.zig");

const log = std.log.scoped(.gateway_server);

pub const ServerConfig = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    auth_key: ?[]const u8 = null,
    kv_path: []const u8,
};

pub const Server = struct {
    config: ServerConfig,
    kv_store: kv.KVStore,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Server {
        log.info("Loading KV store from: {s}", .{config.kv_path});
        var kv_store = try loadKVStore(allocator, config.kv_path);
        errdefer kv_store.deinit(allocator);

        // Bootstrap admin user on first run
        try bootstrapAdminUser(allocator, &kv_store);

        // Bootstrap initial auth key if provided
        if (config.auth_key) |auth_key| {
            try bootstrapInitialAuthKey(allocator, &kv_store, auth_key);
        }

        return Server{
            .config = config,
            .kv_store = kv_store,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Server) void {
        log.info("Saving KV store to: {s}", .{self.config.kv_path});
        saveKVStore(self.allocator, &self.kv_store, self.config.kv_path) catch |err| {
            log.err("Failed to save KV store: {}", .{err});
        };
        self.kv_store.deinit(self.allocator);
    }

    pub fn run(self: *Server) !void {
        const core_config = gateway_core.ServerConfig{
            .port = self.config.port,
            .address = self.config.address,
            .auth_key = self.config.auth_key,
        };

        var core_server = gateway_core.Server.init(core_config, &self.kv_store);

        log.info("Gateway server starting on {s}:{d}", .{ self.config.address, self.config.port });
        try core_server.run(self.allocator);
    }
};

fn saveKVStore(allocator: std.mem.Allocator, store: *kv.KVStore, dir_path: []const u8) !void {
    const snapshot = try store.kv_state.takeSnapshot(allocator);
    defer allocator.free(snapshot);

    const state_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "state.dat" });
    defer allocator.free(state_path);

    const file = try std.fs.cwd().createFile(state_path, .{});
    defer file.close();

    try file.writeAll(snapshot);

    try saveMasterKey(allocator, store, dir_path);
}

fn loadKVStore(allocator: std.mem.Allocator, dir_path: []const u8) !kv.KVStore {
    var store = try kv.KVStore.init(allocator, 1);
    errdefer store.deinit(allocator);

    try store.bootstrap("localhost:0");

    // Load master key if it exists, otherwise generate one
    if (try loadMasterKey(allocator, dir_path)) |master_key| {
        store.setMasterKey(master_key);
    } else {
        try store.generateAndSetMasterKey();
        try saveMasterKey(allocator, &store, dir_path);
        log.info("Generated new master encryption key", .{});
    }

    const state_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "state.dat" });
    defer allocator.free(state_path);

    const file = std.fs.cwd().openFile(state_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            log.info("No existing KV store found, starting fresh", .{});
            return store;
        }
        return err;
    };
    defer file.close();

    const snapshot = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(snapshot);

    try store.kv_state.restoreSnapshot(snapshot);
    log.info("KV store restored from snapshot", .{});

    return store;
}

fn loadMasterKey(allocator: std.mem.Allocator, dir_path: []const u8) !?crypto_mod.EncryptionKey {
    // Check environment variable first
    if (std.process.getEnvVarOwned(allocator, "HT_KV_MASTER_KEY")) |key_str| {
        defer allocator.free(key_str);
        return try crypto_mod.EncryptionKey.fromString(key_str);
    } else |_| {}

    // Try to load from file
    const key_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "master.key" });
    defer allocator.free(key_path);

    const file = std.fs.cwd().openFile(key_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return null;
        }
        return err;
    };
    defer file.close();

    const key_str = try file.readToEndAlloc(allocator, 1024);
    defer allocator.free(key_str);

    return try crypto_mod.EncryptionKey.fromString(key_str);
}

fn saveMasterKey(allocator: std.mem.Allocator, store: *kv.KVStore, dir_path: []const u8) !void {
    const master_key = store.master_key orelse return;

    const key_str = try master_key.toString(allocator);
    defer allocator.free(key_str);

    const key_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "master.key" });
    defer allocator.free(key_path);

    const file = try std.fs.cwd().createFile(key_path, .{ .mode = 0o600 });
    defer file.close();

    try file.writeAll(key_str);
}

fn generateRandomPassword(allocator: std.mem.Allocator) ![]const u8 {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    var password = try allocator.alloc(u8, 24);
    errdefer allocator.free(password);

    var random_bytes: [24]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    for (random_bytes, 0..) |byte, i| {
        password[i] = charset[@as(usize, byte) % charset.len];
    }

    return password;
}

fn bootstrapAdminUser(allocator: std.mem.Allocator, store: *kv.KVStore) !void {
    // Check if admin user already exists
    const admin_exists = blk: {
        _ = auth_mod.getUser(store, allocator, "admin") catch |err| {
            if (err == auth_mod.AuthError.UserNotFound) {
                break :blk false;
            }
            return err;
        };
        break :blk true;
    };

    if (admin_exists) {
        return;
    }

    // Generate random password
    const password = try generateRandomPassword(allocator);
    defer allocator.free(password);

    // Create admin user
    try auth_mod.createUser(store, allocator, "admin", password, "{}");

    // Print password to console (only on first run)
    log.warn("Admin user created - username: admin, password: {s}", .{password});
}

fn bootstrapInitialAuthKey(allocator: std.mem.Allocator, store: *kv.KVStore, auth_key: []const u8) !void {
    const marker_key = "__auth:initial_key_marker";

    if (store.contains(marker_key)) {
        return;
    }

    const api_key = try crypto_mod.ApiKey.fromString(auth_key);
    const key_id = try crypto_mod.generateUuid(allocator);
    errdefer allocator.free(key_id);

    const key_hash = api_key.hash();
    const key_hash_hex = std.fmt.bytesToHex(&key_hash, .lower);
    const key_hash_str = try allocator.dupe(u8, &key_hash_hex);
    defer allocator.free(key_hash_str);

    const now = std.time.milliTimestamp();
    const metadata = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"initial_auth_key\",\"created_at\":{}}}",
        .{now},
    );
    defer allocator.free(metadata);

    const api_key_data = auth_mod.ApiKeyData{
        .key_id = key_id,
        .key_hash = key_hash_str,
        .username = "admin",
        .created_at = now,
        .expires_at = null,
        .last_used = null,
        .metadata = metadata,
    };

    const kv_key = try std.fmt.allocPrint(allocator, "__auth:apikey:{s}", .{key_id});
    defer allocator.free(kv_key);

    const api_key_json = try api_key_data.toJson(allocator);
    defer allocator.free(api_key_json);

    try store.put(kv_key, api_key_json);
    try store.put(marker_key, "1");

    log.info("Initial auth key saved as API key for admin user", .{});
}
