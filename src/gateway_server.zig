const std = @import("std");
const gateway_core = @import("core/gateway/server.zig");
const kv = @import("core/kv/store.zig");

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
}

fn loadKVStore(allocator: std.mem.Allocator, dir_path: []const u8) !kv.KVStore {
    var store = try kv.KVStore.init(allocator, 1);
    errdefer store.deinit(allocator);

    try store.bootstrap("localhost:0");

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
