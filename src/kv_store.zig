const std = @import("std");
const raft = @import("raft");
const raft_types = raft.types;
const kv_state_machine = @import("core/kv/state_machine.zig");
const crypto_mod = @import("core/kv/crypto.zig");

pub const KVError = error{
    KeyNotFound,
    InvalidCommand,
    NoMasterKey,
} || raft_types.RaftError;

// Re-export KVStateMachine for convenience
pub const KVStateMachine = kv_state_machine.KVStateMachine;

// KV Store backed by Raft (Imperative Shell)
pub const KVStore = struct {
    node: raft.Node(KVStateMachine),
    kv_state: *KVStateMachine,
    master_key: ?crypto_mod.EncryptionKey,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, node_id: raft_types.NodeId) !KVStore {
        const kv_state = try allocator.create(KVStateMachine);
        errdefer allocator.destroy(kv_state);

        kv_state.* = KVStateMachine.init(allocator);
        errdefer kv_state.deinit();

        const node = try raft.Node(KVStateMachine).init(
            allocator,
            node_id,
            kv_state.stateMachine(),
            @intCast(std.time.milliTimestamp()),
        );

        return .{
            .node = node,
            .kv_state = kv_state,
            .master_key = null,
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *KVStore, allocator: std.mem.Allocator) void {
        self.node.deinit();
        self.kv_state.deinit();
        allocator.destroy(self.kv_state);
    }

    pub fn setMasterKey(self: *KVStore, key: crypto_mod.EncryptionKey) void {
        self.master_key = key;
    }

    pub fn generateAndSetMasterKey(self: *KVStore) !void {
        self.master_key = try crypto_mod.EncryptionKey.generate();
    }

    // Bootstrap as single-node cluster
    pub fn bootstrap(self: *KVStore, address: []const u8) !void {
        try self.node.bootstrapSingleNode(address);
    }

    // Put a key-value pair
    pub fn put(self: *KVStore, key: []const u8, value: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const command = try std.fmt.allocPrint(
            self.node.allocator,
            "put:{}:{s}:{s}",
            .{ key.len, key, value },
        );
        defer self.node.allocator.free(command);

        const result = try self.node.submitCommand(command);
        defer self.node.allocator.free(result);
    }

    // Get a value by key
    pub fn get(self: *KVStore, allocator: std.mem.Allocator, key: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.kv_state.map.get(key)) |value| {
            return try allocator.dupe(u8, value);
        }
        return KVError.KeyNotFound;
    }

    // Delete a key
    pub fn delete(self: *KVStore, key: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const command = try std.fmt.allocPrint(
            self.node.allocator,
            "delete:{}:{s}",
            .{ key.len, key },
        );
        defer self.node.allocator.free(command);

        const result = try self.node.submitCommand(command);
        defer self.node.allocator.free(result);
    }

    // Check if a key exists
    pub fn contains(self: *KVStore, key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.kv_state.map.contains(key);
    }

    // Get the number of keys
    pub fn count(self: *KVStore) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.kv_state.map.count();
    }

    // Put an encrypted value
    pub fn putEncrypted(self: *KVStore, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        const master_key = self.master_key orelse return KVError.NoMasterKey;

        const encrypted_value = try master_key.encrypt(allocator, value);
        defer allocator.free(encrypted_value);

        const enc_key = try std.fmt.allocPrint(allocator, "__enc:{s}", .{key});
        defer allocator.free(enc_key);

        try self.put(enc_key, encrypted_value);
    }

    // Get an encrypted value
    pub fn getEncrypted(self: *KVStore, allocator: std.mem.Allocator, key: []const u8) ![]const u8 {
        const master_key = self.master_key orelse return KVError.NoMasterKey;

        const enc_key = try std.fmt.allocPrint(allocator, "__enc:{s}", .{key});
        defer allocator.free(enc_key);

        const encrypted_value = try self.get(allocator, enc_key);
        defer allocator.free(encrypted_value);

        return try master_key.decrypt(allocator, encrypted_value);
    }

    // Delete an encrypted value
    pub fn deleteEncrypted(self: *KVStore, allocator: std.mem.Allocator, key: []const u8) !void {
        const enc_key = try std.fmt.allocPrint(allocator, "__enc:{s}", .{key});
        defer allocator.free(enc_key);

        try self.delete(enc_key);
    }
};
