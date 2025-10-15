const std = @import("std");
const raft = @import("raft");
const raft_state_machine = raft.state_machine;
const raft_types = raft.types;
const crypto_mod = @import("crypto.zig");

pub const KVError = error{
    KeyNotFound,
    InvalidCommand,
    NoMasterKey,
} || raft_types.RaftError;

// Key-Value store state machine
pub const KVStateMachine = struct {
    map: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) KVStateMachine {
        return .{
            .map = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *KVStateMachine) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    // Apply a command to the KV store
    // Commands format: "put:<key_len>:<key>:<value>", "delete:<key_len>:<key>"
    pub fn apply(self: *KVStateMachine, command: []const u8) ![]const u8 {
        var parts = std.mem.splitScalar(u8, command, ':');

        const op = parts.next() orelse return KVError.InvalidCommand;

        if (std.mem.eql(u8, op, "put")) {
            return try self.applyPut(&parts);
        }

        if (std.mem.eql(u8, op, "delete")) {
            return try self.applyDelete(&parts);
        }

        return KVError.InvalidCommand;
    }

    fn applyPut(self: *KVStateMachine, parts: anytype) ![]const u8 {
        const key_len_str = parts.next() orelse return KVError.InvalidCommand;
        const key_len = try std.fmt.parseInt(usize, key_len_str, 10);

        const remainder = parts.rest();
        if (remainder.len < key_len + 1) return KVError.InvalidCommand;

        const key = remainder[0..key_len];
        const value = remainder[key_len + 1 ..];

        try self.removeOldKeyValue(key);

        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        try self.map.put(key_copy, value_copy);

        return try std.fmt.allocPrint(self.allocator, "OK", .{});
    }

    fn applyDelete(self: *KVStateMachine, parts: anytype) ![]const u8 {
        const key_len_str = parts.next() orelse return KVError.InvalidCommand;
        const key_len = try std.fmt.parseInt(usize, key_len_str, 10);

        const remainder = parts.rest();
        if (remainder.len < key_len) return KVError.InvalidCommand;

        const key = remainder[0..key_len];

        const value = self.map.get(key) orelse return KVError.KeyNotFound;
        const old_key = self.map.getKey(key).?;
        _ = self.map.remove(key);
        self.allocator.free(value);
        self.allocator.free(old_key);

        return try std.fmt.allocPrint(self.allocator, "OK", .{});
    }

    fn removeOldKeyValue(self: *KVStateMachine, key: []const u8) !void {
        const old_value = self.map.get(key) orelse return;
        const old_key = self.map.getKey(key).?;
        _ = self.map.remove(key);
        self.allocator.free(old_value);
        self.allocator.free(old_key);
    }

    // Take a snapshot of the KV store
    pub fn takeSnapshot(self: *KVStateMachine, allocator: std.mem.Allocator) ![]const u8 {
        var list: std.ArrayList(u8) = .{};
        errdefer list.deinit(allocator);
        const writer = list.writer(allocator);

        var it = self.map.iterator();
        while (it.next()) |entry| {
            try writer.print("{}:{s}:{s}\n", .{ entry.key_ptr.*.len, entry.key_ptr.*, entry.value_ptr.* });
        }

        return try list.toOwnedSlice(allocator);
    }

    // Restore from a snapshot
    pub fn restoreSnapshot(self: *KVStateMachine, snapshot: []const u8) !void {
        self.clearState();

        if (snapshot.len == 0) {
            return;
        }

        var lines = std.mem.splitScalar(u8, snapshot, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) {
                continue;
            }

            try self.restoreLine(line);
        }
    }

    fn clearState(self: *KVStateMachine) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.clearRetainingCapacity();
    }

    fn restoreLine(self: *KVStateMachine, line: []const u8) !void {
        var parts = std.mem.splitScalar(u8, line, ':');
        const key_len_str = parts.next() orelse return KVError.InvalidCommand;
        const key_len = try std.fmt.parseInt(usize, key_len_str, 10);

        const remainder = parts.rest();
        if (remainder.len < key_len + 1) return KVError.InvalidCommand;

        const key = remainder[0..key_len];
        const value = remainder[key_len + 1 ..];

        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        try self.map.put(key_copy, value_copy);
    }

    pub fn stateMachine(self: *KVStateMachine) raft_state_machine.StateMachine(KVStateMachine) {
        return .{
            .applyFn = apply,
            .snapshotFn = takeSnapshot,
            .restoreFn = restoreSnapshot,
            .state = self,
        };
    }
};

// KV Store backed by Raft
pub const KVStore = struct {
    node: raft.Node(KVStateMachine),
    kv_state: *KVStateMachine,
    master_key: ?crypto_mod.EncryptionKey,

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
        if (self.kv_state.map.get(key)) |value| {
            return try allocator.dupe(u8, value);
        }
        return KVError.KeyNotFound;
    }

    // Delete a key
    pub fn delete(self: *KVStore, key: []const u8) !void {
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
        return self.kv_state.map.contains(key);
    }

    // Get the number of keys
    pub fn count(self: *KVStore) usize {
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
