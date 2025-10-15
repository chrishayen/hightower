const std = @import("std");
const raft = @import("raft");
const raft_state_machine = raft.state_machine;

pub const KVError = error{
    KeyNotFound,
    InvalidCommand,
};

// Key-Value store state machine (Pure functional core)
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
