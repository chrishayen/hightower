const std = @import("std");
const types = @import("types.zig");

// Persistent state for a Raft node
pub const PersistentState = struct {
    current_term: types.Term,
    voted_for: ?types.NodeId,
    log: std.ArrayList(types.LogEntry),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PersistentState {
        return .{
            .current_term = 0,
            .voted_for = null,
            .log = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PersistentState) void {
        for (self.log.items) |entry| {
            self.allocator.free(entry.data);
        }
        self.log.deinit(self.allocator);
    }

    pub fn setTerm(self: *PersistentState, term: types.Term) void {
        if (term > self.current_term) {
            self.current_term = term;
            self.voted_for = null;
        }
    }

    pub fn voteFor(self: *PersistentState, node_id: types.NodeId) !void {
        if (self.voted_for != null and self.voted_for.? != node_id) {
            return types.RaftError.InvalidState;
        }
        self.voted_for = node_id;
    }

    pub fn appendEntry(self: *PersistentState, term: types.Term, entry_type: types.LogEntryType, data: []const u8) !types.LogIndex {
        const index = self.log.items.len + 1;
        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);

        try self.log.append(self.allocator, .{
            .index = index,
            .term = term,
            .entry_type = entry_type,
            .data = data_copy,
        });

        return index;
    }

    pub fn getEntry(self: PersistentState, index: types.LogIndex) ?types.LogEntry {
        if (index == 0 or index > self.log.items.len) {
            return null;
        }
        return self.log.items[index - 1];
    }

    pub fn getLastLogIndex(self: PersistentState) types.LogIndex {
        return self.log.items.len;
    }

    pub fn getLastLogTerm(self: PersistentState) types.Term {
        if (self.log.items.len == 0) {
            return 0;
        }
        return self.log.items[self.log.items.len - 1].term;
    }

    pub fn deleteEntriesFrom(self: *PersistentState, index: types.LogIndex) !void {
        if (index == 0 or index > self.log.items.len + 1) {
            return types.RaftError.InvalidIndex;
        }

        const start_idx = index - 1;
        for (self.log.items[start_idx..]) |entry| {
            self.allocator.free(entry.data);
        }

        try self.log.resize(self.allocator, start_idx);
    }

    pub fn truncateLogAfter(self: *PersistentState, index: types.LogIndex) !void {
        if (index > self.log.items.len) {
            return types.RaftError.InvalidIndex;
        }

        for (self.log.items[index..]) |entry| {
            self.allocator.free(entry.data);
        }

        try self.log.resize(self.allocator, index);
    }
};

// Volatile state on all servers
pub const VolatileState = struct {
    commit_index: types.LogIndex,
    last_applied: types.LogIndex,

    pub fn init() VolatileState {
        return .{
            .commit_index = 0,
            .last_applied = 0,
        };
    }

    pub fn updateCommitIndex(self: *VolatileState, new_index: types.LogIndex) void {
        if (new_index > self.commit_index) {
            self.commit_index = new_index;
        }
    }

    pub fn applyEntry(self: *VolatileState) !types.LogIndex {
        if (self.last_applied >= self.commit_index) {
            return types.RaftError.InvalidState;
        }
        self.last_applied += 1;
        return self.last_applied;
    }

    pub fn hasUnappliedEntries(self: VolatileState) bool {
        return self.last_applied < self.commit_index;
    }
};

// Volatile state on leaders
pub const LeaderState = struct {
    next_index: std.AutoHashMap(types.NodeId, types.LogIndex),
    match_index: std.AutoHashMap(types.NodeId, types.LogIndex),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) LeaderState {
        return .{
            .next_index = std.AutoHashMap(types.NodeId, types.LogIndex).init(allocator),
            .match_index = std.AutoHashMap(types.NodeId, types.LogIndex).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LeaderState) void {
        self.next_index.deinit();
        self.match_index.deinit();
    }

    pub fn initializeForNode(self: *LeaderState, node_id: types.NodeId, last_log_index: types.LogIndex) !void {
        try self.next_index.put(node_id, last_log_index + 1);
        try self.match_index.put(node_id, 0);
    }

    pub fn updateForNode(self: *LeaderState, node_id: types.NodeId, match: types.LogIndex) !void {
        try self.match_index.put(node_id, match);
        try self.next_index.put(node_id, match + 1);
    }

    pub fn decrementNextIndex(self: *LeaderState, node_id: types.NodeId) !void {
        const current = self.next_index.get(node_id) orelse return types.RaftError.NodeNotFound;
        if (current > 1) {
            try self.next_index.put(node_id, current - 1);
        }
    }

    pub fn getNextIndex(self: LeaderState, node_id: types.NodeId) ?types.LogIndex {
        return self.next_index.get(node_id);
    }

    pub fn getMatchIndex(self: LeaderState, node_id: types.NodeId) ?types.LogIndex {
        return self.match_index.get(node_id);
    }
};
