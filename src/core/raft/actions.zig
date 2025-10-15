const std = @import("std");
const types = @import("types.zig");
const rpc = @import("rpc.zig");

// Actions that the Raft node wants to perform
// The imperative shell executes these actions
pub const Action = union(enum) {
    // Send RequestVote RPC to a node
    send_request_vote: struct {
        node_id: types.NodeId,
        request: rpc.RequestVoteRequest,
    },

    // Send AppendEntries RPC to a node
    send_append_entries: struct {
        node_id: types.NodeId,
        request: rpc.AppendEntriesRequest,
    },

    // Apply a committed entry to the state machine
    apply_entry: struct {
        index: types.LogIndex,
        data: []const u8,
    },

    // Persist state to disk
    persist_state: void,

    // Schedule next tick (milliseconds from now)
    schedule_tick: u64,
};

pub const ActionList = struct {
    items: std.ArrayList(Action),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ActionList {
        return .{
            .items = std.ArrayList(Action).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ActionList) void {
        self.items.deinit();
    }

    pub fn append(self: *ActionList, action: Action) !void {
        try self.items.append(action);
    }
};
