const std = @import("std");

// Node identifier
pub const NodeId = u64;

// Term number for leader election
pub const Term = u64;

// Log index
pub const LogIndex = u64;

// Node states in Raft protocol
pub const NodeState = enum {
    follower,
    candidate,
    leader,
};

// Type of log entry
pub const LogEntryType = enum {
    command,
    config_change,
    noop,
};

// Configuration change operations
pub const ConfigChangeOp = union(enum) {
    add_node: NodeInfo,
    remove_node: NodeId,

    pub fn format(
        self: ConfigChangeOp,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .add_node => |info| try writer.print("AddNode({}, {})", .{ info.id, info.address }),
            .remove_node => |id| try writer.print("RemoveNode({})", .{id}),
        }
    }
};

// Information about a cluster node
pub const NodeInfo = struct {
    id: NodeId,
    address: []const u8,

    pub fn format(
        self: NodeInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("NodeInfo{{ id={}, address=\"{}\" }}", .{ self.id, self.address });
    }
};

// Entry in the replicated log
pub const LogEntry = struct {
    index: LogIndex,
    term: Term,
    entry_type: LogEntryType,
    data: []const u8,

    pub fn format(
        self: LogEntry,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("LogEntry{{ index={}, term={}, type={s}, data_len={} }}", .{
            self.index,
            self.term,
            @tagName(self.entry_type),
            self.data.len,
        });
    }
};

// Error set for Raft operations
pub const RaftError = error{
    NotLeader,
    NoQuorum,
    InvalidTerm,
    InvalidIndex,
    LogMismatch,
    InvalidConfiguration,
    NodeNotFound,
    NodeAlreadyExists,
    StorageError,
    NetworkError,
    Timeout,
    InvalidState,
};
