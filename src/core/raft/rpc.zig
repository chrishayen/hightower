const std = @import("std");
const types = @import("types.zig");

// RequestVote RPC - invoked by candidates to gather votes
pub const RequestVoteRequest = struct {
    term: types.Term,
    candidate_id: types.NodeId,
    last_log_index: types.LogIndex,
    last_log_term: types.Term,

    pub fn format(
        self: RequestVoteRequest,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("RequestVoteRequest{{ term={}, candidate={}, last_log_index={}, last_log_term={} }}", .{
            self.term,
            self.candidate_id,
            self.last_log_index,
            self.last_log_term,
        });
    }
};

pub const RequestVoteResponse = struct {
    term: types.Term,
    vote_granted: bool,

    pub fn format(
        self: RequestVoteResponse,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("RequestVoteResponse{{ term={}, vote_granted={} }}", .{
            self.term,
            self.vote_granted,
        });
    }
};

// AppendEntries RPC - used for log replication and heartbeats
pub const AppendEntriesRequest = struct {
    term: types.Term,
    leader_id: types.NodeId,
    prev_log_index: types.LogIndex,
    prev_log_term: types.Term,
    entries: []const types.LogEntry,
    leader_commit: types.LogIndex,

    pub fn format(
        self: AppendEntriesRequest,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("AppendEntriesRequest{{ term={}, leader={}, prev_log_index={}, prev_log_term={}, entries_count={}, leader_commit={} }}", .{
            self.term,
            self.leader_id,
            self.prev_log_index,
            self.prev_log_term,
            self.entries.len,
            self.leader_commit,
        });
    }

    pub fn isHeartbeat(self: AppendEntriesRequest) bool {
        return self.entries.len == 0;
    }
};

pub const AppendEntriesResponse = struct {
    term: types.Term,
    success: bool,
    match_index: types.LogIndex,

    pub fn format(
        self: AppendEntriesResponse,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("AppendEntriesResponse{{ term={}, success={}, match_index={} }}", .{
            self.term,
            self.success,
            self.match_index,
        });
    }
};

// RPC message wrapper
pub const RpcMessage = union(enum) {
    request_vote_request: RequestVoteRequest,
    request_vote_response: RequestVoteResponse,
    append_entries_request: AppendEntriesRequest,
    append_entries_response: AppendEntriesResponse,

    pub fn format(
        self: RpcMessage,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .request_vote_request => |req| try writer.print("RPC(RequestVote: {})", .{req}),
            .request_vote_response => |resp| try writer.print("RPC(RequestVote: {})", .{resp}),
            .append_entries_request => |req| try writer.print("RPC(AppendEntries: {})", .{req}),
            .append_entries_response => |resp| try writer.print("RPC(AppendEntries: {})", .{resp}),
        }
    }
};
