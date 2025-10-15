const std = @import("std");
const testing = std.testing;
const rpc = @import("rpc.zig");
const types = @import("types.zig");

test "RequestVoteRequest has correct fields" {
    const req = rpc.RequestVoteRequest{
        .term = 5,
        .candidate_id = 42,
        .last_log_index = 10,
        .last_log_term = 4,
    };

    try testing.expectEqual(@as(types.Term, 5), req.term);
    try testing.expectEqual(@as(types.NodeId, 42), req.candidate_id);
    try testing.expectEqual(@as(types.LogIndex, 10), req.last_log_index);
    try testing.expectEqual(@as(types.Term, 4), req.last_log_term);
}

test "RequestVoteResponse has correct fields" {
    const resp = rpc.RequestVoteResponse{
        .term = 5,
        .vote_granted = true,
    };

    try testing.expectEqual(@as(types.Term, 5), resp.term);
    try testing.expect(resp.vote_granted);
}

test "RequestVoteResponse can reject vote" {
    const resp = rpc.RequestVoteResponse{
        .term = 6,
        .vote_granted = false,
    };

    try testing.expectEqual(@as(types.Term, 6), resp.term);
    try testing.expect(!resp.vote_granted);
}

test "AppendEntriesRequest has correct fields" {
    const entries = [_]types.LogEntry{
        .{ .index = 1, .term = 1, .entry_type = .command, .data = "cmd1" },
        .{ .index = 2, .term = 1, .entry_type = .command, .data = "cmd2" },
    };

    const req = rpc.AppendEntriesRequest{
        .term = 5,
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &entries,
        .leader_commit = 0,
    };

    try testing.expectEqual(@as(types.Term, 5), req.term);
    try testing.expectEqual(@as(types.NodeId, 1), req.leader_id);
    try testing.expectEqual(@as(types.LogIndex, 0), req.prev_log_index);
    try testing.expectEqual(@as(types.Term, 0), req.prev_log_term);
    try testing.expectEqual(@as(usize, 2), req.entries.len);
    try testing.expectEqual(@as(types.LogIndex, 0), req.leader_commit);
}

test "AppendEntriesRequest isHeartbeat returns true for empty entries" {
    const req = rpc.AppendEntriesRequest{
        .term = 5,
        .leader_id = 1,
        .prev_log_index = 10,
        .prev_log_term = 4,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 10,
    };

    try testing.expect(req.isHeartbeat());
}

test "AppendEntriesRequest isHeartbeat returns false for non-empty entries" {
    const entries = [_]types.LogEntry{
        .{ .index = 1, .term = 1, .entry_type = .command, .data = "cmd1" },
    };

    const req = rpc.AppendEntriesRequest{
        .term = 5,
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &entries,
        .leader_commit = 0,
    };

    try testing.expect(!req.isHeartbeat());
}

test "AppendEntriesResponse has correct fields" {
    const resp = rpc.AppendEntriesResponse{
        .term = 5,
        .success = true,
        .match_index = 10,
    };

    try testing.expectEqual(@as(types.Term, 5), resp.term);
    try testing.expect(resp.success);
    try testing.expectEqual(@as(types.LogIndex, 10), resp.match_index);
}

test "AppendEntriesResponse can indicate failure" {
    const resp = rpc.AppendEntriesResponse{
        .term = 6,
        .success = false,
        .match_index = 0,
    };

    try testing.expectEqual(@as(types.Term, 6), resp.term);
    try testing.expect(!resp.success);
    try testing.expectEqual(@as(types.LogIndex, 0), resp.match_index);
}

test "RpcMessage can wrap RequestVoteRequest" {
    const req = rpc.RequestVoteRequest{
        .term = 5,
        .candidate_id = 42,
        .last_log_index = 10,
        .last_log_term = 4,
    };

    const msg = rpc.RpcMessage{ .request_vote_request = req };

    try testing.expectEqual(@as(types.Term, 5), msg.request_vote_request.term);
}

test "RpcMessage can wrap RequestVoteResponse" {
    const resp = rpc.RequestVoteResponse{
        .term = 5,
        .vote_granted = true,
    };

    const msg = rpc.RpcMessage{ .request_vote_response = resp };

    try testing.expect(msg.request_vote_response.vote_granted);
}

test "RpcMessage can wrap AppendEntriesRequest" {
    const req = rpc.AppendEntriesRequest{
        .term = 5,
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 0,
    };

    const msg = rpc.RpcMessage{ .append_entries_request = req };

    try testing.expectEqual(@as(types.NodeId, 1), msg.append_entries_request.leader_id);
}

test "RpcMessage can wrap AppendEntriesResponse" {
    const resp = rpc.AppendEntriesResponse{
        .term = 5,
        .success = true,
        .match_index = 10,
    };

    const msg = rpc.RpcMessage{ .append_entries_response = resp };

    try testing.expect(msg.append_entries_response.success);
}
