const std = @import("std");
const testing = std.testing;
const node_mod = @import("node.zig");
const state_machine = @import("state_machine.zig");
const rpc = @import("rpc.zig");
const types = @import("types.zig");

test "Node init creates follower" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    try testing.expectEqual(types.NodeState.follower, node.getState());
    try testing.expectEqual(@as(types.Term, 0), node.getTerm());
}

test "Node bootstrapSingleNode makes node leader" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    try node.bootstrapSingleNode("localhost:8000");

    try testing.expect(node.isLeader());
    try testing.expectEqual(@as(usize, 1), node.cluster_config.nodes.len);
}

test "Node single-node submitCommand applies immediately" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    try node.bootstrapSingleNode("localhost:8000");

    const result1 = try node.submitCommand("increment");
    defer testing.allocator.free(result1);
    try testing.expectEqualStrings("1", result1);

    const result2 = try node.submitCommand("increment");
    defer testing.allocator.free(result2);
    try testing.expectEqualStrings("2", result2);

    try testing.expectEqual(@as(i64, 2), sm.value);
}

test "Node single-node submitCommand updates commit index" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    try node.bootstrapSingleNode("localhost:8000");

    const result = try node.submitCommand("increment");
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(types.LogIndex, 1), node.volatile_state.commit_index);
    try testing.expectEqual(@as(types.LogIndex, 1), node.volatile_state.last_applied);
}

test "Node non-leader cannot submit commands" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    try testing.expectError(types.RaftError.NotLeader, node.submitCommand("increment"));
}

test "Node handleRequestVote grants vote for valid request" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    const request = rpc.RequestVoteRequest{
        .term = 1,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    const response = try node.handleRequestVote(request);
    try testing.expect(response.vote_granted);
    try testing.expectEqual(@as(types.Term, 1), response.term);
}

test "Node handleRequestVote rejects stale term" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    node.persistent_state.current_term = 5;

    const request = rpc.RequestVoteRequest{
        .term = 3,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    const response = try node.handleRequestVote(request);
    try testing.expect(!response.vote_granted);
    try testing.expectEqual(@as(types.Term, 5), response.term);
}

test "Node handleRequestVote rejects if already voted" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    const request1 = rpc.RequestVoteRequest{
        .term = 1,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    _ = try node.handleRequestVote(request1);

    const request2 = rpc.RequestVoteRequest{
        .term = 1,
        .candidate_id = 3,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    const response = try node.handleRequestVote(request2);
    try testing.expect(!response.vote_granted);
}

test "Node handleRequestVote updates term if higher" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    node.persistent_state.current_term = 1;

    const request = rpc.RequestVoteRequest{
        .term = 5,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    _ = try node.handleRequestVote(request);
    try testing.expectEqual(@as(types.Term, 5), node.getTerm());
}

test "Node handleAppendEntries accepts valid heartbeat" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    const request = rpc.AppendEntriesRequest{
        .term = 1,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 0,
    };

    const response = try node.handleAppendEntries(request);
    try testing.expect(response.success);
    try testing.expectEqual(@as(types.Term, 1), response.term);
}

test "Node handleAppendEntries rejects stale term" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    node.persistent_state.current_term = 5;

    const request = rpc.AppendEntriesRequest{
        .term = 3,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 0,
    };

    const response = try node.handleAppendEntries(request);
    try testing.expect(!response.success);
    try testing.expectEqual(@as(types.Term, 5), response.term);
}

test "Node handleAppendEntries becomes follower on valid request" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    try node.bootstrapSingleNode("localhost:8000");
    try testing.expect(node.isLeader());

    const request = rpc.AppendEntriesRequest{
        .term = 2,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 0,
    };

    _ = try node.handleAppendEntries(request);
    try testing.expectEqual(types.NodeState.follower, node.getState());
    try testing.expectEqual(@as(?types.NodeId, 2), node.current_leader);
}

test "Node handleAppendEntries updates commit index" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    // Add some entries
    _ = try node.persistent_state.appendEntry(1, .command, "increment");
    _ = try node.persistent_state.appendEntry(1, .command, "increment");

    const request = rpc.AppendEntriesRequest{
        .term = 1,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 2,
    };

    _ = try node.handleAppendEntries(request);
    try testing.expectEqual(@as(types.LogIndex, 2), node.volatile_state.commit_index);
}

test "Node handleAppendEntries resolves log conflicts with correct indices" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    var node = try node_mod.Node(state_machine.TestStateMachine).init(
        testing.allocator,
        1,
        sm.stateMachine(),
        12345,
    );
    defer node.deinit();

    // Follower has entries at indices 1, 2, 3 with terms 1, 1, 2
    _ = try node.persistent_state.appendEntry(1, .command, "cmd1");
    _ = try node.persistent_state.appendEntry(1, .command, "cmd2");
    _ = try node.persistent_state.appendEntry(2, .command, "cmd3");

    try testing.expectEqual(@as(types.LogIndex, 3), node.persistent_state.getLastLogIndex());

    // Leader sends entries for indices 3, 4 with term 3
    // This should conflict with existing entry 3 (term 2) and replace it
    const entry3 = types.LogEntry{
        .index = 3,
        .term = 3,
        .entry_type = .command,
        .data = "new_cmd3",
    };
    const entry4 = types.LogEntry{
        .index = 4,
        .term = 3,
        .entry_type = .command,
        .data = "cmd4",
    };
    const entries = [_]types.LogEntry{ entry3, entry4 };

    const request = rpc.AppendEntriesRequest{
        .term = 3,
        .leader_id = 2,
        .prev_log_index = 2,
        .prev_log_term = 1,
        .entries = &entries,
        .leader_commit = 0,
    };

    const response = try node.handleAppendEntries(request);
    try testing.expect(response.success);

    // Should have 4 entries now
    try testing.expectEqual(@as(types.LogIndex, 4), node.persistent_state.getLastLogIndex());

    // Entry 3 should have term 3 and new data
    const actual_entry3 = node.persistent_state.getEntry(3).?;
    try testing.expectEqual(@as(types.Term, 3), actual_entry3.term);
    try testing.expectEqualStrings("new_cmd3", actual_entry3.data);

    // Entry 4 should exist with term 3
    const actual_entry4 = node.persistent_state.getEntry(4).?;
    try testing.expectEqual(@as(types.Term, 3), actual_entry4.term);
    try testing.expectEqualStrings("cmd4", actual_entry4.data);
}
