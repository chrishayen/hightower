const std = @import("std");
const testing = std.testing;
const node_mod = @import("node.zig");
const state_machine = @import("state_machine.zig");
const rpc = @import("rpc.zig");
const types = @import("types.zig");
const config = @import("config.zig");

// Test helper: 3-node cluster
const TestCluster = struct {
    nodes: [3]node_mod.Node(state_machine.TestStateMachine),
    state_machines: [3]state_machine.TestStateMachine,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !TestCluster {
        var cluster: TestCluster = undefined;
        cluster.allocator = allocator;

        // Initialize state machines
        for (0..3) |i| {
            cluster.state_machines[i] = state_machine.TestStateMachine.init(allocator);
        }

        // Initialize nodes with different seeds for different election timeouts
        cluster.nodes[0] = try node_mod.Node(state_machine.TestStateMachine).init(
            allocator,
            1,
            cluster.state_machines[0].stateMachine(),
            100,
        );
        cluster.nodes[1] = try node_mod.Node(state_machine.TestStateMachine).init(
            allocator,
            2,
            cluster.state_machines[1].stateMachine(),
            200,
        );
        cluster.nodes[2] = try node_mod.Node(state_machine.TestStateMachine).init(
            allocator,
            3,
            cluster.state_machines[2].stateMachine(),
            300,
        );

        // Configure cluster membership
        for (0..3) |i| {
            try cluster.nodes[i].cluster_config.addNode(.{ .id = 1, .address = "node1:8000" });
            try cluster.nodes[i].cluster_config.addNode(.{ .id = 2, .address = "node2:8000" });
            try cluster.nodes[i].cluster_config.addNode(.{ .id = 3, .address = "node3:8000" });
        }

        return cluster;
    }

    fn deinit(self: *TestCluster) void {
        for (0..3) |i| {
            self.nodes[i].deinit();
        }
    }

    fn findLeader(self: *TestCluster) ?usize {
        for (0..3) |i| {
            if (self.nodes[i].isLeader()) {
                return i;
            }
        }
        return null;
    }

    fn countLeaders(self: *TestCluster) usize {
        var count: usize = 0;
        for (0..3) |i| {
            if (self.nodes[i].isLeader()) {
                count += 1;
            }
        }
        return count;
    }

    fn countCandidates(self: *TestCluster) usize {
        var count: usize = 0;
        for (0..3) |i| {
            if (self.nodes[i].getState() == .candidate) {
                count += 1;
            }
        }
        return count;
    }
};

test "Election: follower times out and becomes candidate" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    const node = &cluster.nodes[0];

    // Initially follower
    try testing.expectEqual(types.NodeState.follower, node.getState());

    // Simulate election timeout
    const now = 1000;
    node.election_deadline = now - 1; // Expired

    const actions = try node.tick(now);
    defer actions.items.deinit();

    // Should become candidate
    try testing.expectEqual(types.NodeState.candidate, node.getState());
    try testing.expectEqual(@as(types.Term, 1), node.getTerm());

    // Should send RequestVote to other nodes
    var request_vote_count: usize = 0;
    for (actions.items.items) |action| {
        if (action == .send_request_vote) {
            request_vote_count += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), request_vote_count); // 2 other nodes
}

test "Election: candidate wins with majority votes" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var candidate = &cluster.nodes[0];
    const term: types.Term = 1;

    // Become candidate
    try candidate.becomeCandidate();

    // Record votes from majority (self + 1 other)
    const won = try candidate.recordVote(2, true);

    try testing.expect(won);
}

test "Election: candidate loses without majority votes" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var candidate = &cluster.nodes[0];

    // Become candidate
    try candidate.becomeCandidate();

    // Only self vote, no majority (needs 2/3)
    const won = try candidate.recordVote(2, false);

    try testing.expect(!won);
}

test "Election: RequestVote grants vote to first candidate in term" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var node1 = &cluster.nodes[0];
    var node2 = &cluster.nodes[1];

    // Node 2 becomes candidate
    try node2.becomeCandidate();
    const term = node2.getTerm();

    // Node 1 receives RequestVote from node 2
    const request = rpc.RequestVoteRequest{
        .term = term,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    const response = try node1.handleRequestVote(request);

    try testing.expect(response.vote_granted);
    try testing.expectEqual(term, response.term);
}

test "Election: RequestVote rejects if already voted for different candidate" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var node = &cluster.nodes[0];

    const term: types.Term = 1;
    node.persistent_state.current_term = term;

    // Vote for node 2
    const request1 = rpc.RequestVoteRequest{
        .term = term,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };
    _ = try node.handleRequestVote(request1);

    // Node 3 requests vote in same term
    const request2 = rpc.RequestVoteRequest{
        .term = term,
        .candidate_id = 3,
        .last_log_index = 0,
        .last_log_term = 0,
    };
    const response = try node.handleRequestVote(request2);

    try testing.expect(!response.vote_granted);
}

test "Election: higher term causes candidate to step down" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var candidate = &cluster.nodes[0];

    // Become candidate in term 1
    try candidate.becomeCandidate();
    try testing.expectEqual(@as(types.Term, 1), candidate.getTerm());
    try testing.expectEqual(types.NodeState.candidate, candidate.getState());

    // Receive RequestVote from higher term
    const request = rpc.RequestVoteRequest{
        .term = 2,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    };
    _ = try candidate.handleRequestVote(request);

    // Should become follower and update term
    try testing.expectEqual(types.NodeState.follower, candidate.getState());
    try testing.expectEqual(@as(types.Term, 2), candidate.getTerm());
}

test "Replication: leader sends heartbeats on tick" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var leader = &cluster.nodes[0];

    // Manually make node leader
    try leader.becomeLeader();
    leader.last_heartbeat_time = 0;

    // Tick after heartbeat interval
    const now = leader.timing_config.heartbeat_interval + 1;
    const actions = try leader.tick(now);
    defer actions.items.deinit();

    // Should send AppendEntries to followers
    var heartbeat_count: usize = 0;
    for (actions.items.items) |action| {
        if (action == .send_append_entries) {
            heartbeat_count += 1;
            try testing.expect(action.send_append_entries.request.isHeartbeat());
        }
    }
    try testing.expectEqual(@as(usize, 2), heartbeat_count); // 2 followers
}

test "Replication: follower accepts heartbeat and updates commit index" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var follower = &cluster.nodes[0];

    // Add some entries to follower log
    _ = try follower.persistent_state.appendEntry(1, .command, "cmd1");
    _ = try follower.persistent_state.appendEntry(1, .command, "cmd2");

    try testing.expectEqual(@as(types.LogIndex, 0), follower.volatile_state.commit_index);

    // Receive heartbeat from leader with commit index = 2
    const request = rpc.AppendEntriesRequest{
        .term = 1,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 2,
    };

    const response = try follower.handleAppendEntries(request);

    try testing.expect(response.success);
    try testing.expectEqual(@as(types.LogIndex, 2), follower.volatile_state.commit_index);
}

test "Replication: leader updates commit index after quorum replication" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var leader = &cluster.nodes[0];

    // Make node leader
    try leader.becomeLeader();

    // Leader appends entries
    _ = try leader.persistent_state.appendEntry(1, .command, "cmd1");
    _ = try leader.persistent_state.appendEntry(1, .command, "cmd2");

    try testing.expectEqual(@as(types.LogIndex, 0), leader.volatile_state.commit_index);

    // Simulate successful replication to majority (node 2)
    const ls = &leader.leader_state.?;
    try ls.updateForNode(2, 2);

    // Update commit index
    try leader.updateCommitIndex();

    // Should commit entries (leader + 1 follower = quorum)
    try testing.expectEqual(@as(types.LogIndex, 2), leader.volatile_state.commit_index);
}

test "Replication: leader only commits entries from current term" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var leader = &cluster.nodes[0];

    // Make node leader in term 2
    try leader.becomeLeader();
    leader.persistent_state.current_term = 2;

    // Append entries from previous term and current term
    _ = try leader.persistent_state.appendEntry(1, .command, "cmd1");
    _ = try leader.persistent_state.appendEntry(2, .command, "cmd2");

    // Simulate replication to majority
    const ls = &leader.leader_state.?;
    try ls.updateForNode(2, 2);

    // Update commit index
    try leader.updateCommitIndex();

    // Should only commit entry from current term (term 2)
    try testing.expectEqual(@as(types.LogIndex, 2), leader.volatile_state.commit_index);
}

test "Replication: follower rejects entries with mismatched prev_log" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var follower = &cluster.nodes[0];

    // Follower has entry at index 1, term 1
    _ = try follower.persistent_state.appendEntry(1, .command, "cmd1");

    // Leader tries to append with prev_log_index=1, prev_log_term=2 (mismatch)
    const entry = types.LogEntry{
        .index = 2,
        .term = 2,
        .entry_type = .command,
        .data = "cmd2",
    };
    const entries = [_]types.LogEntry{entry};

    const request = rpc.AppendEntriesRequest{
        .term = 2,
        .leader_id = 2,
        .prev_log_index = 1,
        .prev_log_term = 2, // Mismatch
        .entries = &entries,
        .leader_commit = 0,
    };

    const response = try follower.handleAppendEntries(request);

    try testing.expect(!response.success);
}

test "Replication: leader decrements nextIndex on failure" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var leader = &cluster.nodes[0];

    // Make node leader
    try leader.becomeLeader();

    const ls = &leader.leader_state.?;
    const initial_next_index = ls.getNextIndex(2).?;

    // Simulate failed replication
    const response = rpc.AppendEntriesResponse{
        .term = 1,
        .success = false,
        .match_index = 0,
    };

    try leader.handleAppendEntriesResponse(2, response);

    // Should decrement nextIndex
    const new_next_index = ls.getNextIndex(2).?;
    try testing.expectEqual(initial_next_index - 1, new_next_index);
}

test "Replication: leader updates match/next index on success" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var leader = &cluster.nodes[0];

    // Make node leader
    try leader.becomeLeader();

    const ls = &leader.leader_state.?;

    // Simulate successful replication to index 5
    const response = rpc.AppendEntriesResponse{
        .term = 1,
        .success = true,
        .match_index = 5,
    };

    try leader.handleAppendEntriesResponse(2, response);

    // Should update match and next index
    try testing.expectEqual(@as(types.LogIndex, 5), ls.getMatchIndex(2).?);
    try testing.expectEqual(@as(types.LogIndex, 6), ls.getNextIndex(2).?);
}

test "Replication: follower applies committed entries to state machine" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var follower = &cluster.nodes[0];
    const sm = &cluster.state_machines[0];

    // Follower receives entries
    _ = try follower.persistent_state.appendEntry(1, .command, "increment");
    _ = try follower.persistent_state.appendEntry(1, .command, "increment");

    try testing.expectEqual(@as(i64, 0), sm.value);

    // Leader tells follower to commit
    const request = rpc.AppendEntriesRequest{
        .term = 1,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 2,
    };

    _ = try follower.handleAppendEntries(request);

    // State machine should have applied both increments
    try testing.expectEqual(@as(i64, 2), sm.value);
    try testing.expectEqual(@as(types.LogIndex, 2), follower.volatile_state.last_applied);
}

test "Leader failure: higher term causes leader to step down" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var leader = &cluster.nodes[0];

    // Make node leader in term 1
    try leader.becomeLeader();
    leader.persistent_state.current_term = 1;
    try testing.expect(leader.isLeader());

    // Receive AppendEntries from higher term
    const request = rpc.AppendEntriesRequest{
        .term = 2,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 0,
    };

    _ = try leader.handleAppendEntries(request);

    // Should step down
    try testing.expectEqual(types.NodeState.follower, leader.getState());
    try testing.expectEqual(@as(types.Term, 2), leader.getTerm());
    try testing.expect(leader.leader_state == null);
}

test "Reset election timeout on valid AppendEntries" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var follower = &cluster.nodes[0];

    const now: u64 = 1000;
    follower.election_deadline = now + 100;

    const old_deadline = follower.election_deadline;

    // Reset timeout
    follower.resetElectionTimeout(now);

    // Deadline should change
    try testing.expect(follower.election_deadline != old_deadline);
    try testing.expect(follower.election_deadline > now);
}

test "Vote recording counts votes correctly" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    var candidate = &cluster.nodes[0];

    // Become candidate (votes for self)
    try candidate.becomeCandidate();

    // Record one grant
    var won = try candidate.recordVote(2, true);
    try testing.expect(won); // 2/3 = quorum

    // Record one rejection
    won = try candidate.recordVote(3, false);
    try testing.expect(won); // Still have 2/3
}

test "End-to-end: complete election and replication scenario" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    // PHASE 1: Election
    // Node 0 times out first and starts election
    try cluster.nodes[0].becomeCandidate();
    const candidate_term = cluster.nodes[0].getTerm();

    // Node 0 sends RequestVote RPCs
    const request_vote = rpc.RequestVoteRequest{
        .term = candidate_term,
        .candidate_id = 1,
        .last_log_index = 0,
        .last_log_term = 0,
    };

    // Node 1 and 2 receive and grant votes
    const vote1 = try cluster.nodes[1].handleRequestVote(request_vote);
    const vote2 = try cluster.nodes[2].handleRequestVote(request_vote);

    try testing.expect(vote1.vote_granted);
    try testing.expect(vote2.vote_granted);

    // Node 0 records votes and wins
    _ = try cluster.nodes[0].recordVote(2, vote1.vote_granted);
    const won = try cluster.nodes[0].recordVote(3, vote2.vote_granted);
    try testing.expect(won);

    // Node 0 becomes leader
    try cluster.nodes[0].becomeLeader();
    try testing.expect(cluster.nodes[0].isLeader());

    // PHASE 2: Log Replication
    // Leader appends entries
    _ = try cluster.nodes[0].persistent_state.appendEntry(candidate_term, .command, "increment");
    _ = try cluster.nodes[0].persistent_state.appendEntry(candidate_term, .command, "increment");

    // Leader sends AppendEntries to followers
    const entries_to_send = [_]types.LogEntry{
        cluster.nodes[0].persistent_state.getEntry(1).?,
        cluster.nodes[0].persistent_state.getEntry(2).?,
    };

    const append_req = rpc.AppendEntriesRequest{
        .term = candidate_term,
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &entries_to_send,
        .leader_commit = 0,
    };

    // Followers receive and accept entries
    const resp1 = try cluster.nodes[1].handleAppendEntries(append_req);
    const resp2 = try cluster.nodes[2].handleAppendEntries(append_req);

    try testing.expect(resp1.success);
    try testing.expect(resp2.success);
    try testing.expectEqual(@as(types.LogIndex, 2), resp1.match_index);
    try testing.expectEqual(@as(types.LogIndex, 2), resp2.match_index);

    // PHASE 3: Commit
    // Leader records successful replication
    try cluster.nodes[0].handleAppendEntriesResponse(2, resp1);
    try cluster.nodes[0].handleAppendEntriesResponse(3, resp2);

    // Leader updates commit index
    try cluster.nodes[0].updateCommitIndex();

    // Leader should have committed
    try testing.expectEqual(@as(types.LogIndex, 2), cluster.nodes[0].volatile_state.commit_index);

    // Send heartbeat to followers with updated commit index
    const commit_heartbeat = rpc.AppendEntriesRequest{
        .term = candidate_term,
        .leader_id = 1,
        .prev_log_index = 2,
        .prev_log_term = candidate_term,
        .entries = &[_]types.LogEntry{},
        .leader_commit = 2,
    };

    _ = try cluster.nodes[1].handleAppendEntries(commit_heartbeat);
    _ = try cluster.nodes[2].handleAppendEntries(commit_heartbeat);

    // PHASE 4: Verify state machine application
    // All nodes should have applied the commands
    try testing.expectEqual(@as(i64, 2), cluster.state_machines[0].value);
    try testing.expectEqual(@as(i64, 2), cluster.state_machines[1].value);
    try testing.expectEqual(@as(i64, 2), cluster.state_machines[2].value);

    // All nodes should have same log
    for (0..3) |i| {
        try testing.expectEqual(@as(types.LogIndex, 2), cluster.nodes[i].persistent_state.getLastLogIndex());
        try testing.expectEqual(@as(types.LogIndex, 2), cluster.nodes[i].volatile_state.commit_index);
        try testing.expectEqual(@as(types.LogIndex, 2), cluster.nodes[i].volatile_state.last_applied);
    }
}

test "End-to-end: log conflict resolution" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    // Setup: Node 0 is leader in term 2
    try cluster.nodes[0].becomeCandidate();
    cluster.nodes[0].persistent_state.current_term = 2;
    try cluster.nodes[0].becomeLeader();

    // All nodes have entry 1 from term 1
    _ = try cluster.nodes[0].persistent_state.appendEntry(1, .command, "cmd1");
    _ = try cluster.nodes[1].persistent_state.appendEntry(1, .command, "cmd1");
    _ = try cluster.nodes[2].persistent_state.appendEntry(1, .command, "cmd1");

    // Node 1 has a conflicting entry 2 from old term 1
    _ = try cluster.nodes[1].persistent_state.appendEntry(1, .command, "old_cmd2");

    // Leader has correct entry 2 from term 2
    _ = try cluster.nodes[0].persistent_state.appendEntry(2, .command, "new_cmd2");

    // Leader replicates to node 1
    const entries = [_]types.LogEntry{
        cluster.nodes[0].persistent_state.getEntry(2).?,
    };

    const request = rpc.AppendEntriesRequest{
        .term = 2,
        .leader_id = 1,
        .prev_log_index = 1,
        .prev_log_term = 1,
        .entries = &entries,
        .leader_commit = 0,
    };

    const response = try cluster.nodes[1].handleAppendEntries(request);

    // Should succeed
    try testing.expect(response.success);

    // Node 1 should have replaced conflicting entry
    const entry2 = cluster.nodes[1].persistent_state.getEntry(2).?;
    try testing.expectEqual(@as(types.Term, 2), entry2.term);
    try testing.expectEqualStrings("new_cmd2", entry2.data);
}

test "End-to-end: leader handles partial replication" {
    var cluster = try TestCluster.init(testing.allocator);
    defer cluster.deinit();

    // Node 0 is leader
    try cluster.nodes[0].becomeLeader();

    // Leader appends 3 entries
    _ = try cluster.nodes[0].persistent_state.appendEntry(1, .command, "cmd1");
    _ = try cluster.nodes[0].persistent_state.appendEntry(1, .command, "cmd2");
    _ = try cluster.nodes[0].persistent_state.appendEntry(1, .command, "cmd3");

    // Only node 1 replicates successfully (not a quorum)
    try cluster.nodes[0].handleAppendEntriesResponse(2, .{
        .term = 1,
        .success = true,
        .match_index = 3,
    });

    // Update commit index
    try cluster.nodes[0].updateCommitIndex();

    // Should NOT commit (only 2 out of 3 nodes have the entries)
    try testing.expectEqual(@as(types.LogIndex, 0), cluster.nodes[0].volatile_state.commit_index);

    // Node 2 also replicates successfully (now have quorum)
    try cluster.nodes[0].handleAppendEntriesResponse(3, .{
        .term = 1,
        .success = true,
        .match_index = 3,
    });

    // Update commit index
    try cluster.nodes[0].updateCommitIndex();

    // Should commit all entries (3 out of 3 = quorum)
    try testing.expectEqual(@as(types.LogIndex, 3), cluster.nodes[0].volatile_state.commit_index);
}
