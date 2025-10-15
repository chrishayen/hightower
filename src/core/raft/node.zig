const std = @import("std");
const types = @import("types.zig");
const config = @import("config.zig");
const state_mod = @import("state.zig");
const rpc = @import("rpc.zig");
const state_machine = @import("state_machine.zig");
const actions_mod = @import("actions.zig");

pub fn Node(comptime T: type) type {
    return struct {
        const Self = @This();

        // Identity
        node_id: types.NodeId,

        // State
        node_state: types.NodeState,
        persistent_state: state_mod.PersistentState,
        volatile_state: state_mod.VolatileState,
        leader_state: ?state_mod.LeaderState,

        // Configuration
        cluster_config: config.ClusterConfig,
        timing_config: config.TimingConfig,

        // State machine
        state_machine: state_machine.StateMachine(T),

        // Leader tracking
        current_leader: ?types.NodeId,

        // Timing state (milliseconds)
        last_heartbeat_time: u64,
        election_deadline: u64,

        // Vote tracking for candidates
        votes_received: std.AutoHashMap(types.NodeId, bool),

        // Random number generator for election timeout
        rng: std.Random,

        // Allocator
        allocator: std.mem.Allocator,

        pub fn init(
            allocator: std.mem.Allocator,
            node_id: types.NodeId,
            sm: state_machine.StateMachine(T),
            seed: u64,
        ) !Self {
            var prng = std.Random.DefaultPrng.init(seed);
            const timing = config.TimingConfig{};

            return .{
                .node_id = node_id,
                .node_state = .follower,
                .persistent_state = state_mod.PersistentState.init(allocator),
                .volatile_state = state_mod.VolatileState.init(),
                .leader_state = null,
                .cluster_config = config.ClusterConfig.init(allocator),
                .timing_config = timing,
                .state_machine = sm,
                .current_leader = null,
                .last_heartbeat_time = 0,
                .election_deadline = timing.randomElectionTimeout(prng.random()),
                .votes_received = std.AutoHashMap(types.NodeId, bool).init(allocator),
                .rng = prng.random(),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.persistent_state.deinit();
            if (self.leader_state) |*ls| {
                ls.deinit();
            }
            self.cluster_config.deinit();
            self.votes_received.deinit();
        }

        // Bootstrap as a single-node cluster
        pub fn bootstrapSingleNode(self: *Self, address: []const u8) !void {
            try self.cluster_config.addNode(.{
                .id = self.node_id,
                .address = address,
            });

            // Single node immediately becomes leader
            if (self.cluster_config.isSingleNode()) {
                try self.becomeLeader();
            }
        }

        // Submit a command to the cluster
        pub fn submitCommand(self: *Self, command: []const u8) ![]const u8 {
            if (self.node_state != .leader) {
                return types.RaftError.NotLeader;
            }

            // Append to log
            const index = try self.persistent_state.appendEntry(
                self.persistent_state.current_term,
                .command,
                command,
            );

            // Fast path for single-node cluster
            if (self.cluster_config.isSingleNode()) {
                return try self.applySingleNodeCommand(index);
            }

            // Multi-node: would need to replicate to followers
            // For now, return error as we haven't implemented replication yet
            return types.RaftError.NoQuorum;
        }

        // Apply command immediately for single-node cluster
        fn applySingleNodeCommand(self: *Self, index: types.LogIndex) ![]const u8 {
            // Update commit index
            self.volatile_state.updateCommitIndex(index);

            // Apply to state machine
            const entry = self.persistent_state.getEntry(index).?;
            const result = try self.state_machine.apply(entry.data);

            // Update last applied
            _ = try self.volatile_state.applyEntry();

            return result;
        }

        // Become leader
        fn becomeLeader(self: *Self) !void {
            self.node_state = .leader;
            self.current_leader = self.node_id;

            // Initialize leader state if multi-node
            if (!self.cluster_config.isSingleNode()) {
                var ls = state_mod.LeaderState.init(self.allocator);
                const last_log_index = self.persistent_state.getLastLogIndex();

                for (self.cluster_config.nodes) |node| {
                    if (node.id != self.node_id) {
                        try ls.initializeForNode(node.id, last_log_index);
                    }
                }

                self.leader_state = ls;
            }
        }

        // Become follower
        fn becomeFollower(self: *Self, term: types.Term) void {
            self.node_state = .follower;
            self.persistent_state.setTerm(term);

            if (self.leader_state) |*ls| {
                ls.deinit();
                self.leader_state = null;
            }
        }

        // Become candidate
        fn becomeCandidate(self: *Self) !void {
            self.node_state = .candidate;
            self.persistent_state.current_term += 1;
            self.persistent_state.voted_for = null;

            try self.persistent_state.voteFor(self.node_id);

            // Clear previous votes and vote for self
            self.votes_received.clearRetainingCapacity();
            try self.votes_received.put(self.node_id, true);
        }

        // Reset election timeout (call after receiving message from leader)
        pub fn resetElectionTimeout(self: *Self, now: u64) void {
            self.last_heartbeat_time = now;
            self.election_deadline = now + self.timing_config.randomElectionTimeout(self.rng);
        }

        // Record vote received during candidacy
        pub fn recordVote(self: *Self, node_id: types.NodeId, granted: bool) !bool {
            if (self.node_state != .candidate) {
                return false;
            }

            try self.votes_received.put(node_id, granted);

            // Count votes
            var votes: usize = 0;
            var iter = self.votes_received.valueIterator();
            while (iter.next()) |vote| {
                if (vote.*) {
                    votes += 1;
                }
            }

            // Check if we have quorum
            const quorum = self.cluster_config.quorumSize();
            return votes >= quorum;
        }

        // Handle RequestVote RPC
        pub fn handleRequestVote(self: *Self, request: rpc.RequestVoteRequest) !rpc.RequestVoteResponse {
            // If request term is stale, reject
            if (request.term < self.persistent_state.current_term) {
                return .{
                    .term = self.persistent_state.current_term,
                    .vote_granted = false,
                };
            }

            // If request term is higher, become follower
            if (request.term > self.persistent_state.current_term) {
                self.becomeFollower(request.term);
            }

            // Check if we can vote for this candidate
            const can_vote = self.persistent_state.voted_for == null or
                self.persistent_state.voted_for.? == request.candidate_id;

            if (!can_vote) {
                return .{
                    .term = self.persistent_state.current_term,
                    .vote_granted = false,
                };
            }

            // Check if candidate's log is at least as up-to-date as ours
            const our_last_log_term = self.persistent_state.getLastLogTerm();
            const our_last_log_index = self.persistent_state.getLastLogIndex();

            const log_is_up_to_date = request.last_log_term > our_last_log_term or
                (request.last_log_term == our_last_log_term and
                request.last_log_index >= our_last_log_index);

            if (!log_is_up_to_date) {
                return .{
                    .term = self.persistent_state.current_term,
                    .vote_granted = false,
                };
            }

            // Grant vote
            try self.persistent_state.voteFor(request.candidate_id);

            return .{
                .term = self.persistent_state.current_term,
                .vote_granted = true,
            };
        }

        // Handle AppendEntries RPC
        pub fn handleAppendEntries(self: *Self, request: rpc.AppendEntriesRequest) !rpc.AppendEntriesResponse {
            // If request term is stale, reject
            if (request.term < self.persistent_state.current_term) {
                return .{
                    .term = self.persistent_state.current_term,
                    .success = false,
                    .match_index = 0,
                };
            }

            // If request term is higher or equal, become/stay follower
            if (request.term >= self.persistent_state.current_term) {
                self.becomeFollower(request.term);
                self.current_leader = request.leader_id;
            }

            // Check if our log contains an entry at prev_log_index with prev_log_term
            if (request.prev_log_index > 0) {
                const prev_entry = self.persistent_state.getEntry(request.prev_log_index);
                if (prev_entry == null or prev_entry.?.term != request.prev_log_term) {
                    return .{
                        .term = self.persistent_state.current_term,
                        .success = false,
                        .match_index = 0,
                    };
                }
            }

            // If this is a heartbeat (no entries), just update commit index
            if (request.entries.len == 0) {
                if (request.leader_commit > self.volatile_state.commit_index) {
                    const new_commit = @min(request.leader_commit, self.persistent_state.getLastLogIndex());
                    self.volatile_state.updateCommitIndex(new_commit);
                    try self.applyCommittedEntries();
                }
                return .{
                    .term = self.persistent_state.current_term,
                    .success = true,
                    .match_index = self.persistent_state.getLastLogIndex(),
                };
            }

            // Append new entries
            for (request.entries) |entry| {
                const existing = self.persistent_state.getEntry(entry.index);
                if (existing != null and existing.?.term != entry.term) {
                    // Conflict: delete existing entry and all that follow
                    try self.persistent_state.truncateLogAfter(entry.index - 1);
                }

                // Append entry if not already present
                if (self.persistent_state.getEntry(entry.index) == null) {
                    _ = try self.persistent_state.appendEntry(entry.term, entry.entry_type, entry.data);
                }
            }

            // Update commit index
            if (request.leader_commit > self.volatile_state.commit_index) {
                const new_commit = @min(request.leader_commit, self.persistent_state.getLastLogIndex());
                self.volatile_state.updateCommitIndex(new_commit);
                try self.applyCommittedEntries();
            }

            return .{
                .term = self.persistent_state.current_term,
                .success = true,
                .match_index = self.persistent_state.getLastLogIndex(),
            };
        }

        // Apply committed entries to state machine
        fn applyCommittedEntries(self: *Self) !void {
            while (self.volatile_state.hasUnappliedEntries()) {
                const index = try self.volatile_state.applyEntry();
                const entry = self.persistent_state.getEntry(index).?;

                if (entry.entry_type == .command) {
                    const result = try self.state_machine.apply(entry.data);
                    self.allocator.free(result);
                }
            }
        }

        // Get current state
        pub fn getState(self: Self) types.NodeState {
            return self.node_state;
        }

        pub fn isLeader(self: Self) bool {
            return self.node_state == .leader;
        }

        pub fn getTerm(self: Self) types.Term {
            return self.persistent_state.current_term;
        }

        // Tick - called periodically by the shell to process timeouts
        pub fn tick(self: *Self, now: u64) !actions_mod.ActionList {
            var actions = actions_mod.ActionList.init(self.allocator);

            switch (self.node_state) {
                .follower, .candidate => {
                    // Check if election timeout has expired
                    if (now >= self.election_deadline) {
                        try self.becomeCandidate();
                        self.election_deadline = now + self.timing_config.randomElectionTimeout(self.rng);

                        // Send RequestVote to all other nodes
                        const last_log_index = self.persistent_state.getLastLogIndex();
                        const last_log_term = self.persistent_state.getLastLogTerm();

                        for (self.cluster_config.nodes) |node| {
                            if (node.id != self.node_id) {
                                try actions.append(.{
                                    .send_request_vote = .{
                                        .node_id = node.id,
                                        .request = .{
                                            .term = self.persistent_state.current_term,
                                            .candidate_id = self.node_id,
                                            .last_log_index = last_log_index,
                                            .last_log_term = last_log_term,
                                        },
                                    },
                                });
                            }
                        }
                    }
                },
                .leader => {
                    // Send heartbeats/replication messages
                    if (now >= self.last_heartbeat_time + self.timing_config.heartbeat_interval) {
                        self.last_heartbeat_time = now;

                        // Send AppendEntries to each follower
                        if (self.leader_state) |*ls| {
                            for (self.cluster_config.nodes) |node| {
                                if (node.id != self.node_id) {
                                    const next_index = ls.getNextIndex(node.id) orelse continue;
                                    const prev_log_index = if (next_index > 1) next_index - 1 else 0;
                                    const prev_log_term = if (prev_log_index > 0)
                                        self.persistent_state.getEntry(prev_log_index).?.term
                                    else
                                        0;

                                    // Collect entries to send
                                    var entries = std.ArrayList(types.LogEntry).init(self.allocator);
                                    defer entries.deinit();

                                    const last_log_index = self.persistent_state.getLastLogIndex();
                                    if (next_index <= last_log_index) {
                                        var idx = next_index;
                                        while (idx <= last_log_index and entries.items.len < self.timing_config.max_entries_per_rpc) {
                                            const entry = self.persistent_state.getEntry(idx).?;
                                            try entries.append(entry);
                                            idx += 1;
                                        }
                                    }

                                    try actions.append(.{
                                        .send_append_entries = .{
                                            .node_id = node.id,
                                            .request = .{
                                                .term = self.persistent_state.current_term,
                                                .leader_id = self.node_id,
                                                .prev_log_index = prev_log_index,
                                                .prev_log_term = prev_log_term,
                                                .entries = try self.allocator.dupe(types.LogEntry, entries.items),
                                                .leader_commit = self.volatile_state.commit_index,
                                            },
                                        },
                                    });
                                }
                            }
                        }

                        // Update commit index based on quorum
                        try self.updateCommitIndex();
                    }
                },
            }

            // Schedule next tick
            const next_tick_delay = if (self.node_state == .leader)
                self.timing_config.heartbeat_interval
            else
                @min(self.timing_config.heartbeat_interval, self.election_deadline -| now);

            try actions.append(.{ .schedule_tick = next_tick_delay });

            return actions;
        }

        // Update commit index based on matchIndex quorum (leader only)
        fn updateCommitIndex(self: *Self) !void {
            if (self.node_state != .leader) return;
            if (self.leader_state == null) return;

            const ls = &self.leader_state.?;
            const last_log_index = self.persistent_state.getLastLogIndex();

            // Try each index from current commit to last log
            var n = self.volatile_state.commit_index + 1;
            while (n <= last_log_index) : (n += 1) {
                const entry = self.persistent_state.getEntry(n).?;

                // Only commit entries from current term
                if (entry.term != self.persistent_state.current_term) {
                    continue;
                }

                // Count replicas (including self)
                var replicas: usize = 1;
                for (self.cluster_config.nodes) |node| {
                    if (node.id == self.node_id) continue;

                    const match_index = ls.getMatchIndex(node.id) orelse 0;
                    if (match_index >= n) {
                        replicas += 1;
                    }
                }

                // Check if we have quorum
                if (replicas >= self.cluster_config.quorumSize()) {
                    self.volatile_state.updateCommitIndex(n);
                    try self.applyCommittedEntries();
                } else {
                    break;
                }
            }
        }

        // Handle AppendEntries response (leader only)
        pub fn handleAppendEntriesResponse(
            self: *Self,
            node_id: types.NodeId,
            response: rpc.AppendEntriesResponse,
        ) !void {
            if (self.node_state != .leader) return;
            if (response.term > self.persistent_state.current_term) {
                self.becomeFollower(response.term);
                return;
            }

            if (self.leader_state) |*ls| {
                if (response.success) {
                    // Update match_index and next_index
                    try ls.updateForNode(node_id, response.match_index);
                } else {
                    // Decrement next_index and retry
                    try ls.decrementNextIndex(node_id);
                }
            }
        }
    };
}
