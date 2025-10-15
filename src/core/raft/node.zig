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

        // Generate a random election timeout delay
        pub fn randomElectionTimeout(self: *Self) u64 {
            return self.timing_config.randomElectionTimeout(self.rng);
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
            if (request.term < self.persistent_state.current_term) {
                return .{
                    .term = self.persistent_state.current_term,
                    .success = false,
                    .match_index = 0,
                };
            }

            if (request.term >= self.persistent_state.current_term) {
                self.becomeFollower(request.term);
                self.current_leader = request.leader_id;
            }

            if (!try self.validatePrevLogEntry(request.prev_log_index, request.prev_log_term)) {
                return .{
                    .term = self.persistent_state.current_term,
                    .success = false,
                    .match_index = 0,
                };
            }

            if (request.entries.len == 0) {
                try self.updateCommitIndexFromLeader(request.leader_commit);
                return .{
                    .term = self.persistent_state.current_term,
                    .success = true,
                    .match_index = self.persistent_state.getLastLogIndex(),
                };
            }

            try self.appendNewEntries(request.entries);
            try self.updateCommitIndexFromLeader(request.leader_commit);

            return .{
                .term = self.persistent_state.current_term,
                .success = true,
                .match_index = self.persistent_state.getLastLogIndex(),
            };
        }

        fn validatePrevLogEntry(self: *Self, prev_log_index: types.LogIndex, prev_log_term: types.Term) !bool {
            if (prev_log_index == 0) {
                return true;
            }

            const prev_entry = self.persistent_state.getEntry(prev_log_index);
            if (prev_entry == null) {
                return false;
            }

            return prev_entry.?.term == prev_log_term;
        }

        fn updateCommitIndexFromLeader(self: *Self, leader_commit: types.LogIndex) !void {
            if (leader_commit <= self.volatile_state.commit_index) {
                return;
            }

            const new_commit = @min(leader_commit, self.persistent_state.getLastLogIndex());
            self.volatile_state.updateCommitIndex(new_commit);
            try self.applyCommittedEntries();
        }

        fn appendNewEntries(self: *Self, entries: []const types.LogEntry) !void {
            for (entries) |entry| {
                const existing = self.persistent_state.getEntry(entry.index);
                if (existing != null and existing.?.term != entry.term) {
                    try self.persistent_state.truncateLogAfter(entry.index - 1);
                }

                if (self.persistent_state.getEntry(entry.index) == null) {
                    _ = try self.persistent_state.appendEntry(entry.term, entry.entry_type, entry.data);
                }
            }
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

        // Called when election timeout fires - transitions to candidate and requests votes
        pub fn handleElectionTimeout(self: *Self) !actions_mod.ActionList {
            var actions = actions_mod.ActionList.init(self.allocator);

            try self.becomeCandidate();

            const last_log_index = self.persistent_state.getLastLogIndex();
            const last_log_term = self.persistent_state.getLastLogTerm();

            for (self.cluster_config.nodes) |node| {
                if (node.id == self.node_id) {
                    continue;
                }

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

            return actions;
        }

        // Called when heartbeat interval fires - sends heartbeats/AppendEntries to followers
        pub fn handleHeartbeatTimeout(self: *Self) !actions_mod.ActionList {
            var actions = actions_mod.ActionList.init(self.allocator);

            if (self.node_state != .leader) {
                return actions;
            }

            const ls = &(self.leader_state orelse return actions);

            for (self.cluster_config.nodes) |node| {
                if (node.id == self.node_id) {
                    continue;
                }

                try self.buildAndSendAppendEntries(node.id, ls, &actions);
            }

            try self.updateCommitIndex();

            return actions;
        }

        fn buildAndSendAppendEntries(
            self: *Self,
            node_id: types.NodeId,
            ls: *state_mod.LeaderState,
            actions: *actions_mod.ActionList,
        ) !void {
            const next_index = ls.getNextIndex(node_id) orelse return;
            const prev_log_index = if (next_index > 1) next_index - 1 else 0;
            const prev_log_term = if (prev_log_index > 0)
                self.persistent_state.getEntry(prev_log_index).?.term
            else
                0;

            const entries = try self.collectEntriesToSend(next_index);
            defer self.allocator.free(entries);

            try actions.append(.{
                .send_append_entries = .{
                    .node_id = node_id,
                    .request = .{
                        .term = self.persistent_state.current_term,
                        .leader_id = self.node_id,
                        .prev_log_index = prev_log_index,
                        .prev_log_term = prev_log_term,
                        .entries = entries,
                        .leader_commit = self.volatile_state.commit_index,
                    },
                },
            });
        }

        fn collectEntriesToSend(self: *Self, start_index: types.LogIndex) ![]types.LogEntry {
            const last_log_index = self.persistent_state.getLastLogIndex();
            if (start_index > last_log_index) {
                return try self.allocator.alloc(types.LogEntry, 0);
            }

            var entries = std.ArrayList(types.LogEntry).init(self.allocator);
            defer entries.deinit();

            var idx = start_index;
            while (idx <= last_log_index and entries.items.len < self.timing_config.max_entries_per_rpc) {
                const entry = self.persistent_state.getEntry(idx).?;
                try entries.append(entry);
                idx += 1;
            }

            return try self.allocator.dupe(types.LogEntry, entries.items);
        }

        // Update commit index based on matchIndex quorum (leader only)
        fn updateCommitIndex(self: *Self) !void {
            if (self.node_state != .leader) return;
            if (self.leader_state == null) return;

            const ls = &self.leader_state.?;
            const last_log_index = self.persistent_state.getLastLogIndex();

            var n = self.volatile_state.commit_index + 1;
            while (n <= last_log_index) : (n += 1) {
                const entry = self.persistent_state.getEntry(n).?;

                if (entry.term != self.persistent_state.current_term) {
                    continue;
                }

                const replicas = self.countReplicasForIndex(n, ls);
                if (replicas >= self.cluster_config.quorumSize()) {
                    self.volatile_state.updateCommitIndex(n);
                    try self.applyCommittedEntries();
                } else {
                    break;
                }
            }
        }

        fn countReplicasForIndex(self: *Self, index: types.LogIndex, ls: *state_mod.LeaderState) usize {
            var replicas: usize = 1;
            for (self.cluster_config.nodes) |node| {
                if (node.id == self.node_id) {
                    continue;
                }

                const match_index = ls.getMatchIndex(node.id) orelse 0;
                if (match_index >= index) {
                    replicas += 1;
                }
            }
            return replicas;
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
