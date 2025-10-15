const std = @import("std");
const types = @import("types.zig");

// Timing configuration for Raft protocol
pub const TimingConfig = struct {
    // Election timeout range (milliseconds)
    election_timeout_min: u64 = 150,
    election_timeout_max: u64 = 300,

    // Heartbeat interval (milliseconds)
    heartbeat_interval: u64 = 50,

    // RPC timeout (milliseconds)
    rpc_timeout: u64 = 100,

    // Maximum entries to send in one AppendEntries RPC
    max_entries_per_rpc: usize = 100,

    pub fn randomElectionTimeout(self: TimingConfig, rng: std.Random) u64 {
        const range = self.election_timeout_max - self.election_timeout_min;
        return self.election_timeout_min + rng.intRangeAtMost(u64, 0, range);
    }
};

// Cluster configuration
pub const ClusterConfig = struct {
    nodes: []const types.NodeInfo,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ClusterConfig {
        return .{
            .nodes = &[_]types.NodeInfo{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ClusterConfig) void {
        if (self.nodes.len > 0) {
            for (self.nodes) |node| {
                self.allocator.free(node.address);
            }
            self.allocator.free(self.nodes);
        }
    }

    pub fn isSingleNode(self: ClusterConfig) bool {
        return self.nodes.len == 1;
    }

    pub fn quorumSize(self: ClusterConfig) usize {
        return self.nodes.len / 2 + 1;
    }

    pub fn hasNode(self: ClusterConfig, node_id: types.NodeId) bool {
        for (self.nodes) |node| {
            if (node.id == node_id) {
                return true;
            }
        }
        return false;
    }

    pub fn getNode(self: ClusterConfig, node_id: types.NodeId) ?types.NodeInfo {
        for (self.nodes) |node| {
            if (node.id == node_id) {
                return node;
            }
        }
        return null;
    }

    pub fn addNode(self: *ClusterConfig, node_info: types.NodeInfo) !void {
        if (self.hasNode(node_info.id)) {
            return types.RaftError.NodeAlreadyExists;
        }

        const address_copy = try self.allocator.dupe(u8, node_info.address);
        errdefer self.allocator.free(address_copy);

        const new_nodes = try self.allocator.alloc(types.NodeInfo, self.nodes.len + 1);
        errdefer self.allocator.free(new_nodes);

        @memcpy(new_nodes[0..self.nodes.len], self.nodes);
        new_nodes[self.nodes.len] = .{
            .id = node_info.id,
            .address = address_copy,
        };

        if (self.nodes.len > 0) {
            self.allocator.free(self.nodes);
        }
        self.nodes = new_nodes;
    }

    pub fn removeNode(self: *ClusterConfig, node_id: types.NodeId) !void {
        if (!self.hasNode(node_id)) {
            return types.RaftError.NodeNotFound;
        }

        if (self.nodes.len == 1) {
            return types.RaftError.InvalidConfiguration;
        }

        const new_nodes = try self.allocator.alloc(types.NodeInfo, self.nodes.len - 1);
        errdefer self.allocator.free(new_nodes);

        var j: usize = 0;
        for (self.nodes) |node| {
            if (node.id == node_id) {
                self.allocator.free(node.address);
                continue;
            }
            new_nodes[j] = node;
            j += 1;
        }

        self.allocator.free(self.nodes);
        self.nodes = new_nodes;
    }

    pub fn format(
        self: ClusterConfig,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("ClusterConfig{{ nodes={} }}", .{self.nodes.len});
    }
};
