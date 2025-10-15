const std = @import("std");
const testing = std.testing;
const config = @import("config.zig");
const types = @import("types.zig");

test "TimingConfig randomElectionTimeout returns value in range" {
    const timing = config.TimingConfig{};
    var prng = std.Random.DefaultPrng.init(0);
    const rng = prng.random();

    for (0..100) |_| {
        const timeout = timing.randomElectionTimeout(rng);
        try testing.expect(timeout >= timing.election_timeout_min);
        try testing.expect(timeout <= timing.election_timeout_max);
    }
}

test "ClusterConfig init creates empty configuration" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try testing.expectEqual(@as(usize, 0), cluster.nodes.len);
}

test "ClusterConfig isSingleNode returns true for one node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expect(cluster.isSingleNode());
}

test "ClusterConfig isSingleNode returns false for multiple nodes" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try cluster.addNode(.{ .id = 2, .address = "localhost:8001" });
    try testing.expect(!cluster.isSingleNode());
}

test "ClusterConfig quorumSize calculates correctly" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expectEqual(@as(usize, 1), cluster.quorumSize());

    try cluster.addNode(.{ .id = 2, .address = "localhost:8001" });
    try testing.expectEqual(@as(usize, 2), cluster.quorumSize());

    try cluster.addNode(.{ .id = 3, .address = "localhost:8002" });
    try testing.expectEqual(@as(usize, 2), cluster.quorumSize());

    try cluster.addNode(.{ .id = 4, .address = "localhost:8003" });
    try testing.expectEqual(@as(usize, 3), cluster.quorumSize());

    try cluster.addNode(.{ .id = 5, .address = "localhost:8004" });
    try testing.expectEqual(@as(usize, 3), cluster.quorumSize());
}

test "ClusterConfig addNode adds node successfully" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expectEqual(@as(usize, 1), cluster.nodes.len);
    try testing.expectEqual(@as(types.NodeId, 1), cluster.nodes[0].id);
    try testing.expectEqualStrings("localhost:8000", cluster.nodes[0].address);
}

test "ClusterConfig addNode rejects duplicate node id" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expectError(types.RaftError.NodeAlreadyExists, cluster.addNode(.{ .id = 1, .address = "localhost:8001" }));
}

test "ClusterConfig hasNode returns true for existing node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expect(cluster.hasNode(1));
}

test "ClusterConfig hasNode returns false for non-existing node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expect(!cluster.hasNode(2));
}

test "ClusterConfig getNode returns node info for existing node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    const node = cluster.getNode(1);
    try testing.expect(node != null);
    try testing.expectEqual(@as(types.NodeId, 1), node.?.id);
}

test "ClusterConfig getNode returns null for non-existing node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    const node = cluster.getNode(2);
    try testing.expect(node == null);
}

test "ClusterConfig removeNode removes node successfully" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try cluster.addNode(.{ .id = 2, .address = "localhost:8001" });
    try testing.expectEqual(@as(usize, 2), cluster.nodes.len);

    try cluster.removeNode(1);
    try testing.expectEqual(@as(usize, 1), cluster.nodes.len);
    try testing.expect(!cluster.hasNode(1));
    try testing.expect(cluster.hasNode(2));
}

test "ClusterConfig removeNode returns error for non-existing node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expectError(types.RaftError.NodeNotFound, cluster.removeNode(2));
}

test "ClusterConfig removeNode returns error for last node" {
    var cluster = config.ClusterConfig.init(testing.allocator);
    defer cluster.deinit();

    try cluster.addNode(.{ .id = 1, .address = "localhost:8000" });
    try testing.expectError(types.RaftError.InvalidConfiguration, cluster.removeNode(1));
}
