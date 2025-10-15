const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");

test "NodeState has all required states" {
    const follower = types.NodeState.follower;
    const candidate = types.NodeState.candidate;
    const leader = types.NodeState.leader;

    try testing.expect(follower != candidate);
    try testing.expect(candidate != leader);
    try testing.expect(follower != leader);
}

test "LogEntry has correct fields" {
    const entry = types.LogEntry{
        .index = 42,
        .term = 5,
        .entry_type = .command,
        .data = "test_data",
    };

    try testing.expectEqual(@as(types.LogIndex, 42), entry.index);
    try testing.expectEqual(@as(types.Term, 5), entry.term);
    try testing.expectEqual(types.LogEntryType.command, entry.entry_type);
    try testing.expectEqualStrings("test_data", entry.data);
}

test "NodeInfo has correct fields" {
    const node = types.NodeInfo{
        .id = 123,
        .address = "localhost:8080",
    };

    try testing.expectEqual(@as(types.NodeId, 123), node.id);
    try testing.expectEqualStrings("localhost:8080", node.address);
}

test "ConfigChangeOp add_node has correct fields" {
    const op = types.ConfigChangeOp{
        .add_node = .{
            .id = 456,
            .address = "192.168.1.1:9000",
        },
    };

    try testing.expectEqual(@as(types.NodeId, 456), op.add_node.id);
    try testing.expectEqualStrings("192.168.1.1:9000", op.add_node.address);
}

test "ConfigChangeOp remove_node has correct fields" {
    const op = types.ConfigChangeOp{ .remove_node = 789 };

    try testing.expectEqual(@as(types.NodeId, 789), op.remove_node);
}

test "LogEntryType has all required types" {
    const command = types.LogEntryType.command;
    const config_change = types.LogEntryType.config_change;
    const noop = types.LogEntryType.noop;

    try testing.expect(command != config_change);
    try testing.expect(config_change != noop);
    try testing.expect(command != noop);
}
