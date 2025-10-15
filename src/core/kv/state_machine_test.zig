const std = @import("std");
const testing = std.testing;
const state_machine_mod = @import("state_machine.zig");

test "KVStateMachine init creates empty map" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    try testing.expectEqual(@as(usize, 0), kv.map.count());
}

test "KVStateMachine put stores key-value pair" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(result);

    try testing.expectEqualStrings("OK", result);
    try testing.expect(kv.map.contains("key1"));
}

test "KVStateMachine put overwrites existing key" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result1 = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(result1);

    const result2 = try kv.apply("put:4:key1:value2");
    defer testing.allocator.free(result2);

    const value = kv.map.get("key1").?;
    try testing.expectEqualStrings("value2", value);
}

test "KVStateMachine delete removes key" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result1 = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(result1);

    const result2 = try kv.apply("delete:4:key1");
    defer testing.allocator.free(result2);

    try testing.expect(!kv.map.contains("key1"));
}

test "KVStateMachine delete returns error for non-existent key" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    try testing.expectError(state_machine_mod.KVError.KeyNotFound, kv.apply("delete:4:key1"));
}

test "KVStateMachine handles keys with colons in values" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result = try kv.apply("put:4:key1:value:with:colons");
    defer testing.allocator.free(result);

    const value = kv.map.get("key1").?;
    try testing.expectEqualStrings("value:with:colons", value);
}

test "KVStateMachine takeSnapshot captures state" {
    var kv = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const r1 = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(r1);
    const r2 = try kv.apply("put:4:key2:value2");
    defer testing.allocator.free(r2);

    const snapshot = try kv.takeSnapshot(testing.allocator);
    defer testing.allocator.free(snapshot);

    try testing.expect(snapshot.len > 0);
}

test "KVStateMachine restoreSnapshot restores state" {
    var kv1 = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv1.deinit();

    const r1 = try kv1.apply("put:4:key1:value1");
    defer testing.allocator.free(r1);
    const r2 = try kv1.apply("put:4:key2:value2");
    defer testing.allocator.free(r2);

    const snapshot = try kv1.takeSnapshot(testing.allocator);
    defer testing.allocator.free(snapshot);

    var kv2 = state_machine_mod.KVStateMachine.init(testing.allocator);
    defer kv2.deinit();

    try kv2.restoreSnapshot(snapshot);

    try testing.expectEqual(@as(usize, 2), kv2.map.count());
    try testing.expectEqualStrings("value1", kv2.map.get("key1").?);
    try testing.expectEqualStrings("value2", kv2.map.get("key2").?);
}
