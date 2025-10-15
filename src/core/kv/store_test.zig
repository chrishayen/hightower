const std = @import("std");
const testing = std.testing;
const store_mod = @import("store.zig");

test "KVStateMachine init creates empty map" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    try testing.expectEqual(@as(usize, 0), kv.map.count());
}

test "KVStateMachine put stores key-value pair" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(result);

    try testing.expectEqualStrings("OK", result);
    try testing.expect(kv.map.contains("key1"));
}

test "KVStateMachine put overwrites existing key" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result1 = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(result1);

    const result2 = try kv.apply("put:4:key1:value2");
    defer testing.allocator.free(result2);

    const value = kv.map.get("key1").?;
    try testing.expectEqualStrings("value2", value);
}

test "KVStateMachine delete removes key" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result1 = try kv.apply("put:4:key1:value1");
    defer testing.allocator.free(result1);

    const result2 = try kv.apply("delete:4:key1");
    defer testing.allocator.free(result2);

    try testing.expect(!kv.map.contains("key1"));
}

test "KVStateMachine delete returns error for non-existent key" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    try testing.expectError(store_mod.KVError.KeyNotFound, kv.apply("delete:4:key1"));
}

test "KVStateMachine handles keys with colons in values" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
    defer kv.deinit();

    const result = try kv.apply("put:4:key1:value:with:colons");
    defer testing.allocator.free(result);

    const value = kv.map.get("key1").?;
    try testing.expectEqualStrings("value:with:colons", value);
}

test "KVStateMachine takeSnapshot captures state" {
    var kv = store_mod.KVStateMachine.init(testing.allocator);
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
    var kv1 = store_mod.KVStateMachine.init(testing.allocator);
    defer kv1.deinit();

    const r1 = try kv1.apply("put:4:key1:value1");
    defer testing.allocator.free(r1);
    const r2 = try kv1.apply("put:4:key2:value2");
    defer testing.allocator.free(r2);

    const snapshot = try kv1.takeSnapshot(testing.allocator);
    defer testing.allocator.free(snapshot);

    var kv2 = store_mod.KVStateMachine.init(testing.allocator);
    defer kv2.deinit();

    try kv2.restoreSnapshot(snapshot);

    try testing.expectEqual(@as(usize, 2), kv2.map.count());
    try testing.expectEqualStrings("value1", kv2.map.get("key1").?);
    try testing.expectEqualStrings("value2", kv2.map.get("key2").?);
}

test "KVStore init creates store with node" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), store.count());
}

test "KVStore bootstrap makes store ready" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");
    try testing.expect(store.node.isLeader());
}

test "KVStore put and get work correctly" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    try store.put("name", "Alice");

    const value = try store.get(testing.allocator, "name");
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("Alice", value);
}

test "KVStore put overwrites existing value" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    try store.put("counter", "1");
    try store.put("counter", "2");

    const value = try store.get(testing.allocator, "counter");
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("2", value);
}

test "KVStore delete removes key" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    try store.put("temp", "value");
    try testing.expect(store.contains("temp"));

    try store.delete("temp");
    try testing.expect(!store.contains("temp"));
}

test "KVStore get returns error for non-existent key" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    try testing.expectError(store_mod.KVError.KeyNotFound, store.get(testing.allocator, "missing"));
}

test "KVStore count returns number of keys" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    try testing.expectEqual(@as(usize, 0), store.count());

    try store.put("key1", "value1");
    try testing.expectEqual(@as(usize, 1), store.count());

    try store.put("key2", "value2");
    try testing.expectEqual(@as(usize, 2), store.count());

    try store.delete("key1");
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "KVStore handles multiple operations" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    try store.put("users:1", "Alice");
    try store.put("users:2", "Bob");
    try store.put("users:3", "Charlie");

    try testing.expectEqual(@as(usize, 3), store.count());

    const value1 = try store.get(testing.allocator, "users:1");
    defer testing.allocator.free(value1);
    try testing.expectEqualStrings("Alice", value1);

    try store.delete("users:2");
    try testing.expectEqual(@as(usize, 2), store.count());

    try store.put("users:3", "Charles");
    const value3 = try store.get(testing.allocator, "users:3");
    defer testing.allocator.free(value3);
    try testing.expectEqualStrings("Charles", value3);
}
