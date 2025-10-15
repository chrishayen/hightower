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

const ThreadTestContext = struct {
    store: *store_mod.KVStore,
    thread_id: usize,
    iterations: usize,
    errors: std.atomic.Value(usize),
};

fn concurrentWriter(ctx: *ThreadTestContext) void {
    var i: usize = 0;
    while (i < ctx.iterations) : (i += 1) {
        const key_buf = std.fmt.allocPrint(
            testing.allocator,
            "thread{d}:key{d}",
            .{ ctx.thread_id, i },
        ) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
            continue;
        };
        defer testing.allocator.free(key_buf);

        const value_buf = std.fmt.allocPrint(
            testing.allocator,
            "value{d}",
            .{i},
        ) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
            continue;
        };
        defer testing.allocator.free(value_buf);

        ctx.store.put(key_buf, value_buf) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
        };
    }
}

fn concurrentReader(ctx: *ThreadTestContext) void {
    var i: usize = 0;
    while (i < ctx.iterations) : (i += 1) {
        const key_buf = std.fmt.allocPrint(
            testing.allocator,
            "thread{d}:key{d}",
            .{ ctx.thread_id, i },
        ) catch {
            _ = ctx.errors.fetchAdd(1, .monotonic);
            continue;
        };
        defer testing.allocator.free(key_buf);

        if (ctx.store.get(testing.allocator, key_buf)) |value| {
            testing.allocator.free(value);
        } else |_| {}
    }
}

test "KVStore concurrent writes are thread-safe" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    const thread_count = 4;
    const iterations = 50;
    var threads: [thread_count]std.Thread = undefined;
    var contexts: [thread_count]ThreadTestContext = undefined;

    for (&contexts, 0..) |*ctx, i| {
        ctx.* = .{
            .store = &store,
            .thread_id = i,
            .iterations = iterations,
            .errors = std.atomic.Value(usize).init(0),
        };
    }

    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, concurrentWriter, .{&contexts[i]});
    }

    for (&threads) |thread| {
        thread.join();
    }

    for (contexts) |ctx| {
        try testing.expectEqual(@as(usize, 0), ctx.errors.load(.monotonic));
    }

    try testing.expectEqual(@as(usize, thread_count * iterations), store.count());
}

test "KVStore concurrent reads and writes are thread-safe" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");

    const writer_count = 2;
    const reader_count = 2;
    const iterations = 30;

    var writer_threads: [writer_count]std.Thread = undefined;
    var reader_threads: [reader_count]std.Thread = undefined;

    var writer_contexts: [writer_count]ThreadTestContext = undefined;
    var reader_contexts: [reader_count]ThreadTestContext = undefined;

    for (&writer_contexts, 0..) |*ctx, i| {
        ctx.* = .{
            .store = &store,
            .thread_id = i,
            .iterations = iterations,
            .errors = std.atomic.Value(usize).init(0),
        };
    }

    for (&reader_contexts, 0..) |*ctx, i| {
        ctx.* = .{
            .store = &store,
            .thread_id = i,
            .iterations = iterations,
            .errors = std.atomic.Value(usize).init(0),
        };
    }

    for (&writer_threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, concurrentWriter, .{&writer_contexts[i]});
    }

    for (&reader_threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, concurrentReader, .{&reader_contexts[i]});
    }

    for (&writer_threads) |thread| {
        thread.join();
    }

    for (&reader_threads) |thread| {
        thread.join();
    }

    for (writer_contexts) |ctx| {
        try testing.expectEqual(@as(usize, 0), ctx.errors.load(.monotonic));
    }
}

test "KVStore contains is thread-safe" {
    var store = try store_mod.KVStore.init(testing.allocator, 1);
    defer store.deinit(testing.allocator);

    try store.bootstrap("localhost:8000");
    try store.put("test_key", "test_value");

    const thread_count = 4;
    var threads: [thread_count]std.Thread = undefined;

    const CheckContains = struct {
        fn run(s: *store_mod.KVStore) void {
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                _ = s.contains("test_key");
            }
        }
    };

    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, CheckContains.run, .{&store});
    }

    for (&threads) |thread| {
        thread.join();
    }

    try testing.expect(store.contains("test_key"));
}
