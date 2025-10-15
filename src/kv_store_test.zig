const std = @import("std");
const testing = std.testing;
const store_mod = @import("kv_store.zig");

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
