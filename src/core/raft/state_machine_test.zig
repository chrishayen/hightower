const std = @import("std");
const testing = std.testing;
const state_machine = @import("state_machine.zig");

test "TestStateMachine init creates zero value" {
    const sm = state_machine.TestStateMachine.init(testing.allocator);
    try testing.expectEqual(@as(i64, 0), sm.value);
}

test "TestStateMachine increment increases value" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm.apply("increment");
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(i64, 1), sm.value);
    try testing.expectEqualStrings("1", result);
}

test "TestStateMachine decrement decreases value" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result1 = try sm.apply("increment");
    defer testing.allocator.free(result1);
    const result = try sm.apply("decrement");
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(i64, 0), sm.value);
    try testing.expectEqualStrings("0", result);
}

test "TestStateMachine set command sets value" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm.apply("set:42");
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(i64, 42), sm.value);
    try testing.expectEqualStrings("42", result);
}

test "TestStateMachine set command with negative value" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm.apply("set:-10");
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(i64, -10), sm.value);
    try testing.expectEqualStrings("-10", result);
}

test "TestStateMachine takeSnapshot returns current value" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm.apply("set:100");
    defer testing.allocator.free(result);

    const snapshot = try sm.takeSnapshot(testing.allocator);
    defer testing.allocator.free(snapshot);

    try testing.expectEqualStrings("100", snapshot);
}

test "TestStateMachine restoreSnapshot sets value" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm.apply("increment");
    defer testing.allocator.free(result);

    try sm.restoreSnapshot("42");
    try testing.expectEqual(@as(i64, 42), sm.value);
}

test "TestStateMachine restore and snapshot roundtrip" {
    var sm1 = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm1.apply("set:12345");
    defer testing.allocator.free(result);

    const snapshot = try sm1.takeSnapshot(testing.allocator);
    defer testing.allocator.free(snapshot);

    var sm2 = state_machine.TestStateMachine.init(testing.allocator);
    try sm2.restoreSnapshot(snapshot);

    try testing.expectEqual(sm1.value, sm2.value);
}

test "StateMachine interface apply works" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const sm_interface = sm.stateMachine();

    const result = try sm_interface.apply("increment");
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(i64, 1), sm.value);
}

test "StateMachine interface snapshot works" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const result = try sm.apply("set:99");
    defer testing.allocator.free(result);
    const sm_interface = sm.stateMachine();

    const snapshot = try sm_interface.snapshot(testing.allocator);
    defer testing.allocator.free(snapshot);

    try testing.expectEqualStrings("99", snapshot);
}

test "StateMachine interface restore works" {
    var sm = state_machine.TestStateMachine.init(testing.allocator);
    const sm_interface = sm.stateMachine();

    try sm_interface.restore("77");
    try testing.expectEqual(@as(i64, 77), sm.value);
}
