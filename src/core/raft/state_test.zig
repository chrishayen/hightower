const std = @import("std");
const testing = std.testing;
const state = @import("state.zig");
const types = @import("types.zig");

test "PersistentState init creates empty state" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try testing.expectEqual(@as(types.Term, 0), ps.current_term);
    try testing.expectEqual(@as(?types.NodeId, null), ps.voted_for);
    try testing.expectEqual(@as(usize, 0), ps.log.items.len);
}

test "PersistentState setTerm updates term and clears vote" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try ps.voteFor(42);
    try testing.expectEqual(@as(?types.NodeId, 42), ps.voted_for);

    ps.setTerm(5);
    try testing.expectEqual(@as(types.Term, 5), ps.current_term);
    try testing.expectEqual(@as(?types.NodeId, null), ps.voted_for);
}

test "PersistentState setTerm does not update for lower term" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    ps.setTerm(10);
    try ps.voteFor(42);

    ps.setTerm(5);
    try testing.expectEqual(@as(types.Term, 10), ps.current_term);
    try testing.expectEqual(@as(?types.NodeId, 42), ps.voted_for);
}

test "PersistentState voteFor sets voted_for" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try ps.voteFor(42);
    try testing.expectEqual(@as(?types.NodeId, 42), ps.voted_for);
}

test "PersistentState voteFor returns error if already voted for different candidate" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try ps.voteFor(42);
    try testing.expectError(types.RaftError.InvalidState, ps.voteFor(43));
}

test "PersistentState voteFor is idempotent for same candidate" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try ps.voteFor(42);
    try ps.voteFor(42); // Should succeed - idempotent
    try testing.expectEqual(@as(?types.NodeId, 42), ps.voted_for);
}

test "PersistentState appendEntry adds entry to log" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    const index = try ps.appendEntry(1, .command, "test");
    try testing.expectEqual(@as(types.LogIndex, 1), index);
    try testing.expectEqual(@as(usize, 1), ps.log.items.len);
}

test "PersistentState getEntry returns correct entry" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    _ = try ps.appendEntry(1, .command, "test1");
    _ = try ps.appendEntry(2, .command, "test2");

    const entry = ps.getEntry(2);
    try testing.expect(entry != null);
    try testing.expectEqual(@as(types.LogIndex, 2), entry.?.index);
    try testing.expectEqual(@as(types.Term, 2), entry.?.term);
    try testing.expectEqualStrings("test2", entry.?.data);
}

test "PersistentState getEntry returns null for invalid index" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    _ = try ps.appendEntry(1, .command, "test");

    try testing.expect(ps.getEntry(0) == null);
    try testing.expect(ps.getEntry(2) == null);
}

test "PersistentState getLastLogIndex returns correct index" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try testing.expectEqual(@as(types.LogIndex, 0), ps.getLastLogIndex());

    _ = try ps.appendEntry(1, .command, "test1");
    try testing.expectEqual(@as(types.LogIndex, 1), ps.getLastLogIndex());

    _ = try ps.appendEntry(1, .command, "test2");
    try testing.expectEqual(@as(types.LogIndex, 2), ps.getLastLogIndex());
}

test "PersistentState getLastLogTerm returns correct term" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    try testing.expectEqual(@as(types.Term, 0), ps.getLastLogTerm());

    _ = try ps.appendEntry(1, .command, "test1");
    try testing.expectEqual(@as(types.Term, 1), ps.getLastLogTerm());

    _ = try ps.appendEntry(3, .command, "test2");
    try testing.expectEqual(@as(types.Term, 3), ps.getLastLogTerm());
}

test "PersistentState truncateLogAfter removes entries" {
    var ps = state.PersistentState.init(testing.allocator);
    defer ps.deinit();

    _ = try ps.appendEntry(1, .command, "test1");
    _ = try ps.appendEntry(1, .command, "test2");
    _ = try ps.appendEntry(1, .command, "test3");

    try ps.truncateLogAfter(1);
    try testing.expectEqual(@as(usize, 1), ps.log.items.len);
    try testing.expectEqual(@as(types.LogIndex, 1), ps.getLastLogIndex());
}

test "VolatileState init creates state with zero indices" {
    const vs = state.VolatileState.init();
    try testing.expectEqual(@as(types.LogIndex, 0), vs.commit_index);
    try testing.expectEqual(@as(types.LogIndex, 0), vs.last_applied);
}

test "VolatileState updateCommitIndex updates when higher" {
    var vs = state.VolatileState.init();
    vs.updateCommitIndex(5);
    try testing.expectEqual(@as(types.LogIndex, 5), vs.commit_index);
}

test "VolatileState updateCommitIndex does not update when lower" {
    var vs = state.VolatileState.init();
    vs.updateCommitIndex(10);
    vs.updateCommitIndex(5);
    try testing.expectEqual(@as(types.LogIndex, 10), vs.commit_index);
}

test "VolatileState applyEntry increments last_applied" {
    var vs = state.VolatileState.init();
    vs.updateCommitIndex(3);

    const applied1 = try vs.applyEntry();
    try testing.expectEqual(@as(types.LogIndex, 1), applied1);

    const applied2 = try vs.applyEntry();
    try testing.expectEqual(@as(types.LogIndex, 2), applied2);
}

test "VolatileState applyEntry returns error when caught up" {
    var vs = state.VolatileState.init();
    vs.updateCommitIndex(1);

    _ = try vs.applyEntry();
    try testing.expectError(types.RaftError.InvalidState, vs.applyEntry());
}

test "VolatileState hasUnappliedEntries returns true when behind" {
    var vs = state.VolatileState.init();
    vs.updateCommitIndex(5);
    try testing.expect(vs.hasUnappliedEntries());
}

test "VolatileState hasUnappliedEntries returns false when caught up" {
    var vs = state.VolatileState.init();
    vs.updateCommitIndex(1);
    _ = try vs.applyEntry();
    try testing.expect(!vs.hasUnappliedEntries());
}

test "LeaderState init creates empty state" {
    var ls = state.LeaderState.init(testing.allocator);
    defer ls.deinit();

    try testing.expectEqual(@as(usize, 0), ls.next_index.count());
    try testing.expectEqual(@as(usize, 0), ls.match_index.count());
}

test "LeaderState initializeForNode sets indices" {
    var ls = state.LeaderState.init(testing.allocator);
    defer ls.deinit();

    try ls.initializeForNode(42, 10);
    try testing.expectEqual(@as(types.LogIndex, 11), ls.getNextIndex(42).?);
    try testing.expectEqual(@as(types.LogIndex, 0), ls.getMatchIndex(42).?);
}

test "LeaderState updateForNode updates indices" {
    var ls = state.LeaderState.init(testing.allocator);
    defer ls.deinit();

    try ls.initializeForNode(42, 10);
    try ls.updateForNode(42, 15);

    try testing.expectEqual(@as(types.LogIndex, 15), ls.getMatchIndex(42).?);
    try testing.expectEqual(@as(types.LogIndex, 16), ls.getNextIndex(42).?);
}

test "LeaderState decrementNextIndex decrements next_index" {
    var ls = state.LeaderState.init(testing.allocator);
    defer ls.deinit();

    try ls.initializeForNode(42, 10);
    try ls.decrementNextIndex(42);

    try testing.expectEqual(@as(types.LogIndex, 10), ls.getNextIndex(42).?);
}

test "LeaderState decrementNextIndex does not go below 1" {
    var ls = state.LeaderState.init(testing.allocator);
    defer ls.deinit();

    try ls.initializeForNode(42, 0);
    try ls.decrementNextIndex(42);

    try testing.expectEqual(@as(types.LogIndex, 1), ls.getNextIndex(42).?);
}
