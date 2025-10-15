const std = @import("std");
const types = @import("types.zig");

// Interface for state machines that can be replicated via Raft
pub fn StateMachine(comptime T: type) type {
    return struct {
        const Self = @This();

        // Apply a command to the state machine
        // Returns the result of applying the command
        applyFn: *const fn (state: *T, command: []const u8) anyerror![]const u8,

        // Take a snapshot of the current state
        snapshotFn: *const fn (state: *T, allocator: std.mem.Allocator) anyerror![]const u8,

        // Restore state from a snapshot
        restoreFn: *const fn (state: *T, snapshot: []const u8) anyerror!void,

        state: *T,

        pub fn apply(self: Self, command: []const u8) ![]const u8 {
            return self.applyFn(self.state, command);
        }

        pub fn snapshot(self: Self, allocator: std.mem.Allocator) ![]const u8 {
            return self.snapshotFn(self.state, allocator);
        }

        pub fn restore(self: Self, snap: []const u8) !void {
            return self.restoreFn(self.state, snap);
        }
    };
}

// Simple in-memory state machine for testing
pub const TestStateMachine = struct {
    value: i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TestStateMachine {
        return .{
            .value = 0,
            .allocator = allocator,
        };
    }

    pub fn apply(self: *TestStateMachine, command: []const u8) ![]const u8 {
        if (std.mem.eql(u8, command, "increment")) {
            self.value += 1;
        } else if (std.mem.eql(u8, command, "decrement")) {
            self.value -= 1;
        } else if (std.mem.startsWith(u8, command, "set:")) {
            const value_str = command[4..];
            self.value = try std.fmt.parseInt(i64, value_str, 10);
        } else {
            return types.RaftError.InvalidState;
        }

        return std.fmt.allocPrint(self.allocator, "{}", .{self.value});
    }

    pub fn takeSnapshot(self: *TestStateMachine, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{}", .{self.value});
    }

    pub fn restoreSnapshot(self: *TestStateMachine, snapshot: []const u8) !void {
        self.value = try std.fmt.parseInt(i64, snapshot, 10);
    }

    pub fn stateMachine(self: *TestStateMachine) StateMachine(TestStateMachine) {
        return .{
            .applyFn = apply,
            .snapshotFn = takeSnapshot,
            .restoreFn = restoreSnapshot,
            .state = self,
        };
    }
};
