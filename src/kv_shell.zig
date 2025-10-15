const std = @import("std");
const posix = std.posix;
const kv = @import("core/kv/store.zig");

const CommandHistory = struct {
    items: std.ArrayList([]u8),
    position: usize,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !CommandHistory {
        const items = try std.ArrayList([]u8).initCapacity(allocator, 0);
        return .{
            .items = items,
            .position = 0,
            .allocator = allocator,
        };
    }

    fn deinit(self: *CommandHistory) void {
        for (self.items.items) |item| {
            self.allocator.free(item);
        }
        self.items.deinit(self.allocator);
    }

    fn add(self: *CommandHistory, line: []const u8) !void {
        if (line.len == 0) return;

        if (self.items.items.len > 0 and std.mem.eql(u8, self.items.items[self.items.items.len - 1], line)) {
            return;
        }

        const copy = try self.allocator.dupe(u8, line);
        try self.items.append(self.allocator, copy);
        self.position = self.items.items.len;
    }

    fn moveUp(self: *CommandHistory) ?[]const u8 {
        if (self.items.items.len == 0) return null;
        if (self.position > 0) {
            self.position -= 1;
        }
        return self.items.items[self.position];
    }

    fn moveDown(self: *CommandHistory) ?[]const u8 {
        if (self.items.items.len == 0) return null;
        if (self.position < self.items.items.len - 1) {
            self.position += 1;
            return self.items.items[self.position];
        }
        self.position = self.items.items.len;
        return "";
    }

    fn reset(self: *CommandHistory) void {
        self.position = self.items.items.len;
    }
};

const TerminalState = struct {
    original: posix.termios,
    stdin: std.fs.File,

    fn init() !TerminalState {
        const stdin = std.fs.File.stdin();
        const original = try posix.tcgetattr(stdin.handle);
        return .{
            .original = original,
            .stdin = stdin,
        };
    }

    fn enableRawMode(self: *TerminalState) !void {
        var raw = self.original;

        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;

        raw.iflag.IXON = false;
        raw.iflag.ICRNL = false;
        raw.iflag.BRKINT = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;

        raw.oflag.OPOST = false;

        raw.cflag.CSIZE = .CS8;

        raw.cc[@intFromEnum(posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(posix.V.TIME)] = 0;

        try posix.tcsetattr(self.stdin.handle, .FLUSH, raw);
    }

    fn restore(self: *TerminalState) !void {
        try posix.tcsetattr(self.stdin.handle, .FLUSH, self.original);
    }
};

fn readLine(allocator: std.mem.Allocator, history: *CommandHistory, terminal: *TerminalState) !?[]u8 {
    var buffer = try std.ArrayList(u8).initCapacity(allocator, 64);
    defer buffer.deinit(allocator);

    var cursor_pos: usize = 0;
    const stdout = std.fs.File.stdout();

    var stdin_buffer: [8]u8 = undefined;
    var stdin_reader = terminal.stdin.reader(&stdin_buffer);

    while (true) {
        const byte = stdin_reader.interface.peek(1) catch |err| {
            if (err == error.ReadFailed) return null;
            return err;
        };

        if (byte.len == 0) return null;

        _ = try stdin_reader.interface.discard(@enumFromInt(1));
        const c = byte[0];

        if (c == '\n' or c == '\r') {
            try stdout.writeAll("\r\n");
            const result = try buffer.toOwnedSlice(allocator);
            return result;
        } else if (c == 127 or c == 8) {
            if (cursor_pos > 0) {
                cursor_pos -= 1;
                buffer.items.len -= 1;
                try stdout.writeAll("\x08 \x08");
            }
        } else if (c == 4) {
            // Ctrl+D
            if (buffer.items.len == 0) {
                return null;
            }
        } else if (c == 27) {
            const seq = stdin_reader.interface.peek(2) catch continue;
            if (seq.len < 2) continue;

            if (seq[0] == '[') {
                _ = try stdin_reader.interface.discard(@enumFromInt(2));

                if (seq[1] == 'A') {
                    if (history.moveUp()) |line| {
                        try stdout.writeAll("\r\x1b[K> ");
                        try stdout.writeAll(line);
                        buffer.clearRetainingCapacity();
                        try buffer.appendSlice(allocator, line);
                        cursor_pos = line.len;
                    }
                } else if (seq[1] == 'B') {
                    const line = history.moveDown() orelse "";
                    try stdout.writeAll("\r\x1b[K> ");
                    try stdout.writeAll(line);
                    buffer.clearRetainingCapacity();
                    try buffer.appendSlice(allocator, line);
                    cursor_pos = line.len;
                }
            }
        } else if (c >= 32 and c < 127) {
            try buffer.append(allocator, c);
            try stdout.writeAll(&[_]u8{c});
            cursor_pos += 1;
        }
    }
}

fn saveKVStore(allocator: std.mem.Allocator, store: *kv.KVStore, dir_path: []const u8) !void {
    const snapshot = try store.kv_state.takeSnapshot(allocator);
    defer allocator.free(snapshot);

    const state_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "state.dat" });
    defer allocator.free(state_path);

    const file = try std.fs.cwd().createFile(state_path, .{});
    defer file.close();

    try file.writeAll(snapshot);
}

fn loadKVStore(allocator: std.mem.Allocator, dir_path: []const u8) !kv.KVStore {
    var store = try kv.KVStore.init(allocator, 1);
    errdefer store.deinit(allocator);

    try store.bootstrap("localhost:0");

    const state_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "state.dat" });
    defer allocator.free(state_path);

    const file = std.fs.cwd().openFile(state_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return store;
        }
        return err;
    };
    defer file.close();

    const snapshot = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(snapshot);

    try store.kv_state.restoreSnapshot(snapshot);

    return store;
}

pub fn run(allocator: std.mem.Allocator, path: []const u8) !void {
    var store = try loadKVStore(allocator, path);
    defer store.deinit(allocator);

    const stdout = std.fs.File.stdout();

    const connect_msg = try std.fmt.allocPrint(allocator, "Connected to KV store at '{s}'\r\n", .{path});
    defer allocator.free(connect_msg);
    try stdout.writeAll(connect_msg);
    try stdout.writeAll("Commands: get <key>, put <key> <value>, delete <key>, list, count, help, exit\r\n");
    try stdout.writeAll("Press Ctrl+D to save and exit\r\n\r\n");

    var terminal = try TerminalState.init();
    try terminal.enableRawMode();
    defer terminal.restore() catch {};

    var history = try CommandHistory.init(allocator);
    defer history.deinit();

    while (true) {
        try stdout.writeAll("> ");

        const line = (try readLine(allocator, &history, &terminal)) orelse {
            try stdout.writeAll("\r\n");
            try saveKVStore(allocator, &store, path);
            break;
        };
        defer allocator.free(line);

        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;

        try history.add(trimmed);
        history.reset();

        var parts = std.mem.splitScalar(u8, trimmed, ' ');
        const cmd = parts.next() orelse continue;

        if (std.mem.eql(u8, cmd, "exit") or std.mem.eql(u8, cmd, "quit")) {
            try saveKVStore(allocator, &store, path);
            try stdout.writeAll("Saved and exiting.\r\n");
            break;
        } else if (std.mem.eql(u8, cmd, "help")) {
            try stdout.writeAll("Commands:\r\n");
            try stdout.writeAll("  get <key>              Get value for key\r\n");
            try stdout.writeAll("  put <key> <value>      Set key to value\r\n");
            try stdout.writeAll("  delete <key>           Delete key\r\n");
            try stdout.writeAll("  list                   List all keys\r\n");
            try stdout.writeAll("  count                  Show number of keys\r\n");
            try stdout.writeAll("  help                   Show this help\r\n");
            try stdout.writeAll("  exit                   Save and exit\r\n");
        } else if (std.mem.eql(u8, cmd, "get")) {
            const key = parts.rest();
            if (key.len == 0) {
                try stdout.writeAll("Error: get requires a key\r\n");
                continue;
            }

            const value = store.get(allocator, key) catch |err| {
                if (err == kv.KVError.KeyNotFound) {
                    const msg = try std.fmt.allocPrint(allocator, "Key not found: {s}\r\n", .{key});
                    defer allocator.free(msg);
                    try stdout.writeAll(msg);
                } else {
                    const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
                    defer allocator.free(msg);
                    try stdout.writeAll(msg);
                }
                continue;
            };
            defer allocator.free(value);

            try stdout.writeAll(value);
            try stdout.writeAll("\r\n");
        } else if (std.mem.eql(u8, cmd, "put")) {
            const key_start = std.mem.indexOfScalar(u8, trimmed, ' ') orelse {
                try stdout.writeAll("Error: put requires a key and value\r\n");
                continue;
            };

            const remainder = trimmed[key_start + 1 ..];
            const value_start = std.mem.indexOfScalar(u8, remainder, ' ') orelse {
                try stdout.writeAll("Error: put requires a key and value\r\n");
                continue;
            };

            const key = std.mem.trim(u8, remainder[0..value_start], " ");
            const value = std.mem.trim(u8, remainder[value_start + 1 ..], " ");

            if (key.len == 0 or value.len == 0) {
                try stdout.writeAll("Error: put requires a key and value\r\n");
                continue;
            }

            store.put(key, value) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
                defer allocator.free(msg);
                try stdout.writeAll(msg);
                continue;
            };

            try stdout.writeAll("OK\r\n");
        } else if (std.mem.eql(u8, cmd, "delete")) {
            const key = parts.rest();
            if (key.len == 0) {
                try stdout.writeAll("Error: delete requires a key\r\n");
                continue;
            }

            store.delete(key) catch |err| {
                if (err == kv.KVError.KeyNotFound) {
                    const msg = try std.fmt.allocPrint(allocator, "Key not found: {s}\r\n", .{key});
                    defer allocator.free(msg);
                    try stdout.writeAll(msg);
                } else {
                    const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
                    defer allocator.free(msg);
                    try stdout.writeAll(msg);
                }
                continue;
            };

            try stdout.writeAll("OK\r\n");
        } else if (std.mem.eql(u8, cmd, "list")) {
            var it = store.kv_state.map.iterator();
            var count: usize = 0;
            while (it.next()) |entry| {
                const msg = try std.fmt.allocPrint(allocator, "{s} = {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
                defer allocator.free(msg);
                try stdout.writeAll(msg);
                count += 1;
            }
            if (count == 0) {
                try stdout.writeAll("(empty)\r\n");
            }
        } else if (std.mem.eql(u8, cmd, "count")) {
            const msg = try std.fmt.allocPrint(allocator, "{} keys\r\n", .{store.count()});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown command: {s} (type 'help' for commands)\r\n", .{cmd});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
        }
    }
}
