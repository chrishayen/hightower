const std = @import("std");
const posix = std.posix;
const kv = @import("kv_store.zig");
const auth_mod = @import("auth_operations.zig");
const crypto_mod = @import("core/kv/crypto.zig");

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
            return try buffer.toOwnedSlice(allocator);
        }

        if (c == 127 or c == 8) {
            try handleBackspace(&buffer, &cursor_pos, stdout);
            continue;
        }

        if (c == 4) {
            if (buffer.items.len == 0) {
                return null;
            }
            continue;
        }

        if (c == 27) {
            try handleEscapeSequence(&stdin_reader, history, &buffer, &cursor_pos, stdout, allocator);
            continue;
        }

        if (c >= 32 and c < 127) {
            try handlePrintableChar(c, &buffer, &cursor_pos, stdout, allocator);
            continue;
        }
    }
}

fn handleBackspace(buffer: *std.ArrayList(u8), cursor_pos: *usize, stdout: anytype) !void {
    if (cursor_pos.* == 0) {
        return;
    }

    cursor_pos.* -= 1;
    buffer.items.len -= 1;
    try stdout.writeAll("\x08 \x08");
}

fn handleEscapeSequence(
    stdin_reader: anytype,
    history: *CommandHistory,
    buffer: *std.ArrayList(u8),
    cursor_pos: *usize,
    stdout: anytype,
    allocator: std.mem.Allocator,
) !void {
    const seq = stdin_reader.interface.peek(2) catch return;
    if (seq.len < 2) return;
    if (seq[0] != '[') return;

    _ = try stdin_reader.interface.discard(@enumFromInt(2));

    if (seq[1] == 'A') {
        try handleArrowUp(history, buffer, cursor_pos, stdout, allocator);
    } else if (seq[1] == 'B') {
        try handleArrowDown(history, buffer, cursor_pos, stdout, allocator);
    }
}

fn handleArrowUp(
    history: *CommandHistory,
    buffer: *std.ArrayList(u8),
    cursor_pos: *usize,
    stdout: anytype,
    allocator: std.mem.Allocator,
) !void {
    const line = history.moveUp() orelse return;
    try stdout.writeAll("\r\x1b[K> ");
    try stdout.writeAll(line);
    buffer.clearRetainingCapacity();
    try buffer.appendSlice(allocator, line);
    cursor_pos.* = line.len;
}

fn handleArrowDown(
    history: *CommandHistory,
    buffer: *std.ArrayList(u8),
    cursor_pos: *usize,
    stdout: anytype,
    allocator: std.mem.Allocator,
) !void {
    const line = history.moveDown() orelse "";
    try stdout.writeAll("\r\x1b[K> ");
    try stdout.writeAll(line);
    buffer.clearRetainingCapacity();
    try buffer.appendSlice(allocator, line);
    cursor_pos.* = line.len;
}

fn handlePrintableChar(c: u8, buffer: *std.ArrayList(u8), cursor_pos: *usize, stdout: anytype, allocator: std.mem.Allocator) !void {
    try buffer.append(allocator, c);
    try stdout.writeAll(&[_]u8{c});
    cursor_pos.* += 1;
}

fn saveMasterKey(allocator: std.mem.Allocator, store: *kv.KVStore, dir_path: []const u8) !void {
    const master_key = store.master_key orelse return;

    const key_str = try master_key.toString(allocator);
    defer allocator.free(key_str);

    const key_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "master.key" });
    defer allocator.free(key_path);

    const file = try std.fs.cwd().createFile(key_path, .{ .mode = 0o600 });
    defer file.close();

    try file.writeAll(key_str);
}

fn loadMasterKey(allocator: std.mem.Allocator, dir_path: []const u8) !?crypto_mod.EncryptionKey {
    // Check environment variable first
    if (std.process.getEnvVarOwned(allocator, "HT_KV_MASTER_KEY")) |key_str| {
        defer allocator.free(key_str);
        return try crypto_mod.EncryptionKey.fromString(key_str);
    } else |_| {}

    // Try to load from file
    const key_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "master.key" });
    defer allocator.free(key_path);

    const file = std.fs.cwd().openFile(key_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return null;
        }
        return err;
    };
    defer file.close();

    const key_str = try file.readToEndAlloc(allocator, 1024);
    defer allocator.free(key_str);

    return try crypto_mod.EncryptionKey.fromString(key_str);
}

fn saveKVStore(allocator: std.mem.Allocator, store: *kv.KVStore, dir_path: []const u8) !void {
    const snapshot = try store.kv_state.takeSnapshot(allocator);
    defer allocator.free(snapshot);

    const state_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "state.dat" });
    defer allocator.free(state_path);

    const file = try std.fs.cwd().createFile(state_path, .{});
    defer file.close();

    try file.writeAll(snapshot);

    try saveMasterKey(allocator, store, dir_path);
}

fn loadKVStore(allocator: std.mem.Allocator, dir_path: []const u8) !kv.KVStore {
    var store = try kv.KVStore.init(allocator, 1);
    errdefer store.deinit(allocator);

    try store.bootstrap("localhost:0");

    // Load master key if it exists
    if (try loadMasterKey(allocator, dir_path)) |master_key| {
        store.setMasterKey(master_key);
    }

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

    try printWelcome(allocator, stdout, path, store.master_key != null);

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
        }

        if (std.mem.eql(u8, cmd, "help")) {
            try handleHelpCommand(stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "get")) {
            try handleGetCommand(allocator, &store, &parts, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "put")) {
            try handlePutCommand(allocator, &store, trimmed, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "delete")) {
            try handleDeleteCommand(allocator, &store, &parts, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "list")) {
            try handleListCommand(allocator, &store, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "count")) {
            try handleCountCommand(allocator, &store, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "genkey")) {
            try handleGenKeyCommand(allocator, &store, path, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "user")) {
            try handleUserCommand(allocator, &store, trimmed, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "apikey")) {
            try handleApiKeyCommand(allocator, &store, trimmed, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "put-encrypted")) {
            try handlePutEncryptedCommand(allocator, &store, trimmed, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "get-encrypted")) {
            try handleGetEncryptedCommand(allocator, &store, &parts, stdout);
            continue;
        }

        if (std.mem.eql(u8, cmd, "delete-encrypted")) {
            try handleDeleteEncryptedCommand(allocator, &store, &parts, stdout);
            continue;
        }

        const msg = try std.fmt.allocPrint(allocator, "Unknown command: {s} (type 'help' for commands)\r\n", .{cmd});
        defer allocator.free(msg);
        try stdout.writeAll(msg);
    }
}

fn printWelcome(allocator: std.mem.Allocator, stdout: anytype, path: []const u8, has_master_key: bool) !void {
    const connect_msg = try std.fmt.allocPrint(allocator, "Connected to KV store at '{s}'\r\n", .{path});
    defer allocator.free(connect_msg);
    try stdout.writeAll(connect_msg);

    if (has_master_key) {
        try stdout.writeAll("Master key loaded\r\n");
    } else {
        try stdout.writeAll("No master key (use 'genkey' to generate one)\r\n");
    }

    try stdout.writeAll("Commands: get, put, delete, list, count, user, apikey, put-encrypted, get-encrypted, help, exit\r\n");
    try stdout.writeAll("Press Ctrl+D to save and exit\r\n\r\n");
}

fn handleHelpCommand(stdout: anytype) !void {
    try stdout.writeAll("Commands:\r\n");
    try stdout.writeAll("  get <key>                                   Get value for key\r\n");
    try stdout.writeAll("  put <key> <value>                           Set key to value\r\n");
    try stdout.writeAll("  delete <key>                                Delete key\r\n");
    try stdout.writeAll("  list                                        List all keys\r\n");
    try stdout.writeAll("  count                                       Show number of keys\r\n");
    try stdout.writeAll("  genkey                                      Generate master key\r\n");
    try stdout.writeAll("  user create <username> <password>           Create user\r\n");
    try stdout.writeAll("  user get <username>                         Get user info\r\n");
    try stdout.writeAll("  user delete <username>                      Delete user\r\n");
    try stdout.writeAll("  user verify <username> <password>           Verify password\r\n");
    try stdout.writeAll("  user update-password <username> <password>  Update password\r\n");
    try stdout.writeAll("  apikey create <username> [days]             Create API key\r\n");
    try stdout.writeAll("  apikey get <key_id>                         Get API key info\r\n");
    try stdout.writeAll("  apikey revoke <key_id>                      Revoke API key\r\n");
    try stdout.writeAll("  apikey verify <key>                         Verify API key\r\n");
    try stdout.writeAll("  put-encrypted <key> <value>                 Store encrypted value\r\n");
    try stdout.writeAll("  get-encrypted <key>                         Get encrypted value\r\n");
    try stdout.writeAll("  delete-encrypted <key>                      Delete encrypted value\r\n");
    try stdout.writeAll("  help                                        Show this help\r\n");
    try stdout.writeAll("  exit                                        Save and exit\r\n");
}

fn handleGetCommand(allocator: std.mem.Allocator, store: *kv.KVStore, parts: anytype, stdout: anytype) !void {
    const key = parts.rest();
    if (key.len == 0) {
        try stdout.writeAll("Error: get requires a key\r\n");
        return;
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
        return;
    };
    defer allocator.free(value);

    try stdout.writeAll(value);
    try stdout.writeAll("\r\n");
}

fn handlePutCommand(allocator: std.mem.Allocator, store: *kv.KVStore, trimmed: []const u8, stdout: anytype) !void {
    const key_start = std.mem.indexOfScalar(u8, trimmed, ' ') orelse {
        try stdout.writeAll("Error: put requires a key and value\r\n");
        return;
    };

    const remainder = trimmed[key_start + 1 ..];
    const value_start = std.mem.indexOfScalar(u8, remainder, ' ') orelse {
        try stdout.writeAll("Error: put requires a key and value\r\n");
        return;
    };

    const key = std.mem.trim(u8, remainder[0..value_start], " ");
    const value = std.mem.trim(u8, remainder[value_start + 1 ..], " ");

    if (key.len == 0 or value.len == 0) {
        try stdout.writeAll("Error: put requires a key and value\r\n");
        return;
    }

    store.put(key, value) catch |err| {
        const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
        defer allocator.free(msg);
        try stdout.writeAll(msg);
        return;
    };

    try stdout.writeAll("OK\r\n");
}

fn handleDeleteCommand(allocator: std.mem.Allocator, store: *kv.KVStore, parts: anytype, stdout: anytype) !void {
    const key = parts.rest();
    if (key.len == 0) {
        try stdout.writeAll("Error: delete requires a key\r\n");
        return;
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
        return;
    };

    try stdout.writeAll("OK\r\n");
}

fn handleListCommand(allocator: std.mem.Allocator, store: *kv.KVStore, stdout: anytype) !void {
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
}

fn handleCountCommand(allocator: std.mem.Allocator, store: *kv.KVStore, stdout: anytype) !void {
    const msg = try std.fmt.allocPrint(allocator, "{} keys\r\n", .{store.count()});
    defer allocator.free(msg);
    try stdout.writeAll(msg);
}

fn handleGenKeyCommand(allocator: std.mem.Allocator, store: *kv.KVStore, path: []const u8, stdout: anytype) !void {
    if (store.master_key != null) {
        try stdout.writeAll("Master key already exists\r\n");
        return;
    }

    try store.generateAndSetMasterKey();
    try saveMasterKey(allocator, store, path);
    try stdout.writeAll("Master key generated and saved\r\n");
}

fn handleUserCommand(allocator: std.mem.Allocator, store: *kv.KVStore, trimmed: []const u8, stdout: anytype) !void {
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    _ = parts.next(); // skip "user"

    const subcommand = parts.next() orelse {
        try stdout.writeAll("Error: user command requires a subcommand (create, get, delete, verify, update-password)\r\n");
        return;
    };

    if (std.mem.eql(u8, subcommand, "create")) {
        const username = parts.next() orelse {
            try stdout.writeAll("Error: user create requires username and password\r\n");
            return;
        };
        const password = parts.rest();
        if (password.len == 0) {
            try stdout.writeAll("Error: user create requires username and password\r\n");
            return;
        }

        auth_mod.createUser(store, allocator, username, password, "{}") catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        try stdout.writeAll("User created\r\n");
        return;
    }

    if (std.mem.eql(u8, subcommand, "get")) {
        const username = parts.rest();
        if (username.len == 0) {
            try stdout.writeAll("Error: user get requires username\r\n");
            return;
        }

        const user = auth_mod.getUser(store, allocator, username) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        defer user.deinit(allocator);

        const msg = try std.fmt.allocPrint(allocator, "Username: {s}\r\nCreated: {}\r\nUpdated: {}\r\nMetadata: {s}\r\n", .{ user.username, user.created_at, user.updated_at, user.metadata });
        defer allocator.free(msg);
        try stdout.writeAll(msg);
        return;
    }

    if (std.mem.eql(u8, subcommand, "delete")) {
        const username = parts.rest();
        if (username.len == 0) {
            try stdout.writeAll("Error: user delete requires username\r\n");
            return;
        }

        auth_mod.deleteUser(store, allocator, username) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        try stdout.writeAll("User deleted\r\n");
        return;
    }

    if (std.mem.eql(u8, subcommand, "verify")) {
        const username = parts.next() orelse {
            try stdout.writeAll("Error: user verify requires username and password\r\n");
            return;
        };
        const password = parts.rest();
        if (password.len == 0) {
            try stdout.writeAll("Error: user verify requires username and password\r\n");
            return;
        }

        auth_mod.verifyPassword(store, allocator, username, password) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        try stdout.writeAll("Password verified\r\n");
        return;
    }

    if (std.mem.eql(u8, subcommand, "update-password")) {
        const username = parts.next() orelse {
            try stdout.writeAll("Error: user update-password requires username and new password\r\n");
            return;
        };
        const new_password = parts.rest();
        if (new_password.len == 0) {
            try stdout.writeAll("Error: user update-password requires username and new password\r\n");
            return;
        }

        auth_mod.updatePassword(store, allocator, username, new_password) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        try stdout.writeAll("Password updated\r\n");
        return;
    }

    const msg = try std.fmt.allocPrint(allocator, "Unknown user subcommand: {s}\r\n", .{subcommand});
    defer allocator.free(msg);
    try stdout.writeAll(msg);
}

fn handleApiKeyCommand(allocator: std.mem.Allocator, store: *kv.KVStore, trimmed: []const u8, stdout: anytype) !void {
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    _ = parts.next(); // skip "apikey"

    const subcommand = parts.next() orelse {
        try stdout.writeAll("Error: apikey command requires a subcommand (create, get, revoke, verify)\r\n");
        return;
    };

    if (std.mem.eql(u8, subcommand, "create")) {
        const username = parts.next() orelse {
            try stdout.writeAll("Error: apikey create requires username\r\n");
            return;
        };
        const days_str = parts.next();
        const expires_in_days = if (days_str) |d| try std.fmt.parseInt(u32, d, 10) else null;

        const result = auth_mod.createApiKey(store, allocator, username, expires_in_days, "{}") catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        defer allocator.free(result.key_id);
        defer allocator.free(result.key);

        const msg = try std.fmt.allocPrint(allocator, "API Key created\r\nKey ID: {s}\r\nKey: {s}\r\n", .{ result.key_id, result.key });
        defer allocator.free(msg);
        try stdout.writeAll(msg);
        try stdout.writeAll("IMPORTANT: Save this key securely. It will not be shown again.\r\n");
        return;
    }

    if (std.mem.eql(u8, subcommand, "get")) {
        const key_id = parts.rest();
        if (key_id.len == 0) {
            try stdout.writeAll("Error: apikey get requires key_id\r\n");
            return;
        }

        const api_key_data = auth_mod.getApiKey(store, allocator, key_id) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        defer api_key_data.deinit(allocator);

        const expires_msg = if (api_key_data.expires_at) |exp|
            try std.fmt.allocPrint(allocator, "{}", .{exp})
        else
            try allocator.dupe(u8, "never");
        defer allocator.free(expires_msg);

        const last_used_msg = if (api_key_data.last_used) |last|
            try std.fmt.allocPrint(allocator, "{}", .{last})
        else
            try allocator.dupe(u8, "never");
        defer allocator.free(last_used_msg);

        const msg = try std.fmt.allocPrint(allocator, "Key ID: {s}\r\nUsername: {s}\r\nCreated: {}\r\nExpires: {s}\r\nLast used: {s}\r\nMetadata: {s}\r\n", .{ api_key_data.key_id, api_key_data.username, api_key_data.created_at, expires_msg, last_used_msg, api_key_data.metadata });
        defer allocator.free(msg);
        try stdout.writeAll(msg);
        return;
    }

    if (std.mem.eql(u8, subcommand, "revoke")) {
        const key_id = parts.rest();
        if (key_id.len == 0) {
            try stdout.writeAll("Error: apikey revoke requires key_id\r\n");
            return;
        }

        auth_mod.revokeApiKey(store, allocator, key_id) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        try stdout.writeAll("API Key revoked\r\n");
        return;
    }

    if (std.mem.eql(u8, subcommand, "verify")) {
        const key = parts.rest();
        if (key.len == 0) {
            try stdout.writeAll("Error: apikey verify requires key\r\n");
            return;
        }

        const username = auth_mod.verifyApiKey(store, allocator, key) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
            return;
        };
        defer allocator.free(username);

        const msg = try std.fmt.allocPrint(allocator, "API Key verified\r\nUsername: {s}\r\n", .{username});
        defer allocator.free(msg);
        try stdout.writeAll(msg);
        return;
    }

    const msg = try std.fmt.allocPrint(allocator, "Unknown apikey subcommand: {s}\r\n", .{subcommand});
    defer allocator.free(msg);
    try stdout.writeAll(msg);
}

fn handlePutEncryptedCommand(allocator: std.mem.Allocator, store: *kv.KVStore, trimmed: []const u8, stdout: anytype) !void {
    const key_start = std.mem.indexOfScalar(u8, trimmed, ' ') orelse {
        try stdout.writeAll("Error: put-encrypted requires a key and value\r\n");
        return;
    };

    const remainder = trimmed[key_start + 1 ..];
    const value_start = std.mem.indexOfScalar(u8, remainder, ' ') orelse {
        try stdout.writeAll("Error: put-encrypted requires a key and value\r\n");
        return;
    };

    const key = std.mem.trim(u8, remainder[0..value_start], " ");
    const value = std.mem.trim(u8, remainder[value_start + 1 ..], " ");

    if (key.len == 0 or value.len == 0) {
        try stdout.writeAll("Error: put-encrypted requires a key and value\r\n");
        return;
    }

    store.putEncrypted(allocator, key, value) catch |err| {
        const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
        defer allocator.free(msg);
        try stdout.writeAll(msg);
        return;
    };

    try stdout.writeAll("OK\r\n");
}

fn handleGetEncryptedCommand(allocator: std.mem.Allocator, store: *kv.KVStore, parts: anytype, stdout: anytype) !void {
    const key = parts.rest();
    if (key.len == 0) {
        try stdout.writeAll("Error: get-encrypted requires a key\r\n");
        return;
    }

    const value = store.getEncrypted(allocator, key) catch |err| {
        if (err == kv.KVError.KeyNotFound) {
            const msg = try std.fmt.allocPrint(allocator, "Key not found: {s}\r\n", .{key});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
        }
        return;
    };
    defer allocator.free(value);

    try stdout.writeAll(value);
    try stdout.writeAll("\r\n");
}

fn handleDeleteEncryptedCommand(allocator: std.mem.Allocator, store: *kv.KVStore, parts: anytype, stdout: anytype) !void {
    const key = parts.rest();
    if (key.len == 0) {
        try stdout.writeAll("Error: delete-encrypted requires a key\r\n");
        return;
    }

    store.deleteEncrypted(allocator, key) catch |err| {
        if (err == kv.KVError.KeyNotFound) {
            const msg = try std.fmt.allocPrint(allocator, "Key not found: {s}\r\n", .{key});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Error: {}\r\n", .{err});
            defer allocator.free(msg);
            try stdout.writeAll(msg);
        }
        return;
    };

    try stdout.writeAll("OK\r\n");
}
