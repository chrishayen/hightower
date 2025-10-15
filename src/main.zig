const std = @import("std");
const net = std.net;
const posix = std.posix;

const stun_server = @import("stun_server.zig");
const stun_client = @import("stun_client.zig");
const kv = @import("core/kv/store.zig");
const kv_shell = @import("kv_shell.zig");

const log = std.log.scoped(.cli);

const Command = enum {
    help,
    run,
    stun,
    kv,
};

const RunSubcommand = enum {
    stun,
};

const KVSubcommand = enum {
    init,
    connect,
};

fn printHelp() void {
    std.debug.print(
        \\ht - WireGuard implementation CLI
        \\
        \\Usage:
        \\  ht run <service>          Start a service
        \\  ht stun <address> [port]  Query a STUN server
        \\  ht kv init <path>         Create a new KV store at path
        \\  ht kv connect <path>      Connect to KV store and start interactive session
        \\  ht help                   Show this help message
        \\
        \\Services:
        \\  stun                      Start the STUN server
        \\
        \\Examples:
        \\  ht run stun
        \\  ht stun stun.l.google.com 19302
        \\  ht stun stun.l.google.com
        \\  ht kv init ./mystore
        \\  ht kv connect ./mystore
        \\
    , .{});
}

fn parseCommand(arg: []const u8) ?Command {
    if (std.mem.eql(u8, arg, "run")) return .run;
    if (std.mem.eql(u8, arg, "stun")) return .stun;
    if (std.mem.eql(u8, arg, "kv")) return .kv;
    if (std.mem.eql(u8, arg, "help")) return .help;
    return null;
}

fn parseRunSubcommand(arg: []const u8) ?RunSubcommand {
    if (std.mem.eql(u8, arg, "stun")) return .stun;
    return null;
}

fn parseKVSubcommand(arg: []const u8) ?KVSubcommand {
    if (std.mem.eql(u8, arg, "init")) return .init;
    if (std.mem.eql(u8, arg, "connect")) return .connect;
    return null;
}

fn runStunServer(allocator: std.mem.Allocator) !void {
    _ = allocator;

    const config = stun_server.ServerConfig{};
    var server = try stun_server.Server.init(config);
    defer server.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const server_allocator = gpa.allocator();

    try server.run(server_allocator);
}

fn queryStunServer(allocator: std.mem.Allocator, server_host: []const u8, server_port: u16) !void {
    log.info("Querying STUN server {s}:{} for public address...", .{ server_host, server_port });

    const public_address = stun_client.queryPublicAddress(allocator, server_host, server_port) catch |err| {
        log.err("Failed to query STUN server: {}", .{err});
        return err;
    };

    log.info("Public address: {any}", .{public_address});
}

fn handleRunCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 3) {
        std.debug.print("Error: 'run' command requires a service name\n\n", .{});
        printHelp();
        return error.MissingServiceName;
    }

    const subcommand = parseRunSubcommand(args[2]) orelse {
        std.debug.print("Error: Unknown service '{s}'\n\n", .{args[2]});
        printHelp();
        return error.UnknownService;
    };

    switch (subcommand) {
        .stun => try runStunServer(allocator),
    }
}

fn handleStunCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 2) {
        std.debug.print("Error: 'stun' command requires a server address\n\n", .{});
        printHelp();
        return error.MissingServerAddress;
    }

    const server_host = args[1];
    const server_port: u16 = if (args.len >= 3)
        try std.fmt.parseInt(u16, args[2], 10)
    else
        3478;

    try queryStunServer(allocator, server_host, server_port);
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

    const file = openStateFile(state_path) catch |err| {
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

fn openStateFile(path: []const u8) !std.fs.File {
    return try std.fs.cwd().openFile(path, .{});
}

fn kvInit(allocator: std.mem.Allocator, path: []const u8) !void {
    try createDirectory(path);

    var store = try kv.KVStore.init(allocator, 1);
    defer store.deinit(allocator);

    try store.bootstrap("localhost:0");

    try saveKVStore(allocator, &store, path);

    std.debug.print("KV store initialized at '{s}'\n", .{path});
}

fn createDirectory(path: []const u8) !void {
    std.fs.cwd().makeDir(path) catch |err| {
        if (err == error.PathAlreadyExists) {
            std.debug.print("Error: Directory '{s}' already exists\n", .{path});
            return error.PathAlreadyExists;
        }
        return err;
    };
}

fn kvConnect(allocator: std.mem.Allocator, path: []const u8) !void {
    try kv_shell.run(allocator, path);
}

fn handleKvCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 3) {
        std.debug.print("Error: 'kv' command requires a subcommand\n\n", .{});
        printHelp();
        return error.MissingSubcommand;
    }

    const subcommand = parseKVSubcommand(args[2]) orelse {
        std.debug.print("Error: Unknown kv subcommand '{s}'\n\n", .{args[2]});
        printHelp();
        return error.UnknownSubcommand;
    };

    if (args.len < 4) {
        std.debug.print("Error: 'kv {s}' requires a path\n\n", .{args[2]});
        printHelp();
        return error.MissingPath;
    }

    const path = args[3];

    switch (subcommand) {
        .init => try kvInit(allocator, path),
        .connect => try kvConnect(allocator, path),
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printHelp();
        return;
    }

    const command = parseCommand(args[1]) orelse {
        std.debug.print("Error: Unknown command '{s}'\n\n", .{args[1]});
        printHelp();
        return error.UnknownCommand;
    };

    switch (command) {
        .help => printHelp(),
        .run => try handleRunCommand(allocator, args),
        .stun => try handleStunCommand(allocator, args[1..]),
        .kv => try handleKvCommand(allocator, args),
    }
}

test "parseCommand" {
    try std.testing.expectEqual(Command.run, parseCommand("run"));
    try std.testing.expectEqual(Command.stun, parseCommand("stun"));
    try std.testing.expectEqual(Command.kv, parseCommand("kv"));
    try std.testing.expectEqual(Command.help, parseCommand("help"));
    try std.testing.expectEqual(@as(?Command, null), parseCommand("unknown"));
}

test "parseRunSubcommand" {
    try std.testing.expectEqual(RunSubcommand.stun, parseRunSubcommand("stun"));
    try std.testing.expectEqual(@as(?RunSubcommand, null), parseRunSubcommand("unknown"));
}

test "parseKVSubcommand" {
    try std.testing.expectEqual(KVSubcommand.init, parseKVSubcommand("init"));
    try std.testing.expectEqual(KVSubcommand.connect, parseKVSubcommand("connect"));
    try std.testing.expectEqual(@as(?KVSubcommand, null), parseKVSubcommand("unknown"));
}
