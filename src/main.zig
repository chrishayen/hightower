const std = @import("std");
const net = std.net;
const posix = std.posix;

const stun_server = @import("stun_server.zig");
const stun_client = @import("stun_client.zig");
const kv = @import("kv_store.zig");
const kv_shell = @import("kv_shell.zig");
const gateway_server = @import("gateway_server.zig");

const log = std.log.scoped(.cli);

const Command = enum {
    help,
    run,
    stun,
    kv,
};

const RunSubcommand = enum {
    stun,
    gateway,
};

const KVSubcommand = enum {
    init,
    open,
};

fn printHelp() void {
    std.debug.print(
        \\ht - WireGuard implementation CLI
        \\
        \\Usage:
        \\  ht run <service>          Start a service
        \\  ht stun <address> [port]  Query a STUN server
        \\  ht kv init <path>         Create a new KV store at path
        \\  ht kv open <path>         Open KV store and start interactive session
        \\  ht help                   Show this help message
        \\
        \\Services:
        \\  stun                      Start the STUN server
        \\  gateway                   Start the WireGuard gateway server
        \\
        \\Gateway Options:
        \\  --default-auth-key <key>  Set the auth key for registration (or use HT_DEFAULT_AUTH)
        \\  --kv-path <path>          Set the KV store path (default: ~/.ht/gateway, or use HT_KV_PATH)
        \\
        \\Examples:
        \\  ht run stun
        \\  ht run gateway
        \\  ht run gateway --default-auth-key mykey --kv-path ./data
        \\  HT_DEFAULT_AUTH=mykey HT_KV_PATH=./data ht run gateway
        \\  ht stun stun.l.google.com 19302
        \\  ht stun stun.l.google.com
        \\  ht kv init ./mystore
        \\  ht kv open ./mystore
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
    if (std.mem.eql(u8, arg, "gateway")) return .gateway;
    return null;
}

fn parseKVSubcommand(arg: []const u8) ?KVSubcommand {
    if (std.mem.eql(u8, arg, "init")) return .init;
    if (std.mem.eql(u8, arg, "open")) return .open;
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

fn getEnvOrNull(key: []const u8) ?[]const u8 {
    return std.posix.getenv(key);
}

fn expandHomePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, path, "~")) {
        return try allocator.dupe(u8, path);
    }

    const home = getEnvOrNull("HOME") orelse return error.HomeNotSet;

    if (path.len == 1) {
        return try allocator.dupe(u8, home);
    }

    if (path[1] == '/') {
        return try std.fs.path.join(allocator, &[_][]const u8{ home, path[2..] });
    }

    return try allocator.dupe(u8, path);
}

fn ensureDirectoryExists(path: []const u8) !void {
    std.fs.cwd().makePath(path) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };
}

fn parseGatewayConfig(allocator: std.mem.Allocator, args: [][:0]u8, start_index: usize) !gateway_server.ServerConfig {
    var auth_key: ?[]const u8 = null;
    var kv_path: ?[]const u8 = null;

    var i = start_index;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--default-auth-key")) {
            if (i + 1 >= args.len) {
                return error.MissingAuthKey;
            }
            i += 1;
            auth_key = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, arg, "--kv-path")) {
            if (i + 1 >= args.len) {
                return error.MissingKvPath;
            }
            i += 1;
            kv_path = try allocator.dupe(u8, args[i]);
        }
    }

    if (auth_key == null) {
        if (getEnvOrNull("HT_DEFAULT_AUTH")) |env_auth| {
            auth_key = try allocator.dupe(u8, env_auth);
        }
    }

    if (kv_path == null) {
        if (getEnvOrNull("HT_KV_PATH")) |env_path| {
            kv_path = try allocator.dupe(u8, env_path);
        } else {
            kv_path = try expandHomePath(allocator, "~/.ht/gateway");
        }
    }

    const final_kv_path = kv_path.?;
    try ensureDirectoryExists(final_kv_path);

    return gateway_server.ServerConfig{
        .auth_key = auth_key,
        .kv_path = final_kv_path,
    };
}

fn runGateway(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const config = try parseGatewayConfig(allocator, args, 3);

    var server = try gateway_server.Server.init(allocator, config);
    defer server.deinit();

    try server.run();
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
        .gateway => try runGateway(allocator, args),
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

fn kvOpen(allocator: std.mem.Allocator, path: []const u8) !void {
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
        .open => try kvOpen(allocator, path),
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
    try std.testing.expectEqual(RunSubcommand.gateway, parseRunSubcommand("gateway"));
    try std.testing.expectEqual(@as(?RunSubcommand, null), parseRunSubcommand("unknown"));
}

test "parseKVSubcommand" {
    try std.testing.expectEqual(KVSubcommand.init, parseKVSubcommand("init"));
    try std.testing.expectEqual(KVSubcommand.open, parseKVSubcommand("open"));
    try std.testing.expectEqual(@as(?KVSubcommand, null), parseKVSubcommand("unknown"));
}
