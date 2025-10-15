const std = @import("std");
const net = std.net;
const posix = std.posix;

const stun_server = @import("stun_server.zig");
const stun_client = @import("stun_client.zig");

const log = std.log.scoped(.cli);

const Command = enum {
    help,
    run,
    stun,
};

const RunSubcommand = enum {
    stun,
};

fn printHelp() void {
    std.debug.print(
        \\ht - WireGuard implementation CLI
        \\
        \\Usage:
        \\  ht run <service>     Start a service
        \\  ht stun <address> [port]  Query a STUN server
        \\  ht help              Show this help message
        \\
        \\Services:
        \\  stun                 Start the STUN server
        \\
        \\Examples:
        \\  ht run stun
        \\  ht stun stun.l.google.com 19302
        \\  ht stun stun.l.google.com
        \\
    , .{});
}

fn parseCommand(arg: []const u8) ?Command {
    if (std.mem.eql(u8, arg, "run")) return .run;
    if (std.mem.eql(u8, arg, "stun")) return .stun;
    if (std.mem.eql(u8, arg, "help")) return .help;
    return null;
}

fn parseRunSubcommand(arg: []const u8) ?RunSubcommand {
    if (std.mem.eql(u8, arg, "stun")) return .stun;
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
    }
}

test "parseCommand" {
    try std.testing.expectEqual(Command.run, parseCommand("run"));
    try std.testing.expectEqual(Command.stun, parseCommand("stun"));
    try std.testing.expectEqual(Command.help, parseCommand("help"));
    try std.testing.expectEqual(@as(?Command, null), parseCommand("unknown"));
}

test "parseRunSubcommand" {
    try std.testing.expectEqual(RunSubcommand.stun, parseRunSubcommand("stun"));
    try std.testing.expectEqual(@as(?RunSubcommand, null), parseRunSubcommand("unknown"));
}
