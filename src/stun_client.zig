const std = @import("std");
const net = std.net;
const posix = std.posix;
const core_types = @import("core/stun/types.zig");
const core_message = @import("core/stun/message.zig");
const client = @import("core/stun/client.zig");

const log = std.log.scoped(.stun_client);

const DEFAULT_TIMEOUT_MS: u32 = 3000;
const BUFFER_SIZE: usize = 2048;
const MAX_RETRIES: u32 = 5;

pub fn queryPublicAddress(
    allocator: std.mem.Allocator,
    server_host: []const u8,
    server_port: u16,
) !core_types.IpAddress {
    log.debug("Resolving hostname: {s}:{}", .{ server_host, server_port });

    const address_list = try net.getAddressList(allocator, server_host, server_port);
    defer address_list.deinit();

    if (address_list.addrs.len == 0) {
        log.err("No addresses found for hostname: {s}", .{server_host});
        return error.UnknownHostName;
    }

    log.debug("Resolved {} address(es) for {s}", .{ address_list.addrs.len, server_host });

    // Try each IPv4 address until one works (skip IPv6)
    var last_error: anyerror = error.UnknownHostName;
    for (address_list.addrs) |server_address| {
        // Skip IPv6 addresses
        if (server_address.any.family != posix.AF.INET) {
            log.debug("Skipping non-IPv4 address", .{});
            continue;
        }

        var buf: [64]u8 = undefined;
        const addr_str = formatAddress(server_address, &buf);
        log.debug("Trying {s}", .{addr_str});

        const result = queryWithAddress(server_address) catch |err| {
            log.debug("Failed with {s}: {}", .{ addr_str, err });
            last_error = err;
            continue;
        };

        return result;
    }

    log.err("All addresses failed for {s}. Last error: {}", .{ server_host, last_error });
    return last_error;
}

fn queryWithAddress(server_address: net.Address) !core_types.IpAddress {
    const socket = try posix.socket(
        server_address.any.family,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );
    defer posix.close(socket);

    try posix.connect(socket, &server_address.any, server_address.getOsSockLen());

    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = prng.random();
    const transaction_id = core_message.generateTransactionId(random);

    var request_buffer: [BUFFER_SIZE]u8 = undefined;
    const request_size = try client.createBindingRequest(transaction_id, &request_buffer);

    var response_buffer: [BUFFER_SIZE]u8 = undefined;

    var attempt: u32 = 0;
    while (attempt < MAX_RETRIES) : (attempt += 1) {
        if (attempt > 0) {
            log.debug("Retry attempt {} of {}", .{ attempt, MAX_RETRIES - 1 });
        }

        _ = try posix.send(socket, request_buffer[0..request_size], 0);

        const timeout_ms = if (attempt == 0) DEFAULT_TIMEOUT_MS else client.calculateRetryDelay(attempt);

        const received_bytes = receiveWithTimeout(
            socket,
            &response_buffer,
            timeout_ms,
        ) catch |err| {
            if (err == error.Timeout and attempt < MAX_RETRIES - 1) {
                log.debug("Request timed out, retrying...", .{});
                continue;
            }
            return err;
        };

        if (received_bytes == 0) {
            continue;
        }

        const public_address = try client.extractPublicAddress(
            response_buffer[0..received_bytes],
            transaction_id,
        );

        if (public_address) |addr| {
            return addr;
        }
    }

    log.err("Max retries exceeded", .{});
    return error.MaxRetriesExceeded;
}

fn formatAddress(address: net.Address, buffer: []u8) []const u8 {
    const ipv4 = address.in;
    const addr_bytes = std.mem.toBytes(ipv4.sa.addr);
    const port = std.mem.bigToNative(u16, ipv4.sa.port);
    return std.fmt.bufPrint(buffer, "{}.{}.{}.{}:{}", .{
        addr_bytes[0],
        addr_bytes[1],
        addr_bytes[2],
        addr_bytes[3],
        port,
    }) catch "invalid";
}

fn receiveWithTimeout(
    socket: posix.socket_t,
    buffer: []u8,
    timeout_ms: u64,
) !usize {
    const timeout = posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };

    try posix.setsockopt(
        socket,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );

    const received = posix.recv(socket, buffer, 0) catch |err| {
        if (err == error.WouldBlock) {
            return error.Timeout;
        }
        return err;
    };

    return received;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <stun-server> [port]\n", .{args[0]});
        std.debug.print("Example: {s} stun.l.google.com 19302\n", .{args[0]});
        return;
    }

    const server_host = args[1];
    const server_port: u16 = if (args.len >= 3)
        try std.fmt.parseInt(u16, args[2], 10)
    else
        3478;

    log.info("Querying STUN server {s}:{} for public address...", .{ server_host, server_port });

    const public_address = queryPublicAddress(allocator, server_host, server_port) catch |err| {
        log.err("Failed to query STUN server: {}", .{err});
        return err;
    };

    // Format the public address nicely
    var addr_buf: [64]u8 = undefined;
    const addr_str = switch (public_address) {
        .ipv4 => |ipv4| std.fmt.bufPrint(&addr_buf, "{}.{}.{}.{}:{}", .{
            ipv4.addr[0],
            ipv4.addr[1],
            ipv4.addr[2],
            ipv4.addr[3],
            ipv4.port,
        }) catch "invalid",
        .ipv6 => |ipv6| std.fmt.bufPrint(&addr_buf, "[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{}", .{
            ipv6.addr[0],  ipv6.addr[1],
            ipv6.addr[2],  ipv6.addr[3],
            ipv6.addr[4],  ipv6.addr[5],
            ipv6.addr[6],  ipv6.addr[7],
            ipv6.addr[8],  ipv6.addr[9],
            ipv6.addr[10], ipv6.addr[11],
            ipv6.addr[12], ipv6.addr[13],
            ipv6.addr[14], ipv6.addr[15],
            ipv6.port,
        }) catch "invalid",
    };
    log.info("Public address: {s}", .{addr_str});
}
