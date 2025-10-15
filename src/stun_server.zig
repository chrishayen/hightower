const std = @import("std");
const net = std.net;
const posix = std.posix;
const core_types = @import("core/stun/types.zig");
const server = @import("core/stun/server.zig");

const log = std.log.scoped(.stun_server);

const DEFAULT_PORT: u16 = 3478;
const BUFFER_SIZE: usize = 2048;

pub const ServerConfig = struct {
    port: u16 = DEFAULT_PORT,
    bind_address: []const u8 = "0.0.0.0",
};

pub const Server = struct {
    socket: posix.socket_t,
    config: ServerConfig,

    pub fn init(config: ServerConfig) !Server {
        const address = try net.Address.parseIp(config.bind_address, config.port);

        const socket = try posix.socket(
            address.any.family,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        );
        errdefer posix.close(socket);

        try posix.bind(socket, &address.any, address.getOsSockLen());

        return Server{
            .socket = socket,
            .config = config,
        };
    }

    pub fn deinit(self: *Server) void {
        posix.close(self.socket);
    }

    pub fn run(self: *Server, allocator: std.mem.Allocator) !void {
        log.info("STUN server listening on {s}:{}", .{ self.config.bind_address, self.config.port });

        var recv_buffer = try allocator.alloc(u8, BUFFER_SIZE);
        defer allocator.free(recv_buffer);

        const response_buffer = try allocator.alloc(u8, BUFFER_SIZE);
        defer allocator.free(response_buffer);

        while (true) {
            var client_address: net.Address = undefined;
            var client_address_len: posix.socklen_t = @sizeOf(net.Address);

            const received_bytes = posix.recvfrom(
                self.socket,
                recv_buffer,
                0,
                @as(*posix.sockaddr, @ptrCast(&client_address)),
                &client_address_len,
            ) catch |err| {
                log.err("Error receiving datagram: {}", .{err});
                continue;
            };

            if (received_bytes == 0) {
                continue;
            }

            self.handleRequest(
                recv_buffer[0..received_bytes],
                client_address,
                response_buffer,
            ) catch |err| {
                var buf: [64]u8 = undefined;
                const addr_str = formatNetAddress(client_address, &buf);
                log.err("Error handling request from {s}: {}", .{ addr_str, err });
            };
        }
    }

    fn handleRequest(
        self: *Server,
        request_data: []const u8,
        client_address: net.Address,
        response_buffer: []u8,
    ) !void {
        var addr_buf: [64]u8 = undefined;
        const client_addr_str = formatNetAddress(client_address, &addr_buf);

        if (!server.isValidBindingRequest(request_data)) {
            log.debug("Received invalid STUN request from {s}", .{client_addr_str});
            return;
        }

        const client_ip = extractIpAddress(client_address);

        const response_size = try server.processBindingRequest(
            request_data,
            client_ip,
            response_buffer,
        );

        _ = try posix.sendto(
            self.socket,
            response_buffer[0..response_size],
            0,
            &client_address.any,
            client_address.getOsSockLen(),
        );

        var ip_buf: [64]u8 = undefined;
        const client_ip_str = formatStunAddress(client_ip, &ip_buf);
        log.debug("Responded to {s} with their public address: {s}", .{ client_addr_str, client_ip_str });
    }
};

fn extractIpAddress(address: net.Address) core_types.IpAddress {
    switch (address.any.family) {
        posix.AF.INET => {
            const ipv4 = address.in;
            const addr_bytes = std.mem.toBytes(ipv4.sa.addr);
            return core_types.IpAddress{
                .ipv4 = .{
                    .addr = addr_bytes,
                    .port = std.mem.bigToNative(u16, ipv4.sa.port),
                },
            };
        },
        posix.AF.INET6 => {
            const ipv6 = address.in6;
            return core_types.IpAddress{
                .ipv6 = .{
                    .addr = ipv6.sa.addr,
                    .port = std.mem.bigToNative(u16, ipv6.sa.port),
                },
            };
        },
        else => unreachable,
    }
}

fn formatNetAddress(address: net.Address, buffer: []u8) []const u8 {
    switch (address.any.family) {
        posix.AF.INET => {
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
        },
        posix.AF.INET6 => {
            const ipv6 = address.in6;
            const port = std.mem.bigToNative(u16, ipv6.sa.port);
            return std.fmt.bufPrint(buffer, "[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{}", .{
                ipv6.sa.addr[0],  ipv6.sa.addr[1],
                ipv6.sa.addr[2],  ipv6.sa.addr[3],
                ipv6.sa.addr[4],  ipv6.sa.addr[5],
                ipv6.sa.addr[6],  ipv6.sa.addr[7],
                ipv6.sa.addr[8],  ipv6.sa.addr[9],
                ipv6.sa.addr[10], ipv6.sa.addr[11],
                ipv6.sa.addr[12], ipv6.sa.addr[13],
                ipv6.sa.addr[14], ipv6.sa.addr[15],
                port,
            }) catch "invalid";
        },
        else => return "unknown",
    }
}

fn formatStunAddress(address: core_types.IpAddress, buffer: []u8) []const u8 {
    switch (address) {
        .ipv4 => |ipv4| {
            return std.fmt.bufPrint(buffer, "{}.{}.{}.{}:{}", .{
                ipv4.addr[0],
                ipv4.addr[1],
                ipv4.addr[2],
                ipv4.addr[3],
                ipv4.port,
            }) catch "invalid";
        },
        .ipv6 => |ipv6| {
            return std.fmt.bufPrint(buffer, "[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{}", .{
                ipv6.addr[0],  ipv6.addr[1],
                ipv6.addr[2],  ipv6.addr[3],
                ipv6.addr[4],  ipv6.addr[5],
                ipv6.addr[6],  ipv6.addr[7],
                ipv6.addr[8],  ipv6.addr[9],
                ipv6.addr[10], ipv6.addr[11],
                ipv6.addr[12], ipv6.addr[13],
                ipv6.addr[14], ipv6.addr[15],
                ipv6.port,
            }) catch "invalid";
        },
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = ServerConfig{};
    var stun_server = try Server.init(config);
    defer stun_server.deinit();

    try stun_server.run(allocator);
}
