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
                const client_ip = extractIpAddress(client_address);
                log.err("Error handling request from {any}: {}", .{ client_ip, err });
            };
        }
    }

    fn handleRequest(
        self: *Server,
        request_data: []const u8,
        client_address: net.Address,
        response_buffer: []u8,
    ) !void {
        const client_ip = extractIpAddress(client_address);

        if (!server.isValidBindingRequest(request_data)) {
            log.debug("Received invalid STUN request from {any}", .{client_ip});
            return;
        }

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

        log.debug("Responded to {any} with their public address", .{client_ip});
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = ServerConfig{};
    var stun_server = try Server.init(config);
    defer stun_server.deinit();

    try stun_server.run(allocator);
}
