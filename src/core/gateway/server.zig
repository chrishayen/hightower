const std = @import("std");
const http = std.http;
const net = std.net;
const registration = @import("registration.zig");
const kv = @import("../kv/store.zig");

pub const ServerConfig = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    auth_key: ?[]const u8 = null,
};

pub const Server = struct {
    config: ServerConfig,
    kv_store: *kv.KVStore,

    pub fn init(config: ServerConfig, kv_store: *kv.KVStore) Server {
        return Server{
            .config = config,
            .kv_store = kv_store,
        };
    }

    pub fn run(self: *Server, allocator: std.mem.Allocator) !void {
        const address = try net.Address.parseIp(self.config.address, self.config.port);

        var server = try address.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        std.log.info("Gateway server listening on {s}:{d}", .{ self.config.address, self.config.port });

        while (true) {
            const connection = try server.accept();
            try self.handleConnection(allocator, connection);
        }
    }

    fn handleConnection(self: *Server, allocator: std.mem.Allocator, connection: net.Server.Connection) !void {
        defer connection.stream.close();

        var buffer: [8192]u8 = undefined;
        const bytes_read = try connection.stream.read(&buffer);

        if (bytes_read == 0) {
            return;
        }

        const request_data = buffer[0..bytes_read];
        try self.handleRequest(allocator, connection.stream, request_data);
    }

    fn handleRequest(self: *Server, allocator: std.mem.Allocator, stream: net.Stream, request_data: []const u8) !void {
        const request = parseHttpRequest(request_data) catch {
            try sendResponse(stream, 400, "text/plain", "Bad Request");
            return;
        };

        if (std.mem.startsWith(u8, request.path, "/api/register")) {
            try self.handleRegisterEndpoint(allocator, stream, request);
            return;
        }

        try sendResponse(stream, 200, "text/plain", "Hello World\n");
    }

    fn handleRegisterEndpoint(self: *Server, allocator: std.mem.Allocator, stream: net.Stream, request: HttpRequest) !void {
        if (!std.mem.eql(u8, request.method, "POST")) {
            try sendResponse(stream, 405, "text/plain", "Method Not Allowed");
            return;
        }

        const response = registration.handleRegistration(allocator, request.body, self.config.auth_key) catch |err| {
            std.log.err("Registration error: {}", .{err});
            try sendResponse(stream, 400, "application/json", "{\"success\":false,\"message\":\"Invalid request\"}");
            return;
        };

        const json = try response.toJson(allocator);
        defer allocator.free(json);

        try sendResponse(stream, 200, "application/json", json);
    }
};

pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    body: []const u8,
};

pub fn parseHttpRequest(data: []const u8) !HttpRequest {
    var lines = std.mem.splitScalar(u8, data, '\n');

    const first_line = lines.next() orelse return error.InvalidRequest;
    var parts = std.mem.splitScalar(u8, first_line, ' ');

    const method = parts.next() orelse return error.InvalidRequest;
    const path = parts.next() orelse return error.InvalidRequest;

    const body = if (std.mem.indexOf(u8, data, "\r\n\r\n")) |pos|
        data[pos + 4..]
    else if (std.mem.indexOf(u8, data, "\n\n")) |pos|
        data[pos + 2..]
    else
        "";

    return HttpRequest{
        .method = method,
        .path = path,
        .body = body,
    };
}

fn sendResponse(stream: net.Stream, status: u16, content_type: []const u8, body: []const u8) !void {
    const status_text = switch (status) {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        else => "Unknown",
    };

    var response_buffer: [4096]u8 = undefined;
    const response = try std.fmt.bufPrint(&response_buffer,
        "HTTP/1.1 {d} {s}\r\n" ++
        "Content-Type: {s}\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "{s}",
        .{ status, status_text, content_type, body.len, body }
    );

    _ = try stream.writeAll(response);
}
