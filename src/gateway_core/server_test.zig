const std = @import("std");
const testing = std.testing;
const server = @import("server.zig");
const kv = @import("../kv/store.zig");

test "Server.init with default config" {
    const allocator = testing.allocator;

    var kv_store = try kv.KVStore.init(allocator, 1);
    defer kv_store.deinit(allocator);
    try kv_store.bootstrap("localhost:0");

    const config = server.ServerConfig{};
    const s = server.Server.init(config, &kv_store);

    try testing.expectEqual(@as(u16, 8080), s.config.port);
    try testing.expectEqualStrings("127.0.0.1", s.config.address);
}

test "Server.init with custom config" {
    const allocator = testing.allocator;

    var kv_store = try kv.KVStore.init(allocator, 1);
    defer kv_store.deinit(allocator);
    try kv_store.bootstrap("localhost:0");

    const config = server.ServerConfig{
        .port = 9000,
        .address = "0.0.0.0",
    };
    const s = server.Server.init(config, &kv_store);

    try testing.expectEqual(@as(u16, 9000), s.config.port);
    try testing.expectEqualStrings("0.0.0.0", s.config.address);
}

test "parseHttpRequest with GET request" {
    const request_data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const request = try server.parseHttpRequest(request_data);

    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("/", request.path);
    try testing.expectEqualStrings("", request.body);
}

test "parseHttpRequest with POST request and body" {
    const request_data =
        \\POST /api/register HTTP/1.1
        \\Host: localhost
        \\Content-Length: 13
        \\
        \\{"key":"value"}
    ;
    const request = try server.parseHttpRequest(request_data);

    try testing.expectEqualStrings("POST", request.method);
    try testing.expectEqualStrings("/api/register", request.path);
    try testing.expectEqualStrings("{\"key\":\"value\"}", request.body);
}

test "parseHttpRequest with POST request and CRLF line endings" {
    const request_data = "POST /api/register HTTP/1.1\r\nHost: localhost\r\n\r\n{\"key\":\"value\"}";
    const request = try server.parseHttpRequest(request_data);

    try testing.expectEqualStrings("POST", request.method);
    try testing.expectEqualStrings("/api/register", request.path);
    try testing.expectEqualStrings("{\"key\":\"value\"}", request.body);
}

test "parseHttpRequest with invalid request" {
    const request_data = "INVALID";
    const result = server.parseHttpRequest(request_data);

    try testing.expectError(error.InvalidRequest, result);
}
