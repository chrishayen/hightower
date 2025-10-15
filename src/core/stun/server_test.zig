const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const message = @import("message.zig");
const server = @import("server.zig");

test "processBindingRequest - ipv4 client" {
    const transaction_id = [_]u8{0xAB} ** 12;

    // Create a binding request
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    // Client address
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 198, 51, 100, 42 },
            .port = 54321,
        },
    };

    // Process the request
    var response: [256]u8 = undefined;
    const response_size = try server.processBindingRequest(&request, client_addr, &response);

    // Verify response is valid
    try testing.expect(response_size > types.MessageHeader.SIZE);

    const response_header = try message.parseHeader(response[0..response_size]);
    try testing.expectEqual(types.MessageType.binding_response, response_header.message_type);
    try testing.expectEqualSlices(u8, &transaction_id, &response_header.transaction_id);

    // Verify the XOR-MAPPED-ADDRESS can be parsed
    const parsed_addr = try message.parseXorMappedAddress(response[0..response_size], transaction_id);
    try testing.expect(parsed_addr != null);
    try testing.expectEqual(client_addr.ipv4.port, parsed_addr.?.ipv4.port);
    try testing.expectEqualSlices(u8, &client_addr.ipv4.addr, &parsed_addr.?.ipv4.addr);
}

test "processBindingRequest - ipv6 client" {
    const transaction_id = [_]u8{0x12} ** 12;

    // Create a binding request
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    // Client address (IPv6)
    const ipv6_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 8 ++ [_]u8{ 0, 0, 0, 1 };
    const client_addr = types.IpAddress{
        .ipv6 = .{
            .addr = ipv6_addr,
            .port = 9999,
        },
    };

    // Process the request
    var response: [256]u8 = undefined;
    const response_size = try server.processBindingRequest(&request, client_addr, &response);

    // Verify response is valid
    try testing.expect(response_size > types.MessageHeader.SIZE);

    const response_header = try message.parseHeader(response[0..response_size]);
    try testing.expectEqual(types.MessageType.binding_response, response_header.message_type);
    try testing.expectEqualSlices(u8, &transaction_id, &response_header.transaction_id);

    // Verify the XOR-MAPPED-ADDRESS can be parsed
    const parsed_addr = try message.parseXorMappedAddress(response[0..response_size], transaction_id);
    try testing.expect(parsed_addr != null);
    try testing.expectEqual(client_addr.ipv6.port, parsed_addr.?.ipv6.port);
    try testing.expectEqualSlices(u8, &client_addr.ipv6.addr, &parsed_addr.?.ipv6.addr);
}

test "processBindingRequest - invalid request" {
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 192, 168, 1, 1 },
            .port = 8080,
        },
    };

    // Invalid request (too short)
    const request = [_]u8{0} ** 10;
    var response: [256]u8 = undefined;

    try testing.expectError(types.StunError.MessageTooShort, server.processBindingRequest(&request, client_addr, &response));
}

test "processBindingRequest - buffer too small" {
    const transaction_id = [_]u8{0xCD} ** 12;

    // Create a valid binding request
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 10, 0, 0, 1 },
            .port = 3478,
        },
    };

    // Response buffer too small
    var response: [10]u8 = undefined;
    try testing.expectError(types.StunError.BufferTooSmall, server.processBindingRequest(&request, client_addr, &response));
}

test "isValidBindingRequest - valid request" {
    const transaction_id = [_]u8{0x55} ** 12;
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    try testing.expect(server.isValidBindingRequest(&request));
}

test "isValidBindingRequest - too short" {
    const request = [_]u8{0} ** 10;
    try testing.expect(!server.isValidBindingRequest(&request));
}

test "isValidBindingRequest - invalid magic cookie" {
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, request[0..2], 0x0001, .big); // Binding request
    std.mem.writeInt(u16, request[2..4], 0, .big);
    std.mem.writeInt(u32, request[4..8], 0xBADC0FFE, .big); // Wrong magic cookie
    @memset(request[8..20], 0);

    try testing.expect(!server.isValidBindingRequest(&request));
}

test "isValidBindingRequest - wrong message type" {
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, request[0..2], 0x0101, .big); // Binding response (not request)
    std.mem.writeInt(u16, request[2..4], 0, .big);
    std.mem.writeInt(u32, request[4..8], types.MAGIC_COOKIE, .big);
    @memset(request[8..20], 0);

    try testing.expect(!server.isValidBindingRequest(&request));
}

test "processBindingRequest - verify correct endianness for XOR" {
    // Test that the server correctly XORs addresses with big-endian magic cookie
    const transaction_id = [_]u8{0} ** 12;

    // Create a binding request
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    // Use a known IP address to verify correct XOR operation
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 71, 179, 184, 7 },
            .port = 12345,
        },
    };

    // Process the request
    var response: [256]u8 = undefined;
    const response_size = try server.processBindingRequest(&request, client_addr, &response);

    // Parse the response and verify we get the original address back
    const parsed_addr = try message.parseXorMappedAddress(response[0..response_size], transaction_id);
    try testing.expect(parsed_addr != null);
    try testing.expectEqual(client_addr.ipv4.port, parsed_addr.?.ipv4.port);
    try testing.expectEqualSlices(u8, &client_addr.ipv4.addr, &parsed_addr.?.ipv4.addr);
}
