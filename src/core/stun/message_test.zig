const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const message = @import("message.zig");

test "parseHeader - valid binding request" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0001, .big); // Binding request
    std.mem.writeInt(u16, data[2..4], 0, .big); // Length
    std.mem.writeInt(u32, data[4..8], types.MAGIC_COOKIE, .big);
    const transaction_id = [_]u8{1} ** 12;
    @memcpy(data[8..20], &transaction_id);

    const header = try message.parseHeader(&data);
    try testing.expectEqual(types.MessageType.binding_request, header.message_type);
    try testing.expectEqual(0, header.message_length);
    try testing.expectEqual(types.MAGIC_COOKIE, header.magic_cookie);
    try testing.expectEqualSlices(u8, &transaction_id, &header.transaction_id);
}

test "parseHeader - message too short" {
    const data = [_]u8{0} ** 10;
    try testing.expectError(types.StunError.MessageTooShort, message.parseHeader(&data));
}

test "parseHeader - invalid magic cookie" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0001, .big);
    std.mem.writeInt(u16, data[2..4], 0, .big);
    std.mem.writeInt(u32, data[4..8], 0x12345678, .big); // Wrong magic cookie
    @memset(data[8..20], 0);

    try testing.expectError(types.StunError.InvalidMagicCookie, message.parseHeader(&data));
}

test "parseHeader - invalid message type" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x9999, .big); // Invalid type
    std.mem.writeInt(u16, data[2..4], 0, .big);
    std.mem.writeInt(u32, data[4..8], types.MAGIC_COOKIE, .big);
    @memset(data[8..20], 0);

    try testing.expectError(types.StunError.InvalidMessageType, message.parseHeader(&data));
}

test "encodeHeader - binding response" {
    const transaction_id = [_]u8{0xAA} ** 12;
    const header = types.MessageHeader{
        .message_type = .binding_response,
        .message_length = 12,
        .magic_cookie = types.MAGIC_COOKIE,
        .transaction_id = transaction_id,
    };

    var buffer: [types.MessageHeader.SIZE]u8 = undefined;
    try message.encodeHeader(header, &buffer);

    try testing.expectEqual(0x0101, std.mem.readInt(u16, buffer[0..2], .big));
    try testing.expectEqual(12, std.mem.readInt(u16, buffer[2..4], .big));
    try testing.expectEqual(types.MAGIC_COOKIE, std.mem.readInt(u32, buffer[4..8], .big));
    try testing.expectEqualSlices(u8, &transaction_id, buffer[8..20]);
}

test "encodeHeader - buffer too small" {
    const header = types.MessageHeader{
        .message_type = .binding_request,
        .message_length = 0,
        .magic_cookie = types.MAGIC_COOKIE,
        .transaction_id = [_]u8{0} ** 12,
    };

    var buffer: [10]u8 = undefined;
    try testing.expectError(types.StunError.BufferTooSmall, message.encodeHeader(header, &buffer));
}

test "parseAddress - ipv4" {
    var data: [8]u8 = undefined;
    data[0] = 0x00; // Reserved
    data[1] = 0x01; // IPv4
    std.mem.writeInt(u16, data[2..4], 8080, .big);
    data[4] = 192;
    data[5] = 168;
    data[6] = 1;
    data[7] = 1;

    const addr = try message.parseAddress(&data);
    try testing.expect(addr == .ipv4);
    try testing.expectEqual(8080, addr.ipv4.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &addr.ipv4.addr);
}

test "parseAddress - ipv6" {
    var data: [20]u8 = undefined;
    data[0] = 0x00; // Reserved
    data[1] = 0x02; // IPv6
    std.mem.writeInt(u16, data[2..4], 443, .big);
    const ipv6_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    @memcpy(data[4..20], &ipv6_addr);

    const addr = try message.parseAddress(&data);
    try testing.expect(addr == .ipv6);
    try testing.expectEqual(443, addr.ipv6.port);
    try testing.expectEqualSlices(u8, &ipv6_addr, &addr.ipv6.addr);
}

test "parseAddress - attribute too short" {
    const data = [_]u8{0} ** 3;
    try testing.expectError(types.StunError.AttributeTooShort, message.parseAddress(&data));
}

test "parseAddress - invalid family" {
    var data: [8]u8 = undefined;
    data[0] = 0x00;
    data[1] = 0x99; // Invalid family
    std.mem.writeInt(u16, data[2..4], 8080, .big);
    @memset(data[4..8], 0);

    try testing.expectError(types.StunError.InvalidAddressFamily, message.parseAddress(&data));
}

test "encodeAddress - ipv4" {
    const addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 10, 0, 0, 1 },
            .port = 3478,
        },
    };

    var buffer: [8]u8 = undefined;
    const size = try message.encodeAddress(addr, &buffer);
    try testing.expectEqual(8, size);
    try testing.expectEqual(0x00, buffer[0]);
    try testing.expectEqual(0x01, buffer[1]);
    try testing.expectEqual(3478, std.mem.readInt(u16, buffer[2..4], .big));
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, buffer[4..8]);
}

test "encodeAddress - ipv6" {
    const ipv6_addr = [_]u8{0xfe} ** 16;
    const addr = types.IpAddress{
        .ipv6 = .{
            .addr = ipv6_addr,
            .port = 9999,
        },
    };

    var buffer: [20]u8 = undefined;
    const size = try message.encodeAddress(addr, &buffer);
    try testing.expectEqual(20, size);
    try testing.expectEqual(0x00, buffer[0]);
    try testing.expectEqual(0x02, buffer[1]);
    try testing.expectEqual(9999, std.mem.readInt(u16, buffer[2..4], .big));
    try testing.expectEqualSlices(u8, &ipv6_addr, buffer[4..20]);
}

test "xorAddress - ipv4" {
    const addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 192, 168, 1, 100 },
            .port = 12345,
        },
    };
    const transaction_id = [_]u8{0x12} ** 12;

    const xor_addr = message.xorAddress(addr, transaction_id);
    try testing.expect(xor_addr == .ipv4);

    // XOR twice should give original
    const original = message.xorAddress(xor_addr, transaction_id);
    try testing.expectEqual(addr.ipv4.port, original.ipv4.port);
    try testing.expectEqualSlices(u8, &addr.ipv4.addr, &original.ipv4.addr);
}

test "xorAddress - ipv6" {
    const ipv6_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    const addr = types.IpAddress{
        .ipv6 = .{
            .addr = ipv6_addr,
            .port = 8080,
        },
    };
    const transaction_id = [_]u8{0xAB} ** 12;

    const xor_addr = message.xorAddress(addr, transaction_id);
    try testing.expect(xor_addr == .ipv6);

    // XOR twice should give original
    const original = message.xorAddress(xor_addr, transaction_id);
    try testing.expectEqual(addr.ipv6.port, original.ipv6.port);
    try testing.expectEqualSlices(u8, &addr.ipv6.addr, &original.ipv6.addr);
}

test "parseRequest - valid" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0001, .big); // Binding request
    std.mem.writeInt(u16, data[2..4], 0, .big);
    std.mem.writeInt(u32, data[4..8], types.MAGIC_COOKIE, .big);
    const transaction_id = [_]u8{0x55} ** 12;
    @memcpy(data[8..20], &transaction_id);

    const header = try message.parseRequest(&data);
    try testing.expectEqual(types.MessageType.binding_request, header.message_type);
    try testing.expectEqualSlices(u8, &transaction_id, &header.transaction_id);
}

test "parseRequest - wrong type" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0101, .big); // Binding response
    std.mem.writeInt(u16, data[2..4], 0, .big);
    std.mem.writeInt(u32, data[4..8], types.MAGIC_COOKIE, .big);
    @memset(data[8..20], 0);

    try testing.expectError(types.StunError.InvalidMessageType, message.parseRequest(&data));
}

test "encodeResponse - ipv4 address" {
    const transaction_id = [_]u8{0x11} ** 12;
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 203, 0, 113, 45 },
            .port = 54321,
        },
    };

    var buffer: [256]u8 = undefined;
    const size = try message.encodeResponse(transaction_id, client_addr, &buffer);

    try testing.expect(size > types.MessageHeader.SIZE);

    const header = try message.parseHeader(buffer[0..size]);
    try testing.expectEqual(types.MessageType.binding_response, header.message_type);
    try testing.expectEqualSlices(u8, &transaction_id, &header.transaction_id);
}

test "encodeResponse - buffer too small" {
    const transaction_id = [_]u8{0x11} ** 12;
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 192, 168, 1, 1 },
            .port = 8080,
        },
    };

    var buffer: [10]u8 = undefined;
    try testing.expectError(types.StunError.BufferTooSmall, message.encodeResponse(transaction_id, client_addr, &buffer));
}

test "generateTransactionId - produces 12 bytes" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const tx_id = message.generateTransactionId(random);
    try testing.expectEqual(12, tx_id.len);
}

test "generateTransactionId - different values" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const tx_id1 = message.generateTransactionId(random);
    const tx_id2 = message.generateTransactionId(random);

    try testing.expect(!std.mem.eql(u8, &tx_id1, &tx_id2));
}

test "encodeRequest - basic" {
    const transaction_id = [_]u8{0x99} ** 12;
    var buffer: [types.MessageHeader.SIZE]u8 = undefined;

    const size = try message.encodeRequest(transaction_id, &buffer);
    try testing.expectEqual(types.MessageHeader.SIZE, size);

    const header = try message.parseHeader(&buffer);
    try testing.expectEqual(types.MessageType.binding_request, header.message_type);
    try testing.expectEqual(0, header.message_length);
    try testing.expectEqualSlices(u8, &transaction_id, &header.transaction_id);
}

test "parseXorMappedAddress - valid response" {
    const transaction_id = [_]u8{0x77} ** 12;
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 198, 51, 100, 200 },
            .port = 40000,
        },
    };

    var buffer: [256]u8 = undefined;
    const size = try message.encodeResponse(transaction_id, client_addr, &buffer);

    const parsed_addr = try message.parseXorMappedAddress(buffer[0..size], transaction_id);
    try testing.expect(parsed_addr != null);
    try testing.expect(parsed_addr.? == .ipv4);
    try testing.expectEqual(client_addr.ipv4.port, parsed_addr.?.ipv4.port);
    try testing.expectEqualSlices(u8, &client_addr.ipv4.addr, &parsed_addr.?.ipv4.addr);
}

test "parseXorMappedAddress - no attribute" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0101, .big); // Binding response
    std.mem.writeInt(u16, data[2..4], 0, .big); // No attributes
    std.mem.writeInt(u32, data[4..8], types.MAGIC_COOKIE, .big);
    const transaction_id = [_]u8{0x33} ** 12;
    @memcpy(data[8..20], &transaction_id);

    const result = try message.parseXorMappedAddress(&data, transaction_id);
    try testing.expectEqual(null, result);
}

test "parseXorMappedAddress - wrong message type" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0001, .big); // Binding request (not response)
    std.mem.writeInt(u16, data[2..4], 0, .big);
    std.mem.writeInt(u32, data[4..8], types.MAGIC_COOKIE, .big);
    const transaction_id = [_]u8{0x44} ** 12;
    @memcpy(data[8..20], &transaction_id);

    try testing.expectError(types.StunError.InvalidMessageType, message.parseXorMappedAddress(&data, transaction_id));
}
