const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");
const message = @import("message.zig");
const client = @import("client.zig");

test "createBindingRequest - valid request" {
    const transaction_id = [_]u8{0xDE} ** 12;
    var buffer: [types.MessageHeader.SIZE]u8 = undefined;

    const size = try client.createBindingRequest(transaction_id, &buffer);
    try testing.expectEqual(types.MessageHeader.SIZE, size);

    const header = try message.parseHeader(&buffer);
    try testing.expectEqual(types.MessageType.binding_request, header.message_type);
    try testing.expectEqual(0, header.message_length);
    try testing.expectEqualSlices(u8, &transaction_id, &header.transaction_id);
}

test "createBindingRequest - buffer too small" {
    const transaction_id = [_]u8{0xDE} ** 12;
    var buffer: [10]u8 = undefined;

    try testing.expectError(types.StunError.BufferTooSmall, client.createBindingRequest(transaction_id, &buffer));
}

test "extractPublicAddress - valid response" {
    const transaction_id = [_]u8{0xAA} ** 12;
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 203, 0, 113, 99 },
            .port = 55555,
        },
    };

    // Create a valid response
    var response: [256]u8 = undefined;
    const response_size = try message.encodeResponse(transaction_id, client_addr, &response);

    // Extract address
    const extracted = try client.extractPublicAddress(response[0..response_size], transaction_id);
    try testing.expect(extracted != null);
    try testing.expectEqual(client_addr.ipv4.port, extracted.?.ipv4.port);
    try testing.expectEqualSlices(u8, &client_addr.ipv4.addr, &extracted.?.ipv4.addr);
}

test "extractPublicAddress - transaction id mismatch" {
    const transaction_id = [_]u8{0xBB} ** 12;
    const wrong_transaction_id = [_]u8{0xCC} ** 12;
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 192, 0, 2, 1 },
            .port = 12345,
        },
    };

    // Create a response with one transaction ID
    var response: [256]u8 = undefined;
    const response_size = try message.encodeResponse(transaction_id, client_addr, &response);

    // Try to extract with a different transaction ID
    try testing.expectError(
        types.StunError.InvalidMessageType,
        client.extractPublicAddress(response[0..response_size], wrong_transaction_id),
    );
}

test "extractPublicAddress - invalid message type" {
    const transaction_id = [_]u8{0x11} ** 12;

    // Create a binding request (not a response)
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    try testing.expectError(
        types.StunError.InvalidMessageType,
        client.extractPublicAddress(&request, transaction_id),
    );
}

test "extractPublicAddress - response too short" {
    const transaction_id = [_]u8{0x22} ** 12;
    const data = [_]u8{0} ** 10;

    try testing.expectError(
        types.StunError.MessageTooShort,
        client.extractPublicAddress(&data, transaction_id),
    );
}

test "extractPublicAddress - no xor mapped address attribute" {
    const transaction_id = [_]u8{0x33} ** 12;

    // Create a response without any attributes
    var response: [types.MessageHeader.SIZE]u8 = undefined;
    const header = types.MessageHeader{
        .message_type = .binding_response,
        .message_length = 0,
        .magic_cookie = types.MAGIC_COOKIE,
        .transaction_id = transaction_id,
    };
    try message.encodeHeader(header, &response);

    const extracted = try client.extractPublicAddress(&response, transaction_id);
    try testing.expectEqual(null, extracted);
}

test "isValidBindingResponse - valid response" {
    const transaction_id = [_]u8{0x44} ** 12;
    const client_addr = types.IpAddress{
        .ipv4 = .{
            .addr = .{ 198, 51, 100, 1 },
            .port = 9999,
        },
    };

    var response: [256]u8 = undefined;
    const response_size = try message.encodeResponse(transaction_id, client_addr, &response);

    try testing.expect(client.isValidBindingResponse(response[0..response_size]));
}

test "isValidBindingResponse - too short" {
    const data = [_]u8{0} ** 10;
    try testing.expect(!client.isValidBindingResponse(&data));
}

test "isValidBindingResponse - wrong type" {
    const transaction_id = [_]u8{0x55} ** 12;
    var request: [types.MessageHeader.SIZE]u8 = undefined;
    _ = try message.encodeRequest(transaction_id, &request);

    try testing.expect(!client.isValidBindingResponse(&request));
}

test "isValidBindingResponse - invalid magic cookie" {
    var data: [types.MessageHeader.SIZE]u8 = undefined;
    std.mem.writeInt(u16, data[0..2], 0x0101, .big); // Binding response
    std.mem.writeInt(u16, data[2..4], 0, .big);
    std.mem.writeInt(u32, data[4..8], 0xBADC0FFE, .big); // Wrong magic
    @memset(data[8..20], 0);

    try testing.expect(!client.isValidBindingResponse(&data));
}

test "calculateRetryDelay - attempt 0" {
    const delay = client.calculateRetryDelay(0);
    try testing.expectEqual(100, delay);
}

test "calculateRetryDelay - attempt 1" {
    const delay = client.calculateRetryDelay(1);
    try testing.expectEqual(200, delay);
}

test "calculateRetryDelay - attempt 2" {
    const delay = client.calculateRetryDelay(2);
    try testing.expectEqual(400, delay);
}

test "calculateRetryDelay - attempt 3" {
    const delay = client.calculateRetryDelay(3);
    try testing.expectEqual(800, delay);
}

test "calculateRetryDelay - attempt 4" {
    const delay = client.calculateRetryDelay(4);
    try testing.expectEqual(1600, delay);
}

test "calculateRetryDelay - attempt 5 and beyond" {
    const delay = client.calculateRetryDelay(5);
    try testing.expectEqual(3200, delay);

    const delay_10 = client.calculateRetryDelay(10);
    try testing.expectEqual(3200, delay_10);
}
