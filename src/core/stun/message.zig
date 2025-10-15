const std = @import("std");
const types = @import("types.zig");

/// Parse a STUN message header from bytes
pub fn parseHeader(data: []const u8) !types.MessageHeader {
    if (data.len < types.MessageHeader.SIZE) {
        return types.StunError.MessageTooShort;
    }

    const message_type_raw = std.mem.readInt(u16, data[0..2], .big);
    const message_type = types.MessageType.fromU16(message_type_raw) orelse {
        return types.StunError.InvalidMessageType;
    };

    const message_length = std.mem.readInt(u16, data[2..4], .big);

    if (message_length > types.MAX_MESSAGE_LENGTH) {
        return types.StunError.InvalidMessageLength;
    }

    const magic_cookie = std.mem.readInt(u32, data[4..8], .big);

    if (magic_cookie != types.MAGIC_COOKIE) {
        return types.StunError.InvalidMagicCookie;
    }

    var transaction_id: [12]u8 = undefined;
    @memcpy(&transaction_id, data[8..20]);

    return types.MessageHeader{
        .message_type = message_type,
        .message_length = message_length,
        .magic_cookie = magic_cookie,
        .transaction_id = transaction_id,
    };
}

/// Encode a STUN message header to bytes
pub fn encodeHeader(header: types.MessageHeader, buffer: []u8) !void {
    if (buffer.len < types.MessageHeader.SIZE) {
        return types.StunError.BufferTooSmall;
    }

    std.mem.writeInt(u16, buffer[0..2], @intFromEnum(header.message_type), .big);
    std.mem.writeInt(u16, buffer[2..4], header.message_length, .big);
    std.mem.writeInt(u32, buffer[4..8], header.magic_cookie, .big);
    @memcpy(buffer[8..20], &header.transaction_id);
}

/// Parse an IP address from STUN address attribute format
pub fn parseAddress(data: []const u8) !types.IpAddress {
    if (data.len < 4) {
        return types.StunError.AttributeTooShort;
    }

    const family = types.AddressFamily.fromU8(data[1]) orelse {
        return types.StunError.InvalidAddressFamily;
    };

    const port = std.mem.readInt(u16, data[2..4], .big);

    switch (family) {
        .ipv4 => {
            if (data.len < 8) {
                return types.StunError.AttributeTooShort;
            }
            var addr: [4]u8 = undefined;
            @memcpy(&addr, data[4..8]);
            return types.IpAddress{ .ipv4 = .{ .addr = addr, .port = port } };
        },
        .ipv6 => {
            if (data.len < 20) {
                return types.StunError.AttributeTooShort;
            }
            var addr: [16]u8 = undefined;
            @memcpy(&addr, data[4..20]);
            return types.IpAddress{ .ipv6 = .{ .addr = addr, .port = port } };
        },
    }
}

/// Encode an IP address to STUN address attribute format
pub fn encodeAddress(address: types.IpAddress, buffer: []u8) !usize {
    switch (address) {
        .ipv4 => |ipv4| {
            if (buffer.len < 8) {
                return types.StunError.BufferTooSmall;
            }
            buffer[0] = 0x00; // Reserved
            buffer[1] = @intFromEnum(types.AddressFamily.ipv4);
            std.mem.writeInt(u16, buffer[2..4], ipv4.port, .big);
            @memcpy(buffer[4..8], &ipv4.addr);
            return 8;
        },
        .ipv6 => |ipv6| {
            if (buffer.len < 20) {
                return types.StunError.BufferTooSmall;
            }
            buffer[0] = 0x00; // Reserved
            buffer[1] = @intFromEnum(types.AddressFamily.ipv6);
            std.mem.writeInt(u16, buffer[2..4], ipv6.port, .big);
            @memcpy(buffer[4..20], &ipv6.addr);
            return 20;
        },
    }
}

/// XOR an IP address with the magic cookie and transaction ID
pub fn xorAddress(address: types.IpAddress, transaction_id: [12]u8) types.IpAddress {
    switch (address) {
        .ipv4 => |ipv4| {
            // Magic cookie must be in big-endian byte order for XOR
            const magic_bytes: [4]u8 = @bitCast(std.mem.nativeToBig(u32, types.MAGIC_COOKIE));
            var xor_addr: [4]u8 = undefined;
            for (0..4) |i| {
                xor_addr[i] = ipv4.addr[i] ^ magic_bytes[i];
            }
            const xor_port = ipv4.port ^ (@as(u16, magic_bytes[0]) << 8 | magic_bytes[1]);
            return types.IpAddress{ .ipv4 = .{ .addr = xor_addr, .port = xor_port } };
        },
        .ipv6 => |ipv6| {
            // Magic cookie must be in big-endian byte order for XOR
            const magic_bytes: [4]u8 = @bitCast(std.mem.nativeToBig(u32, types.MAGIC_COOKIE));
            var xor_key: [16]u8 = undefined;
            @memcpy(xor_key[0..4], &magic_bytes);
            @memcpy(xor_key[4..16], &transaction_id);

            var xor_addr: [16]u8 = undefined;
            for (0..16) |i| {
                xor_addr[i] = ipv6.addr[i] ^ xor_key[i];
            }
            const xor_port = ipv6.port ^ (@as(u16, magic_bytes[0]) << 8 | magic_bytes[1]);
            return types.IpAddress{ .ipv6 = .{ .addr = xor_addr, .port = xor_port } };
        },
    }
}

/// Parse a STUN binding request (validates header)
pub fn parseRequest(data: []const u8) !types.MessageHeader {
    const header = try parseHeader(data);

    if (header.message_type != .binding_request) {
        return types.StunError.InvalidMessageType;
    }

    return header;
}

/// Encode a STUN binding response with XOR-MAPPED-ADDRESS attribute
pub fn encodeResponse(
    transaction_id: [12]u8,
    client_address: types.IpAddress,
    buffer: []u8,
) !usize {
    const header_size = types.MessageHeader.SIZE;
    const attr_header_size = types.AttributeHeader.SIZE;

    // Calculate required size
    const addr_value_size: usize = switch (client_address) {
        .ipv4 => 8,
        .ipv6 => 20,
    };
    const total_attr_size = attr_header_size + addr_value_size;
    const total_size = header_size + total_attr_size;

    if (buffer.len < total_size) {
        return types.StunError.BufferTooSmall;
    }

    // Encode header
    const header = types.MessageHeader{
        .message_type = .binding_response,
        .message_length = @intCast(total_attr_size),
        .magic_cookie = types.MAGIC_COOKIE,
        .transaction_id = transaction_id,
    };
    try encodeHeader(header, buffer[0..header_size]);

    // Encode XOR-MAPPED-ADDRESS attribute
    const attr_start = header_size;
    std.mem.writeInt(u16, buffer[attr_start .. attr_start + 2], @intFromEnum(types.AttributeType.xor_mapped_address), .big);
    std.mem.writeInt(u16, buffer[attr_start + 2 .. attr_start + 4], @intCast(addr_value_size), .big);

    // XOR the address and encode it
    const xor_addr = xorAddress(client_address, transaction_id);
    _ = try encodeAddress(xor_addr, buffer[attr_start + attr_header_size ..]);

    return total_size;
}

/// Generate a random transaction ID
pub fn generateTransactionId(random: std.Random) [12]u8 {
    var transaction_id: [12]u8 = undefined;
    random.bytes(&transaction_id);
    return transaction_id;
}

/// Encode a STUN binding request
pub fn encodeRequest(transaction_id: [12]u8, buffer: []u8) !usize {
    if (buffer.len < types.MessageHeader.SIZE) {
        return types.StunError.BufferTooSmall;
    }

    const header = types.MessageHeader{
        .message_type = .binding_request,
        .message_length = 0, // No attributes in basic binding request
        .magic_cookie = types.MAGIC_COOKIE,
        .transaction_id = transaction_id,
    };

    try encodeHeader(header, buffer);
    return types.MessageHeader.SIZE;
}

/// Parse XOR-MAPPED-ADDRESS from a response
pub fn parseXorMappedAddress(data: []const u8, transaction_id: [12]u8) !?types.IpAddress {
    if (data.len < types.MessageHeader.SIZE) {
        return types.StunError.MessageTooShort;
    }

    const header = try parseHeader(data);
    if (header.message_type != .binding_response) {
        return types.StunError.InvalidMessageType;
    }

    if (header.message_length > types.MAX_MESSAGE_LENGTH) {
        return types.StunError.InvalidMessageLength;
    }

    if (header.message_length > data.len - types.MessageHeader.SIZE) {
        return types.StunError.InvalidMessageLength;
    }

    var offset: usize = types.MessageHeader.SIZE;
    const body_end = types.MessageHeader.SIZE + header.message_length;

    while (offset + types.AttributeHeader.SIZE <= body_end) {
        const attr_type_raw = std.mem.readInt(u16, data[offset..][0..2], .big);
        const attr_length = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
        const attr_type = types.AttributeType.fromU16(attr_type_raw);

        offset += types.AttributeHeader.SIZE;

        if (offset + attr_length > body_end) {
            return types.StunError.AttributeTooShort;
        }

        if (attr_type == .xor_mapped_address) {
            const xor_addr = try parseAddress(data[offset .. offset + attr_length]);
            return xorAddress(xor_addr, transaction_id); // XOR again to decode
        }

        // Move to next attribute (attributes are padded to 4-byte boundary)
        const padding = (4 - (attr_length % 4)) % 4;
        offset += attr_length + padding;
    }

    return null;
}
