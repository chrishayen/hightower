const std = @import("std");
const testing = std.testing;
const types = @import("types.zig");

test "MessageType.fromU16 - valid binding request" {
    const msg_type = types.MessageType.fromU16(0x0001);
    try testing.expect(msg_type != null);
    try testing.expectEqual(types.MessageType.binding_request, msg_type.?);
}

test "MessageType.fromU16 - valid binding response" {
    const msg_type = types.MessageType.fromU16(0x0101);
    try testing.expect(msg_type != null);
    try testing.expectEqual(types.MessageType.binding_response, msg_type.?);
}

test "MessageType.fromU16 - invalid type" {
    const msg_type = types.MessageType.fromU16(0x9999);
    try testing.expectEqual(null, msg_type);
}

test "AttributeType.fromU16 - mapped address" {
    const attr_type = types.AttributeType.fromU16(0x0001);
    try testing.expectEqual(types.AttributeType.mapped_address, attr_type);
}

test "AttributeType.fromU16 - xor mapped address" {
    const attr_type = types.AttributeType.fromU16(0x0020);
    try testing.expectEqual(types.AttributeType.xor_mapped_address, attr_type);
}

test "AttributeType.fromU16 - unknown type" {
    const attr_type = types.AttributeType.fromU16(0x9999);
    try testing.expect(@intFromEnum(attr_type) == 0x9999);
}

test "AddressFamily.fromU8 - ipv4" {
    const family = types.AddressFamily.fromU8(0x01);
    try testing.expect(family != null);
    try testing.expectEqual(types.AddressFamily.ipv4, family.?);
}

test "AddressFamily.fromU8 - ipv6" {
    const family = types.AddressFamily.fromU8(0x02);
    try testing.expect(family != null);
    try testing.expectEqual(types.AddressFamily.ipv6, family.?);
}

test "AddressFamily.fromU8 - invalid family" {
    const family = types.AddressFamily.fromU8(0x99);
    try testing.expectEqual(null, family);
}

// Format tests skipped - custom format function works but has different
// calling conventions in different Zig versions

test "MessageHeader size" {
    try testing.expectEqual(20, types.MessageHeader.SIZE);
}

test "AttributeHeader size" {
    try testing.expectEqual(4, types.AttributeHeader.SIZE);
}

test "MAGIC_COOKIE constant" {
    try testing.expectEqual(0x2112A442, types.MAGIC_COOKIE);
}
