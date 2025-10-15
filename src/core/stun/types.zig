const std = @import("std");

// STUN magic cookie as defined in RFC 5389
pub const MAGIC_COOKIE: u32 = 0x2112A442;

// STUN message types
pub const MessageType = enum(u16) {
    binding_request = 0x0001,
    binding_response = 0x0101,
    binding_error_response = 0x0111,

    pub fn fromU16(value: u16) ?MessageType {
        return std.meta.intToEnum(MessageType, value) catch null;
    }
};

// STUN attribute types
pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    xor_mapped_address = 0x0020,
    _,

    pub fn fromU16(value: u16) AttributeType {
        return @enumFromInt(value);
    }
};

// Address family for STUN addresses
pub const AddressFamily = enum(u8) {
    ipv4 = 0x01,
    ipv6 = 0x02,

    pub fn fromU8(value: u8) ?AddressFamily {
        return std.meta.intToEnum(AddressFamily, value) catch null;
    }
};

// STUN message header (20 bytes)
pub const MessageHeader = struct {
    message_type: MessageType,
    message_length: u16, // Length of message body (not including 20-byte header)
    magic_cookie: u32,
    transaction_id: [12]u8,

    pub const SIZE = 20;
};

// STUN attribute header (4 bytes)
pub const AttributeHeader = struct {
    attribute_type: AttributeType,
    length: u16, // Length of attribute value (not including 4-byte header)

    pub const SIZE = 4;
};

// Parsed IP address from STUN message
pub const IpAddress = union(AddressFamily) {
    ipv4: struct {
        addr: [4]u8,
        port: u16,
    },
    ipv6: struct {
        addr: [16]u8,
        port: u16,
    },

    pub fn format(
        self: IpAddress,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .ipv4 => |ipv4| {
                try writer.print("{}.{}.{}.{}:{}", .{
                    ipv4.addr[0],
                    ipv4.addr[1],
                    ipv4.addr[2],
                    ipv4.addr[3],
                    ipv4.port,
                });
            },
            .ipv6 => |ipv6| {
                try writer.print("[{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}]:{}", .{
                    ipv6.addr[0],  ipv6.addr[1],
                    ipv6.addr[2],  ipv6.addr[3],
                    ipv6.addr[4],  ipv6.addr[5],
                    ipv6.addr[6],  ipv6.addr[7],
                    ipv6.addr[8],  ipv6.addr[9],
                    ipv6.addr[10], ipv6.addr[11],
                    ipv6.addr[12], ipv6.addr[13],
                    ipv6.addr[14], ipv6.addr[15],
                    ipv6.port,
                });
            },
        }
    }
};

// Error for STUN operations
pub const StunError = error{
    InvalidMessageLength,
    InvalidMagicCookie,
    InvalidMessageType,
    InvalidAttributeType,
    InvalidAddressFamily,
    MessageTooShort,
    AttributeTooShort,
    BufferTooSmall,
    TransactionIdMismatch,
};

// Maximum allowed STUN message length (RFC 5389 suggests reasonable bounds)
pub const MAX_MESSAGE_LENGTH: usize = 65535;
