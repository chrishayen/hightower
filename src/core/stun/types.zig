//! Core types and constants for STUN (Session Traversal Utilities for NAT) protocol.
//!
//! Implements RFC 5389 STUN message format with binding requests and responses.
//! Used for NAT traversal to discover public IP addresses and ports.

const std = @import("std");

/// STUN magic cookie as defined in RFC 5389 (0x2112A442)
///
/// This fixed value helps distinguish STUN packets from other protocols
/// and provides additional entropy for XOR operations.
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types for binding transactions
pub const MessageType = enum(u16) {
    binding_request = 0x0001,
    binding_response = 0x0101,
    binding_error_response = 0x0111,

    /// Convert u16 to MessageType, returns null if invalid
    pub fn fromU16(value: u16) ?MessageType {
        return std.meta.intToEnum(MessageType, value) catch null;
    }
};

/// STUN attribute types
pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    xor_mapped_address = 0x0020,
    _,

    /// Convert u16 to AttributeType, supporting unknown types
    pub fn fromU16(value: u16) AttributeType {
        return @enumFromInt(value);
    }
};

/// Address family for STUN IP addresses
pub const AddressFamily = enum(u8) {
    ipv4 = 0x01,
    ipv6 = 0x02,

    /// Convert u8 to AddressFamily, returns null if invalid
    pub fn fromU8(value: u8) ?AddressFamily {
        return std.meta.intToEnum(AddressFamily, value) catch null;
    }
};

/// STUN message header (20 bytes fixed size)
///
/// All STUN messages begin with this header containing message type,
/// length, magic cookie, and transaction ID.
pub const MessageHeader = struct {
    message_type: MessageType,
    /// Length of message body in bytes (excludes the 20-byte header)
    message_length: u16,
    magic_cookie: u32,
    transaction_id: [12]u8,

    pub const SIZE = 20;
};

/// STUN attribute header (4 bytes)
///
/// Attributes follow the message header and each has a type and length.
pub const AttributeHeader = struct {
    attribute_type: AttributeType,
    /// Length of attribute value in bytes (excludes the 4-byte header)
    length: u16,

    pub const SIZE = 4;
};

/// IP address with port parsed from STUN message
///
/// Tagged union supporting both IPv4 and IPv6 addresses.
pub const IpAddress = union(AddressFamily) {
    ipv4: struct {
        addr: [4]u8,
        port: u16,
    },
    ipv6: struct {
        addr: [16]u8,
        port: u16,
    },

    /// Format IP address as string (e.g., "192.168.1.1:8080")
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

/// Errors that can occur during STUN operations
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

/// Maximum allowed STUN message length per RFC 5389
pub const MAX_MESSAGE_LENGTH: usize = 65535;
