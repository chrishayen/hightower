//! STUN client operations for NAT traversal and public address discovery.
//!
//! Provides functions to create binding requests, extract public addresses
//! from responses, and handle retry logic with exponential backoff.

const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");

/// Create STUN binding request message
///
/// Returns the size of the request written to the buffer.
/// Buffer must be at least 20 bytes for the header.
pub fn createBindingRequest(
    transaction_id: [12]u8,
    buffer: []u8,
) !usize {
    return try message.encodeRequest(transaction_id, buffer);
}

/// Validate STUN binding response and extract public address
///
/// Verifies transaction ID matches and extracts XOR-MAPPED-ADDRESS.
/// Returns the public IP address or null if XOR-MAPPED-ADDRESS not present.
pub fn extractPublicAddress(
    response_data: []const u8,
    expected_transaction_id: [12]u8,
) !?types.IpAddress {
    const header = try message.parseHeader(response_data);

    if (header.message_type != .binding_response) {
        return types.StunError.InvalidMessageType;
    }

    if (!std.mem.eql(u8, &header.transaction_id, &expected_transaction_id)) {
        return types.StunError.TransactionIdMismatch;
    }

    return try message.parseXorMappedAddress(response_data, expected_transaction_id);
}

/// Check if data is a valid STUN binding response
///
/// Quick validation without transaction ID checking.
pub fn isValidBindingResponse(data: []const u8) bool {
    if (data.len < types.MessageHeader.SIZE) {
        return false;
    }

    const header = message.parseHeader(data) catch return false;
    return header.message_type == .binding_response;
}

/// Calculate retry delay using exponential backoff
///
/// Implements exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms, 3200ms (max).
/// Returns delay in milliseconds for the given 0-based attempt number.
pub fn calculateRetryDelay(attempt: u32) u64 {
    const base_delay_ms: u64 = 100;
    const max_delay_ms: u64 = 3200;

    if (attempt >= 5) {
        return max_delay_ms;
    }

    const delay = base_delay_ms * (@as(u64, 1) << @intCast(attempt));
    return @min(delay, max_delay_ms);
}
