const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");

/// Create a STUN binding request
/// Returns the size of the request written to the buffer
pub fn createBindingRequest(
    transaction_id: [12]u8,
    buffer: []u8,
) !usize {
    return try message.encodeRequest(transaction_id, buffer);
}

/// Validate a STUN binding response and extract the public address
/// Returns the extracted IP address or null if not found
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

/// Validate that incoming data is a valid STUN binding response
pub fn isValidBindingResponse(data: []const u8) bool {
    if (data.len < types.MessageHeader.SIZE) {
        return false;
    }

    const header = message.parseHeader(data) catch return false;
    return header.message_type == .binding_response;
}

/// Calculate retry delay using exponential backoff
/// attempt: 0-based retry attempt number
/// Returns delay in milliseconds
pub fn calculateRetryDelay(attempt: u32) u64 {
    const base_delay_ms: u64 = 100;
    const max_delay_ms: u64 = 3200;

    if (attempt >= 5) {
        return max_delay_ms;
    }

    const delay = base_delay_ms * (@as(u64, 1) << @intCast(attempt));
    return @min(delay, max_delay_ms);
}
