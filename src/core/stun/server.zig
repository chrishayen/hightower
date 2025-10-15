//! STUN server operations for handling binding requests.
//!
//! Provides functions to process incoming STUN binding requests and
//! generate responses containing the client's observed address.

const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");

/// Process STUN binding request and generate response
///
/// Extracts transaction ID from request and creates response with
/// client's observed address in XOR-MAPPED-ADDRESS attribute.
/// Returns the size of the response written to the buffer.
pub fn processBindingRequest(
    request_data: []const u8,
    client_address: types.IpAddress,
    response_buffer: []u8,
) !usize {
    const header = try message.parseRequest(request_data);
    return try message.encodeResponse(header.transaction_id, client_address, response_buffer);
}

/// Check if data is a valid STUN binding request
///
/// Quick validation to filter non-STUN traffic.
pub fn isValidBindingRequest(data: []const u8) bool {
    if (data.len < types.MessageHeader.SIZE) {
        return false;
    }

    const header = message.parseRequest(data) catch return false;
    return header.message_type == .binding_request;
}
