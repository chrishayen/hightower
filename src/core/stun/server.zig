const std = @import("std");
const types = @import("types.zig");
const message = @import("message.zig");

/// Process a STUN binding request and generate a response
/// Returns the size of the response written to the buffer
pub fn processBindingRequest(
    request_data: []const u8,
    client_address: types.IpAddress,
    response_buffer: []u8,
) !usize {
    const header = try message.parseRequest(request_data);
    return try message.encodeResponse(header.transaction_id, client_address, response_buffer);
}

/// Validate that incoming data is a valid STUN binding request
pub fn isValidBindingRequest(data: []const u8) bool {
    if (data.len < types.MessageHeader.SIZE) {
        return false;
    }

    const header = message.parseRequest(data) catch return false;
    return header.message_type == .binding_request;
}
