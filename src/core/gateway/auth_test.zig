const std = @import("std");
const testing = std.testing;
const auth = @import("auth.zig");

test "AuthRequest fromJson parses valid JSON" {
    const json =
        \\{"username":"testuser","password":"testpass123"}
    ;

    var request = try auth.AuthRequest.fromJson(testing.allocator, json);
    defer request.deinit(testing.allocator);

    try testing.expectEqualStrings("testuser", request.username);
    try testing.expectEqualStrings("testpass123", request.password);
}

test "AuthRequest fromJson returns error for invalid JSON" {
    const json =
        \\{"username":"testuser"}
    ;

    const result = auth.AuthRequest.fromJson(testing.allocator, json);
    try testing.expectError(error.MissingField, result);
}

test "AuthResponse toJson formats success with api_key" {
    const response = auth.AuthResponse{
        .success = true,
        .message = "Authentication successful",
        .api_key = "test_key_123",
        .key_id = "id_123",
    };

    const json = try response.toJson(testing.allocator);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"success\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"api_key\":\"test_key_123\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"key_id\":\"id_123\"") != null);
}

test "AuthResponse toJson formats failure without api_key" {
    const response = auth.AuthResponse{
        .success = false,
        .message = "Invalid credentials",
    };

    const json = try response.toJson(testing.allocator);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"success\":false") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"message\":\"Invalid credentials\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "api_key") == null);
}

test "createInvalidCredentialsResponse returns failure response" {
    const response = auth.createInvalidCredentialsResponse();

    try testing.expect(!response.success);
    try testing.expectEqualStrings("Invalid username or password", response.message);
    try testing.expect(response.api_key == null);
}

test "createSuccessResponse returns success with credentials" {
    const response = auth.createSuccessResponse("test_key", "test_id");

    try testing.expect(response.success);
    try testing.expectEqualStrings("Authentication successful", response.message);
    try testing.expectEqualStrings("test_key", response.api_key.?);
    try testing.expectEqualStrings("test_id", response.key_id.?);
}
