const std = @import("std");
const testing = std.testing;
const registration = @import("registration.zig");

test "RegistrationRequest.fromJson with valid data and auth key" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        \\  "auth_key": "myauthkey"
        \\}
    ;

    var request = try registration.RegistrationRequest.fromJson(allocator, json);
    defer request.deinit(allocator);

    try testing.expectEqualStrings("1.2.3.4", request.public_ip);
    try testing.expectEqual(@as(u16, 51820), request.public_port);
    try testing.expectEqualStrings("10.0.0.1", request.private_ip);
    try testing.expectEqual(@as(u16, 51821), request.private_port);
    try testing.expectEqual(@as(usize, 32), request.public_key.len);
    try testing.expect(request.auth_key != null);
    try testing.expectEqualStrings("myauthkey", request.auth_key.?);
}

test "RegistrationRequest.fromJson without auth key" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        \\}
    ;

    var request = try registration.RegistrationRequest.fromJson(allocator, json);
    defer request.deinit(allocator);

    try testing.expectEqualStrings("1.2.3.4", request.public_ip);
    try testing.expectEqual(@as(u16, 51820), request.public_port);
    try testing.expectEqualStrings("10.0.0.1", request.private_ip);
    try testing.expectEqual(@as(u16, 51821), request.private_port);
    try testing.expectEqual(@as(usize, 32), request.public_key.len);
    try testing.expect(request.auth_key == null);
}

test "RegistrationRequest.fromJson with invalid public key" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "short",
        \\  "auth_key": "myauthkey"
        \\}
    ;

    const result = registration.RegistrationRequest.fromJson(allocator, json);
    try testing.expectError(error.InvalidPublicKeyLength, result);
}

test "RegistrationResponse.toJson" {
    const allocator = testing.allocator;

    const response = registration.RegistrationResponse{
        .success = true,
        .message = "Registration successful",
    };

    const json = try response.toJson(allocator);
    defer allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"success\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"message\":\"Registration successful\"") != null);
}

test "handleRegistration with no auth required and client provides auth" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        \\  "auth_key": "anykey"
        \\}
    ;

    const response = try registration.handleRegistration(allocator, json, null);

    try testing.expectEqual(true, response.success);
    try testing.expectEqualStrings("Registration successful", response.message);
}

test "handleRegistration with no auth required and client doesn't provide auth" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        \\}
    ;

    const response = try registration.handleRegistration(allocator, json, null);

    try testing.expectEqual(true, response.success);
    try testing.expectEqualStrings("Registration successful", response.message);
}

test "handleRegistration with valid auth key" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        \\  "auth_key": "correctkey"
        \\}
    ;

    const response = try registration.handleRegistration(allocator, json, "correctkey");

    try testing.expectEqual(true, response.success);
    try testing.expectEqualStrings("Registration successful", response.message);
}

test "handleRegistration with invalid auth key" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        \\  "auth_key": "wrongkey"
        \\}
    ;

    const response = try registration.handleRegistration(allocator, json, "correctkey");

    try testing.expectEqual(false, response.success);
    try testing.expectEqualStrings("Invalid auth key", response.message);
}

test "handleRegistration with missing auth key when required" {
    const allocator = testing.allocator;

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        \\}
    ;

    const response = try registration.handleRegistration(allocator, json, "correctkey");

    try testing.expectEqual(false, response.success);
    try testing.expectEqualStrings("Auth key required", response.message);
}
