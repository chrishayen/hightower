const std = @import("std");
const testing = std.testing;
const registration = @import("registration.zig");
const kv = @import("../kv/store.zig");
const auth_mod = @import("../kv/auth.zig");
const crypto_mod = @import("../kv/crypto.zig");

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

    var store = try kv.KVStore.init(allocator, 1);
    defer store.deinit(allocator);
    try store.bootstrap("localhost:0");

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

    const response = try registration.handleRegistration(&store, allocator, json);

    try testing.expectEqual(true, response.success);
    try testing.expectEqualStrings("Registration successful", response.message);
}

test "handleRegistration with no auth required and client doesn't provide auth" {
    const allocator = testing.allocator;

    var store = try kv.KVStore.init(allocator, 1);
    defer store.deinit(allocator);
    try store.bootstrap("localhost:0");

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        \\}
    ;

    const response = try registration.handleRegistration(&store, allocator, json);

    try testing.expectEqual(true, response.success);
    try testing.expectEqualStrings("Registration successful", response.message);
}

test "handleRegistration with valid API key" {
    const allocator = testing.allocator;

    var store = try kv.KVStore.init(allocator, 1);
    defer store.deinit(allocator);
    try store.bootstrap("localhost:0");

    try auth_mod.createUser(&store, allocator, "testuser", "password123", "{}");

    const key_result = try auth_mod.createApiKey(&store, allocator, "testuser", null, "{}");
    defer allocator.free(key_result.key_id);
    defer allocator.free(key_result.key);

    const json_template =
        \\{{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        \\  "auth_key": "{s}"
        \\}}
    ;

    const json = try std.fmt.allocPrint(allocator, json_template, .{key_result.key});
    defer allocator.free(json);

    const response = try registration.handleRegistration(&store, allocator, json);

    try testing.expectEqual(true, response.success);
    try testing.expectEqualStrings("Registration successful", response.message);
}

test "handleRegistration with invalid API key" {
    const allocator = testing.allocator;

    var store = try kv.KVStore.init(allocator, 1);
    defer store.deinit(allocator);
    try store.bootstrap("localhost:0");

    try auth_mod.createUser(&store, allocator, "testuser", "password123", "{}");

    const key_result = try auth_mod.createApiKey(&store, allocator, "testuser", null, "{}");
    defer allocator.free(key_result.key_id);
    defer allocator.free(key_result.key);

    const wrong_key = try crypto_mod.ApiKey.generate();
    const wrong_key_str = try wrong_key.toString(allocator);
    defer allocator.free(wrong_key_str);

    const json_template =
        \\{{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        \\  "auth_key": "{s}"
        \\}}
    ;

    const json = try std.fmt.allocPrint(allocator, json_template, .{wrong_key_str});
    defer allocator.free(json);

    const response = try registration.handleRegistration(&store, allocator, json);

    try testing.expectEqual(false, response.success);
    try testing.expectEqualStrings("Invalid auth key", response.message);
}

test "handleRegistration with missing auth key when required" {
    const allocator = testing.allocator;

    var store = try kv.KVStore.init(allocator, 1);
    defer store.deinit(allocator);
    try store.bootstrap("localhost:0");

    try auth_mod.createUser(&store, allocator, "testuser", "password123", "{}");

    const key_result = try auth_mod.createApiKey(&store, allocator, "testuser", null, "{}");
    defer allocator.free(key_result.key_id);
    defer allocator.free(key_result.key);

    const json =
        \\{
        \\  "public_ip": "1.2.3.4",
        \\  "public_port": 51820,
        \\  "private_ip": "10.0.0.1",
        \\  "private_port": 51821,
        \\  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        \\}
    ;

    const response = try registration.handleRegistration(&store, allocator, json);

    try testing.expectEqual(false, response.success);
    try testing.expectEqualStrings("Auth key required", response.message);
}
