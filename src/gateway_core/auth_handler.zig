const std = @import("std");
const auth_core = @import("../core/gateway/auth.zig");
const auth_ops = @import("../auth_operations.zig");
const kv_store_mod = @import("../kv_store.zig");

// Imperative shell for handling authentication

pub const AuthRequest = auth_core.AuthRequest;
pub const AuthResponse = auth_core.AuthResponse;

pub fn handleAuth(store: *kv_store_mod.KVStore, allocator: std.mem.Allocator, body: []const u8) !AuthResponse {
    var request = try AuthRequest.fromJson(allocator, body);
    defer request.deinit(allocator);

    // Verify the password
    auth_ops.verifyPassword(store, allocator, request.username, request.password) catch {
        return auth_core.createInvalidCredentialsResponse();
    };

    // Create an API key for the user (30 days expiration)
    const api_key_result = auth_ops.createApiKey(store, allocator, request.username, 30, "{}") catch {
        return auth_core.createInvalidCredentialsResponse();
    };

    return auth_core.createSuccessResponse(api_key_result.key, api_key_result.key_id);
}
