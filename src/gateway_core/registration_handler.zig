const std = @import("std");
const registration_core = @import("../core/gateway/registration.zig");
const auth_ops = @import("../auth_operations.zig");
const kv_store_mod = @import("../kv_store.zig");

// Imperative shell for handling registration with auth

pub const RegistrationRequest = registration_core.RegistrationRequest;
pub const RegistrationResponse = registration_core.RegistrationResponse;

pub fn handleRegistration(store: *kv_store_mod.KVStore, allocator: std.mem.Allocator, body: []const u8) !RegistrationResponse {
    var request = try RegistrationRequest.fromJson(allocator, body);
    defer request.deinit(allocator);

    if (requiresAuth(store)) {
        if (request.auth_key) |provided_key| {
            const username = auth_ops.verifyApiKey(store, allocator, provided_key) catch {
                return registration_core.createInvalidAuthResponse();
            };
            defer allocator.free(username);

            std.log.info("Registration authenticated for user: {s}", .{username});
        } else {
            return registration_core.createAuthRequiredResponse();
        }
    }

    return registration_core.validateRegistration(request);
}

fn requiresAuth(store: *kv_store_mod.KVStore) bool {
    var locked_view = store.lock();
    defer locked_view.deinit();

    var it = locked_view.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "__auth:apikey:")) {
            return true;
        }
    }
    return false;
}
