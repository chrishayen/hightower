const std = @import("std");
const noise_ik = @import("../noise_ik/types.zig");
const kv = @import("../kv/store.zig");
const auth_mod = @import("../kv/auth.zig");

pub const RegistrationRequest = struct {
    public_ip: []const u8,
    public_port: u16,
    private_ip: []const u8,
    private_port: u16,
    public_key: [noise_ik.key_len]u8,
    auth_key: ?[]const u8,

    pub fn fromJson(allocator: std.mem.Allocator, json_str: []const u8) !RegistrationRequest {
        const parsed = try std.json.parseFromSlice(JsonRequest, allocator, json_str, .{});
        defer parsed.deinit();

        const value = parsed.value;

        var public_key: [noise_ik.key_len]u8 = undefined;
        const decoder = std.base64.standard.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(value.public_key);

        if (decoded_len != noise_ik.key_len) {
            return error.InvalidPublicKeyLength;
        }

        try decoder.decode(&public_key, value.public_key);

        const auth_key = if (value.auth_key) |key|
            try allocator.dupe(u8, key)
        else
            null;

        return RegistrationRequest{
            .public_ip = try allocator.dupe(u8, value.public_ip),
            .public_port = value.public_port,
            .private_ip = try allocator.dupe(u8, value.private_ip),
            .private_port = value.private_port,
            .public_key = public_key,
            .auth_key = auth_key,
        };
    }

    pub fn deinit(self: *RegistrationRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.public_ip);
        allocator.free(self.private_ip);
        if (self.auth_key) |key| {
            allocator.free(key);
        }
    }
};

const JsonRequest = struct {
    public_ip: []const u8,
    public_port: u16,
    private_ip: []const u8,
    private_port: u16,
    public_key: []const u8,
    auth_key: ?[]const u8 = null,
};

pub const RegistrationResponse = struct {
    success: bool,
    message: []const u8,

    pub fn toJson(self: RegistrationResponse, allocator: std.mem.Allocator) ![]u8 {
        const success_str = if (self.success) "true" else "false";
        return std.fmt.allocPrint(allocator, "{{\"success\":{s},\"message\":\"{s}\"}}", .{
            success_str,
            self.message,
        });
    }
};

pub fn handleRegistration(store: *kv.KVStore, allocator: std.mem.Allocator, body: []const u8) !RegistrationResponse {
    var request = try RegistrationRequest.fromJson(allocator, body);
    defer request.deinit(allocator);

    if (requiresAuth(store)) {
        if (request.auth_key) |provided_key| {
            const username = auth_mod.verifyApiKey(store, allocator, provided_key) catch {
                return RegistrationResponse{
                    .success = false,
                    .message = "Invalid auth key",
                };
            };
            defer allocator.free(username);

            std.log.info("Registration authenticated for user: {s}", .{username});
        } else {
            return RegistrationResponse{
                .success = false,
                .message = "Auth key required",
            };
        }
    }

    std.log.info("Registration request: public={s}:{}, private={s}:{}, key_len={}", .{
        request.public_ip,
        request.public_port,
        request.private_ip,
        request.private_port,
        request.public_key.len,
    });

    return RegistrationResponse{
        .success = true,
        .message = "Registration successful",
    };
}

fn requiresAuth(store: *kv.KVStore) bool {
    store.mutex.lock();
    defer store.mutex.unlock();

    var it = store.kv_state.map.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "__auth:apikey:")) {
            return true;
        }
    }
    return false;
}
