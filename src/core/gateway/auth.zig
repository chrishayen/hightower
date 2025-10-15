const std = @import("std");

// Pure auth validation logic (Functional Core)

pub const AuthRequest = struct {
    username: []const u8,
    password: []const u8,

    pub fn fromJson(allocator: std.mem.Allocator, json_str: []const u8) !AuthRequest {
        const parsed = try std.json.parseFromSlice(JsonRequest, allocator, json_str, .{});
        defer parsed.deinit();

        const value = parsed.value;

        return AuthRequest{
            .username = try allocator.dupe(u8, value.username),
            .password = try allocator.dupe(u8, value.password),
        };
    }

    pub fn deinit(self: *AuthRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.password);
    }
};

const JsonRequest = struct {
    username: []const u8,
    password: []const u8,
};

pub const AuthResponse = struct {
    success: bool,
    message: []const u8,
    api_key: ?[]const u8 = null,
    key_id: ?[]const u8 = null,

    pub fn toJson(self: AuthResponse, allocator: std.mem.Allocator) ![]u8 {
        const success_str = if (self.success) "true" else "false";

        if (self.api_key) |key| {
            if (self.key_id) |id| {
                return std.fmt.allocPrint(allocator, "{{\"success\":{s},\"message\":\"{s}\",\"api_key\":\"{s}\",\"key_id\":\"{s}\"}}", .{
                    success_str,
                    self.message,
                    key,
                    id,
                });
            }
        }

        return std.fmt.allocPrint(allocator, "{{\"success\":{s},\"message\":\"{s}\"}}", .{
            success_str,
            self.message,
        });
    }
};

// Pure function: Create invalid credentials response
pub fn createInvalidCredentialsResponse() AuthResponse {
    return AuthResponse{
        .success = false,
        .message = "Invalid username or password",
    };
}

// Pure function: Create success response
pub fn createSuccessResponse(api_key: []const u8, key_id: []const u8) AuthResponse {
    return AuthResponse{
        .success = true,
        .message = "Authentication successful",
        .api_key = api_key,
        .key_id = key_id,
    };
}
