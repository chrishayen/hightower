const std = @import("std");
const httpz = @import("httpz");
const registration_handler = @import("registration_handler.zig");
const auth_handler = @import("auth_handler.zig");
const kv_store_mod = @import("../kv_store.zig");

pub const ServerConfig = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    auth_key: ?[]const u8 = null,
};

pub const Server = struct {
    config: ServerConfig,
    kv_store: *kv_store_mod.KVStore,

    pub fn init(config: ServerConfig, kv_store: *kv_store_mod.KVStore) Server {
        return Server{
            .config = config,
            .kv_store = kv_store,
        };
    }

    pub fn run(self: *Server, allocator: std.mem.Allocator) !void {
        var http_server = try httpz.Server(*Server).init(allocator, .{
            .port = self.config.port,
            .address = self.config.address,
        }, self);
        defer http_server.deinit();

        var router = try http_server.router(.{});
        router.get("/", helloHandler, .{});
        router.post("/api/register", registerHandler, .{});
        router.post("/api/auth", authHandler, .{});

        std.log.info("Gateway server listening on {s}:{d}", .{ self.config.address, self.config.port });

        try http_server.listen();
    }
};

fn helloHandler(_: *Server, _: *httpz.Request, res: *httpz.Response) !void {
    res.status = 200;
    res.body = "Hello World\n";
}

fn registerHandler(self: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    const body = req.body() orelse {
        res.status = 400;
        res.body = "{\"success\":false,\"message\":\"Missing request body\"}";
        return;
    };

    const response = registration_handler.handleRegistration(
        self.kv_store,
        req.arena,
        body,
    ) catch |err| {
        std.log.err("Registration error: {}", .{err});
        res.status = 400;
        res.body = "{\"success\":false,\"message\":\"Invalid request\"}";
        return;
    };

    const json = try response.toJson(req.arena);

    res.status = 200;
    res.header("Content-Type", "application/json");
    res.body = json;
}

fn authHandler(self: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    const body = req.body() orelse {
        res.status = 400;
        res.body = "{\"success\":false,\"message\":\"Missing request body\"}";
        return;
    };

    const response = auth_handler.handleAuth(
        self.kv_store,
        req.arena,
        body,
    ) catch |err| {
        std.log.err("Auth error: {}", .{err});
        res.status = 401;
        res.body = "{\"success\":false,\"message\":\"Authentication failed\"}";
        return;
    };

    const json = try response.toJson(req.arena);

    res.status = 200;
    res.header("Content-Type", "application/json");
    res.body = json;
}
