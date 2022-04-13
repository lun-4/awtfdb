const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const http = @import("apple_pie");
const Context = manage_main.Context;

const log = std.log.scoped(.ahydrus_api);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ ahydrus_api: hydrus client api provider for awtfdb (read only)
    \\
    \\ usage:
    \\  ahydrus_api [options]
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\ 	--key <key>			run the server with this access key
    \\ 					being able to be used in the server
    \\ 					(multiple can be defined)
    \\
    \\ examples:
    \\  ahydrus_api --key a867e7abdf8e1a717928b8505be0c1cc776cb32773695
;

fn methodString(request: http.Request) []const u8 {
    return switch (request.method()) {
        .get => "GET",
        .head => "HEAD",
        .post => "POST",
        .put => "PUT",
        .delete => "DELETE",
        .connect => "CONNECT",
        .options => "OPTIONS",
        .trace => "TRACE",
        .patch => "PATCH",
        .any => "ANY",
    };
}

pub fn main() anyerror!void {
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, manage_main.sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        std.log.err("failed to configure: {d} '{s}'", .{
            rc, sqlite.c.sqlite3_errstr(rc),
        });
        return error.ConfigFail;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var args_it = std.process.args();
    _ = args_it.skip();

    const StringList = std.ArrayList([]const u8);
    const Args = struct {
        help: bool = false,
        version: bool = false,
        access_keys: StringList,
        pub fn deinit(self: *@This()) void {
            self.access_keys.deinit();
        }
    };

    var given_args = Args{ .access_keys = StringList.init(allocator) };
    defer given_args.deinit();
    var state: enum { None, FetchAccessKey } = .None;

    while (args_it.next()) |arg| {
        if (state == .FetchAccessKey) {
            try given_args.access_keys.append(arg);
            state = .None;
        }

        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "--key")) {
            state = .FetchAccessKey;
        } else {
            log.err("unknown argument {s}", .{arg});
            return error.UnknownArgument;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ahydrus_api {s}\n", .{VERSION});
        return;
    }

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    if (given_args.access_keys.items.len == 0) {
        log.warn("no access keys defined, nobody will be able to access the api", .{});
    }

    try http.listenAndServe(
        allocator,
        try std.net.Address.parseIp("127.0.0.1", 8080),
        &ctx,
        mainHandler,
    );
}

fn mainHandler(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
) !void {
    const builder = http.router.Builder(*Context);
    const router = comptime http.router.Router(*Context, &.{
        builder.get("/", null, index),
    });

    try router(ctx, response, request);
    log.info("{s} {s} {d}", .{
        methodString(request),
        request.path(),
        @enumToInt(response.status_code),
    });
}

fn index(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    std.debug.assert(captures == null);
    _ = request;
    _ = ctx;
    try response.writer().writeAll("Hello Zig!\n");
}
