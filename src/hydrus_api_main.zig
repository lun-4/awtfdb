const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const http = @import("apple_pie");
const ManageContext = manage_main.Context;
const SqlGiver = @import("./find_main.zig").SqlGiver;

const Context = struct {
    manage: *ManageContext,
    given_args: *Args,
};

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

const StringList = std.ArrayList([]const u8);
const Args = struct {
    help: bool = false,
    version: bool = false,
    access_keys: StringList,
    pub fn deinit(self: *@This()) void {
        self.access_keys.deinit();
    }
};

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

    var given_args = Args{ .access_keys = StringList.init(allocator) };
    defer given_args.deinit();
    var state: enum { None, FetchAccessKey } = .None;

    while (args_it.next()) |arg| {
        if (state == .FetchAccessKey) {
            try given_args.access_keys.append(arg);
            state = .None;
            continue;
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

    var manage_ctx = ManageContext{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer manage_ctx.deinit();

    try manage_ctx.loadDatabase(.{});

    if (given_args.access_keys.items.len == 0) {
        log.warn("no access keys defined, nobody will be able to access the api", .{});
    }

    var ctx = Context{ .manage = &manage_ctx, .given_args = &given_args };

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
        builder.get("/api_version", null, apiVersion),
        builder.options("/verify_access_key", null, corsHandler),
        builder.get("/verify_access_key", null, verifyAccessKey),
        builder.options("/get_files/search_files", null, corsHandler),
        builder.get("/get_files/search_files", null, searchFiles),
    });

    try writeCors(response);
    try router(ctx, response, request);
    log.info("{s} {s} {d}", .{
        methodString(request),
        request.path(),
        @enumToInt(response.status_code),
    });
}

fn corsHandler(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    if (!wantMethod(request, response, .{.options})) return;
    std.debug.assert(captures == null);
    _ = request;
    _ = ctx;
    try writeCors(response);
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

const hzzp = @import("hzzp");

test "index test" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    const address = try std.net.Address.parseIp("0.0.0.0", 8080);
    var server = http.Server.init();

    var manage_ctx = try manage_main.makeTestContext();
    defer manage_ctx.deinit();
    var main_ctx = Context{ .manage = &manage_ctx, .given_args = undefined };

    const server_thread = struct {
        var _addr: std.net.Address = undefined;

        fn runServer(context: *http.Server, ctx: *Context) !void {
            try context.run(ctx.manage.allocator, _addr, ctx, mainHandler);
        }
    };
    server_thread._addr = address;

    const thread = try std.Thread.spawn(
        .{},
        server_thread.runServer,
        .{ &server, &main_ctx },
    );
    errdefer server.shutdown();

    var stream = while (true) {
        var conn = std.net.tcpConnectToAddress(address) catch |err| switch (err) {
            error.ConnectionRefused => continue,
            else => return err,
        };

        break conn;
    } else unreachable;
    errdefer stream.close();
    // tell server to shutdown
    // fill finish current request and then shutdown
    server.shutdown();

    var buffer: [256]u8 = undefined;
    var client = hzzp.base.client.create(&buffer, {}, stream.writer());
    try client.writeStatusLine("GET", "/");
    try client.writeHeaderValue("Host", "localhost");
    try client.finishHeaders();
    try client.writePayload(null);

    var output_buf: [512]u8 = undefined;
    const len = try stream.reader().read(&output_buf);
    const output = output_buf[0..len];
    stream.close();
    thread.join();

    var buffer_stream = std.io.fixedBufferStream(output);
    var read_buffer: [256]u8 = undefined;
    var read_client = hzzp.base.client.create(&read_buffer, buffer_stream.reader(), {});
    const received_status_line = (try read_client.next()).?;
    try std.testing.expectEqual(@as(u16, 200), received_status_line.status.code);
}

//test "index works (the universe also works)" {
//    var ctx = try manage_main.makeTestContext();
//    defer ctx.deinit();
//
//    var request = http.Request{ .arena = std.testing.allocator, .context = http.Request.Context{
//        .method = .get,
//        .uri = http.Uri.empty,
//        .raw_header_data = undefined,
//        .protocol = .http_1_1,
//        .host = null,
//        .raw_body = "",
//        .connection_type = .close,
//    } };
//
//    var list = std.ArrayList(u8).init(std.testing.allocator);
//    defer list.deinit();
//
//    var response = http.Response{
//        .headers = std.StringArrayHashMap([]const u8).init(std.testing.allocator),
//        .buffered_writer = std.io.bufferedWriter(list.writer()),
//        .is_flushed = false,
//        .body = list.writer(),
//        .close = false,
//    };
//    defer response.headers.deinit();
//
//    try index(ctx, &response, request, null);
//
//    try std.testing.expectEqual(http.Response.StatusCode.ok, response.status_code);
//}

fn apiVersion(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    std.debug.assert(captures == null);
    _ = request;
    _ = ctx;

    try std.json.stringify(.{
        .version = 17,
        .hydrus_version = 441,
    }, .{}, response.writer());
}

fn wantMethod(request: http.Request, response: *http.Response, allowed_methods: anytype) bool {
    var method_fail_count: usize = 0;
    inline for (allowed_methods) |allowed_method| {
        if (request.method() != allowed_method) method_fail_count += 1;
    }

    // if all method checks failed, then send 405
    if (method_fail_count == allowed_methods.len) {
        response.status_code = .method_not_allowed;
        return false;
    } else {
        return true;
    }
}

fn writeCors(response: *http.Response) !void {
    try response.headers.put("access-control-allow-origin", "https://hydrus.app");
    try response.headers.put("access-control-allow-headers", "*");
    try response.headers.put("access-control-allow-methods", "*");
    try response.headers.put("access-control-expose-headers", "*");
}

const HydrusAPIInput = struct {
    const Self = @This();
    pub fn deinit(self: Self) void {
        _ = self;
    }
    pub fn getAccessKey(self: Self) []const u8 {
        _ = self;
        return "TODO";
    }
    pub fn getTags(self: Self) []const u8 {
        _ = self;
        return "TODO";
    }
};

fn fetchInput(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
) !HydrusAPIInput {
    //TODO
    _ = ctx;
    _ = request;
    _ = response;
    return undefined;
}

//test "hydrus api input parsing" {
//    var ctx = try manage_main.makeTestContext();
//    defer ctx.deinit();
//
//    var request = http.Request{};
//    var response = http.Response{};
//    var input = try fetchInput(ctx, &response, request);
//    _ = input;
//
//    try std.testing.expectEqual(http.Response.StatusCode.ok, response.status_code);
//}

fn wantAuth(ctx: *Context, response: *http.Response, input: HydrusAPIInput) bool {
    const access_key = input.getAccessKey();

    for (ctx.given_args.access_keys.items) |correct_access_key| {
        if (std.mem.eql(u8, access_key, correct_access_key)) return true;
    }

    response.status_code = .unauthorized;
    return false;
}

fn verifyAccessKey(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    if (!wantMethod(request, response, .{.get})) return;
    std.debug.assert(captures == null);
    _ = request;
    _ = ctx;

    const input = fetchInput(ctx, response, request) catch return;
    defer input.deinit();
    if (!wantAuth(ctx, response, input)) return;

    try std.json.stringify(
        .{
            .basic_permissions = .{ 0, 1, 3 },
            .human_description = "this is a test",
        },
        .{},
        response.writer(),
    );
}

fn convertTagsToFindQuery(tags_string: []const u8) []const u8 {
    //parse json out of tags_string
    //construct afind query out of it
    _ = tags_string;
    return "";
}

fn writeError(
    response: *http.Response,
    status_code: http.Response.Status,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    response.status_code = status_code;
    try response.writer().print(fmt, args);
}

fn searchFiles(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    if (!wantMethod(request, response, .{.get})) return;
    std.debug.assert(captures == null);
    _ = ctx;

    const input = fetchInput(ctx, response, request) catch return;
    defer input.deinit();
    if (!wantAuth(ctx, response, input)) return;

    const tags_string = input.getTags();
    const find_query = convertTagsToFindQuery(tags_string);

    const wrapped_result = try SqlGiver.giveMeSql(ctx.manage.allocator, find_query);
    defer wrapped_result.deinit();

    const result = switch (wrapped_result) {
        .Ok => |ok_body| ok_body,
        .Error => |error_body| {
            try writeError(
                response,
                .bad_request,
                "query has error at character {d}: {s}",
                .{ error_body.character, error_body.error_type },
            );
            return;
        },
    };

    var resolved_tag_cores = std.ArrayList(i64).init(ctx.manage.allocator);
    defer resolved_tag_cores.deinit();

    for (result.tags) |tag_text| {
        const maybe_tag = try ctx.manage.fetchNamedTag(tag_text, "en");
        if (maybe_tag) |tag| {
            try resolved_tag_cores.append(tag.core.id);
        } else {
            try writeError(response, .bad_request, "query has unknown tag: {s}", .{tag_text});
            return;
        }
    }

    var stmt = try ctx.manage.db.?.prepareDynamic(result.query);
    defer stmt.deinit();

    log.debug("generated query: {s}", .{result.query});
    log.debug("found tag cores: {any}", .{resolved_tag_cores.items});

    var it = try stmt.iterator(i64, resolved_tag_cores.items);

    var returned_file_ids = std.ArrayList(i64).init(ctx.manage.allocator);
    defer returned_file_ids.deinit();

    while (try it.next(.{})) |file_hash_id| {
        //var file = (try ctx.manage.fetchFile(file_hash)).?;
        //defer file.deinit();
        try returned_file_ids.append(file_hash_id);
    }

    try std.json.stringify(
        .{ .file_ids = returned_file_ids.items },
        .{},
        response.writer(),
    );
}
