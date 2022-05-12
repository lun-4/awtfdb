const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const http = @import("apple_pie");
const ManageContext = manage_main.Context;
const SqlGiver = @import("./find_main.zig").SqlGiver;
const magick = @import("./magick.zig");

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
        .args_it = &args_it,
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
    @setEvalBranchQuota(1000000);

    const router = comptime http.router.Router(*Context, &.{
        builder.get("/", null, index),
        builder.get("/api_version", null, apiVersion),
        builder.options("/verify_access_key", null, corsHandler),
        builder.get("/verify_access_key", null, verifyAccessKey),
        builder.options("/get_files/search_files", null, corsHandler),
        builder.get("/get_files/search_files", null, searchFiles),
        builder.options("/get_files/file_metadata", null, corsHandler),
        builder.get("/get_files/file_metadata", null, fileMetadata),
        builder.options("/get_files/thumbnail", null, corsHandler),
        builder.get("/get_files/thumbnail", null, fileThumbnail),
        builder.options("/get_files/file", null, corsHandler),
        builder.get("/get_files/file", null, fileContents),
    });

    try writeCors(response);
    router(ctx, response, request) catch |err| {
        log.info("{s} {s} got error: {s}", .{
            methodString(request),
            request.path(),
            @errorName(err),
        });

        return err;
    };
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

const HydrusAPIInputResult = union(enum) {
    Error: struct {},
    Ok: struct {},
};

const ACCESS_KEY_NAME = "Hydrus-Client-API-Access-Key";
fn fetchInput(
    ctx: *ManageContext,
    headers: http.Headers,
    raw_query: []const u8,
) !HydrusAPIInputResult {
    const param_map = try http.Uri.decodeQueryString(ctx.allocator, raw_query);
    errdefer param_map.deinit();
    log.info("uri: {s}", .{param_map});

    _ = ctx;
    _ = headers;

    return .{
        .Ok = .{},
    };
}

test "hydrus api input parsing" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();

    // var wrapped_input = try fetchInput(
    //     &ctx,
    //     headers,
    //     "file_sort_type=6&file_sort_asc=false&tags=%5B%22character%3Asamus%20aran%22%2C%20%22creator%3A%5Cu9752%5Cu3044%5Cu685c%22%2C%20%22system%3Aheight%20%3E%202000%22%5D",
    // );

    // const input = wrapped_input.Ok;
    // _ = input;

    // return error.Thing;

    //try std.testing.expectEqual(http.Response.StatusCode.ok, response.status_code);
}

fn wantAuth(ctx: *Context, response: *http.Response, request: http.Request) bool {
    var headers_it = request.iterator();
    var access_key: ?[]const u8 = null;
    while (headers_it.next()) |header| {
        if (std.mem.eql(u8, header.key, "Hydrus-Client-API-Access-Key")) {
            access_key = header.value;
        }
    }

    var param_map = request.context.uri.queryParameters(ctx.manage.allocator) catch |err| {
        writeError(
            response,
            .bad_request,
            "invalid query parameters: {s}",
            .{@errorName(err)},
        ) catch return false;
        return false;
    };
    defer param_map.deinit(ctx.manage.allocator);
    access_key = access_key orelse param_map.get("Hydrus-Client-API-Access-Key");

    if (access_key == null) {
        response.status_code = .unauthorized;
        return false;
    }

    for (ctx.given_args.access_keys.items) |correct_access_key| {
        if (std.mem.eql(u8, access_key.?, correct_access_key)) return true;
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

    if (!wantAuth(ctx, response, request)) return;

    try std.json.stringify(
        .{
            .basic_permissions = .{ 0, 1, 3 },
            .human_description = "this is a test",
        },
        .{},
        response.writer(),
    );
}

fn convertTagsToFindQuery(allocator: std.mem.Allocator, tags_string: []const u8) ![]const u8 {
    //parse json out of tags_string
    //construct afind query out of it

    log.debug("tags string: '{s}'", .{tags_string});
    var tokens = std.json.TokenStream.init(tags_string);
    const opts = std.json.ParseOptions{ .allocator = allocator };
    const tags = try std.json.parse([][]const u8, &tokens, opts);
    defer std.json.parseFree([][]const u8, tags, opts);

    return std.mem.join(allocator, " ", tags);
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

    if (!wantAuth(ctx, response, request)) return;

    var param_map = try request.context.uri.queryParameters(ctx.manage.allocator);
    defer param_map.deinit(ctx.manage.allocator);
    const unsafe_tags_string = param_map.get("tags") orelse {
        writeError(response, .bad_request, "need tags", .{}) catch return;
        return;
    };

    const safe_tags_string = try http.Uri.decode(ctx.manage.allocator, unsafe_tags_string);
    defer ctx.manage.allocator.free(safe_tags_string);

    const find_query = try convertTagsToFindQuery(ctx.manage.allocator, safe_tags_string);
    defer ctx.manage.allocator.free(find_query);

    var giver = try SqlGiver.init();
    defer giver.deinit();

    const wrapped_result = try giver.giveMeSql(ctx.manage.allocator, find_query);
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

fn fileMetadata(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    _ = captures;
    if (!wantMethod(request, response, .{.get})) return;
    if (!wantAuth(ctx, response, request)) return;

    var param_map = try request.context.uri.queryParameters(ctx.manage.allocator);
    defer param_map.deinit(ctx.manage.allocator);
    const file_ids_serialized = param_map.get("file_ids") orelse {
        writeError(response, .bad_request, "need file_ids", .{}) catch return;
        return;
    };

    log.info("file ids: {s}", .{file_ids_serialized});

    var tokens = std.json.TokenStream.init(file_ids_serialized);

    const opts = std.json.ParseOptions{ .allocator = ctx.manage.allocator };
    const file_ids = try std.json.parse([]i64, &tokens, opts);
    defer std.json.parseFree([]i64, file_ids, opts);

    const HydrusFile = struct {
        file_id: i64,
        hash: []const u8,
        size: i64 = 0,
        mime: []const u8,
        ext: []const u8,
        width: usize = 100,
        height: usize = 100,
        duration: ?usize = null,
        time_modified: ?usize = null,
        file_services: ?usize = null, // TODO add current+deleted
        has_audio: bool = false,
        num_frames: ?usize = null,
        num_words: ?usize = null,
        is_inbox: bool = false,
        is_local: bool = true, // should this be true?
        is_trashed: bool = false,
        known_urls: ?[]usize = null, // TODO this is array
        service_names_to_statuses_to_tags: ?[]usize = null,
        service_keys_to_statuses_to_tags: ?[]usize = null,
        service_names_to_statuses_to_display_tags: ?[]usize = null,
        service_keys_to_statuses_to_display_tags: ?[]usize = null,
    };

    var hydrus_files = std.ArrayList(HydrusFile).init(ctx.manage.allocator);
    defer {
        for (hydrus_files.items) |file| {
            ctx.manage.allocator.free(file.hash);
            ctx.manage.allocator.free(file.mime);
            ctx.manage.allocator.free(file.ext);
        }
        hydrus_files.deinit();
    }

    for (file_ids) |file_id| {
        var maybe_file = try ctx.manage.fetchFile(file_id);
        if (maybe_file) |file| {
            var hex_hash = file.hash.toHex();

            try hydrus_files.append(.{
                .file_id = file_id,
                .hash = try ctx.manage.allocator.dupe(u8, &hex_hash),
                .mime = try ctx.manage.allocator.dupe(u8, "image/png"),
                .ext = try ctx.manage.allocator.dupe(u8, ".png"),
            });
        }
    }

    try std.json.stringify(
        .{ .metadata = hydrus_files.items },
        .{},
        response.writer(),
    );
}

const c = @cImport({
    @cInclude("magic.h");
});

const MagicResult = struct {
    cookie: c.magic_t,
    result: ?[]const u8,
};

fn inferMimetype(response: *http.Response, allocator: std.mem.Allocator, local_path: []const u8) !?MagicResult {
    var cookie = c.magic_open(
        c.MAGIC_SYMLINK | c.MAGIC_MIME,
    ) orelse return error.UnableToMakeMagicCookie;

    // TODO use MAGIC variable if set here????
    if (c.magic_load(cookie, "/usr/share/misc/magic.mgc") == -1) {
        const magic_error_value = c.magic_error(cookie);
        log.err("failed to load magic file: {s}", .{magic_error_value});

        try writeError(
            response,
            .internal_server_error,
            "an error occoured while calculating magic: {s}",
            .{magic_error_value},
        );
        return null;
    }

    const local_path_cstr = try std.cstr.addNullByte(allocator, local_path);
    defer allocator.free(local_path_cstr);

    return MagicResult{ .cookie = cookie, .result = std.mem.span(c.magic_file(cookie, local_path_cstr)) };
}

fn fileThumbnail(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    _ = captures;
    if (!wantMethod(request, response, .{.get})) return;
    if (!wantAuth(ctx, response, request)) return;

    var param_map = try request.context.uri.queryParameters(ctx.manage.allocator);
    defer param_map.deinit(ctx.manage.allocator);
    const maybe_file_id = param_map.get("file_id");
    const maybe_file_hash = param_map.get("hash");

    if (maybe_file_id != null and maybe_file_hash != null) {
        writeError(response, .bad_request, "cant have both hash and id", .{}) catch return;
        return;
    }

    var hash_id_parsed: ?i64 = null;
    var hash_parsed: [32]u8 = undefined;

    if (maybe_file_hash) |file_hash| {
        var out = try std.fmt.hexToBytes(&hash_parsed, file_hash);
        if (out.len != 32) {
            writeError(response, .bad_request, "invalid file hash size", .{}) catch return;
            return;
        }
    }

    if (maybe_file_id) |file_id| {
        hash_id_parsed = std.fmt.parseInt(i64, file_id, 10) catch |err| {
            writeError(
                response,
                .bad_request,
                "invalid file id (must be number): {s}",
                .{@errorName(err)},
            ) catch return;
            return;
        };
    }

    log.debug("id? {s} hash? {s}", .{ maybe_file_id, maybe_file_hash });

    var maybe_file: ?ManageContext.File = if (maybe_file_id != null)
        try ctx.manage.fetchFile(hash_id_parsed.?)
    else if (maybe_file_hash != null)
        try ctx.manage.fetchFileByHash(hash_parsed)
    else
        unreachable;

    if (maybe_file) |file| {
        defer file.deinit();

        const mimetype_result = (try inferMimetype(response, ctx.manage.allocator, file.local_path)) orelse return;
        defer c.magic_close(mimetype_result.cookie);
        const mimetype_cstr = mimetype_result.result;
        if (mimetype_cstr == null) {
            const magic_error_value = c.magic_error(mimetype_result.cookie);
            log.err("failed to get mimetype: {s}", .{magic_error_value});
            try writeError(
                response,
                .internal_server_error,
                "an error occoured while calculating magic: {s}",
                .{magic_error_value},
            );
            return;
        } else {
            const mimetype = mimetype_cstr.?;
            log.debug("mimetype found: {s}", .{mimetype});
            if (std.mem.startsWith(u8, mimetype, "image/")) {
                //var mctx = try magick.loadImage(local_path_cstr);
                //defer mctx.deinit();

                const file_fd = try std.fs.openFileAbsolute(file.local_path, .{ .mode = .read_only });
                defer file_fd.close();

                // we need a better API to pass header values whose lifetime are
                // beyond the request handler's, or else we're passing undefined
                // memory to the response.
                //
                // this hack is required so that the values live in constant
                // memory inside the executable, rather than stack/heap.
                if (std.mem.startsWith(u8, mimetype, "image/png")) {
                    try response.headers.put("Content-Type", "image/png");
                } else if (std.mem.startsWith(u8, mimetype, "application/pdf")) {
                    try response.headers.put("Content-Type", "application/pdf");
                }

                var buf: [4096]u8 = undefined;
                while (true) {
                    const read_bytes = try file_fd.read(&buf);
                    if (read_bytes == 0) break;
                    try response.writer().writeAll(&buf);
                }
            } else if (std.mem.startsWith(u8, mimetype, "application/pdf")) {
                var PREFIX = "/tmp/awtf/ahydrus-thumbnails";

                const dirpath = std.fs.path.dirname(file.local_path).?;
                const basename = std.fs.path.basename(file.local_path);

                const local_path_cstr = try std.cstr.addNullByte(ctx.manage.allocator, file.local_path);
                defer ctx.manage.allocator.free(local_path_cstr);

                const basename_png = try std.fmt.allocPrint(ctx.manage.allocator, "{s}.png", .{basename});
                defer ctx.manage.allocator.free(basename_png);

                const thumbnail_path = try std.fs.path.resolve(ctx.manage.allocator, &[_][]const u8{
                    PREFIX,
                    dirpath,
                    basename_png,
                });
                defer ctx.manage.allocator.free(thumbnail_path);

                try std.fs.cwd().makePath(std.fs.path.dirname(thumbnail_path).?);

                var maybe_file_fd: ?std.fs.File = std.fs.openFileAbsolute(
                    thumbnail_path,
                    .{ .mode = .read_only },
                ) catch |err| switch (err) {
                    error.FileNotFound => blk: {
                        break :blk null;
                    },
                    else => return err,
                };
                defer if (maybe_file_fd) |file_fd| file_fd.close();

                if (maybe_file_fd == null) {
                    var mctx = try magick.loadImage(local_path_cstr);
                    defer mctx.deinit();

                    const thumbnail_path_cstr = try std.cstr.addNullByte(ctx.manage.allocator, thumbnail_path);
                    defer ctx.manage.allocator.free(thumbnail_path_cstr);

                    if (magick.c.MagickWriteImage(mctx.wand, thumbnail_path_cstr) == 0)
                        return error.MagickWriteFail;

                    //should work now
                    maybe_file_fd = try std.fs.openFileAbsolute(
                        thumbnail_path,
                        .{ .mode = .read_only },
                    );
                }

                var file_fd = maybe_file_fd.?;
                var buf: [4096]u8 = undefined;
                while (true) {
                    const read_bytes = try file_fd.read(&buf);
                    if (read_bytes == 0) break;
                    try response.writer().writeAll(&buf);
                }

                return;
            } else {

                // todo return default thumbnail
                try writeError(response, .internal_server_error, "unsupported mimetype: {s}", .{mimetype});
            }
        }
    } else {
        response.status_code = .not_found;
    }
}

fn fileContents(
    ctx: *Context,
    response: *http.Response,
    request: http.Request,
    captures: ?*const anyopaque,
) !void {
    _ = captures;
    if (!wantMethod(request, response, .{.get})) return;
    if (!wantAuth(ctx, response, request)) return;

    var param_map = try request.context.uri.queryParameters(ctx.manage.allocator);
    defer param_map.deinit(ctx.manage.allocator);

    // TODO decrease repetition
    const maybe_file_id = param_map.get("file_id");
    const maybe_file_hash = param_map.get("hash");

    if (maybe_file_id != null and maybe_file_hash != null) {
        writeError(response, .bad_request, "cant have both hash and id", .{}) catch return;
        return;
    }

    var hash_id_parsed: ?i64 = null;
    var hash_parsed: [32]u8 = undefined;

    if (maybe_file_hash) |file_hash| {
        var out = try std.fmt.hexToBytes(&hash_parsed, file_hash);
        if (out.len != 32) {
            writeError(response, .bad_request, "invalid file hash size", .{}) catch return;
            return;
        }
    }

    if (maybe_file_id) |file_id| {
        hash_id_parsed = std.fmt.parseInt(i64, file_id, 10) catch |err| {
            writeError(
                response,
                .bad_request,
                "invalid file id (must be number): {s}",
                .{@errorName(err)},
            ) catch return;
            return;
        };
    }

    log.debug("id? {s} hash? {s}", .{ maybe_file_id, maybe_file_hash });

    var maybe_file: ?ManageContext.File = if (maybe_file_id != null)
        try ctx.manage.fetchFile(hash_id_parsed.?)
    else if (maybe_file_hash != null)
        try ctx.manage.fetchFileByHash(hash_parsed)
    else
        unreachable;

    if (maybe_file) |file| {
        defer file.deinit();

        const mimetype_result = (try inferMimetype(response, ctx.manage.allocator, file.local_path)) orelse return;
        defer c.magic_close(mimetype_result.cookie);
        const maybe_mimetype = mimetype_result.result;
        if (maybe_mimetype) |mimetype| {
            log.debug("mimetype found: {s}", .{mimetype});

            const file_fd = try std.fs.openFileAbsolute(file.local_path, .{ .mode = .read_only });
            defer file_fd.close();

            // we need a better API to pass header values whose lifetime are
            // beyond the request handler's, or else we're passing undefined
            // memory to the response.
            //
            // this hack is required so that the values live in constant
            // memory inside the executable, rather than stack/heap.
            if (std.mem.startsWith(u8, mimetype, "image/png")) {
                try response.headers.put("Content-Type", "image/png");
            } else if (std.mem.startsWith(u8, mimetype, "application/pdf")) {
                try response.headers.put("Content-Type", "application/pdf");
            }

            var buf: [4096]u8 = undefined;
            while (true) {
                const read_bytes = try file_fd.read(&buf);
                if (read_bytes == 0) break;
                try response.writer().writeAll(&buf);
            }
        } else {
            const magic_error_value = c.magic_error(mimetype_result.cookie);
            log.err("failed to get mimetype: {s}", .{magic_error_value});
            try writeError(
                response,
                .internal_server_error,
                "an error occoured while calculating magic: {s}",
                .{magic_error_value},
            );
            return;
        }
    } else {
        response.status_code = .not_found;
    }
}
