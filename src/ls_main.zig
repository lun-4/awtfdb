const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const log = std.log.scoped(.als);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ als: list file tags
    \\
    \\ usage:
    \\ 	als path
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\
    \\ examples:
    \\ 	als path/to/file
    \\ 		shows tags about a single file
    \\ 	als path/to/directory
    \\ 		shows files and their respective tags inside a directory
;

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

    const Args = struct {
        help: bool = false,
        version: bool = false,
        query: ?[]const u8 = null,
    };

    var given_args = Args{};

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            given_args.query = arg;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.query == null) {
        std.log.err("query is a required argument", .{});
        return error.MissingQuery;
    }
    const query = given_args.query.?;

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    var stdout = std.io.getStdOut().writer();

    const maybe_file = try ctx.fetchFileByPath(query);
    if (maybe_file) |file| {
        defer file.deinit();
        std.debug.todo("impl files");
    } else {
        var dir = std.fs.cwd().openDir(query, .{ .iterate = true }) catch |err| switch (err) {
            std.fs.Dir.OpenError.FileNotFound => {
                log.err("path not found: {s}", .{query});
                return err;
            },
            else => return err,
        };

        var it = dir.iterate();
        while (try it.next()) |entry| {
            // TODO get stat?
            switch (entry.kind) {
                .File => try stdout.print("-", .{}),
                .Directory => try stdout.print("d", .{}),
                else => try stdout.print("-", .{}),
            }
            try stdout.print(" {s}", .{entry.name});
            if (entry.kind == .File) {
                var realpath_buf: [std.os.PATH_MAX]u8 = undefined;
                const full_path = try dir.realpath(entry.name, &realpath_buf);
                var maybe_inner_file = try ctx.fetchFileByPath(full_path);
                if (maybe_inner_file) |*file| {
                    defer file.deinit();
                    try file.printTagsTo(allocator, stdout);
                }
            }
            try stdout.print("\n", .{});
        }
    }
}
