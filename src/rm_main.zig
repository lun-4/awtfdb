const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const log = std.log.scoped(.arm);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ arm: remove files from the index
    \\
    \\ usage:
    \\ 	arm [options] path
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\ 	-r				remove files recursively (in a folder)
    \\ 	--dry-run			don't edit the index database
    \\
    \\ examples:
    \\  arm path/to/file
    \\  arm -r path/to/folder
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
        recursive: bool = false,
        dry_run: bool = false,
        path: ?[]const u8 = null,
    };

    var given_args = Args{};

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "-r")) {
            given_args.recursive = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            given_args.dry_run = true;
        } else {
            given_args.path = arg;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.path == null) {
        std.log.err("path is a required argument", .{});
        return error.MissingPath;
    }
    const path = given_args.path.?;

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});
    if (given_args.dry_run) try ctx.turnIntoMemoryDb();

    var full_path_buffer: [std.os.PATH_MAX]u8 = undefined;
    const full_path = try std.fs.cwd().realpath(path, &full_path_buffer);
    const maybe_file = try ctx.fetchFileByPath(full_path);

    var count: usize = 0;

    if (maybe_file) |file| {
        defer file.deinit();
        try file.delete();
        count += 1;
    } else {
        var dir = std.fs.cwd().openDir(full_path, .{ .iterate = true }) catch |err| switch (err) {
            std.fs.Dir.OpenError.FileNotFound => {
                log.err("path not found: {s}", .{full_path});
                return err;
            },
            else => return err,
        };

        if (!given_args.recursive) {
            log.err("given path is a folder but -r is not set", .{});
            return error.MissingRecursiveFlag;
        }

        var walker = try dir.walk(allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind != .File) continue;
            log.debug("checking path {s}", .{entry.path});
            var inner_realpath_buffer: [std.os.PATH_MAX]u8 = undefined;
            const inner_full_path = try entry.dir.realpath(entry.basename, &inner_realpath_buffer);
            const maybe_inner_file = try ctx.fetchFileByPath(inner_full_path);

            if (maybe_inner_file) |file| {
                defer file.deinit();
                log.info("removing path {s}", .{entry.path});
                try file.delete();
                count += 1;
            }
        }
    }

    log.info("deleted {d} files", .{count});
}
