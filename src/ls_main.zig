const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;
const ID = manage_main.ID;

const logger = std.log.scoped(.als);

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
    \\  als @1234
    \\  	list file by id
;

pub const log_level = .debug;
pub var current_log_level: std.log.Level = .info;
pub const log = manage_main.log;

pub fn main() anyerror!void {
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, manage_main.sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        logger.err("failed to configure: {d} '{s}'", .{
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
        force: bool = false,
        paths: StringList,
    };

    var given_args = Args{ .paths = StringList.init(allocator) };
    defer given_args.paths.deinit();

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            current_log_level = .debug;
        } else if (std.mem.eql(u8, arg, "-f")) {
            given_args.force = true;
        } else {
            try given_args.paths.append(arg);
        }
    }

    if (given_args.paths.items.len == 0) {
        try given_args.paths.append(".");
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
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

    var stdout = std.io.getStdOut().writer();

    for (given_args.paths.items) |query| {
        if (std.mem.startsWith(u8, query, "@")) {
            // direct file id fetch
            var it = std.mem.split(u8, query, "@");
            _ = it.next();
            const file_hash_as_str = it.next() orelse return error.InvalidFileIdSyntax;
            const file_hash = ID.fromString(file_hash_as_str);

            var maybe_file = try ctx.fetchFile(file_hash);
            if (maybe_file) |file| {
                defer file.deinit();

                try stdout.print("- {s}", .{file.local_path});
                try file.printTagsTo(allocator, stdout);
                try stdout.print("\n", .{});
            }
            continue;
        }

        if (given_args.force) {
            var maybe_inner_file = try ctx.fetchFileByPath(query);
            try stdout.print("- {s}", .{query});
            if (maybe_inner_file) |*file| {
                defer file.deinit();
                try file.printTagsTo(allocator, stdout);
            }

            continue;
        }

        var maybe_dir: ?std.fs.IterableDir = std.fs.cwd().openIterableDir(query, .{}) catch |err| blk: {
            switch (err) {
                error.FileNotFound => {
                    logger.err("path not found: {s}", .{query});
                    return err;
                },
                error.NotDir => {
                    break :blk null;
                },
                else => return err,
            }
        };

        if (maybe_dir) |dir| {
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
                    const full_path = try dir.dir.realpath(entry.name, &realpath_buf);
                    var maybe_inner_file = try ctx.fetchFileByPath(full_path);
                    if (maybe_inner_file) |*file| {
                        defer file.deinit();
                        try file.printTagsTo(allocator, stdout);
                    }
                }
                try stdout.print("\n", .{});
            }
        } else {
            var realpath_buf: [std.os.PATH_MAX]u8 = undefined;
            const full_path = try std.fs.cwd().realpath(query, &realpath_buf);

            const maybe_file = try ctx.fetchFileByPath(full_path);
            try stdout.print("- {s}", .{query});
            if (maybe_file) |file| {
                defer file.deinit();
                try file.printTagsTo(allocator, stdout);
            }
            try stdout.print("\n", .{});
        }
    }
}
