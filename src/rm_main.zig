const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const logger = std.log.scoped(.arm);

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
    \\ 	-f				forcefully delete a path
    \\ 					(TODO support folder paths)
    \\ 	-r				remove files recursively (in a folder)
    \\ 	-t tag				remove a tag from a file
    \\ 					(does not delete the file)
    \\ 	-p pool_id			remove a file from a pool
    \\ 					(does not delete the file)
    \\ 	--dry-run			don't edit the index database
    \\
    \\ examples:
    \\  arm path/to/file
    \\  arm -r path/to/folder
    \\  arm -t mytag path/to/file
    \\  arm -p 1234 file/in/pool
;

const StringList = std.ArrayList([]const u8);
const CoreList = std.ArrayList(Context.Hash);

const Args = struct {
    help: bool = false,
    version: bool = false,
    recursive: bool = false,
    force: bool = false,
    dry_run: bool = false,
    paths: StringList,
    tags: CoreList,
    pool: ?Context.Pool = null,
    cli_v1: bool = true,
};

fn processFile(given_args: Args, file: *Context.File) !usize {
    if (given_args.tags.items.len > 0) {
        for (given_args.tags.items) |tag_core| {
            try file.removeTag(tag_core);
        }

        return 0;
    } else if (given_args.pool) |pool| {
        try pool.removeFile(file.hash.id);
        return 0;
    } else {
        try file.delete();
        return 1;
    }
}

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

    var given_args = Args{
        .paths = StringList.init(allocator),
        .tags = CoreList.init(allocator),
    };
    defer given_args.paths.deinit();
    defer given_args.tags.deinit();

    var state: enum { FetchTag, None, FetchPool } = .None;

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    while (args_it.next()) |arg| {
        switch (state) {
            .FetchTag => {
                var tag = (try ctx.fetchNamedTag(arg, "en")) orelse {
                    logger.err("tag '{s}' not found", .{arg});
                    return error.UnknownNamedTag;
                };
                try given_args.tags.append(tag.core);
                state = .None;
                continue;
            },

            .FetchPool => {
                const pool_id = try std.fmt.parseInt(i64, arg, 10);
                given_args.pool = (try ctx.fetchPool(pool_id)) orelse return error.PoolNotFound;
                state = .None;
                continue;
            },

            .None => {},
        }

        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            current_log_level = .debug;
        } else if (std.mem.eql(u8, arg, "-r")) {
            given_args.recursive = true;
        } else if (std.mem.eql(u8, arg, "-f")) {
            given_args.force = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            given_args.dry_run = true;
        } else if (std.mem.eql(u8, arg, "-t")) {
            state = .FetchTag;
        } else if (std.mem.eql(u8, arg, "-p")) {
            state = .FetchPool;
        } else if (std.mem.eql(u8, arg, "--v1")) {
            given_args.cli_v1 = true; // doesn't do anything yet
        } else {
            try given_args.paths.append(arg);
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.paths.items.len == 0) {
        logger.err("path is a required argument", .{});
        return error.MissingPath;
    }
    if (given_args.dry_run) try ctx.turnIntoMemoryDb();

    defer if (given_args.pool) |pool| pool.deinit();

    var savepoint = try ctx.db.?.savepoint("remove_files");
    errdefer savepoint.rollback();
    defer savepoint.commit();

    var count: usize = 0;

    for (given_args.paths.items) |path| {
        var full_path_buffer: [std.os.PATH_MAX]u8 = undefined;
        // if forcing a deletion, do not give a shit about filesystem
        const full_path = if (given_args.force)
            path
        else
            try std.fs.cwd().realpath(path, &full_path_buffer);
        var maybe_file = try ctx.fetchFileByPath(full_path);

        if (maybe_file) |*file| {
            defer file.deinit();
            count += try processFile(given_args, file);
        } else {
            var dir = std.fs.cwd().openIterableDir(full_path, .{}) catch |err| {
                logger.err("path not found: {s}", .{full_path});
                return err;
            };

            if (!given_args.recursive) {
                logger.err("given path is a folder but -r is not set", .{});
                return error.MissingRecursiveFlag;
            }

            var walker = try dir.walk(allocator);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                if (entry.kind != .File) continue;
                logger.debug("checking path {s}", .{entry.path});
                var inner_realpath_buffer: [std.os.PATH_MAX]u8 = undefined;
                const inner_full_path = try entry.dir.realpath(entry.basename, &inner_realpath_buffer);
                var maybe_inner_file = try ctx.fetchFileByPath(inner_full_path);

                if (maybe_inner_file) |*file| {
                    defer file.deinit();
                    logger.info("removing path {s}", .{entry.path});
                    count += try processFile(given_args, file);
                }
            }
        }
    }

    if (count > 0) {
        logger.info("deleted {d} files", .{count});
    }
}
