const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const Context = manage_main.Context;

const log = std.log.scoped(.awtfdb_janitor);
pub const io_mode = .evented;

const VERSION = "0.0.1";
const HELPTEXT =
    \\ awtfdb-metrics: run analytical queries on db and submit results inside db
    \\
    \\ run this daily, at a time you're not going to use your computer
    \\ that much. maybe 5am
    \\
    \\ usage:
    \\ 	awtfdb-metrics
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
;

const StringList = std.ArrayList([]const u8);
const Args = struct {
    help: bool = false,
    version: bool = false,
};

pub fn main() anyerror!u8 {
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

    var given_args = Args{};
    //var state: enum { None } = .None;

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            return error.InvalidArgument;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return 1;
    } else if (given_args.version) {
        std.debug.print("awtfdb-metrics {s}\n", .{VERSION});
        return 1;
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

    const metrics_timestamp = std.time.timestamp();
    log.info("running metrics queries at timestamp {d}", .{metrics_timestamp});

    const file_count = (try ctx.db.?.one(i64, "select count(*) from files", .{}, .{})).?;
    log.info("{d} files", .{file_count});
    const tag_core_count = (try ctx.db.?.one(i64, "select count(*) from tag_cores", .{}, .{})).?;
    log.info("{d} tag_cores", .{tag_core_count});
    const tag_name_count = (try ctx.db.?.one(i64, "select count(*) from tag_names", .{}, .{})).?;
    log.info("{d} tag_names", .{tag_name_count});

    return 0;
}
