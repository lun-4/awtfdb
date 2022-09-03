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

const METRICS_COUNT_TABLES = .{ "metrics_count_files", "metrics_count_tag_cores", "metrics_count_tag_names" };

fn maybeInsertFirstRow(ctx: *Context) !void {
    const db_creation_timestamp =
        (try ctx.db.?.one(i64, "select applied_at from migration_logs where version=1", .{}, .{})).?;

    inline for (METRICS_COUNT_TABLES) |count_table| {
        const count_rows = (try ctx.db.?.one(i64, "select count(*) from " ++ count_table, .{}, .{})).?;
        if (count_rows == 0) {
            try ctx.db.?.exec(
                "insert into " ++ count_table ++ " (timestamp, value) values (?, ?)",
                .{},
                .{ db_creation_timestamp, 0 },
            );
        }
    }
}

fn runMetricsCounter(
    ctx: *Context,
    metrics_timestamp: i64,
    comptime input_table: []const u8,
    comptime output_metrics_table: []const u8,
) !void {
    const row_count = (try ctx.db.?.one(i64, "select count(*) from " ++ input_table, .{}, .{})).?;
    log.info("{d} rows in table '{s}'", .{ row_count, input_table });

    try ctx.db.?.exec(
        "insert into " ++ output_metrics_table ++ " (timestamp, value) values (?, ?)",
        .{},
        .{ metrics_timestamp, row_count },
    );
}

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

    // if metrics tables are count 0, insert first row:
    // timestamp = db creation (migration 0), count 0

    const metrics_timestamp = std.time.timestamp();
    log.info("running metrics queries at timestamp {d}", .{metrics_timestamp});

    // execute inserts here
    {
        var savepoint = try ctx.db.?.savepoint("metrics");
        errdefer savepoint.rollback();
        defer savepoint.commit();

        try maybeInsertFirstRow(&ctx);
        try runAllMetricsCounters(&ctx, metrics_timestamp);
    }

    return 0;
}

fn runAllMetricsCounters(ctx: *Context, metrics_timestamp: i64) !void {
    try runMetricsCounter(ctx, metrics_timestamp, "files", "metrics_count_files");
    try runMetricsCounter(ctx, metrics_timestamp, "tag_cores", "metrics_count_tag_cores");
    try runMetricsCounter(ctx, metrics_timestamp, "tag_names", "metrics_count_tag_names");
    try runMetricsCounter(ctx, metrics_timestamp, "tag_files", "metrics_count_tag_files");
}

test "metrics (tags)" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tag1 = try ctx.createNamedTag("test_tag1", "en", null);
    var tag2 = try ctx.createNamedTag("test_tag2", "en", null);
    _ = tag2;
    var tag3 = try ctx.createNamedTag("test_tag3", "en", null);
    _ = tag3;
    var tag_named1 = try ctx.createNamedTag("test_tag1_samecore", "en", tag1.core);
    _ = tag_named1;

    // run metrics code
    try runAllMetricsCounters(&ctx, 0);

    // fact on this test: names > cores

    const last_metrics_tag_core = (try ctx.db.?.one(i64, "select value from metrics_count_tag_cores", .{}, .{})).?;
    const last_metrics_tag_name = (try ctx.db.?.one(i64, "select value from metrics_count_tag_names", .{}, .{})).?;

    try std.testing.expect(last_metrics_tag_name > last_metrics_tag_core);
}

test "metrics (tags and files)" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    // setup tags

    var tag1 = try ctx.createNamedTag("test_tag1", "en", null);
    var tag2 = try ctx.createNamedTag("test_tag2", "en", null);
    var tag3 = try ctx.createNamedTag("test_tag3", "en", null);
    var tag_named1 = try ctx.createNamedTag("test_tag1_samecore", "en", tag1.core);

    // setup files

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file1 = try tmp.dir.createFile("test_file1", .{});
    defer file1.close();
    _ = try file1.write("awooga1");

    var file2 = try tmp.dir.createFile("test_file2", .{});
    defer file2.close();
    _ = try file2.write("awooga2");

    var file3 = try tmp.dir.createFile("test_file3", .{});
    defer file3.close();
    _ = try file3.write("awooga3");

    var indexed_file1 = try ctx.createFileFromDir(tmp.dir, "test_file1");
    defer indexed_file1.deinit();
    var indexed_file2 = try ctx.createFileFromDir(tmp.dir, "test_file2");
    defer indexed_file2.deinit();
    var indexed_file3 = try ctx.createFileFromDir(tmp.dir, "test_file3");
    defer indexed_file3.deinit();

    // setup tag links

    try indexed_file1.addTag(tag1.core);
    try indexed_file1.addTag(tag_named1.core); // should be a noop in db terms
    try indexed_file2.addTag(tag1.core);
    try indexed_file3.addTag(tag1.core);
    try indexed_file2.addTag(tag2.core);
    try indexed_file2.addTag(tag3.core);
    try indexed_file3.addTag(tag3.core);

    // run metrics code
    try runAllMetricsCounters(&ctx, 0);

    // fact on this test: there are 6 file<->tag relations
    const last_metrics_tag_file = (try ctx.db.?.one(i64, "select value from metrics_count_tag_files", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 6), last_metrics_tag_file);

    // fact on this test: there are 3 files
    const last_metrics_file = (try ctx.db.?.one(i64, "select value from metrics_count_files", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 3), last_metrics_file);
}
