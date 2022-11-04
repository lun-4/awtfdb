const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const Context = manage_main.Context;

const logger = std.log.scoped(.awtfdb_janitor);

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
    full: bool = false,
};

const METRICS_COUNT_TABLES = .{ "metrics_count_files", "metrics_count_tag_cores", "metrics_count_tag_names" };

fn runMetricsCounter(
    ctx: *Context,
    metrics_timestamp: i64,
    comptime input_table: []const u8,
    comptime output_metrics_table: []const u8,
) !void {
    const row_count = (try ctx.db.?.one(i64, "select count(*) from " ++ input_table, .{}, .{})).?;
    logger.info("{d} rows in table '{s}'", .{ row_count, input_table });

    try ctx.db.?.exec(
        "insert into " ++ output_metrics_table ++ " (timestamp, value) values (?, ?)",
        .{},
        .{ metrics_timestamp, row_count },
    );
}

pub const log_level = .debug;
pub var current_log_level: std.log.Level = .info;
pub const log = manage_main.log;

pub fn main() anyerror!u8 {
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

    var given_args = Args{};
    //var state: enum { None } = .None;

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            current_log_level = .debug;
        } else if (std.mem.eql(u8, arg, "--full")) {
            given_args.full = true;
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
    logger.info("running metrics queries at timestamp {d}", .{metrics_timestamp});

    // execute inserts here
    {
        var savepoint = try ctx.db.?.savepoint("metrics");
        errdefer savepoint.rollback();
        defer savepoint.commit();

        try runAllMetricsCounters(given_args, &ctx, metrics_timestamp);
    }

    return 0;
}

const TagUsageResult = struct {
    core_hash: i64,
    relationship_count: i64,
};

const TagUsageInputChannel = std.event.Channel(i64);
const TagUsageResultChannel = std.event.Channel(TagUsageResult);

fn runMetricsTagUsageSingleCore(
    tag_files_stmt: *sqlite.DynamicStatement,
    core_hash: i64,
) callconv(.Async) anyerror!i64 {
    suspend {}

    var timer = try std.time.Timer.start();

    const tag_files_count = (try tag_files_stmt.one(i64, .{}, .{core_hash})).?;
    tag_files_stmt.reset();

    const core_count_time_taken_ns = timer.lap();
    logger.info(
        "core {d} has {d} files (took {:.2}ms)",
        .{ core_hash, tag_files_count, core_count_time_taken_ns / std.time.ns_per_ms },
    );

    return tag_files_count;
}

fn runMetricsTagUsage(ctx: *Context, metrics_timestamp: i64) !void {
    try ctx.db.?.exec(
        "insert into metrics_tag_usage_timestamps (timestamp) values (?)",
        .{},
        .{metrics_timestamp},
    );

    // for every tag core, run count(*) over tag_files

    var stmt = try ctx.db.?.prepare(
        \\ select distinct tag_names.core_hash,
        \\   (select count(*) from tag_files where core_hash = tag_names.core_hash) AS relationship_count
        \\ from tag_names;
    );
    defer stmt.deinit();

    var it = try stmt.iterator(struct { core_hash: i64, relationship_count: i64 }, .{});
    var timer = try std.time.Timer.start();
    while (try it.next(.{})) |row| {
        const exec_time_ns = timer.lap();
        logger.info("{} took {:.2}ms to fetch", .{ row, exec_time_ns / std.time.ns_per_ms });

        try ctx.db.?.exec(
            "insert into metrics_tag_usage_values (timestamp, core_hash, relationship_count) values (?, ?, ?)",
            .{},
            .{ metrics_timestamp, row.core_hash, row.relationship_count },
        );
    }
}

fn runTagSourceCounters(ctx: *Context, metrics_timestamp: i64) !void {
    var stmt = try ctx.db.?.prepare(
        \\ select distinct type, id,
        \\  (select count(*) from tag_files where tag_source_type  = tag_sources.type and tag_source_id=tag_sources.id) AS relationship_count
        \\  from tag_sources;
    );
    defer stmt.deinit();

    var it = try stmt.iterator(struct {
        tag_source_type: i64,
        tag_source_id: i64,
        relationship_count: i64,
    }, .{});
    var timer = try std.time.Timer.start();
    while (try it.next(.{})) |row| {
        const exec_time_ns = timer.lap();
        logger.info("{} took {:.2}ms to fetch", .{ row, exec_time_ns / std.time.ns_per_ms });

        try ctx.db.?.exec(
            "insert into metrics_tag_source_usage (timestamp, tag_source_type, tag_source_id, relationship_count) values (?, ?, ?, ?)",
            .{},
            .{ metrics_timestamp, row.tag_source_type, row.tag_source_id, row.relationship_count },
        );
    }
}

fn runAllMetricsCounters(given_args: Args, ctx: *Context, metrics_timestamp: i64) !void {
    try runMetricsCounter(ctx, metrics_timestamp, "files", "metrics_count_files");
    try runMetricsCounter(ctx, metrics_timestamp, "tag_cores", "metrics_count_tag_cores");
    try runMetricsCounter(ctx, metrics_timestamp, "tag_names", "metrics_count_tag_names");
    try runMetricsCounter(ctx, metrics_timestamp, "tag_files", "metrics_count_tag_files");
    try runTagSourceCounters(ctx, metrics_timestamp);
    if (given_args.full) {
        try runMetricsTagUsage(ctx, metrics_timestamp);
    }
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
    try runAllMetricsCounters(.{}, &ctx, std.time.timestamp());

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

    try indexed_file1.addTag(tag1.core, .{});
    try indexed_file1.addTag(tag_named1.core, .{}); // should be a noop in db terms
    try indexed_file2.addTag(tag1.core, .{});
    try indexed_file3.addTag(tag1.core, .{});
    try indexed_file2.addTag(tag2.core, .{});
    try indexed_file2.addTag(tag3.core, .{});
    try indexed_file3.addTag(tag3.core, .{});

    // run metrics code
    try runAllMetricsCounters(.{ .full = true }, &ctx, std.time.timestamp());

    // fact on this test: there are 6 file<->tag relations
    const last_metrics_tag_file = (try ctx.db.?.one(i64, "select value from metrics_count_tag_files", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 6), last_metrics_tag_file);

    // fact on this test: there are 3 files
    const last_metrics_file = (try ctx.db.?.one(i64, "select value from metrics_count_files", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 3), last_metrics_file);

    // fact on this test:
    // 	tag1 has 3 relationships,
    // 	tag2 has 1 relationship,
    // 	tag3 has 2 relationships

    const last_metrics_tag_usage_timestamp = (try ctx.db.?.one(i64, "select timestamp from metrics_tag_usage_timestamps", .{}, .{})).?;

    var metrics_tag_usage_values_stmt = try ctx.db.?.prepare(
        \\ select core_hash, relationship_count
        \\ from metrics_tag_usage_values
        \\ where timestamp = ?
    );
    defer metrics_tag_usage_values_stmt.deinit();

    var it = try metrics_tag_usage_values_stmt.iterator(
        struct { core_hash: i64, relationship_count: usize },
        .{last_metrics_tag_usage_timestamp},
    );

    var checked_count: usize = 0;

    while (try it.next(.{})) |row| {
        checked_count += 1;
        if (row.core_hash == tag1.core.id)
            try std.testing.expectEqual(@as(usize, 3), row.relationship_count)
        else if (row.core_hash == tag2.core.id)
            try std.testing.expectEqual(@as(usize, 1), row.relationship_count)
        else if (row.core_hash == tag3.core.id)
            try std.testing.expectEqual(@as(usize, 2), row.relationship_count)
        else
            return error.InvalidCoreHashFound;
    }

    try std.testing.expectEqual(@as(usize, 3), checked_count);

    // fact on this test
    // source type=0 and id=0 has 6 relationships

    const source_usage = try ctx.db.?.one(i64,
        \\ select relationship_count
        \\ from metrics_tag_source_usage
        \\ where timestamp = ? and tag_source_type = 0 and tag_source_id = 0
    , .{}, .{last_metrics_tag_usage_timestamp});

    try std.testing.expectEqual(@as(?i64, 6), source_usage);
}
