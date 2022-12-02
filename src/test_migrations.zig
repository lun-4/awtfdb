const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("./main.zig");
const AnimeSnowflake = @import("./snowflake.zig").AnimeSnowflake;

const Context = manage_main.Context;
const Migration = manage_main.Migration;

const logger = std.log.scoped(.migration_tests);

var set_log = false;

/// Make test context without any migrations loaded for proper testing.
///
/// Inspired by manage_main.makeTestContext
pub fn makeTestContext() !Context {
    if (!set_log) {
        _ = sqlite.c.sqlite3_shutdown();

        const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, manage_main.sqliteLog, @as(?*anyopaque, null));
        set_log = true;
        if (rc != sqlite.c.SQLITE_OK) {
            logger.err("failed to configure ({}): {d} '{s}'", .{
                set_log, rc, sqlite.c.sqlite3_errstr(rc),
            });
            return error.ConfigFail;
        }
        _ = sqlite.c.sqlite3_initialize();
    }
    const homepath = try std.fs.cwd().realpath(".", &manage_main.test_db_path_buffer);
    var ctx = Context{
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = std.testing.allocator,
        .home_path = homepath,
        .db_path = null,
    };

    ctx.db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .Memory = {} },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });

    try ctx.loadDatabase(.{ .create = true });
    return ctx;
}

// Inspired by loadMigration
fn loadSingleMigration(ctx: *Context, comptime index: usize) !void {
    try ctx.loadDatabase(.{});
    try ctx.db.?.exec(manage_main.MIGRATION_LOG_TABLE, .{}, .{});

    const current_version: i32 = (try ctx.db.?.one(i32, "select max(version) from migration_logs", .{}, .{})) orelse 0;
    logger.info("db version: {d}", .{current_version});

    var savepoint = try ctx.db.?.savepoint("migrations");
    errdefer savepoint.rollback();
    defer savepoint.commit();

    var run: bool = false;

    inline for (manage_main.MIGRATIONS) |migration_decl| {
        const migration = Migration.fromTuple(migration_decl);

        if (index == migration.version) {
            run = true;
            if (migration.sql) |migration_sql| {
                logger.info("running migration {d} '{s}'", .{ migration.version, migration.name });
                var diags = sqlite.Diagnostics{};
                ctx.db.?.execMulti(migration_sql, .{ .diags = &diags }) catch |err| {
                    logger.err("unable to prepare statement, got error {s}. diagnostics: {s}", .{ @errorName(err), diags });
                    return err;
                };
            } else {
                try migration.options.function.?(ctx);
            }

            try ctx.db.?.exec(
                "INSERT INTO migration_logs (version, applied_at, description) values (?, ?, ?);",
                .{},
                .{
                    .version = migration.version,
                    .applied_at = std.time.timestamp(),
                    .description = migration.name,
                },
            );
        }
    }
}

test "single migration test" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    try loadSingleMigration(&ctx, 1);
    const count = try ctx.db.?.one(i64, "select count(*) from hashes", .{}, .{});
    try std.testing.expectEqual(@as(?i64, 0), count);
}

test "validate migration 2 works" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    try loadSingleMigration(&ctx, 1);
    try ctx.db.?.execMulti(
        \\ insert into hashes (id, hash_data) values (1, X'7cecc98d9dc7503dcdad71adbbdf45d06667fd38c386f5d37489ea2c24d7a4dc');
        \\ insert into files (file_hash, local_path) values (1, '/test.file');
    , .{});
    try loadSingleMigration(&ctx, 2);
    const file_hash = try ctx.db.?.one(i64, "select file_hash from files where local_path = '/test.file'", .{}, .{});
    try std.testing.expectEqual(@as(?i64, 1), file_hash);
}

fn loadMigrationUpTo(ctx: *Context, comptime upper_index: usize) !void {
    try ctx.loadDatabase(.{});
    try ctx.db.?.exec(manage_main.MIGRATION_LOG_TABLE, .{}, .{});

    const current_version: i32 = (try ctx.db.?.one(i32, "select max(version) from migration_logs", .{}, .{})) orelse 0;
    logger.info("db version: {d}", .{current_version});

    var savepoint = try ctx.db.?.savepoint("migrations");
    errdefer savepoint.rollback();
    defer savepoint.commit();

    var run: bool = false;

    inline for (manage_main.MIGRATIONS) |migration_decl| {
        const migration = Migration.fromTuple(migration_decl);

        if (migration.version < upper_index) {
            run = true;

            if (migration.sql) |migration_sql| {
                logger.info("running migration {d} '{s}'", .{ migration.version, migration.name });
                var diags = sqlite.Diagnostics{};
                ctx.db.?.execMulti(migration_sql, .{ .diags = &diags }) catch |err| {
                    logger.err("unable to prepare statement, got error {s}. diagnostics: {s}", .{ @errorName(err), diags });
                    return err;
                };
            } else {
                try migration.options.function.?(ctx);
            }

            try ctx.db.?.exec(
                "INSERT INTO migration_logs (version, applied_at, description) values (?, ?, ?);",
                .{},
                .{
                    .version = migration.version,
                    .applied_at = std.time.timestamp(),
                    .description = migration.name,
                },
            );
        }
    }
}

test "validate snowflake migration works" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    const file_realpath = try tmp.dir.realpathAlloc(ctx.allocator, "test_file");
    defer ctx.allocator.free(file_realpath);

    const stat = try tmp.dir.statFile("test_file");

    const query = try std.fmt.allocPrint(ctx.allocator,
        \\insert into hashes (id, hash_data) values (1, X'7cecc98d9dc7503dcdad71adbbdf45d06667fd38c386f5d37489ea2c24d7a4dc');
        \\insert into files (file_hash, local_path) values (1, '{s}');
    , .{file_realpath});
    defer ctx.allocator.free(query);
    const query_cstr = try std.cstr.addNullByte(ctx.allocator, query);
    defer ctx.allocator.free(query_cstr);
    std.log.warn("query={s}", .{query});

    try loadMigrationUpTo(&ctx, 7);
    var diags = sqlite.Diagnostics{};
    logger.warn("error before exec={s}", .{diags.message});
    ctx.db.?.execMulti(query_cstr, .{ .diags = &diags }) catch |err| {
        logger.warn("err={s}", .{diags});
        return err;
    };

    try loadSingleMigration(&ctx, 8);
    const file_hash = try ctx.db.?.one(i64, "select file_hash from files where local_path = ?", .{}, .{file_realpath});
    try std.testing.expect(file_hash != @as(i64, 1));
    const snowflake = AnimeSnowflake{ .value = @intCast(u63, file_hash.?) };
    try std.testing.expect(snowflake.fields.timestamp > 0);
    try std.testing.expectEqual(stat.ctime, snowflake.fields.timestamp);
}
