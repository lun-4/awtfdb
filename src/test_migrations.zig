const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("./main.zig");
const AnimeSnowflake = @import("./snowflake.zig").AnimeSnowflake;
const ulid = @import("ulid");

const Context = manage_main.Context;
const Migration = manage_main.Migration;

const logger = std.log.scoped(.migration_tests);

pub fn makeTestContext() !Context {
    return manage_main.makeTestContextWithOptions(.{ .load_migrations = false });
}

/// Create a test context backed up by a real file, rather than memory.
pub fn makeTestContextRealFile() !Context {
    return manage_main.makeTestContextRealFileWithOptions(.{ .load_migrations = false });
}

// Inspired by loadMigration
fn loadSingleMigration(ctx: *Context, comptime index: usize) !void {
    try ctx.db.exec(manage_main.MIGRATION_LOG_TABLE, .{}, .{});

    const current_version: i32 = (try ctx.db.one(i32, "select max(version) from migration_logs", .{}, .{})) orelse 0;
    logger.info("db version: {d}", .{current_version});

    var savepoint = try ctx.db.savepoint("migrations");
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
                ctx.db.execMulti(migration_sql, .{ .diags = &diags }) catch |err| {
                    logger.err("unable to prepare statement, got error {s}. diagnostics: {s}", .{ @errorName(err), diags });
                    return err;
                };
            } else {
                try migration.options.function.?(ctx);
            }

            try ctx.db.exec(
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
    const count = try ctx.db.one(usize, "select count(*) from hashes", .{}, .{});
    try std.testing.expectEqual(@as(?usize, 0), count);
}

test "validate migration 2 works" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    try loadSingleMigration(&ctx, 1);
    try ctx.db.execMulti(
        \\ insert into hashes (id, hash_data) values (1, X'7cecc98d9dc7503dcdad71adbbdf45d06667fd38c386f5d37489ea2c24d7a4dc');
        \\ insert into files (file_hash, local_path) values (1, '/test.file');
    , .{});
    try loadSingleMigration(&ctx, 2);
    const file_hash = try ctx.db.one(i64, "select file_hash from files where local_path = '/test.file'", .{}, .{});
    try std.testing.expectEqual(@as(?i64, 1), file_hash);
}

fn loadMigrationUpTo(ctx: *Context, comptime upper_index: usize) !void {
    try ctx.db.exec(manage_main.MIGRATION_LOG_TABLE, .{}, .{});

    const current_version: i32 = (try ctx.db.one(i32, "select max(version) from migration_logs", .{}, .{})) orelse 0;
    logger.info("db version: {d}", .{current_version});

    var savepoint = try ctx.db.savepoint("migrations");
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
                ctx.db.execMulti(migration_sql, .{ .diags = &diags }) catch |err| {
                    logger.err("unable to prepare statement, got error {s}. diagnostics: {s}", .{ @errorName(err), diags });
                    return err;
                };
            } else {
                try migration.options.function.?(ctx);
            }

            try ctx.db.exec(
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
    var ctx = try makeTestContextRealFile();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var file2 = try tmp.dir.createFile("test_file2", .{});
    defer file2.close();
    _ = try file2.write("awooga3");

    var file3 = try tmp.dir.createFile("test_file3", .{});
    defer file3.close();
    _ = try file3.write("awooga3");

    const file_realpath = try tmp.dir.realpathAlloc(ctx.allocator, "test_file");
    defer ctx.allocator.free(file_realpath);

    const file2_realpath = try tmp.dir.realpathAlloc(ctx.allocator, "test_file2");
    defer ctx.allocator.free(file2_realpath);

    const file3_realpath = try tmp.dir.realpathAlloc(ctx.allocator, "test_file3");
    defer ctx.allocator.free(file3_realpath);

    const stat = try tmp.dir.statFile("test_file");
    const stat3 = try tmp.dir.statFile("test_file3");

    const AMOGUS = "424242424269696969420420420420";
    const AMOGUS2 = "420696969696942042069696969696";

    const query = try std.fmt.allocPrint(ctx.allocator,
        \\insert into hashes (id, hash_data) values (1, X'7cecc98d9dc7503dcdad71adbbdf45d06667fd38c386f5d37489ea2c24d7a4dc');
        \\insert into hashes (id, hash_data) values (2, X'39f2c50b236858c0e4a536f0c1de75acb2a2dd709958b05bb511667a818da73a');
        \\insert into hashes (id, hash_data) values (3, X'f45d9c5ac7426d38c89f49ef4f6cb0f69ca58f968d03eb6a81b5c6eeb5ac7d03');
        \\insert into hashes (id, hash_data) values (4, X'c3ef18ab3140c21152699955202659b5ad79ab48452ec554e8d4401f72f4cdb5');
        \\insert into hashes (id, hash_data) values (5, X'8ac1f7439d2de6eb4b48eddfc680cab6d79fd4dde30f834f66ac7b823a9c6a9c');
        \\insert into files (file_hash, local_path) values (1, '{s}');
        \\insert into files (file_hash, local_path) values (1, '{s}');
        \\insert into files (file_hash, local_path) values (2, '{s}');
        \\insert into tag_cores (core_hash, core_data) values (3, x'{s}');
        \\insert into tag_names (core_hash, tag_text, tag_language) values (3, 'amongus', 'en');
        \\insert into tag_cores (core_hash, core_data) values (4, x'{s}');
        \\insert into tag_names (core_hash, tag_text, tag_language) values (4, 'amongus2', 'en');
        \\insert into tag_files (file_hash, core_hash) values (1, 3);
        \\insert into tag_files (file_hash, core_hash) values (2, 3);
        \\insert into tag_implications (rowid, parent_tag, child_tag) values (1, 3, 4);
        \\insert into tag_files (file_hash, core_hash, parent_source_id) values (1, 4, 1);
        \\insert into tag_files (file_hash, core_hash, parent_source_id) values (2, 4, 1);
        \\insert into pools (pool_hash, pool_core_data, title) values (5, X'c840ae7bc4a42b59c65abcba425595e2e758f89a0ea654ea7e1c87a4162afd90c840ae7bc4a42b59c65abcba425595e2e758f89a0ea654ea7e1c87a4162afd90', 'among us chronicles');
        \\insert into pool_entries (file_hash, pool_hash, entry_index) values (1, 5, 0);
        \\insert into pool_entries (file_hash, pool_hash, entry_index) values (2, 5, 1);
        \\insert into metrics_tag_usage_timestamps (timestamp) values (0);
        \\insert into metrics_tag_usage_values (timestamp, core_hash, relationship_count) values (0, 3, 2);
        \\insert into metrics_tag_usage_values (timestamp, core_hash, relationship_count) values (0, 4, 2);
    , .{ file_realpath, file2_realpath, file3_realpath, AMOGUS, AMOGUS2 });
    defer ctx.allocator.free(query);
    const query_cstr = try std.cstr.addNullByte(ctx.allocator, query);
    defer ctx.allocator.free(query_cstr);
    std.log.warn("query={s}", .{query});

    try loadMigrationUpTo(&ctx, 7);
    var diags = sqlite.Diagnostics{};
    logger.warn("error before exec={s}", .{diags.message});
    ctx.db.execMulti(query_cstr, .{ .diags = &diags }) catch |err| {
        logger.warn("err={s}", .{diags});
        return err;
    };

    try loadSingleMigration(&ctx, 8);

    const file_hash = (try ctx.db.one([26]u8, "select file_hash from files where local_path = ?", .{}, .{file_realpath})).?;
    const new_file_hash = try ulid.ULID.parse(&file_hash);
    try std.testing.expectEqual(@divTrunc(stat.mtime, std.time.ns_per_ms), new_file_hash.timestamp);

    const file2_hash = (try ctx.db.one([26]u8, "select file_hash from files where local_path = ?", .{}, .{file2_realpath})).?;
    try std.testing.expectEqualSlices(u8, &file_hash, &file2_hash);

    const file3_hash = (try ctx.db.one([26]u8, "select file_hash from files where local_path = ?", .{}, .{file3_realpath})).?;
    const new_file3_hash = try ulid.ULID.parse(&file3_hash);
    try std.testing.expectEqual(@divTrunc(stat3.mtime, std.time.ns_per_ms), new_file3_hash.timestamp);

    const core_hash = (try ctx.db.one(
        [26]u8,
        "select core_hash from tag_cores where hex(core_data) = ?",
        .{},
        .{sqlite.Text{ .data = AMOGUS }},
    )).?;
    const new_core_hash = try ulid.ULID.parse(&core_hash);
    try std.testing.expect(new_core_hash.timestamp > 1000);

    const name_data = (try ctx.db.oneAlloc(
        []const u8,
        ctx.allocator,
        "select tag_text from tag_names where core_hash = ?",
        .{},
        .{manage_main.ID.ul(new_core_hash).sql()},
    )).?;
    defer ctx.allocator.free(name_data);
    try std.testing.expectEqualStrings("amongus", name_data);

    const tagfile_count = (try ctx.db.one(
        usize,
        "select count(*) from tag_files where core_hash = ?",
        .{},
        .{manage_main.ID.ul(new_core_hash).sql()},
    )).?;
    try std.testing.expectEqual(@as(usize, 2), tagfile_count);
}
