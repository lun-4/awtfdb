const std = @import("std");
const sqlite = @import("sqlite");
const ulid = @import("ulid");
const main = @import("main.zig");

const Context = main.Context;
const ID = main.ID;
const logger = main.logger;

fn generateSqlReadonly(comptime table: []const u8) []const u8 {
    comptime var result: []const u8 = undefined;
    comptime var buffer: [8192]u8 = undefined;
    comptime {
        result = std.fmt.bufPrint(&buffer,
            \\ CREATE TRIGGER IF NOT EXISTS {s}_readonly_update
            \\ BEFORE UPDATE ON {s}
            \\ BEGIN
            \\     SELECT raise(abort, 'this is a software bug, use {s}_v2 table');
            \\ END;
            \\
            \\ CREATE TRIGGER IF NOT EXISTS {s}_readonly_insert
            \\ BEFORE INSERT ON {s}
            \\ BEGIN
            \\     SELECT raise(abort, 'this is a software bug, use {s}_v2 table');
            \\ END;
            \\
            \\ CREATE TRIGGER IF NOT EXISTS {s}_readonly_delete
            \\ BEFORE DELETE ON {s}
            \\ BEGIN
            \\     SELECT raise(abort, 'this is a software bug, use {s}_v2 table');
            \\ END;
        , .{table} ** 9) catch unreachable;
    }
    return result;
}

fn assertSameCount(self: *Context, comptime table1: []const u8, comptime table2: []const u8) !void {
    const table1_count = try self.db.one(usize, "select count(*) from " ++ table1, .{}, .{});
    const table2_count = try self.db.one(usize, "select count(*) from " ++ table2, .{}, .{});
    try std.testing.expectEqual(table1_count, table2_count);
}

fn migrateFiles(self: *Context) !void {
    var stmt = try self.db.prepare(
        \\ select file_hash, local_path, hashes.hash_data from files
        \\ join hashes on files.file_hash = hashes.id
    );
    defer stmt.deinit();

    var rng = std.rand.DefaultPrng.init(
        @truncate(u64, @intCast(u128, std.time.nanoTimestamp())),
    );
    const random = rng.random();

    var it = try stmt.iterator(struct {
        file_hash: i64,
        local_path: []const u8,
        hash_data: sqlite.Blob,
    }, .{});
    logger.info("migrating files...", .{});
    while (try it.nextAlloc(self.allocator, .{})) |data| {
        defer self.allocator.free(data.local_path);
        defer self.allocator.free(data.hash_data.data);

        const maybe_existing_hash = try self.db.one(
            ID.SQL,
            "select id from hashes_v2 where hash_data = ?",
            .{},
            .{data.hash_data},
        );

        logger.warn("file {d} {s}", .{ data.file_hash, data.local_path });
        if (maybe_existing_hash) |existing_hash| {
            logger.warn("existing as {s} {s}", .{ existing_hash, data.local_path });

            const existing_id = ID.new(existing_hash);
            try self.db.exec(
                "insert into files_v2 (file_hash, local_path) VALUES (?, ?)",
                .{},
                .{ existing_id.sql(), data.local_path },
            );
        } else {
            const stat = try std.fs.cwd().statFile(data.local_path);
            const timestamp_as_milliseconds = @divTrunc(stat.mtime, std.time.ns_per_ms);
            const new_ulid = main.ulidFromTimestamp(random, timestamp_as_milliseconds);
            const new_id = ID.new(new_ulid.bytes());
            const parsed_ulid = try ulid.ULID.parse(new_id.str());
            try std.testing.expectEqual(new_ulid.timestamp, parsed_ulid.timestamp);

            logger.warn("creating as {s} {s} {s}", .{ new_id, std.fmt.fmtSliceHexLower(data.hash_data.data), data.local_path });
            try self.db.exec(
                "insert into hashes_v2 (id, hash_data) VALUES (?, ?)",
                .{},
                .{ new_id.sql(), data.hash_data },
            );
            const must_exist = try self.db.one(
                ID.SQL,
                "select id from hashes_v2 where hash_data = ?",
                .{},
                .{data.hash_data},
            );
            try std.testing.expectEqualSlices(u8, new_id.str(), &(must_exist.?));
            try self.db.exec(
                "insert into files_v2 (file_hash, local_path) VALUES (?, ?)",
                .{},
                .{ new_id.sql(), data.local_path },
            );
        }
    }

    try assertSameCount(self, "files", "files_v2");
}

fn migrateCores(self: *Context) !void {
    var rng = std.rand.DefaultPrng.init(
        @truncate(u64, @intCast(u128, std.time.nanoTimestamp())),
    );
    const random = rng.random();

    var stmt_tag_cores = try self.db.prepare(
        \\ select core_hash, core_data, hashes.hash_data from tag_cores
        \\ join hashes on tag_cores.core_hash = hashes.id
        \\ order by hashes.id asc
    );
    defer stmt_tag_cores.deinit();

    const TAG_CORE_EPOCH = 1644980400 * std.time.ms_per_s;

    var it_tag_cores = try stmt_tag_cores.iterator(struct {
        core_hash: i64,
        core_data: sqlite.Blob,
        hash_data: sqlite.Blob,
    }, .{});
    logger.info("migrating tag cores...", .{});
    while (try it_tag_cores.nextAlloc(self.allocator, .{})) |data_v1| {
        logger.warn("processing tag core {d} {x} {x}", .{
            data_v1.core_hash,
            std.fmt.fmtSliceHexLower(data_v1.core_data.data),
            std.fmt.fmtSliceHexLower(data_v1.hash_data.data),
        });
        // keep them in order
        defer self.allocator.free(data_v1.core_data.data);
        defer self.allocator.free(data_v1.hash_data.data);

        const core_timestamp = TAG_CORE_EPOCH + data_v1.core_hash;

        // tag core data is unique so we do not implement UPSERT

        const new_ulid = main.ulidFromTimestamp(random, core_timestamp);
        const new_id = ID.new(new_ulid.bytes());
        const parsed_ulid = try ulid.ULID.parse(new_id.str());
        try std.testing.expectEqual(new_ulid.timestamp, parsed_ulid.timestamp);

        logger.warn("tag core creating as {s} {x}", .{ new_id, std.fmt.fmtSliceHexLower(data_v1.hash_data.data) });
        try self.db.exec(
            "insert into hashes_v2 (id, hash_data) VALUES (?, ?)",
            .{},
            .{ new_id.sql(), data_v1.hash_data },
        );
        try self.db.exec(
            "insert into tag_cores_v2 (core_hash, core_data) VALUES (?, ?)",
            .{},
            .{ new_id.sql(), data_v1.core_data },
        );
    }
    try assertSameCount(self, "tag_cores", "tag_cores_v2");
}

fn migrateTagNames(self: *Context) !void {
    var stmt_tag_names = try self.db.prepare(
        \\ select hashes_v2.id AS new_core_id, tag_language, tag_text from tag_names
        \\ join hashes on tag_names.core_hash = hashes.id
        \\ join hashes_v2 on hashes.hash_data = hashes_v2.hash_data;
    );
    defer stmt_tag_names.deinit();
    var it_tag_names = try stmt_tag_names.iterator(struct {
        new_core_id: ID.SQL,
        tag_language: []const u8,
        tag_text: []const u8,
    }, .{});
    logger.info("migrating tag names...", .{});
    while (try it_tag_names.nextAlloc(self.allocator, .{})) |row| {
        defer self.allocator.free(row.tag_language);
        defer self.allocator.free(row.tag_text);

        const new_id = ID.new(row.new_core_id);
        logger.warn("creating tag name {s} {s} {s}", .{ new_id, row.tag_language, row.tag_text });
        try self.db.exec(
            "insert into tag_names_v2 (core_hash, tag_language, tag_text) VALUES (?, ?, ?)",
            .{},
            .{ new_id.sql(), row.tag_language, row.tag_text },
        );
    }
}

fn migrateTagImplications(self: *Context) !void {
    var stmt_tag_implications = try self.db.prepare(
        \\ select rowid, child_tag, parent_tag
        \\ from tag_implications
    );
    defer stmt_tag_implications.deinit();
    var it_tag_implications = try stmt_tag_implications.iterator(struct {
        rowid: i64,
        child_tag: i64,
        parent_tag: i64,
    }, .{});
    logger.info("migrating tag_implications...", .{});
    while (try it_tag_implications.next(.{})) |row| {
        const new_child_tag = try snowflakeNewHash(self, row.child_tag);
        const new_parent_tag = try snowflakeNewHash(self, row.parent_tag);
        logger.warn("implication {d}->{d} => {}->{}", .{ row.parent_tag, row.child_tag, new_child_tag, new_parent_tag });
        try self.db.exec(
            "insert into tag_implications_v2 (rowid, child_tag, parent_tag) VALUES (?,?, ?)",
            .{},
            .{ row.rowid, new_child_tag.sql(), new_parent_tag.sql() },
        );
    }
}

fn migrateTagFiles(self: *Context) !void {
    var stmt_tag_files = try self.db.prepare(
        \\ select file_hash, core_hash, tag_source_type, tag_source_id, parent_source_id
        \\ from tag_files
    );
    defer stmt_tag_files.deinit();
    var it_tag_files = try stmt_tag_files.iterator(struct {
        file_hash: i64,
        core_hash: i64,
        tag_source_type: i64,
        tag_source_id: i64,
        parent_source_id: ?i64,
    }, .{});
    logger.info("migrating tag_files...", .{});
    while (try it_tag_files.next(.{})) |row| {
        const new_file_hash = try snowflakeNewHash(self, row.file_hash);
        const new_core_hash = try snowflakeNewHash(self, row.core_hash);

        if (row.parent_source_id) |parent_source_id| {
            // assert it exists in tag_implications_v2
            logger.warn("verify source id {d}", .{parent_source_id});
            _ = (try self.db.one(
                ID.SQL,
                "select parent_tag from tag_implications_v2 where rowid = ?",
                .{},
                .{parent_source_id},
            )) orelse {
                //               logger.warn("source id {d} does not exist anymore :(", .{});
                return error.InconsistentDatabase;
            };
        }

        logger.warn(
            "insert tag files {} {} {d} {d} {?d}",
            .{ new_file_hash, new_core_hash, row.tag_source_type, row.tag_source_id, row.parent_source_id },
        );
        try self.db.exec(
            "insert into tag_files_v2 (file_hash, core_hash, tag_source_type, tag_source_id, parent_source_id) VALUES (?, ?, ?, ?, ?)",
            .{},
            .{ new_file_hash.sql(), new_core_hash.sql(), row.tag_source_type, row.tag_source_id, row.parent_source_id },
        );
    }
}

fn migratePools(self: *Context) !void {
    var rng = std.rand.DefaultPrng.init(@truncate(u64, @intCast(u128, std.time.nanoTimestamp())));
    const random = rng.random();

    var stmt = try self.db.prepare(
        \\ select pool_hash, hashes.hash_data, pool_core_data, title
        \\ from pools
        \\ join hashes on hashes.id = pool_hash
    );
    defer stmt.deinit();

    const POOL_CORE_EPOCH = 1658545200 * std.time.ms_per_s;

    var it = try stmt.iterator(struct {
        pool_hash: i64,
        hash_data: sqlite.Blob,
        pool_core_data: sqlite.Blob,
        title: []const u8,
    }, .{});
    while (try it.nextAlloc(self.allocator, .{})) |row| {
        logger.warn("process pool {d} {x} {s}", .{
            row.pool_hash,
            std.fmt.fmtSliceHexLower(row.pool_core_data.data),
            row.title,
        });

        defer self.allocator.free(row.hash_data.data);
        defer self.allocator.free(row.pool_core_data.data);
        defer self.allocator.free(row.title);

        const timestamp = POOL_CORE_EPOCH + row.pool_hash;

        // core data is unique so we do not implement UPSERT

        const new_ulid = main.ulidFromTimestamp(random, timestamp);
        const new_id = ID.ul(new_ulid);
        // TODO move this to ulid test
        const parsed_ulid = try ulid.ULID.parse(new_id.str());
        try std.testing.expectEqual(new_ulid.timestamp, parsed_ulid.timestamp);

        logger.warn("pool creating as {s} {s} {x}", .{ row.title, new_id, std.fmt.fmtSliceHexLower(row.hash_data.data) });
        try self.db.exec(
            "insert into hashes_v2 (id, hash_data) VALUES (?, ?)",
            .{},
            .{ new_id.sql(), row.hash_data },
        );
        try self.db.exec(
            "insert into pools_v2 (pool_hash, pool_core_data, title) VALUES (?, ?, ?)",
            .{},
            .{ new_id.sql(), row.pool_core_data, row.title },
        );
    }
}

fn migratePoolEntries(self: *Context) !void {
    var stmt = try self.db.prepare(
        \\ select file_hash, pool_hash, entry_index
        \\ from pool_entries
    );
    defer stmt.deinit();

    var it = try stmt.iterator(struct {
        file_hash: i64,
        pool_hash: i64,
        entry_index: i64,
    }, .{});
    while (try it.nextAlloc(self.allocator, .{})) |row| {
        const new_file_hash = try snowflakeNewHash(self, row.file_hash);
        const new_pool_hash = try snowflakeNewHash(self, row.pool_hash);

        const args = .{ new_file_hash.sql(), new_pool_hash.sql(), row.entry_index };
        logger.warn("creating pool entry {} {} {d}", args);
        try self.db.exec(
            "insert into pool_entries_v2 (file_hash,pool_hash,entry_index) VALUES (?, ?, ?)",
            .{},
            args,
        );
    }
}

fn migrateTagUsageCounts(self: *Context) !void {
    var stmt = try self.db.prepare(
        \\ select timestamp, core_hash, relationship_count
        \\ from metrics_tag_usage_values
    );
    defer stmt.deinit();

    var it = try stmt.iterator(struct {
        timestamp: i64,
        core_hash: i64,
        relationship_count: i64,
    }, .{});
    while (try it.nextAlloc(self.allocator, .{})) |row| {
        const new_core_hash = snowflakeNewHash(self, row.core_hash) catch |err| switch (err) {
            error.TargetHashNotFound => {
                logger.warn("target not found for {d}, ignoring metrics for it", .{row.core_hash});
                continue;
            },
            else => return err,
        };

        logger.warn("creating metrics entry {d} {} {d}", .{ row.timestamp, new_core_hash, row.relationship_count });
        try self.db.exec(
            "insert into metrics_tag_usage_values_v2 (timestamp, core_hash, relationship_count) VALUES (?, ?, ?)",
            .{},
            .{ row.timestamp, new_core_hash.sql(), row.relationship_count },
        );
    }
}

fn lockTable(self: *Context, comptime old_table: []const u8) !void {
    const renamed_table = old_table ++ "_v1";
    const query = "ALTER TABLE " ++ old_table ++ " RENAME TO " ++ renamed_table ++ ";" ++ comptime generateSqlReadonly(renamed_table);
    //logger.warn("readonly table query {s}", .{query});
    try self.db.exec(query, .{}, .{});
}

fn renameToOriginal(self: *Context, comptime table: []const u8) !void {
    const query = "ALTER TABLE " ++ table ++ "_v2 RENAME TO " ++ table ++ ";";
    try self.db.exec(query, .{}, .{});
}

fn migrateSingleTable(
    self: *Context,
    comptime old_table: []const u8,
    comptime new_table: []const u8,
    function: *const fn (*Context) anyerror!void,
) !void {
    logger.warn("migrating {s} to {s}...", .{ old_table, new_table });
    try function(self);
    if (!std.mem.eql(u8, old_table, "metrics_tag_usage_values")) {
        try assertSameCount(self, old_table, new_table);
    }
    try lockTable(self, old_table);
}

pub fn migrate(self: *Context) !void {
    logger.info("this migration may take a while!", .{});

    var diags = sqlite.Diagnostics{};

    self.db.execMulti(
        \\ CREATE TABLE IF NOT EXISTS hashes_v2 (
        \\     id text primary key,
        \\     hash_data blob
        \\        constraint hashes_length check (length(hash_data) == 32)
        \\        constraint hashes_unique unique
        \\ ) without rowid, strict;
        \\
        \\ CREATE TABLE IF NOT EXISTS files_v2 (
        \\     file_hash text
        \\        constraint files_v2_file_hash_fk references hashes_v2 (id) on delete restrict,
        \\     local_path text not null
        \\        constraint files_v2_local_path_uniq unique on conflict abort,
        \\     constraint files_v2_pk primary key (file_hash, local_path)
        \\ ) without rowid, strict;
        \\
        // TODO rename old tables with some '++ comptime renameTable("files", "_old_files_int_id") ++'
        \\ CREATE TABLE IF NOT EXISTS tag_cores_v2 (
        \\      core_hash text primary key
        \\         constraint tag_cores_v2_hash_fk references hashes_v2 (id) on delete restrict,
        \\      core_data blob not null
        \\  ) without rowid, strict;
        \\
        \\ CREATE TABLE IF NOT EXISTS tag_names_v2 (
        \\ 	tag_text text not null,
        \\ 	tag_language text not null,
        \\      core_hash text
        \\         constraint tag_names_v2_core_fk references tag_cores_v2 (core_hash) on delete restrict,
        \\ 	constraint tag_names_v2_pk primary key (tag_text, tag_language)
        \\  ) without rowid, strict;
        \\
        \\CREATE TABLE IF NOT EXISTS tag_implications_v2 (
        \\     rowid integer primary key,
        \\     child_tag text not null
        \\        constraint tag_implications_v2_child_fk references tag_cores_v2 (core_hash) on delete cascade,
        \\     parent_tag text not null
        \\        constraint tag_implications_v2_parent_fk references tag_cores_v2 (core_hash) on delete cascade,
        \\     constraint tag_implications_v2_uniq unique (child_tag, parent_tag)
        \\) strict;
        \\
        \\CREATE TABLE IF NOT EXISTS tag_files_v2 (
        \\     file_hash text not null
        \\        constraint tag_files_file_fk references hashes_v2 (id) on delete cascade,
        \\     core_hash text not null
        \\        constraint tag_files_core_fk references tag_cores_v2 (core_hash) on delete cascade,
        \\     tag_source_type int default 0,
        \\     tag_source_id int default 0,
        \\     parent_source_id int default null,
        \\
        \\      constraint tag_files_tag_source_fk
        \\       foreign key (tag_source_type, tag_source_id)
        \\       references tag_sources (type, id) on delete restrict,
        \\
        \\      constraint tag_files_parent_source_id_fk
        \\       foreign key (parent_source_id)
        \\       references tag_implications_v2 (rowid) on delete restrict,
        \\
        \\      constraint tag_files_pk primary key (file_hash, core_hash)
        \\ ) without rowid, strict;
        \\
        \\CREATE TABLE IF NOT EXISTS pools_v2 (
        \\     pool_hash text primary key
        \\        constraint pools_hash_fk references hashes_v2 (id) on delete restrict,
        \\     pool_core_data blob not null
        \\        constraint pool_core_data check (length(pool_core_data) >= 64),
        \\     title text not null
        \\ ) without rowid, strict;
        \\
        \\CREATE TABLE IF NOT EXISTS pool_entries_v2 (
        \\     file_hash text not null
        \\        -- cant reference files.file_hash due to composite primary key
        \\        constraint pool_entries_file_fk references hashes_v2 (id) on delete cascade,
        \\     pool_hash text not null
        \\        constraint pool_entries_pool_fk references pools_v2 (pool_hash) on delete cascade,
        \\     entry_index int not null,
        \\     constraint pool_entries_pk primary key (file_hash, pool_hash),
        \\     -- prevent inconsistent pool due to bug in entry index selection
        \\     constraint pool_unique_index unique (pool_hash, entry_index)
        \\ ) without rowid, strict;
        \\
        \\CREATE TABLE IF NOT EXISTS metrics_tag_usage_values_v2 (
        \\     timestamp integer,
        \\     core_hash text not null
        \\       constraint metrics_core_hash_fk references tag_cores_v2 (core_hash) on delete cascade,
        \\     relationship_count int not null,
        \\     constraint relationship_count_not_negative check (relationship_count >= 0),
        \\     constraint metrics_tag_usage_values_pk primary key (timestamp, core_hash)
        \\ ) without rowid, strict;
    , .{ .diags = &diags }) catch |err| {
        logger.err("diags={}", .{diags});
        return err;
    };

    // to convert from sqlite's PRIMARY KEY AUTOINCREMENT column towards an ulid
    // we need to convert from int primary key to text primary key
    try migrateSingleTable(self, "files", "files_v2", migrateFiles);
    try migrateSingleTable(self, "tag_cores", "tag_cores_v2", migrateCores);
    try migrateSingleTable(self, "tag_names", "tag_names_v2", migrateTagNames);
    try migrateSingleTable(self, "tag_implications", "tag_implications_v2", migrateTagImplications);
    try migrateSingleTable(self, "tag_files", "tag_files_v2", migrateTagFiles);
    try migrateSingleTable(self, "pools", "pools_v2", migratePools);
    try migrateSingleTable(self, "pool_entries", "pool_entries_v2", migratePoolEntries);

    try migrateSingleTable(self, "metrics_tag_usage_values", "metrics_tag_usage_values_v2", migrateTagUsageCounts);
    {
        try lockTable(self, "hashes");
        try renameToOriginal(self, "hashes");
        try renameToOriginal(self, "files");
        try renameToOriginal(self, "tag_cores");
        try renameToOriginal(self, "tag_names");
        try renameToOriginal(self, "tag_implications");
        try renameToOriginal(self, "tag_files");
        try renameToOriginal(self, "pools");
        try renameToOriginal(self, "pool_entries");
        try renameToOriginal(self, "metrics_tag_usage_values");
    }
}

fn snowflakeNewHash(self: *Context, old_hash: i64) !ID {
    const new_file_hash_id = (try self.db.one(
        ID.SQL,
        \\ select hashes_v2.id
        \\ from hashes
        \\ join hashes_v2 on hashes.hash_data = hashes_v2.hash_data
        \\ where hashes.id = ?
    ,
        .{},
        .{old_hash},
    )) orelse return error.TargetHashNotFound;
    return ID.new(new_file_hash_id);
}
