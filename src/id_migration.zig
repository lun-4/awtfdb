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
            \\ CREATE TRIGGER IF NOT EXISTS {s}_v1_readonly_update
            \\ BEFORE UPDATE ON {s}
            \\ BEGIN
            \\     SELECT raise(abort, 'this is a software bug, use {s}_v2 table');
            \\ END;
            \\
            \\ CREATE TRIGGER IF NOT EXISTS {s}_v1_readonly_insert
            \\ BEFORE INSERT ON {s}
            \\ BEGIN
            \\     SELECT raise(abort, 'this is a software bug, use {s}_v2 table');
            \\ END;
            \\
            \\ CREATE TRIGGER IF NOT EXISTS {s}_v1_readonly_delete
            \\ BEFORE DELETE ON {s}
            \\ BEGIN
            \\     SELECT raise(abort, 'this is a software bug, use {s}_v2 table');
            \\ END;
        , .{table} ** 9) catch unreachable;
    }
    return result;
}

fn assertSameCount(self: *Context, comptime table1: []const u8, comptime table2: []const u8) !void {
    const table1_count = try self.db.?.one(usize, "select count(*) from " ++ table1, .{}, .{});
    const table2_count = try self.db.?.one(usize, "select count(*) from " ++ table2, .{}, .{});
    try std.testing.expectEqual(table1_count, table2_count);
}

pub fn migrate(self: *Context) !void {
    logger.info("this migration may take a while!", .{});

    var diags = sqlite.Diagnostics{};

    self.db.?.execMulti(
        \\ CREATE TABLE hashes_v2 (
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
        \\     child_tag text not null
        \\        constraint tag_implications_v2_child_fk references tag_cores_v2 (core_hash) on delete cascade,
        \\     parent_tag text not null
        \\        constraint tag_implications_v2_parent_fk references tag_cores_v2 (core_hash) on delete cascade,
        \\     constraint tag_implications_v2_pk primary key (child_tag, parent_tag)
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
        \\      constraint tag_files_tag_source_fk
        \\       foreign key (tag_source_type, tag_source_id)
        \\       references tag_sources (type, id) on delete restrict,
        \\      constraint tag_files_pk primary key (file_hash, core_hash)
        \\ ) without rowid, strict;
    , .{ .diags = &diags }) catch |err| {
        logger.err("diags={}", .{diags});
        return err;
    };

    var stmt = try self.db.?.prepare(
        \\ select file_hash, local_path, hashes.hash_data from files
        \\ join hashes on files.file_hash = hashes.id
    );
    defer stmt.deinit();

    // to convert from sqlite's PRIMARY KEY AUTOINCREMENT column towards an ulid
    // we need to convert from int primary key to text primary key

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

        const maybe_existing_hash = try self.db.?.one(
            ID.SQL,
            "select id from hashes_v2 where hash_data = ?",
            .{},
            .{data.hash_data},
        );

        logger.warn("file {d} {s}", .{ data.file_hash, data.local_path });
        if (maybe_existing_hash) |existing_hash| {
            logger.warn("existing as {s} {s}", .{ existing_hash, data.local_path });

            const existing_id = ID.new(existing_hash);
            try self.db.?.exec(
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
            try self.db.?.exec(
                "insert into hashes_v2 (id, hash_data) VALUES (?, ?)",
                .{},
                .{ new_id.sql(), data.hash_data },
            );
            const must_exist = try self.db.?.one(
                ID.SQL,
                "select id from hashes_v2 where hash_data = ?",
                .{},
                .{data.hash_data},
            );
            try std.testing.expectEqualSlices(u8, new_id.str(), &(must_exist.?));
            try self.db.?.exec(
                "insert into files_v2 (file_hash, local_path) VALUES (?, ?)",
                .{},
                .{ new_id.sql(), data.local_path },
            );
        }
    }

    try assertSameCount(self, "files", "files_v2");

    // migrate tag cores

    var stmt_tag_cores = try self.db.?.prepare(
        \\ select core_hash, core_data, hashes.hash_data from tag_cores
        \\ join hashes on tag_cores.core_hash = hashes.id
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
        try self.db.?.exec(
            "insert into hashes_v2 (id, hash_data) VALUES (?, ?)",
            .{},
            .{ new_id.sql(), data_v1.hash_data },
        );
        try self.db.?.exec(
            "insert into tag_cores_v2 (core_hash, core_data) VALUES (?, ?)",
            .{},
            .{ new_id.sql(), data_v1.core_data },
        );
    }
    try assertSameCount(self, "tag_cores", "tag_cores_v2");

    // migrate tag names

    var stmt_tag_names = try self.db.?.prepare(
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
        try self.db.?.exec(
            "insert into tag_names_v2 (core_hash, tag_language, tag_text) VALUES (?, ?, ?)",
            .{},
            .{ new_id.sql(), row.tag_language, row.tag_text },
        );
    }
    try assertSameCount(self, "tag_names", "tag_names_v2");

    var stmt_tag_implications = try self.db.?.prepare(
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
        try self.db.?.exec(
            "insert into tag_implications_v2 (rowid, child_tag, parent_tag) VALUES (?,?, ?)",
            .{},
            .{ row.rowid, new_child_tag.sql(), new_parent_tag.sql() },
        );
    }
    try assertSameCount(self, "tag_implications", "tag_implications_v2");

    var stmt_tag_files = try self.db.?.prepare(
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
            _ = (try self.db.?.one(
                ID.SQL,
                "select parent_tag from tag_implications_v2 where rowid = ?",
                .{},
                .{parent_source_id},
            )) orelse {
                return error.InconsistentSemantics;
            };
        }

        logger.warn(
            "insert tag files {} {} {d} {d} {?d}",
            .{ new_file_hash, new_core_hash, row.tag_source_type, row.tag_source_id, row.parent_source_id },
        );
        try self.db.?.exec(
            "insert into tag_files_v2 (file_hash, core_hash, tag_source_type, tag_source_id, parent_source_id) VALUES (?, ?, ?, ?, ?)",
            .{},
            .{ new_file_hash.sql(), new_core_hash.sql(), row.tag_source_type, row.tag_source_id, row.parent_source_id },
        );
    }
    try assertSameCount(self, "tag_files", "tag_files_v2");
}

fn snowflakeNewHash(self: *Context, old_hash: i64) !ID {
    const new_file_hash_id = (try self.db.?.one(
        ID.SQL,
        \\ select hashes_v2.id
        \\ from hashes
        \\ join hashes_v2 on hashes.hash_data = hashes_v2.hash_data
        \\ where hashes.id = ?
    ,
        .{},
        .{old_hash},
    )).?;
    return ID.new(new_file_hash_id);
}