const std = @import("std");
const builtin = @import("builtin");
const sqlite = @import("sqlite");
const ulid = @import("ulid");
const IdMigration = @import("id_migration.zig");

const RowID = i64;

pub const AWTFDB_BLAKE3_CONTEXT = "awtfdb Sun Mar 20 16:58:11 AM +00 2022 main hash key";

const HELPTEXT =
    \\ awtfdb-manage: main program for awtfdb file management
    \\
    \\ usage:
    \\ 	awtfdb-manage [global options..] <action> [action options...]
    \\
    \\ global options:
    \\  -h		prints this help and exits
    \\ 	-V		prints version and exits
    \\ 	-v		turns on verbosity (debug logging)
    \\
    \\ creating an awtfdb index file:
    \\  awtfdb-manage create
    \\
    \\ migrating to new versions:
    \\  awtfdb-manage migrate
    \\
    \\ getting statistics:
    \\  awtfdb-manage stats
    \\
    \\ current running jobs:
    \\  awtfdb-manage jobs
;

const MigrationOptions = struct {
    function: ?*const fn (*Context) anyerror!void = null,
};

pub const Migration = struct {
    version: usize,
    name: []const u8,
    sql: ?[]const u8 = null,
    options: MigrationOptions,

    const Self = @This();

    pub fn fromTuple(decl: anytype) Self {
        const self = if (decl.len == 3) Self{
            .version = decl.@"0",
            .name = decl.@"1",
            .sql = decl.@"2",
            .options = .{},
        } else Self{
            .version = decl.@"0",
            .name = decl.@"1",
            .options = decl.@"2",
            .sql = decl.@"3",
        };
        return self;
    }
};

pub const MIGRATIONS = .{
    .{
        1, "initial table",
        \\ -- we optimize table size by storing hashes in a dedicated table
        \\ -- and then only using the int id (which is more efficiency) for
        \\ -- references into other tables
        \\ create table hashes (
        \\     id integer primary key,
        \\     hash_data blob
        \\     	constraint hashes_length check (length(hash_data) == 32)
        \\     	constraint hashes_unique unique
        \\ ) strict;
        \\
        \\ -- uniquely identifies a tag in the ENTIRE UNIVERSE!!!
        \\ -- since this uses random data for core_data, and core_hash is blake3
        \\ --
        \\ -- this is not randomly generated UUIDs, of which anyone can cook up 128-bit
        \\ -- numbers out of thin air. using a cryptographic hash function lets us be
        \\ -- sure that we have an universal tag for 'new york' or 'tree', while also
        \\ -- enabling different language representations of the same tag
        \\ -- (since they all reference the core!)
        \\ create table tag_cores (
        \\     core_hash int
        \\     	constraint tag_cores_hash_fk references hashes (id) on delete restrict
        \\     	constraint tag_cores_pk primary key,
        \\     core_data blob not null
        \\ ) strict;
        \\ 
        \\ -- files that are imported into the index are here
        \\ -- this is how we learn that a certain path means a certain hash without
        \\ -- having to recalculate the hash over and over.
        \\ create table files (
        \\     file_hash int not null
        \\     	constraint files_hash_fk references hashes (id) on delete restrict,
        \\     local_path text not null,
        \\     constraint files_pk primary key (file_hash, local_path)
        \\ ) strict;
        \\ 
        \\ -- this is the main tag<->file mapping. to find out which tags a file has,
        \\ -- execute your SELECT here.
        \\ create table tag_files (
        \\     file_hash int not null
        \\      -- not referencing files (file_hash) so that it still works
        \\     	constraint tag_files_file_fk references hashes (id) on delete cascade,
        \\     core_hash int not null
        \\     	constraint tag_files_core_fk references tag_cores (core_hash) on delete cascade,
        \\     constraint tag_files_pk primary key (file_hash, core_hash)
        \\ ) strict;
        \\ 
        \\ -- this is the main name<->tag mapping.
        \\ create table tag_names (
        \\     tag_text text not null,
        \\     tag_language text not null,
        \\     core_hash int not null
        \\     	constraint tag_names_core_fk references tag_cores (core_hash) on delete cascade,
        \\     constraint tag_names_pk primary key (tag_text, tag_language, core_hash)
        \\ ) strict;
    },

    // to do the new constraint, we need to reconstruct the table.
    .{
        2, "fix missing unqiue constraint for local paths",
        \\ create table files_local_path_constraint_fix (
        \\     file_hash int not null
        \\     	constraint files_hash_fk references hashes (id) on delete restrict,
        \\     local_path text not null
        \\     	constraint files_local_path_uniq unique on conflict abort,
        \\     constraint files_pk primary key (file_hash, local_path)
        \\ ) strict;
        \\
        \\ insert into files_local_path_constraint_fix select * from files;
        \\ drop table files;
        \\ alter table files_local_path_constraint_fix rename to files;
    },

    // child tag implies parent tag
    .{
        3, "add tag implication system",
        \\ create table tag_implications (
        \\     child_tag int not null
        \\     	constraint tag_implications_child_fk references tag_cores (core_hash) on delete cascade,
        \\     parent_tag int not null
        \\     	constraint tag_implications_parent_fk references tag_cores (core_hash) on delete cascade,
        \\     constraint tag_implications_pk primary key (child_tag, parent_tag)
        \\ ) strict;
    },

    .{
        4, "add pool system",
        \\ create table pools (
        \\     pool_hash int
        \\     	constraint pools_hash_fk references hashes (id) on delete restrict
        \\     	constraint pools_pk primary key,
        \\
        \\     pool_core_data blob not null
        \\     	constraint pool_core_data check (length(pool_core_data) >= 64),
        \\
        \\     title text not null
        \\ ) strict;
        \\
        \\ create table pool_entries (
        \\     file_hash int not null
        \\      -- not referencing files (file_hash) so that it still works
        \\     	constraint pool_entries_file_fk references hashes (id) on delete cascade,
        \\     pool_hash int not null
        \\     	constraint pool_entries_pool_fk references pools (pool_hash) on delete cascade,
        \\     entry_index int not null,
        \\     constraint pool_entries_pk primary key (file_hash, pool_hash),
        \\     constraint pool_unique_index unique (pool_hash, entry_index)
        \\ ) strict;
    },

    .{
        5, "add metrics count tables",
        \\ create table metrics_count_files (
        \\     timestamp integer primary key,
        \\     value integer,
        \\     check(value >= 0)
        \\ ) strict;
        \\
        \\ create table metrics_count_tag_cores (
        \\     timestamp integer primary key,
        \\     value integer,
        \\     constraint value_not_negative check(value >= 0)
        \\ ) strict;
        \\
        \\ create table metrics_count_tag_names (
        \\     timestamp integer primary key,
        \\     value integer,
        \\     constraint value_not_negative check(value >= 0)
        \\ ) strict;
        \\
        \\ create table metrics_count_tag_files (
        \\     timestamp integer primary key,
        \\     value integer,
        \\     constraint value_not_negative check(value >= 0)
        \\ ) strict;
        \\
        // create graphs of tag usage over time
        // we do this through two tables
        //  - one of them contains the timestamps (x axis)
        //  - the other contains y axis for every tag for that timestamp
        \\ create table metrics_tag_usage_timestamps (
        \\     timestamp integer primary key
        \\ ) strict;
        \\
        // we use foreign key AND hash id as a composite primary key,
        // removing the need to have rowid in this table
        //
        // see https://stackoverflow.com/questions/65422890/how-to-use-time-series-with-sqlite-with-fast-time-range-queries
        \\ create table metrics_tag_usage_values (
        \\     timestamp integer,
        \\     core_hash int not null,
        \\     relationship_count int not null,
        \\     constraint relationship_count_not_negative check (relationship_count >= 0),
        \\     constraint metrics_tag_usage_values_pk primary key (timestamp, core_hash)
        \\ ) without rowid, strict;
    },

    .{
        6, "add tag sources",
        \\ create table tag_sources (
        \\    type int not null,
        \\    id int not null,
        \\    name text not null,
        \\    primary key (type, id)
        \\ ) strict;
        // tag_sources with type=0 must have synchronization with the SystemTagSources enum
        \\ insert into tag_sources values (0, 0, 'manual insertion');
        \\ insert into tag_sources values (0, 1, 'tag parenting');
        // ADD COLUMN tag_source_type (int)
        // ADD COLUMN tag_source_id (int)
        // ADD COLUMN parent_source_id (default null)
        // to do all of that, we need to copy into a new table
        \\ create table tag_files_with_tag_sources (
        \\     file_hash int not null
        \\     	constraint tag_files_file_fk references hashes (id) on delete cascade,
        \\     core_hash int not null
        \\     	constraint tag_files_core_fk references tag_cores (core_hash) on delete cascade,
        \\     tag_source_type int default 0,
        \\     tag_source_id int default 0,
        \\     parent_source_id int default null,
        // deleting a source requires manual action from the user if
        //  the relationships will be mainained or if the relationships
        //  should be removed, so do this action before removing the tag
        //  source itself from the table
        \\      constraint tag_files_tag_source_fk
        \\       foreign key (tag_source_type, tag_source_id)
        \\       references tag_sources (type, id) on delete restrict,
        \\      constraint tag_files_pk primary key (file_hash, core_hash)
        \\ ) strict;
        // actually do the migration to the new table
        \\ insert into tag_files_with_tag_sources select file_hash, core_hash, 0, 0, null from tag_files;
        \\ alter table tag_files rename to _old_tag_files_without_sources;
        \\ alter table tag_files_with_tag_sources rename to tag_files;
        ,
    },

    .{
        7, "add tag source metrics",
        \\ create table metrics_tag_source_usage (
        \\     timestamp int not null,
        \\     tag_source_type int not null,
        \\     tag_source_id int not null,
        \\     relationship_count int not null,
        \\     constraint relationship_count_not_negative check (relationship_count >= 0)
        \\ ) strict;
    },

    .{
        8, "migrate to ulids for local ids",
        .{
            .function = IdMigration.migrate,
        },
        null,
    },
};

pub const MIGRATION_LOG_TABLE =
    \\ create table if not exists migration_logs (
    \\     version int primary key,
    \\     applied_at int,
    \\     description text
    \\ );
;

pub const logger = std.log.scoped(.awtfdb_main);

pub const TagSourceType = enum(usize) {
    /// This tag source is a part of the core awtfdb system
    /// (e.g tag parenting or manual insertion).
    system = 0,

    /// This tag source is an external tool that uses awtfdb.
    external = 1,
};

pub const SystemTagSources = enum(usize) {
    /// The user manually inserted this tag through a tool like ainclude.
    manual_insertion = 0,

    /// This tag was inferred through the tag parent tree.
    ///
    /// If this value is set, tag_files.parent_source_id will be set
    /// to the parent tree entry that generated this entry
    tag_parenting = 1,
};

pub fn ulidFromTimestamp(rand: std.rand.Random, timestamp: anytype) ulid.ULID {
    return ulid.ULID{
        .timestamp = std.math.cast(u48, timestamp) orelse @panic("time.milliTimestamp() is higher than 281474976710655"),
        .randomnes = rand.int(u80),
    };
}
pub fn ulidFromBoth(timestamp: anytype, randomnes: u80) ulid.ULID {
    return ulid.ULID{
        .timestamp = std.math.cast(u48, timestamp) orelse @panic("time.milliTimestamp() is higher than 281474976710655"),
        .randomnes = randomnes,
    };
}

pub const ID = struct {
    data: [26]u8,
    pub const SQL = [26]u8;
    const Self = @This();

    pub fn generate() Self {
        var rng = std.rand.DefaultPrng.init(
            @truncate(u64, @intCast(u128, std.time.nanoTimestamp())),
        );
        const rand = rng.random();
        const generated_ulid = ulidFromTimestamp(rand, std.time.milliTimestamp());
        return Self.ul(generated_ulid);
    }

    pub fn generateWithTimestamp(milliTimestamp: anytype) Self {
        var rng = std.rand.DefaultPrng.init(
            @truncate(u64, @intCast(u128, std.time.nanoTimestamp())),
        );
        const rand = rng.random();

        const generated_ulid = ulidFromTimestamp(rand, milliTimestamp);
        return Self.ul(generated_ulid);
    }

    pub fn new(data: [26]u8) Self {
        return Self{ .data = data };
    }
    pub fn fromString(data: []const u8) Self {
        std.debug.assert(data.len == 26);
        return Self.new(data[0..26].*);
    }

    pub fn ul(ulid_data: ulid.ULID) Self {
        return Self{ .data = ulid_data.bytes() };
    }

    pub fn str(self: *const Self) []const u8 {
        return &self.data;
    }

    pub fn sql(self: *const Self) sqlite.Text {
        return sqlite.Text{ .data = &self.data };
    }

    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll(&self.data);
    }
};

pub const Context = struct {
    home_path: ?[]const u8 = null,
    db_path: ?[]const u8 = null,
    args_it: *std.process.ArgIterator,
    stdout: std.fs.File,
    allocator: std.mem.Allocator,
    /// Always call loadDatabase before using this attribute.
    db: ?sqlite.Db = null,

    const Self = @This();

    pub const LoadDatabaseOptions = struct {
        create: bool = false,
    };

    pub fn loadDatabase(self: *Self, options: LoadDatabaseOptions) !void {
        if (self.db != null) return;

        // try to create the file always. this is done because
        // i give up. tried a lot of things to make sqlite create the db file
        // itself but it just hates me (SQLITE_CANTOPEN my beloathed).
        if (self.db_path == null) {
            self.home_path = self.home_path orelse std.os.getenv("HOME");
            const resolved_path = try std.fs.path.resolve(
                self.allocator,
                &[_][]const u8{ self.home_path.?, "awtf.db" },
            );

            if (options.create) {
                var file = try std.fs.cwd().createFile(resolved_path, .{ .truncate = false });
                defer file.close();
            } else {
                try std.fs.cwd().access(resolved_path, .{});
            }
            self.db_path = resolved_path;
        }

        const db_path_cstr = try std.cstr.addNullByte(self.allocator, self.db_path.?);
        defer self.allocator.free(db_path_cstr);

        var diags: sqlite.Diagnostics = undefined;
        self.db = try sqlite.Db.init(.{
            .mode = sqlite.Db.Mode{ .File = db_path_cstr },
            .open_flags = .{
                .write = true,
                .create = true,
            },
            .threading_mode = .MultiThread,
            .diags = &diags,
        });

        // ensure our database functions work
        const result = try self.db.?.one(i32, "select 123;", .{}, .{});
        if (result != @as(?i32, 123)) {
            const result_packed = result orelse 0;
            logger.err("error on test statement: expected 123, got {?d} {d} ({})", .{ result, result_packed, (result orelse 0) == 123 });
            return error.TestStatementFailed;
        }

        try self.db.?.exec("PRAGMA foreign_keys = ON", .{}, .{});
    }

    /// Convert the current connection into an in-memory database connection
    /// so that operations are done non-destructively
    ///
    /// This function is useful for '--dry-run' switches in CLI applications.
    pub fn turnIntoMemoryDb(self: *Self) !void {

        // first, make sure our current connection can't do shit
        try self.db.?.exec("PRAGMA query_only = ON;", .{}, .{});

        // open a new one in memory
        var new_db = try sqlite.Db.init(.{
            .mode = sqlite.Db.Mode{ .Memory = {} },
            .open_flags = .{
                .write = true,
                .create = true,
            },
            .threading_mode = .MultiThread,
        });

        // backup the one we have into the memory one
        const maybe_backup = sqlite.c.sqlite3_backup_init(new_db.db, "main", self.db.?.db, "main");
        defer if (maybe_backup) |backup| {
            const result = sqlite.c.sqlite3_backup_finish(backup);
            if (result != sqlite.c.SQLITE_OK) {
                std.debug.panic("unexpected result code from backup finish: {d}", .{result});
            }
        };

        if (maybe_backup) |backup| {
            const result = sqlite.c.sqlite3_backup_step(backup, -1);
            if (result != sqlite.c.SQLITE_DONE) {
                return sqlite.errorFromResultCode(result);
            }
        }

        // then, close the db
        self.db.?.deinit();

        // then, make this new db the real db
        self.db = new_db;
    }

    pub fn deinit(self: *Self) void {
        if (self.db_path) |db_path| self.allocator.free(db_path);

        if (self.db) |*db| {
            logger.info("possibly optimizing database...", .{});
            // The results of analysis are not as good when only part of each index is examined,
            // but the results are usually good enough. Setting N to 100 or 1000 allows
            // the ANALYZE command to run very quickly, even on multi-gigabyte database files.
            _ = db.one(i64, "PRAGMA analysis_limit=1000;", .{}, .{}) catch {};
            _ = db.exec("PRAGMA optimize;", .{}, .{}) catch {};
            db.deinit();
        }
    }

    pub const Blake3Hash = [std.crypto.hash.Blake3.digest_length]u8;
    pub const Blake3HashHex = [std.crypto.hash.Blake3.digest_length * 2]u8;

    const NamedTagValue = struct {
        text: []const u8,
        language: []const u8,
    };

    pub const Tag = struct {
        core: Hash,
        kind: union(enum) {
            Named: NamedTagValue,
        },

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            _ = fmt;
            // TODO better format logic (add switch case)
            return std.fmt.format(writer, "{s}", .{self.kind.Named.text});
        }

        /// Deletes all the tags reffering to this core
        pub fn deleteAll(self: @This(), db: *sqlite.Db) !usize {
            try db.exec(
                \\ delete from tag_names
                \\ where core_hash = ?
            ,
                .{},
                .{self.core.id.sql()},
            );
            const deleted_tag_count = db.rowsAffected();

            try db.exec("delete from tag_cores where core_hash = ?", .{}, .{self.core.id.sql()});
            std.debug.assert(db.rowsAffected() == 1);
            try db.exec("delete from hashes where id = ?", .{}, .{self.core.id.sql()});
            std.debug.assert(db.rowsAffected() == 1);

            return deleted_tag_count;
        }
    };

    const OwnedTagList = struct {
        allocator: std.mem.Allocator,
        items: []Tag,
        pub fn deinit(self: @This()) void {
            for (self.items) |tag| {
                switch (tag.kind) {
                    .Named => |named_tag| {
                        self.allocator.free(named_tag.text);
                        self.allocator.free(named_tag.language);
                    },
                }
            }
            self.allocator.free(self.items);
        }
    };

    const TagList = std.ArrayList(Tag);

    /// Caller owns returned memory.
    pub fn fetchTagsFromCore(self: *Self, allocator: std.mem.Allocator, core_hash: Hash) !OwnedTagList {
        var stmt = try self.db.?.prepare("select tag_text, tag_language from tag_names where core_hash = ?");
        defer stmt.deinit();

        var named_tag_values = try stmt.all(
            NamedTagValue,
            allocator,
            .{},
            .{core_hash.id.sql()},
        );
        defer allocator.free(named_tag_values);

        var list = TagList.init(allocator);
        defer list.deinit();

        for (named_tag_values) |named_tag| {
            try list.append(Tag{
                .core = core_hash,
                .kind = .{ .Named = named_tag },
            });
        }

        return OwnedTagList{
            .allocator = allocator,
            .items = try list.toOwnedSlice(),
        };
    }

    /// Helper struct to convert hash data given in an sqlite.Blob
    /// back into [32]u8 for the API.
    pub const HashSQL = struct {
        id: ID.SQL,
        hash_data: sqlite.Blob,

        pub fn toRealHash(self: @This()) Hash {
            var hash_value: [32]u8 = undefined;
            std.mem.copy(u8, &hash_value, self.hash_data.data);
            return Hash{ .id = ID.new(self.id), .hash_data = hash_value };
        }
    };

    pub fn fetchNamedTag(self: *Self, text: []const u8, language: []const u8) !?Tag {
        var maybe_core_hash = try self.db.?.oneAlloc(
            HashSQL,
            self.allocator,
            \\ select hashes.id, hashes.hash_data
            \\ from tag_names
            \\ join hashes
            \\ 	on tag_names.core_hash = hashes.id
            \\ where tag_text = ? and tag_language = ?
        ,
            .{},
            .{ text, language },
        );
        defer if (maybe_core_hash) |hash| self.allocator.free(hash.hash_data.data);

        if (maybe_core_hash) |core_hash| {
            return Tag{
                .core = core_hash.toRealHash(),
                .kind = .{ .Named = .{ .text = text, .language = language } },
            };
        } else {
            return null;
        }
    }

    /// Caller owns the returned memory.
    fn randomCoreData(self: *Self, core_output: []u8) void {
        _ = self;
        const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
        var r = std.rand.DefaultPrng.init(seed);
        for (core_output) |_, index| {
            var random_byte = r.random().uintAtMost(u8, 255);
            core_output[index] = random_byte;
        }
    }

    pub const Hash = struct {
        id: ID,
        hash_data: [32]u8,

        const HashSelf = @This();

        pub fn toHex(self: HashSelf) Blake3HashHex {
            var core_hash_text_buffer: Blake3HashHex = undefined;
            _ = std.fmt.bufPrint(
                &core_hash_text_buffer,
                "{x}",
                .{std.fmt.fmtSliceHexLower(&self.hash_data)},
            ) catch unreachable;
            return core_hash_text_buffer;
        }

        pub fn format(
            self: HashSelf,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            _ = fmt;

            return std.fmt.format(writer, "{s} {s}", .{ self.id, &self.toHex() });
        }
    };

    // TODO add sources to tag cores (needs a new Hash struct dedicated to it
    // as things like files use Hash but do not have tag sources)

    pub const CreateHashOptions = struct {
        milliTimestamp: ?i128 = null,
    };

    fn createHash(self: *Self, hash_blob: sqlite.Blob, options: CreateHashOptions) !ID {
        const id = if (options.milliTimestamp) |timestamp|
            ID.generateWithTimestamp(timestamp)
        else
            ID.generate();

        try self.db.?.exec(
            "insert into hashes (id, hash_data) values (?, ?)",
            .{},
            .{ id.sql(), hash_blob },
        );
        return id;
    }

    pub fn createNamedTag(
        self: *Self,
        text: []const u8,
        language: []const u8,
        maybe_core: ?Hash,
    ) !Tag {
        var core_hash: Hash = undefined;
        if (maybe_core) |existing_core_hash| {
            core_hash = existing_core_hash;
        } else {
            var core_data: [128]u8 = undefined;
            self.randomCoreData(&core_data);

            var core_hash_bytes: Blake3Hash = undefined;
            var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
            hasher.update(&core_data);
            hasher.final(&core_hash_bytes);

            var savepoint = try self.db.?.savepoint("named_tag");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            const hash_blob = sqlite.Blob{ .data = &core_hash_bytes };

            // core_hash_bytes is passed by reference here, so we don't
            // have to worry about losing it to undefined memory hell.
            const hash_id = try self.createHash(hash_blob, .{});
            core_hash = .{ .id = hash_id, .hash_data = core_hash_bytes };

            const id_data = try self.db.?.one(ID.SQL, "select id from hashes where hash_data= ?", .{}, .{hash_blob});
            const id = ID.new(id_data.?);
            std.log.warn("id = {}", .{id});

            const core_data_blob = sqlite.Blob{ .data = &core_data };
            try self.db.?.exec(
                "insert into tag_cores (core_hash, core_data) values (?, ?)",
                .{},
                .{ core_hash.id.sql(), core_data_blob },
            );

            logger.warn("created tag core with hash {s}", .{core_hash});
        }

        try self.db.?.exec(
            "insert into tag_names (core_hash, tag_text, tag_language) values (?, ?, ?)",
            .{},
            .{ core_hash.id.sql(), text, language },
        );
        logger.warn("created name tag with value {s} language {s} core {s}", .{ text, language, core_hash });

        return Tag{
            .core = core_hash,
            .kind = .{ .Named = .{ .text = text, .language = language } },
        };
    }

    pub const HashList = std.ArrayList(Hash);

    pub const File = struct {
        ctx: *Context,
        local_path: []const u8,
        hash: Hash,

        const FileSelf = @This();

        pub fn deinit(self: FileSelf) void {
            self.ctx.allocator.free(self.local_path);
        }

        const AddTagOptions = struct {
            source: ?Source = null,
            parent_source_id: ?i64 = null,
        };

        // TODO create Source.addTagTo(), as its a safer api overall
        //  (prevent people from having to audit every addTag call)
        pub fn addTag(self: *FileSelf, core_hash: Hash, options: AddTagOptions) !void {
            logger.debug("link file {s} (hash {s}) with tag core hash {d} {s}", .{ self.local_path, self.hash, core_hash.id, core_hash });

            if (options.source) |source| {
                if (options.parent_source_id) |parent_source_id| {
                    if (source.kind != TagSourceType.system) return error.InvalidSourceType;
                    if (source.id != @enumToInt(SystemTagSources.tag_parenting)) {
                        logger.err("expected tag parent source, got {}", .{source});
                        return error.InvalidSourceID;
                    }

                    try self.ctx.db.?.exec(
                        \\insert into tag_files (core_hash, file_hash, tag_source_type, tag_source_id, parent_source_id)
                        \\values (?, ?, ?, ?, ?) on conflict do nothing
                    ,
                        .{},
                        .{ core_hash.id.sql(), self.hash.id.sql(), @enumToInt(source.kind), source.id, parent_source_id },
                    );
                } else {
                    try self.ctx.db.?.exec(
                        \\insert into tag_files (core_hash, file_hash, tag_source_type, tag_source_id)
                        \\values (?, ?, ?, ?) on conflict do nothing
                    ,
                        .{},
                        .{ core_hash.id.sql(), self.hash.id.sql(), @enumToInt(source.kind), source.id },
                    );
                }
            } else {
                // TODO compileError if parent_source_id here but no source
                // provided
                if (options.parent_source_id != null) unreachable;

                try self.ctx.db.?.exec(
                    "insert into tag_files (core_hash, file_hash) values (?, ?) on conflict do nothing",
                    .{},
                    .{ core_hash.id.sql(), self.hash.id.sql() },
                );
            }
        }

        pub fn removeTag(self: *FileSelf, core_hash: Hash) !void {
            try self.ctx.db.?.exec(
                "delete from tag_files where core_hash = ? and file_hash = ?",
                .{},
                .{ core_hash.id.sql(), self.hash.id.sql() },
            );
            logger.debug("remove file {s} (hash {s}) with tag core hash {d}", .{ self.local_path, self.hash, core_hash.id });
        }

        // Copies ownership of given new_local_path
        pub fn setLocalPath(self: *FileSelf, new_local_path: []const u8) !void {
            try self.ctx.db.?.exec(
                "update files set local_path = ? where file_hash = ? and local_path = ?",
                .{},
                .{ new_local_path, self.hash.id.sql(), self.local_path },
            );

            self.ctx.allocator.free(self.local_path);
            self.local_path = try self.ctx.allocator.dupe(u8, new_local_path);
        }

        pub fn delete(self: FileSelf) !void {
            logger.info("deleted file {d} {s}", .{ self.hash.id, self.local_path });
            try self.ctx.db.?.exec(
                "delete from files where file_hash = ? and local_path = ?",
                .{},
                .{ self.hash.id.sql(), self.local_path },
            );

            // NOTE how that we don't delete it from hashes table.
            // awtfdb-janitor will garbage collect the hash entries over time
        }

        pub const Source = struct {
            ctx: *Context,
            kind: TagSourceType,
            id: i64,

            const SourceSelf = @This();

            pub fn fetchName(self: SourceSelf, allocator: std.mem.Allocator) []const u8 {
                _ = self;
                _ = allocator;
                std.debug.todo("todo this");
            }

            pub fn delete(self: SourceSelf) !void {
                if (self.kind == .system) unreachable; // invalid api usage (system sources must not be manually deleted)

                try self.ctx.db.?.exec(
                    "delete from tag_sources where type = ? and id = ?",
                    .{},
                    .{ @enumToInt(TagSourceType.external), self.id },
                );
            }
        };

        pub const FileTag = struct {
            core: Hash,
            source: Source,
            parent_source_id: ?i64,
        };

        /// Returns all tag core hashes for the file.
        pub fn fetchTags(self: FileSelf, allocator: std.mem.Allocator) ![]FileTag {
            var stmt = try self.ctx.db.?.prepare(
                \\ select hashes.id, hashes.hash_data, tag_source_type, tag_source_id, parent_source_id
                \\ from tag_files
                \\ join hashes
                \\ 	on tag_files.core_hash = hashes.id
                \\ where tag_files.file_hash = ?
            );
            defer stmt.deinit();

            const rows = try stmt.all(
                struct {
                    id: ID.SQL,
                    hash_data: sqlite.Blob,
                    tag_source_type: i64,
                    tag_source_id: i64,
                    parent_source_id: ?i64,
                },
                allocator,
                .{},
                .{self.hash.id.sql()},
            );
            defer {
                for (rows) |row| allocator.free(row.hash_data.data);
                allocator.free(rows);
            }

            var list = std.ArrayList(FileTag).init(allocator);
            defer list.deinit();

            for (rows) |row| {
                const hash_with_blob = HashSQL{ .id = row.id, .hash_data = row.hash_data };

                const file_tag = FileTag{
                    .core = hash_with_blob.toRealHash(),
                    .source = Source{
                        .ctx = self.ctx,
                        .kind = @intToEnum(TagSourceType, row.tag_source_type),
                        .id = row.tag_source_id,
                    },
                    .parent_source_id = row.parent_source_id,
                };

                try list.append(file_tag);
            }

            return try list.toOwnedSlice();
        }

        pub fn printTagsTo(
            self: FileSelf,
            allocator: std.mem.Allocator,
            writer: anytype,
        ) !void {
            var file_tags = try self.fetchTags(allocator);
            defer allocator.free(file_tags);

            for (file_tags) |file_tag| {
                // TODO some kind of stack buffer that lives outside of this
                // loop so its faster?
                var tags = try self.ctx.fetchTagsFromCore(allocator, file_tag.core);
                defer tags.deinit();
                for (tags.items) |tag| {
                    try writer.print(" '{s}'", .{tag});
                }
            }
        }

        pub fn fetchPools(self: FileSelf, allocator: std.mem.Allocator) ![]Hash {
            _ = self;
            _ = allocator;
            std.debug.todo("impl");
        }
    };

    const TagSourceOptions = struct {};

    pub fn createTagSource(self: *Self, name: []const u8, options: TagSourceOptions) !File.Source {
        _ = options;

        logger.debug("create tag source '{s}'", .{name});

        // fetch max id, do max(id) + 1
        // TODO (before merge) is this a good idea for ids?
        //   maybe a tag core-ish kind of deal would be better...

        const manual_source_max_id = (try self.db.?.one(i64, "select max(id) from tag_sources where type = 1", .{}, .{})) orelse 0;

        const source_id = manual_source_max_id + 1;

        try self.db.?.exec(
            "insert into tag_sources (type, id, name) values (?, ?, ?)",
            .{},
            .{ @enumToInt(TagSourceType.external), source_id, name },
        );

        return File.Source{ .ctx = self, .kind = .external, .id = source_id };
    }

    pub fn fetchTagSource(self: *Self, kind: TagSourceType, id: i64) !?File.Source {
        return switch (kind) {
            .system => {
                _ = std.meta.intToEnum(SystemTagSources, id) catch |err| switch (err) {
                    error.InvalidEnumTag => return null,
                };
                return File.Source{ .ctx = self, .kind = .system, .id = id };
            },
            .external => {
                const maybe_row = try self.db.?.one(
                    struct { type: i64, id: i64 },
                    "select type, id from tag_sources where type = ? and id = ?",
                    .{},
                    .{ @enumToInt(TagSourceType.external), id },
                );

                if (maybe_row) |row| {
                    return File.Source{ .ctx = self, .kind = .external, .id = row.id };
                } else {
                    return null;
                }
            },
        };
    }

    pub const CreateFileOptions = struct {
        use_file_timestamp: bool = false,
    };

    /// Caller owns returned memory.
    pub fn createFileFromPath(self: *Self, local_path: []const u8, options: CreateFileOptions) !File {
        const absolute_local_path = try std.fs.realpathAlloc(self.allocator, local_path);
        var possible_file_entry = try self.fetchFileByPath(absolute_local_path);
        if (possible_file_entry) |file_entry| {
            // fetchFileByPath dupes the string so we need to free it here
            defer self.allocator.free(absolute_local_path);
            return file_entry;
        }

        var file = try std.fs.openFileAbsolute(absolute_local_path, .{ .mode = .read_only });
        defer file.close();

        var file_hash: Hash = try self.calculateHash(file, .{
            .use_file_timestamp = options.use_file_timestamp,
        });
        return try self.insertFile(file_hash, absolute_local_path);
    }

    pub const CalculateHashOptions = struct {
        insert_new_hash: bool = true,
        use_file_timestamp: bool = false,
    };

    pub fn fetchHashId(self: *Self, blob: sqlite.Blob) !?ID {
        const maybe_id_bytes = try self.db.?.one(
            ID.SQL,
            "select id from hashes where hash_data = ?",
            .{},
            .{blob},
        );
        return if (maybe_id_bytes) |id_bytes| ID.new(id_bytes) else null;
    }

    /// if the file is not indexed and options.insert_new_hash is false,
    /// do not rely on the returned hash's id object making any sense.
    pub fn calculateHash(self: *Self, file: std.fs.File, options: CalculateHashOptions) !Hash {
        var data_chunk_buffer: [8192]u8 = undefined;
        var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
        while (true) {
            const bytes_read = try file.read(&data_chunk_buffer);
            if (bytes_read == 0) break;
            const data_chunk = data_chunk_buffer[0..bytes_read];
            hasher.update(data_chunk);
        }

        var file_hash: Hash = undefined;
        hasher.final(&file_hash.hash_data);

        const hash_blob = sqlite.Blob{ .data = &file_hash.hash_data };
        const maybe_hash_id = try self.fetchHashId(hash_blob);
        if (maybe_hash_id) |hash_id| {
            file_hash.id = hash_id;
        } else {
            if (options.insert_new_hash) {
                if (options.use_file_timestamp) {
                    const stat = try file.stat();
                    const timestamp_as_milliseconds = @divTrunc(stat.ctime, std.time.ns_per_ms);
                    file_hash.id = try self.createHash(hash_blob, .{
                        .milliTimestamp = timestamp_as_milliseconds,
                    });
                } else {
                    file_hash.id = try self.createHash(hash_blob, .{});
                }
            } else {
                file_hash.id = .{ .data = undefined };
            }
        }

        return file_hash;
    }

    pub fn calculateHashFromMemory(self: *Self, block: []const u8, options: CalculateHashOptions) !Hash {
        var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
        hasher.update(block);

        var hash_entry: Hash = undefined;
        hasher.final(&hash_entry.hash_data);

        const hash_blob = sqlite.Blob{ .data = &hash_entry.hash_data };
        const maybe_hash_id = try self.fetchHashId(hash_blob);
        if (maybe_hash_id) |hash_id| {
            hash_entry.id = hash_id;
        } else {
            // TODO remove insertion capabilities from this API,
            // as it is only used to double check against tag cores in the janitor
            if (options.insert_new_hash) {
                hash_entry.id = try self.createHash(hash_blob, .{});
            } else {
                hash_entry.id = .{ .data = undefined };
            }
        }

        return hash_entry;
    }

    fn insertFile(
        self: *Self,
        file_hash: Hash,
        absolute_local_path: []const u8,
    ) !File {
        try self.db.?.exec(
            "insert into files (file_hash, local_path) values (?, ?) on conflict do nothing",
            .{},
            .{ file_hash.id.sql(), absolute_local_path },
        );
        logger.debug("created file entry hash={s} path={s}", .{
            absolute_local_path,
            file_hash,
        });

        return File{
            .ctx = self,
            .local_path = absolute_local_path,
            .hash = file_hash,
        };
    }

    pub fn createFileFromDir(
        self: *Self,
        dir: std.fs.Dir,
        dir_path: []const u8,
        options: CreateFileOptions,
    ) !File {
        var file = try dir.openFile(dir_path, .{ .mode = .read_only });
        defer file.close();
        const absolute_local_path = try dir.realpathAlloc(self.allocator, dir_path);

        var possible_file_entry = try self.fetchFileByPath(absolute_local_path);
        if (possible_file_entry) |file_entry| {
            // fetchFileByPath dupes the string so we need to free it here
            defer self.allocator.free(absolute_local_path);
            return file_entry;
        }

        var file_hash: Hash = try self.calculateHash(file, .{
            .use_file_timestamp = options.use_file_timestamp,
        });
        return try self.insertFile(file_hash, absolute_local_path);
    }

    // TODO create fetchFileFromHash that receives full hash object and automatically
    // prefers hash instead of id-search
    pub fn fetchFile(self: *Self, hash_id: ID) !?File {
        var maybe_local_path = try self.db.?.oneAlloc(
            struct {
                local_path: []const u8,
                hash_data: sqlite.Blob,
            },
            self.allocator,
            \\ select local_path, hashes.hash_data
            \\ from files
            \\ join hashes
            \\ 	on files.file_hash = hashes.id
            \\ where files.file_hash = ?
        ,
            .{},
            .{hash_id.sql()},
        );

        if (maybe_local_path) |*local_path| {
            // string memory is passed to client
            defer self.allocator.free(local_path.hash_data.data);

            const almost_good_hash = HashSQL{
                .id = hash_id.data,
                .hash_data = local_path.hash_data,
            };
            return File{
                .ctx = self,
                .local_path = local_path.local_path,
                .hash = almost_good_hash.toRealHash(),
            };
        } else {
            return null;
        }
    }

    pub fn fetchFileExact(self: *Self, hash_id: ID, given_local_path: []const u8) !?File {
        var maybe_local_path = try self.db.?.oneAlloc(
            struct {
                local_path: []const u8,
                hash_data: sqlite.Blob,
            },
            self.allocator,
            \\ select files.local_path, hashes.hash_data
            \\ from files
            \\ join hashes
            \\ 	on files.file_hash = hashes.id
            \\ where files.file_hash = ? and files.local_path = ?
        ,
            .{},
            .{ hash_id.sql(), given_local_path },
        );

        if (maybe_local_path) |*local_path| {
            // string memory is passed to client
            defer self.allocator.free(local_path.hash_data.data);

            const almost_good_hash = HashSQL{
                .id = hash_id.data,
                .hash_data = local_path.hash_data,
            };
            return File{
                .ctx = self,
                .local_path = local_path.local_path,
                .hash = almost_good_hash.toRealHash(),
            };
        } else {
            return null;
        }
    }

    pub fn fetchFileByHash(self: *Self, hash_data: [32]u8) !?File {
        const hash_blob = sqlite.Blob{ .data = &hash_data };

        var maybe_local_path = try self.db.?.oneAlloc(
            struct {
                local_path: []const u8,
                hash_id: ID.SQL,
            },
            self.allocator,
            \\ select local_path, hashes.id
            \\ from files
            \\ join hashes
            \\ 	on files.file_hash = hashes.id
            \\ where hashes.hash_data = ?
        ,
            .{},
            .{hash_blob},
        );

        if (maybe_local_path) |*local_path| {
            return File{
                .ctx = self,
                .local_path = local_path.local_path,
                .hash = Hash{
                    .id = ID.new(local_path.hash_id),
                    .hash_data = hash_data,
                },
            };
        } else {
            return null;
        }
    }

    pub fn fetchFileByPath(self: *Self, absolute_local_path: []const u8) !?File {
        var maybe_hash = try self.db.?.oneAlloc(
            HashSQL,
            self.allocator,
            \\ select hashes.id, hashes.hash_data
            \\ from files
            \\ join hashes
            \\ 	on files.file_hash = hashes.id
            \\ where files.local_path = ?
        ,
            .{},
            .{absolute_local_path},
        );

        if (maybe_hash) |hash| {
            // string memory is passed to client
            defer self.allocator.free(hash.hash_data.data);
            return File{
                .ctx = self,
                .local_path = try self.allocator.dupe(u8, absolute_local_path),
                .hash = hash.toRealHash(),
            };
        } else {
            return null;
        }
    }

    pub fn createTagParent(self: *Self, child_tag: Tag, parent_tag: Tag) !i64 {
        return (try self.db.?.one(
            i64,
            "insert into tag_implications (child_tag, parent_tag) values (?, ?) returning rowid",
            .{},
            .{ child_tag.core.id.sql(), parent_tag.core.id.sql() },
        )).?;
    }

    fn processSingleFileIntoTagTree(self: *Self, file_hash: ID, treemap: TagTreeMap) !void {
        var file = (try self.fetchFile(file_hash)).?;
        defer file.deinit();

        const TagEntry = struct {
            tag_id: ID,
            parent_entry_id: RowID,
        };
        const TagSet = std.AutoHashMap(TagEntry, void);
        var tags_to_add = TagSet.init(self.allocator);
        defer tags_to_add.deinit();

        var file_tags = try file.fetchTags(self.allocator);
        defer self.allocator.free(file_tags);

        while (true) {
            const old_tags_to_add_len = tags_to_add.count();

            for (file_tags) |file_tag| {
                var maybe_parents = treemap.get(file_tag.core.id);
                if (maybe_parents) |parents| {
                    for (parents) |parent| {
                        try tags_to_add.put(.{
                            .tag_id = parent.tag_id,
                            .parent_entry_id = parent.row_id,
                        }, {});
                    }
                }
            }

            // "recurse" into the tree by running the same loop
            // until the list doesnt change size

            var tags_iter = tags_to_add.iterator();
            while (tags_iter.next()) |entry| {
                var maybe_parents = treemap.get(entry.key_ptr.*.tag_id);
                if (maybe_parents) |parents| {
                    for (parents) |parent| {
                        try tags_to_add.put(.{
                            .tag_id = parent.tag_id,
                            .parent_entry_id = parent.row_id,
                        }, {});
                    }
                }
            }

            const new_tags_to_add_len = tags_to_add.count();
            if (old_tags_to_add_len == new_tags_to_add_len) break;
        }

        var tags_iter = tags_to_add.iterator();
        while (tags_iter.next()) |entry| {
            const tag_entry = entry.key_ptr.*;
            // don't need to readd tags that are already in
            // (prevent db locking i/o)
            var already_has_it = false;
            for (file_tags) |file_tag| {
                if (std.meta.eql(tag_entry.tag_id, file_tag.core.id)) already_has_it = true;
            }
            if (already_has_it) continue;

            try file.addTag(.{ .id = tag_entry.tag_id, .hash_data = undefined }, .{
                .source = try self.fetchTagSource(.system, @enumToInt(SystemTagSources.tag_parenting)),
                .parent_source_id = tag_entry.parent_entry_id,
            });
        }
    }

    const ProcessTagTreeOptions = struct {
        /// Only process the given file ids.
        ///
        /// Useful if you are ainclude(1) and don't want to process the entire
        /// file database.
        files: ?[]ID = null,
    };

    const TagTreeEntry = struct { tag_id: ID, row_id: RowID };
    const TagTreeMap = std.AutoHashMap(ID, []TagTreeEntry);

    pub fn processTagTree(self: *Self, options: ProcessTagTreeOptions) !void {
        logger.info("processing tag tree...", .{});

        var tree_stmt = try self.db.?.prepare(
            "select rowid, child_tag, parent_tag from tag_implications",
        );
        defer tree_stmt.deinit();
        var tree_rows = try tree_stmt.all(
            struct { row_id: RowID, child_tag: ID.SQL, parent_tag: ID.SQL },
            self.allocator,
            .{},
            .{},
        );
        defer self.allocator.free(tree_rows);

        var treemap = TagTreeMap.init(self.allocator);
        defer {
            var iter = treemap.iterator();
            while (iter.next()) |entry| self.allocator.free(entry.value_ptr.*);
            treemap.deinit();
        }

        for (tree_rows) |tree_row| {
            const child_tag = ID.new(tree_row.child_tag);
            const maybe_parents = treemap.get(child_tag);
            if (maybe_parents) |parents| {
                // realloc
                var new_parents = try self.allocator.alloc(TagTreeEntry, parents.len + 1);
                std.mem.copy(TagTreeEntry, new_parents, parents);
                new_parents[new_parents.len - 1] = .{
                    .tag_id = ID.new(tree_row.parent_tag),
                    .row_id = tree_row.row_id,
                };
                self.allocator.free(parents);
                try treemap.put(child_tag, new_parents);
            } else {
                var new_parents = try self.allocator.alloc(TagTreeEntry, 1);
                new_parents[0] = .{
                    .tag_id = ID.new(tree_row.parent_tag),
                    .row_id = tree_row.row_id,
                };
                try treemap.put(child_tag, new_parents);
            }
        }

        if (options.files) |files_array| {
            for (files_array) |file_hash| {
                try self.processSingleFileIntoTagTree(file_hash, treemap);
            }
        } else {
            var stmt = try self.db.?.prepare(
                \\ select file_hash
                \\ from files
            );
            defer stmt.deinit();

            const FileRow = struct {
                file_hash: ID.SQL,
            };
            var iter = try stmt.iterator(
                FileRow,
                .{},
            );

            while (try iter.next(.{})) |file_row| {
                const file_hash = ID.new(file_row.file_hash);
                try self.processSingleFileIntoTagTree(file_hash, treemap);
            }
        }
    }

    pub const Pool = struct {
        ctx: *Context,
        hash: Hash,
        title: []const u8,

        const PoolSelf = @This();

        pub fn deinit(self: PoolSelf) void {
            self.ctx.allocator.free(self.title);
        }

        fn availableIndex(self: PoolSelf) !usize {
            const maybe_max_index = try self.ctx.db.?.one(
                usize,
                "select max(entry_index) from pool_entries where pool_hash = ?",
                .{},
                .{self.hash.id.sql()},
            );

            return if (maybe_max_index) |max_index| max_index + 1 else 0;
        }

        pub fn delete(self: PoolSelf) !void {
            try self.ctx.db.?.exec(
                "delete from pools where pool_hash = ?",
                .{},
                .{self.hash.id.sql()},
            );
        }

        pub fn addFile(self: PoolSelf, file_id: ID) !void {
            const index = try self.availableIndex();
            logger.warn("adding file {d} to pool {d} index {d}", .{ file_id, self.hash.id, index });
            try self.ctx.db.?.exec(
                "insert into pool_entries (file_hash, pool_hash, entry_index) values (?, ?, ?)",
                .{},
                .{ file_id.sql(), self.hash.id.sql(), index },
            );
        }

        pub fn removeFile(self: PoolSelf, file_id: ID) !void {
            try self.ctx.db.?.exec(
                "delete from pool_entries where file_hash = ? and pool_hash = ?",
                .{},
                .{ file_id.sql(), self.hash.id.sql() },
            );
        }

        pub fn addFileAtIndex(
            self: PoolSelf,
            new_file_id: ID,
            index: usize,
        ) !void {
            var all_file_hashes = try self.fetchFiles(self.ctx.allocator);
            defer self.ctx.allocator.free(all_file_hashes);

            var all_hash_ids = std.ArrayList(ID).init(self.ctx.allocator);
            defer all_hash_ids.deinit();
            for (all_file_hashes) |hash| try all_hash_ids.append(hash.id);

            try all_hash_ids.insert(index, new_file_id);

            // now we need to insert this *somewhere* in the table
            //
            // the "safest" way (in terms of DB consistency) to do so is to
            // delete all pool_entries then reinsert them with the newly
            // calculated indexes
            //
            // it's expensive, but the preffered API will always be
            // addFile/removeFile which should be "blazing-fast"

            {
                var savepoint = try self.ctx.db.?.savepoint("pool_add_at_index");
                errdefer savepoint.rollback();
                defer savepoint.commit();

                try self.ctx.db.?.exec(
                    "delete from pool_entries where pool_hash = ?",
                    .{},
                    .{self.hash.id.sql()},
                );
                for (all_hash_ids.items) |pool_file_id, pool_index| {
                    try self.ctx.db.?.exec(
                        "insert into pool_entries (file_hash, pool_hash, entry_index) values (?, ?, ?)",
                        .{},
                        .{ pool_file_id.sql(), self.hash.id.sql(), pool_index },
                    );
                }
            }
        }

        pub fn fetchFiles(self: PoolSelf, allocator: std.mem.Allocator) ![]Hash {
            // TODO decrease repetition between this and File.fetchTags

            var diags = sqlite.Diagnostics{};
            var stmt = self.ctx.db.?.prepareWithDiags(
                \\ select hashes.id, hashes.hash_data
                \\ from pool_entries
                \\ join hashes
                \\ 	on pool_entries.file_hash = hashes.id
                \\ where pool_entries.pool_hash = ?
                \\ order by pool_entries.entry_index asc
            , .{ .diags = &diags }) catch |err| {
                logger.err("unable to prepare statement, got error {}. diagnostics: {s}", .{ err, diags });
                return err;
            };
            defer stmt.deinit();

            const internal_hashes = try stmt.all(
                HashSQL,
                allocator,
                .{},
                .{self.hash.id.sql()},
            );
            defer {
                for (internal_hashes) |hash| allocator.free(hash.hash_data.data);
                allocator.free(internal_hashes);
            }

            var list = HashList.init(allocator);
            defer list.deinit();

            for (internal_hashes) |hash| {
                try list.append(hash.toRealHash());
            }

            return try list.toOwnedSlice();
        }
    };

    pub fn createPool(self: *Self, title: []const u8) !Pool {
        // TODO decrease repetition with createNamedTag
        var core_data: [64]u8 = undefined;
        self.randomCoreData(&core_data);

        var core_hash_bytes: Blake3Hash = undefined;
        var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
        hasher.update(&core_data);
        hasher.final(&core_hash_bytes);

        var savepoint = try self.db.?.savepoint("pool_core");
        errdefer savepoint.rollback();
        defer savepoint.commit();

        const hash_blob = sqlite.Blob{ .data = &core_hash_bytes };
        const core_hash_id = try self.createHash(hash_blob, .{});

        // core_hash_bytes is passed by reference here, so we don't
        // have to worry about losing it to undefined memory hell.

        const core_data_blob = sqlite.Blob{ .data = &core_data };
        try self.db.?.exec(
            "insert into pools (pool_hash, pool_core_data, title) values (?, ?, ?)",
            .{},
            .{ core_hash_id.sql(), core_data_blob, title },
        );

        var pool_hash = Hash{ .id = core_hash_id, .hash_data = core_hash_bytes };
        logger.debug("created pool with hash {s}", .{pool_hash});
        return Pool{
            .ctx = self,
            .hash = pool_hash,
            .title = try self.allocator.dupe(u8, title),
        };
    }

    pub fn fetchPool(self: *Self, hash_id: ID) !?Pool {
        var maybe_pool = try self.db.?.oneAlloc(
            struct {
                title: []const u8,
                hash_data: sqlite.Blob,
            },
            self.allocator,
            \\ select title, hashes.hash_data
            \\ from pools
            \\ join hashes
            \\ 	on pools.pool_hash = hashes.id
            \\ where pools.pool_hash = ?
        ,
            .{},
            .{hash_id.sql()},
        );

        if (maybe_pool) |*pool| {
            // string memory is passed to client
            defer self.allocator.free(pool.hash_data.data);

            const almost_good_hash = HashSQL{
                .id = hash_id.data,
                .hash_data = pool.hash_data,
            };
            return Pool{
                .ctx = self,
                .hash = almost_good_hash.toRealHash(),
                .title = pool.title,
            };
        } else {
            return null;
        }
    }

    pub fn createCommand(self: *Self) !void {
        try self.loadDatabase(.{ .create = true });
        try self.migrateCommand();
    }

    pub fn migrateCommand(self: *Self) !void {
        try self.loadDatabase(.{});

        // migration log table is forever
        try self.db.?.exec(MIGRATION_LOG_TABLE, .{}, .{});

        const current_version: i32 = (try self.db.?.one(i32, "select max(version) from migration_logs", .{}, .{})) orelse 0;
        logger.info("db version: {d}", .{current_version});

        // before running migrations, copy the database over

        if (self.db_path) |db_path| {
            const backup_db_path = try std.fs.path.resolve(
                self.allocator,
                &[_][]const u8{ self.home_path.?, ".awtf.before-migration.db" },
            );
            defer self.allocator.free(backup_db_path);
            logger.info("starting transaction for backup from {s} to {s}", .{ db_path, backup_db_path });

            try self.db.?.exec("begin exclusive transaction", .{}, .{});
            errdefer {
                self.db.?.exec("rollback transaction", .{}, .{}) catch |err| {
                    const detailed_error = self.db.?.getDetailedError();
                    std.debug.panic(
                        "unable to rollback transaction, error: {}, message: {s}\n",
                        .{ err, detailed_error },
                    );
                };
            }
            defer {
                self.db.?.exec("commit transaction", .{}, .{}) catch |err| {
                    const detailed_error = self.db.?.getDetailedError();
                    std.debug.panic(
                        "unable to commit transaction, error: {}, message: {s}\n",
                        .{ err, detailed_error },
                    );
                };
            }

            logger.info("copying database to {s}", .{backup_db_path});
            try std.fs.copyFileAbsolute(db_path, backup_db_path, .{});
        }

        {
            var savepoint = try self.db.?.savepoint("migrations");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            inline for (MIGRATIONS) |migration_decl| {
                const migration = Migration.fromTuple(migration_decl);

                if (current_version < migration.version) {
                    logger.info("running migration {d} '{s}'", .{ migration.version, migration.name });

                    if (migration.sql) |migration_sql| {
                        var diags = sqlite.Diagnostics{};
                        self.db.?.execMulti(migration_sql, .{ .diags = &diags }) catch |err| {
                            logger.err(
                                "unable to prepare statement, got error {s}. diagnostics: {s}",
                                .{ @errorName(err), diags },
                            );
                            return err;
                        };
                    } else {
                        try migration.options.function.?(self);
                    }

                    try self.db.?.exec(
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

        const val = (try self.db.?.one(i64, "PRAGMA integrity_check", .{}, .{})) orelse return error.PossiblyFailedIntegrityCheck;
        logger.debug("integrity check returned {d}", .{val});
        try self.db.?.exec("PRAGMA foreign_key_check", .{}, .{});
    }

    pub fn statsCommand(self: *Self) !void {
        try self.loadDatabase(.{});
    }

    pub fn jobsCommand(self: *Self) !void {
        try self.loadDatabase(.{});
    }
};

pub export fn sqliteLog(_: ?*anyopaque, level: c_int, message: ?[*:0]const u8) callconv(.C) void {
    logger.warn("sqlite logged level={d} msg={?s}", .{ level, message });
}

pub const log_level = .debug;

pub var current_log_level: std.log.Level = .info;

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@enumToInt(message_level) <= @enumToInt(@import("root").current_log_level)) {
        std.log.defaultLog(message_level, scope, format, args);
    }
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        logger.err("failed to configure: {d} '{s}'", .{
            rc, sqlite.c.sqlite3_errstr(rc),
        });
        return error.ConfigFail;
    }

    var args_it = std.process.args();
    _ = args_it.skip();
    const stdout = std.io.getStdOut();

    const Args = struct {
        help: bool = false,
        verbose: bool = false,
        version: bool = false,
        maybe_action: ?[]const u8 = null,
    };

    var given_args = Args{};
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            given_args.verbose = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            given_args.maybe_action = arg;
        }
    }

    if (given_args.help) {
        try stdout.writer().print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        try stdout.writer().print("awtfdb-manage 0.0.1\n", .{});
        return;
    }

    if (given_args.verbose) {
        current_log_level = .debug;
    }

    if (given_args.maybe_action == null) {
        logger.err("action argument is required", .{});
        return error.MissingActionArgument;
    }

    var ctx = Context{
        .home_path = null,
        .args_it = &args_it,
        .stdout = stdout,
        .allocator = allocator,
        .db = null,
    };
    defer ctx.deinit();

    const action = given_args.maybe_action.?;
    if (std.mem.eql(u8, action, "create")) {
        try ctx.createCommand();
    } else if (std.mem.eql(u8, action, "migrate")) {
        try ctx.migrateCommand();
    } else {
        logger.err("unknown action {s}", .{action});
        return error.UnknownAction;
    }
}

pub var test_db_path_buffer: [std.os.PATH_MAX]u8 = undefined;

pub var test_set_log = false;

pub fn makeTestContext() !Context {
    if (!test_set_log) {
        _ = sqlite.c.sqlite3_shutdown();

        const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, sqliteLog, @as(?*anyopaque, null));
        test_set_log = true;
        if (rc != sqlite.c.SQLITE_OK) {
            logger.err("failed to configure ({}): {d} '{s}'", .{
                test_set_log, rc, sqlite.c.sqlite3_errstr(rc),
            });
            return error.ConfigFail;
        }
        _ = sqlite.c.sqlite3_initialize();
    }

    const homepath = try std.fs.cwd().realpath(".", &test_db_path_buffer);
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

    try ctx.createCommand();

    return ctx;
}

/// Create a test context backed up by a real file, rather than memory.
pub fn makeTestContextRealFile() !Context {
    var tmp = std.testing.tmpDir(.{});
    // lol, lmao, etc
    //defer tmp.cleanup();

    const homepath = try tmp.dir.realpath(".", &test_db_path_buffer);

    var file = try tmp.dir.createFile("test.db", .{});
    defer file.close();
    const dbpath = try tmp.dir.realpath("test.db", test_db_path_buffer[homepath.len..]);

    logger.warn("using test context database file '{s}'", .{dbpath});

    var ctx = Context{
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = std.testing.allocator,
        .home_path = homepath,
        .db_path = try std.testing.allocator.dupe(u8, dbpath),
    };

    try ctx.createCommand();

    return ctx;
}

test "basic db initialization" {
    var ctx = try makeTestContext();
    defer ctx.deinit();
}

test "tag creation" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tag = try ctx.createNamedTag("test_tag", "en", null);
    var fetched_tag = (try ctx.fetchNamedTag("test_tag", "en")).?;

    try std.testing.expectEqualStrings("test_tag", tag.kind.Named.text);
    try std.testing.expectEqualStrings("en", tag.kind.Named.language);
    try std.testing.expectEqualStrings("test_tag", fetched_tag.kind.Named.text);
    try std.testing.expectEqualStrings("en", fetched_tag.kind.Named.language);

    try std.testing.expectEqual(tag.core.id, fetched_tag.core.id);
    try std.testing.expectEqualStrings(tag.core.hash_data[0..], fetched_tag.core.hash_data[0..]);

    var same_core_tag = try ctx.createNamedTag("another_test_tag", "en", tag.core);
    var fetched_same_core_tag = (try ctx.fetchNamedTag("another_test_tag", "en")).?;
    try std.testing.expectEqualStrings(tag.core.hash_data[0..], same_core_tag.core.hash_data[0..]);
    try std.testing.expectEqualStrings(fetched_tag.core.hash_data[0..], fetched_same_core_tag.core.hash_data[0..]);

    var tags_from_core = try ctx.fetchTagsFromCore(std.testing.allocator, tag.core);
    defer tags_from_core.deinit();

    try std.testing.expectEqual(@as(usize, 2), tags_from_core.items.len);
    try std.testing.expectEqualStrings(tag.core.hash_data[0..], tags_from_core.items[0].core.hash_data[0..]);
    try std.testing.expectEqualStrings(tag.core.hash_data[0..], tags_from_core.items[1].core.hash_data[0..]);

    const deleted_tags = try tag.deleteAll(&ctx.db.?);
    try std.testing.expectEqual(@as(usize, 2), deleted_tags);

    var tags_from_core_after_deletion = try ctx.fetchTagsFromCore(std.testing.allocator, tag.core);
    defer tags_from_core_after_deletion.deinit();

    try std.testing.expectEqual(@as(usize, 0), tags_from_core_after_deletion.items.len);
}

test "file creation" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file", .{});
    defer indexed_file.deinit();

    try std.testing.expect(std.mem.endsWith(u8, indexed_file.local_path, "/test_file"));

    // also try to create indexed file via absolute path
    const full_tmp_file = try tmp.dir.realpathAlloc(std.testing.allocator, "test_file");
    defer std.testing.allocator.free(full_tmp_file);
    var path_indexed_file = try ctx.createFileFromPath(full_tmp_file, .{});
    defer path_indexed_file.deinit();

    try std.testing.expectStringEndsWith(path_indexed_file.local_path, "/test_file");
    try std.testing.expectEqual(indexed_file.hash.id, path_indexed_file.hash.id);
    try std.testing.expectEqualStrings(indexed_file.hash.hash_data[0..], path_indexed_file.hash.hash_data[0..]);

    var fetched_file = (try ctx.fetchFile(indexed_file.hash.id)).?;
    defer fetched_file.deinit();
    try std.testing.expectStringEndsWith(fetched_file.local_path, "/test_file");
    try std.testing.expectEqual(indexed_file.hash.id, fetched_file.hash.id);
    try std.testing.expectEqualStrings(indexed_file.hash.hash_data[0..], fetched_file.hash.hash_data[0..]);

    var fetched_by_path_file = (try ctx.fetchFileByPath(indexed_file.local_path)).?;
    defer fetched_by_path_file.deinit();
    try std.testing.expectStringEndsWith(fetched_by_path_file.local_path, "/test_file");
    try std.testing.expectEqual(indexed_file.hash.id, fetched_by_path_file.hash.id);
    try std.testing.expectEqualStrings(indexed_file.hash.hash_data[0..], fetched_by_path_file.hash.hash_data[0..]);

    var fetched_by_exact_combo = (try ctx.fetchFileExact(indexed_file.hash.id, indexed_file.local_path)).?;
    defer fetched_by_exact_combo.deinit();
    try std.testing.expectEqual(indexed_file.hash.id, fetched_by_exact_combo.hash.id);
    try std.testing.expectEqualStrings(indexed_file.hash.hash_data[0..], fetched_by_exact_combo.hash.hash_data[0..]);

    try indexed_file.delete();
    try std.testing.expectEqual(@as(?Context.File, null), try ctx.fetchFile(indexed_file.hash.id));
}

test "file and tags" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file", .{});
    defer indexed_file.deinit();

    var tag = try ctx.createNamedTag("test_tag", "en", null);

    // add tag
    try indexed_file.addTag(tag.core, .{});

    var file_tags = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(file_tags);

    var saw_correct_tag_core = false;
    for (file_tags) |file_tag| {
        if (std.mem.eql(u8, &tag.core.hash_data, &file_tag.core.hash_data)) {
            saw_correct_tag_core = true;
        }
    }
    try std.testing.expect(saw_correct_tag_core);

    // remove tag
    try indexed_file.removeTag(tag.core);

    var file_tags_after_removal = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(file_tags_after_removal);
    for (file_tags_after_removal) |file_tag| {
        if (std.mem.eql(u8, &tag.core.hash_data, &file_tag.core.hash_data))
            return error.TagShouldNotBeThere;
    }
}

test "in memory database" {
    var ctx = try makeTestContextRealFile();
    defer ctx.deinit();

    var tag1 = try ctx.createNamedTag("test_tag", "en", null);
    _ = tag1;

    try ctx.turnIntoMemoryDb();

    var tag1_inmem = try ctx.fetchNamedTag("test_tag", "en");
    try std.testing.expect(tag1_inmem != null);

    var tag2 = try ctx.createNamedTag("test_tag2", "en", null);
    _ = tag2;

    var tag2_inmem = try ctx.fetchNamedTag("test_tag2", "en");
    try std.testing.expect(tag2_inmem != null);

    ctx.db.?.deinit();
    ctx.db = null;
    try ctx.loadDatabase(.{});

    var tag2_infile = try ctx.fetchNamedTag("test_tag2", "en");
    try std.testing.expect(tag2_infile == null);
}

test "tag parenting" {
    var ctx = try makeTestContextRealFile();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file", .{});
    defer indexed_file.deinit();

    var child_tag = try ctx.createNamedTag("child_test_tag", "en", null);
    try indexed_file.addTag(child_tag.core, .{});

    // only add this through inferrence
    var parent_tag = try ctx.createNamedTag("parent_test_tag", "en", null);
    var parent_tag2 = try ctx.createNamedTag("parent_test_tag2", "en", null);
    var parent_tag3 = try ctx.createNamedTag("parent_test_tag3", "en", null);
    const tag_tree_entry_id = try ctx.createTagParent(child_tag, parent_tag);
    const tag_tree_entry2_id = try ctx.createTagParent(child_tag, parent_tag2);
    const tag_tree_entry3_id = try ctx.createTagParent(parent_tag2, parent_tag3);
    try ctx.processTagTree(.{});

    // assert both now exist

    var file_tags = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(file_tags);

    var saw_child = false;
    var saw_parent = false;
    var saw_parent2 = false;
    var saw_parent3 = false;

    for (file_tags) |file_tag| {
        if (std.meta.eql(file_tag.core.id, parent_tag.core.id)) {
            try std.testing.expectEqual(TagSourceType.system, file_tag.source.kind);
            try std.testing.expectEqual(@as(i64, @enumToInt(SystemTagSources.tag_parenting)), file_tag.source.id);
            try std.testing.expectEqual(tag_tree_entry_id, file_tag.parent_source_id.?);
            saw_parent = true;
        }
        if (std.meta.eql(file_tag.core.id, parent_tag2.core.id)) {
            try std.testing.expectEqual(tag_tree_entry2_id, file_tag.parent_source_id.?);
            saw_parent2 = true;
        }
        if (std.meta.eql(file_tag.core.id, parent_tag3.core.id)) {
            try std.testing.expectEqual(tag_tree_entry3_id, file_tag.parent_source_id.?);
            saw_parent3 = true;
        }
        if (std.meta.eql(file_tag.core.id, child_tag.core.id)) saw_child = true;
    }

    try std.testing.expect(saw_parent);
    try std.testing.expect(saw_parent2);
    try std.testing.expect(saw_parent3);
    try std.testing.expect(saw_child);
}

test "file pools" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

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

    var indexed_file1 = try ctx.createFileFromDir(tmp.dir, "test_file1", .{});
    defer indexed_file1.deinit();
    var indexed_file2 = try ctx.createFileFromDir(tmp.dir, "test_file2", .{});
    defer indexed_file2.deinit();
    var indexed_file3 = try ctx.createFileFromDir(tmp.dir, "test_file3", .{});
    defer indexed_file3.deinit();

    var child_tag = try ctx.createNamedTag("child_test_tag", "en", null);
    try indexed_file1.addTag(child_tag.core, .{});
    try indexed_file2.addTag(child_tag.core, .{});
    try indexed_file3.addTag(child_tag.core, .{});

    // create pool
    var pool = try ctx.createPool("this is my test pool title!");
    defer pool.deinit();

    {
        var fetched_pool = (try ctx.fetchPool(pool.hash.id)).?;
        defer fetched_pool.deinit();
        try std.testing.expectEqual(pool.hash.id, fetched_pool.hash.id);
    }

    // add them all, assert its in order
    {
        try pool.addFile(indexed_file3.hash.id);
        try pool.addFile(indexed_file1.hash.id);
        try pool.addFile(indexed_file2.hash.id);

        var file_hashes = try pool.fetchFiles(ctx.allocator);
        defer ctx.allocator.free(file_hashes);

        try std.testing.expectEqual(@as(usize, 3), file_hashes.len);
        try std.testing.expect(std.meta.eql(file_hashes[0].id, indexed_file3.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[1].id, indexed_file1.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[2].id, indexed_file2.hash.id));
    }

    // remove one, assert it remains in order
    {
        try pool.removeFile(indexed_file1.hash.id);

        var file_hashes = try pool.fetchFiles(ctx.allocator);
        defer ctx.allocator.free(file_hashes);

        try std.testing.expectEqual(@as(usize, 2), file_hashes.len);
        try std.testing.expect(std.meta.eql(file_hashes[0].id, indexed_file3.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[1].id, indexed_file2.hash.id));
    }

    // add it again, see it at end
    {
        try pool.addFile(indexed_file1.hash.id);

        var file_hashes = try pool.fetchFiles(ctx.allocator);
        defer ctx.allocator.free(file_hashes);

        try std.testing.expectEqual(@as(usize, 3), file_hashes.len);
        try std.testing.expect(std.meta.eql(file_hashes[0].id, indexed_file3.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[1].id, indexed_file2.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[2].id, indexed_file1.hash.id));
    }

    // remove one, assert it remains in order
    {
        try pool.removeFile(indexed_file1.hash.id);

        var file_hashes = try pool.fetchFiles(ctx.allocator);
        defer ctx.allocator.free(file_hashes);

        try std.testing.expectEqual(@as(usize, 2), file_hashes.len);
        try std.testing.expect(std.meta.eql(file_hashes[0].id, indexed_file3.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[1].id, indexed_file2.hash.id));
    }

    // add it IN A SPECIFIED INDEX, see it at end
    {
        try pool.addFileAtIndex(indexed_file1.hash.id, 0);

        var file_hashes = try pool.fetchFiles(ctx.allocator);
        defer ctx.allocator.free(file_hashes);

        try std.testing.expectEqual(@as(usize, 3), file_hashes.len);
        try std.testing.expect(std.meta.eql(file_hashes[0].id, indexed_file1.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[1].id, indexed_file3.hash.id));
        try std.testing.expect(std.meta.eql(file_hashes[2].id, indexed_file2.hash.id));
    }
}

test "tag source basic" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var source = try ctx.createTagSource("my test tag source", .{});

    var source_fetched_from_id = try ctx.fetchTagSource(.external, source.id);
    try std.testing.expect(source_fetched_from_id != null);

    try source.delete();

    var source_after_delete = try ctx.fetchTagSource(.external, source.id);
    try std.testing.expect(source_after_delete == null);
}

test "tag sources" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file1 = try tmp.dir.createFile("test_file1", .{});
    defer file1.close();
    _ = try file1.write("awooga1");

    var indexed_file1 = try ctx.createFileFromDir(tmp.dir, "test_file1", .{});
    defer indexed_file1.deinit();

    var source = try ctx.createTagSource("my test tag source", .{});

    var source2 = try ctx.createTagSource("my test tag source 2", .{});
    _ = source2;

    var tag1 = try ctx.createNamedTag("child_test_tag", "en", null);
    var tag2 = try ctx.createNamedTag("child_test_tag2", "en", null);

    try indexed_file1.addTag(tag1.core, .{ .source = source });
    try indexed_file1.addTag(tag2.core, .{ .source = null });

    {
        var file_tags = try indexed_file1.fetchTags(std.testing.allocator);
        defer std.testing.allocator.free(file_tags);

        var saw_source = false;
        for (file_tags) |file_tag| {
            if (file_tag.source.id == source.id) saw_source = true;
        }
        try std.testing.expect(saw_source);
    }
}

test "everyone else" {
    std.testing.refAllDecls(@import("./include_main.zig"));
    std.testing.refAllDecls(@import("./find_main.zig"));
    std.testing.refAllDecls(@import("./ls_main.zig"));
    std.testing.refAllDecls(@import("./rm_main.zig"));
    //std.testing.refAllDecls(@import("./hydrus_api_main.zig"));
    std.testing.refAllDecls(@import("./tags_main.zig"));
    std.testing.refAllDecls(@import("./janitor_main.zig"));
    std.testing.refAllDecls(@import("./metrics_main.zig"));
    std.testing.refAllDecls(@import("./test_migrations.zig"));
    std.testing.refAllDecls(@import("./snowflake.zig"));

    if (builtin.os.tag == .linux) {
        std.testing.refAllDecls(@import("./rename_watcher_main.zig"));
    }
}
