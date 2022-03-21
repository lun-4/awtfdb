const std = @import("std");
const sqlite = @import("sqlite");

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
    \\ creating an awtfdb file:
    \\  awtfdb-manage create
    \\
    \\ getting statistics:
    \\  awtfdb-manage stats
    \\
    \\ current running jobs:
    \\  awtfdb-manage jobs
;

const MIGRATIONS = .{
    .{
        1, "initial table",
        \\ -- uniquely identifies a tag in the ENTIRE UNIVERSE!!!
        \\ -- since this uses random data for core_data, and core_hash is blake3
        \\ --
        \\ -- this is not randomly generated UUIDs, of which anyone can cook up 128-bit
        \\ -- numbers out of thin air. using a cryptographic hash function lets us be
        \\ -- sure that we have an universal tag for 'new york' or 'tree', while also
        \\ -- enabling different language representations of the same tag
        \\ -- (since they all reference the core!)
        \\ create table tag_cores (
        \\     core_hash text,
        \\     core_data blob not null,
        \\     constraint tag_cores_pk primary key (core_hash)
        \\ );
        \\ 
        \\ -- files that are imported by bimport/badd are here
        \\ -- this is how we learn that a certain path means a certain hash without
        \\ -- having to recalculate the hash over and over.
        \\ create table files (
        \\     file_hash text not null,
        \\     local_path text not null,
        \\     constraint files_pk primary key (file_hash, local_path)
        \\ );
        \\ 
        \\ -- this is the main tag<->file mapping. to find out which tags a file has,
        \\ -- execute your SELECT here.
        \\ create table tag_files (
        \\     file_hash text not null,
        \\     core_hash text not null,
        \\     constraint tag_files_core_fk foreign key (core_hash)
        \\         references tag_cores (core_hash) on delete cascade,
        \\     constraint tag_files_file_fk foreign key (file_hash)
        \\         references files (file_hash) on delete cascade,
        \\     constraint tag_files_pk primary key (file_hash, core_hash)
        \\ );
        \\ 
        \\ -- this is the main name<->tag mapping. to find out the
        \\ -- UNIVERSALLY RECOGNIZABLE id of a tag name, execute your SELECT here.
        \\ create table tag_names (
        \\     tag_text text not null,
        \\     tag_language text not null,
        \\     core_hash text not null,
        \\     constraint tag_names_core_fk foreign key (core_hash) references tag_cores on delete cascade,
        \\     constraint tag_names_pk primary key (tag_text, tag_language, core_hash)
        \\ );
    },
};

const MIGRATION_LOG_TABLE =
    \\ create table if not exists migration_logs (
    \\     version int primary key,
    \\     applied_at int,
    \\     description text
    \\ );
;

pub const Context = struct {
    home_path: ?[]const u8 = null,
    args_it: *std.process.ArgIterator,
    stdout: std.fs.File,
    allocator: std.mem.Allocator,
    /// Always call loadDatabase before using this attribute.
    db: ?sqlite.Db = null,

    const Self = @This();

    pub fn loadDatabase(self: *Self) !void {
        if (self.db != null) return;

        // try to create the file always. this is done because
        // i give up. tried a lot of things to make sqlite create the db file
        // itself but it just hates me (SQLITE_CANTOPEN my beloathed).

        // TODO other people do exist! (use HOME env var)
        const db_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ self.home_path orelse "/home/luna", "boorufs.db" },
        );
        defer self.allocator.free(db_path);

        {
            var file = try std.fs.cwd().createFile(db_path, .{ .truncate = false });
            defer file.close();
        }
        const db_path_cstr = try std.cstr.addNullByte(self.allocator, db_path);
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
        var result = try self.fetchValue(i32, "select 123;");
        if (result == null or result.? != 123) {
            std.log.err("error on test statement: expected 123, got {d}", .{result});
            return error.TestStatementFailed;
        }
    }

    fn executeOnce(self: *Self, comptime statement: []const u8) !void {
        var stmt = try self.db.?.prepare(statement);
        defer stmt.deinit();
        try stmt.exec(.{}, .{});
    }

    fn fetchValue(self: *Self, comptime T: type, comptime statement: []const u8) !?T {
        var stmt = try self.db.?.prepare(statement);
        defer stmt.deinit();
        return try stmt.one(T, .{}, .{});
    }

    pub fn deinit(self: *Self) void {
        if (self.db != null) {
            self.db.?.deinit();
        }
    }

    const Blake3Hash = [std.crypto.hash.Blake3.digest_length]u8;
    const Blake3HashHex = [std.crypto.hash.Blake3.digest_length * 2]u8;

    const NamedTagValue = struct {
        text: []const u8,
        language: []const u8,
    };

    const Tag = struct {
        core: Blake3HashHex,
        kind: union(enum) {
            Named: NamedTagValue,
        },
    };

    const OwnedTagList = struct {
        allocator: std.mem.Allocator,
        items: []Tag,
        pub fn deinit(self: @This()) void {
            for (self.items) |*tag| {
                switch (tag.kind) {
                    .Named => |named_tag| {
                        self.allocator.free(named_tag.text);
                        self.allocator.free(named_tag.language);
                    },
                }
                self.allocator.destroy(tag);
            }
        }
    };

    const TagList = std.ArrayList(Tag);

    /// Caller owns returned memory.
    pub fn fetchTagsFromCore(self: *Self, allocator: std.mem.Allocator, core_hash: Blake3HashHex) !OwnedTagList {
        var maybe_named_tag = try self.db.?.oneAlloc(
            NamedTagValue,
            allocator,
            "select tag_text, tag_language from tag_names where core_hash = ?",
            .{},
            .{ .core_hash = &core_hash },
        );

        var list = TagList.init(allocator);
        defer list.deinit();

        if (maybe_named_tag) |named_tag| {
            try list.append(Tag{
                .core = core_hash,
                .kind = .{ .Named = named_tag },
            });
        }

        return OwnedTagList{
            .allocator = allocator,
            .items = list.toOwnedSlice(),
        };
    }

    pub fn fetchNamedTag(self: *Self, text: []const u8, language: []const u8) !?Tag {
        var maybe_core_hash = try self.db.?.one(
            Blake3HashHex,
            "select core_hash from tag_names where tag_text = ? and tag_language = ?",
            .{},
            .{ .tag_text = text, .tag_language = language },
        );

        if (maybe_core_hash) |core_hash| {
            return Tag{
                .core = core_hash,
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

    pub fn createNamedTag(self: *Self, text: []const u8, language: []const u8, maybe_core: ?Blake3HashHex) !Tag {
        var core_hash: Blake3HashHex = undefined;
        if (maybe_core) |existing_core_hash| {
            core_hash = existing_core_hash;
        } else {
            var core_data: [1024]u8 = undefined;
            self.randomCoreData(&core_data);

            var core_hash_bytes: Blake3Hash = undefined;

            var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
            hasher.update(&core_data);
            hasher.final(&core_hash_bytes);

            var core_hash_text_buffer: Blake3HashHex = undefined;
            _ = try std.fmt.bufPrint(
                &core_hash_text_buffer,
                "{x}",
                .{std.fmt.fmtSliceHexLower(&core_hash_bytes)},
            );

            const core_hash_text = core_hash_text_buffer[0..(std.crypto.hash.Blake3.digest_length * 2)];

            try self.db.?.exec(
                "insert into tag_cores (core_hash, core_data) values (?, ?)",
                .{},
                .{ .core_hash = core_hash_text, .core_data = &core_data },
            );
            core_hash = core_hash_text.*;

            std.log.debug("created tag core with hash {s}", .{core_hash_text});
        }

        try self.db.?.exec(
            "insert into tag_names (core_hash, tag_text, tag_language) values (?, ?, ?)",
            .{},
            .{ .core_hash = core_hash, .tag_text = text, .tag_language = language },
        );
        std.log.debug("created name tag with value {s} language {s} core {s}", .{ text, language, core_hash });

        return Tag{
            .core = core_hash,
            .kind = .{ .Named = .{ .text = text, .language = language } },
        };
    }

    const File = struct {
        ctx: *Context,
        local_path: []const u8,
        hash: Blake3HashHex,

        const FileSelf = @This();

        pub fn deinit(self: *FileSelf) void {
            self.ctx.allocator.free(self.local_path);
        }

        pub fn addTag(self: *FileSelf, core_hash: Blake3HashHex) !void {
            try self.ctx.db.?.exec(
                "insert into tag_files (core_hash, file_hash) values (?, ?) on conflict do nothing",
                .{},
                .{ .core_hash = &core_hash, .file_hash = &self.hash },
            );
            std.log.debug("link file {s} (hash {s}) with tag core hash {s}", .{ self.local_path, self.hash, core_hash });
        }

        pub fn fetchTags(self: *FileSelf, allocator: std.mem.Allocator) ![]Blake3HashHex {
            var stmt = try self.ctx.db.?.prepare(
                "select core_hash from tag_files where file_hash = ?",
            );
            defer stmt.deinit();

            return try stmt.all(
                [64]u8,
                allocator,
                .{},
                .{ .file_hash = &self.hash },
            );
        }
    };

    /// Caller owns returned memory.
    pub fn createFileFromPath(self: *Self, local_path: []const u8) !File {
        const absolute_local_path = try std.fs.cwd().realpathAlloc(self.allocator, local_path);

        var file_hash_text_buffer: [std.crypto.hash.Blake3.digest_length * 2]u8 = undefined;
        var file_hash_text: Blake3HashHex = undefined;
        {
            var file = try std.fs.openFileAbsolute(absolute_local_path, .{ .mode = .read_only });
            defer file.close();

            var data_chunk_buffer: [1024]u8 = undefined;
            var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
            while (true) {
                const bytes_read = try file.read(&data_chunk_buffer);
                if (bytes_read == 0) break;
                const data_chunk = data_chunk_buffer[0..bytes_read];
                hasher.update(data_chunk);
            }

            var file_hash_bytes: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
            hasher.final(&file_hash_bytes);

            _ = try std.fmt.bufPrint(
                &file_hash_text_buffer,
                "{x}",
                .{std.fmt.fmtSliceHexLower(&file_hash_bytes)},
            );

            file_hash_text = file_hash_text_buffer[0..(std.crypto.hash.Blake3.digest_length * 2)].*;
        }

        try self.db.?.exec(
            "insert into files (file_hash, local_path) values (?, ?) on conflict do nothing",
            .{},
            .{ .file_hash = &file_hash_text, .local_path = absolute_local_path },
        );
        std.log.debug("created file entry hash={s} path={s}", .{
            absolute_local_path,
            file_hash_text,
        });

        return File{
            .ctx = self,
            .local_path = absolute_local_path,
            .hash = file_hash_text,
        };
    }

    pub fn createFileFromDir(self: *Self, dir: std.fs.Dir, dir_path: []const u8) !File {
        const absolute_local_path = try dir.realpathAlloc(self.allocator, dir_path);

        var file_hash_text_buffer: [std.crypto.hash.Blake3.digest_length * 2]u8 = undefined;
        var file_hash_text: Blake3HashHex = undefined;
        {
            var file = try dir.openFile(dir_path, .{ .mode = .read_only });
            defer file.close();

            var data_chunk_buffer: [1024]u8 = undefined;
            var hasher = std.crypto.hash.Blake3.initKdf(AWTFDB_BLAKE3_CONTEXT, .{});
            while (true) {
                const bytes_read = try file.read(&data_chunk_buffer);
                if (bytes_read == 0) break;
                const data_chunk = data_chunk_buffer[0..bytes_read];
                hasher.update(data_chunk);
            }

            var file_hash_bytes: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
            hasher.final(&file_hash_bytes);

            _ = try std.fmt.bufPrint(
                &file_hash_text_buffer,
                "{x}",
                .{std.fmt.fmtSliceHexLower(&file_hash_bytes)},
            );

            file_hash_text = file_hash_text_buffer[0..(std.crypto.hash.Blake3.digest_length * 2)].*;
        }

        try self.db.?.exec(
            "insert into files (file_hash, local_path) values (?, ?) on conflict do nothing",
            .{},
            .{ .file_hash = &file_hash_text, .local_path = absolute_local_path },
        );
        std.log.debug("created file entry hash={s} path={s}", .{
            absolute_local_path,
            file_hash_text,
        });

        return File{
            .ctx = self,
            .local_path = absolute_local_path,
            .hash = file_hash_text,
        };
    }

    pub fn createCommand(self: *Self) !void {
        try self.loadDatabase();
        try self.migrateCommand();
    }

    pub fn migrateCommand(self: *Self) !void {
        try self.loadDatabase();

        // migration log table is forever
        try self.executeOnce(MIGRATION_LOG_TABLE);

        const current_version: i32 = (try self.fetchValue(i32, "select max(version) from migration_logs")) orelse 0;
        std.log.info("db version: {d}", .{current_version});

        {
            var savepoint = try self.db.?.savepoint("migrations");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            inline for (MIGRATIONS) |migration_decl| {
                const decl_version = migration_decl.@"0";
                const decl_name = migration_decl.@"1";
                const decl_sql = migration_decl.@"2";

                if (current_version < decl_version) {
                    std.log.info("running migration {d}", .{decl_version});
                    var diags = sqlite.Diagnostics{};
                    self.db.?.runMulti(decl_sql, .{ .diags = &diags }) catch |err| {
                        std.log.err("unable to prepare statement, got error {s}. diagnostics: {s}", .{ err, diags });
                        return err;
                    };

                    try self.db.?.exec(
                        "INSERT INTO migration_logs (version, applied_at, description) values (?, ?, ?);",
                        .{},
                        .{
                            .version = decl_version,
                            .applied_at = 0,
                            .description = decl_name,
                        },
                    );
                }
            }
        }
    }

    pub fn statsCommand(self: *Self) !void {
        try self.loadDatabase();
    }

    pub fn jobsCommand(self: *Self) !void {
        try self.loadDatabase();
    }
};

pub export fn sqliteLog(_: ?*anyopaque, level: c_int, message: ?[*:0]const u8) callconv(.C) void {
    std.log.info("sqlite logged level={d} msg={s}", .{ level, message });
}

pub fn main() anyerror!void {
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        std.log.err("failed to configure: {d} '{s}'", .{
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
        std.debug.todo("lmao help");
    }

    if (given_args.maybe_action == null) {
        std.log.err("action argument is required", .{});
        return error.MissingActionArgument;
    }

    var ctx = Context{
        .home_path = null,
        .args_it = &args_it,
        .stdout = stdout,
        .allocator = undefined,
        .db = null,
    };
    defer ctx.deinit();

    const action = given_args.maybe_action.?;
    if (std.mem.eql(u8, action, "create")) {
        try ctx.createCommand();
    } else {
        std.log.err("unknown action {s}", .{action});
        return error.UnknownAction;
    }
}

fn makeTestContext() !Context {
    var ctx = Context{
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = std.testing.allocator,
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

    try std.testing.expectEqualStrings(tag.core[0..], fetched_tag.core[0..]);

    var same_core_tag = try ctx.createNamedTag("another_test_tag", "en", tag.core);
    var fetched_same_core_tag = (try ctx.fetchNamedTag("another_test_tag", "en")).?;
    try std.testing.expectEqualStrings(tag.core[0..], same_core_tag.core[0..]);
    try std.testing.expectEqualStrings(fetched_tag.core[0..], fetched_same_core_tag.core[0..]);

    var tags_from_core = try ctx.fetchTagsFromCore(std.testing.allocator, tag.core);
    defer tags_from_core.deinit();

    try std.testing.expectEqual(@as(usize, 1), tags_from_core.items.len);
    try std.testing.expectEqualStrings(tag.core[0..], tags_from_core.items[0].core[0..]);
}

test "file creation" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file");
    defer indexed_file.deinit();

    try std.testing.expect(std.mem.endsWith(u8, indexed_file.local_path, "/test_file"));

    // also try to create indexed file via absolute path
    const full_tmp_file = try tmp.dir.realpathAlloc(std.testing.allocator, "test_file");
    defer std.testing.allocator.free(full_tmp_file);
    var path_indexed_file = try ctx.createFileFromPath(full_tmp_file);
    defer path_indexed_file.deinit();

    try std.testing.expectStringEndsWith(path_indexed_file.local_path, "/test_file");
    try std.testing.expectEqualStrings(indexed_file.hash[0..], path_indexed_file.hash[0..]);
}

test "file and tags" {
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file");
    defer indexed_file.deinit();

    var tag = try ctx.createNamedTag("test_tag", "en", null);
    try indexed_file.addTag(tag.core);

    var tag_cores = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(tag_cores);

    var saw_correct_tag_core = false;

    for (tag_cores) |core| {
        if (std.mem.eql(u8, &tag.core, &core))
            saw_correct_tag_core = true;
    }

    try std.testing.expect(saw_correct_tag_core);
}
