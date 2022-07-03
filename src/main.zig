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

const MIGRATIONS = .{
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
};

const MIGRATION_LOG_TABLE =
    \\ create table if not exists migration_logs (
    \\     version int primary key,
    \\     applied_at int,
    \\     description text
    \\ );
;

const log = std.log.scoped(.awtfdb_main);

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
        var result = try self.db.?.one(i32, "select 123;", .{}, .{});
        if (result == null or result.? != 123) {
            log.err("error on test statement: expected 123, got {d}", .{result});
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
            log.info("possibly optimizing database...", .{});
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
                .{self.core.id},
            );
            const deleted_tag_count = db.rowsAffected();

            try db.exec("delete from tag_cores where core_hash = ?", .{}, .{self.core.id});
            std.debug.assert(db.rowsAffected() == 1);
            try db.exec("delete from hashes where id = ?", .{}, .{self.core.id});
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
            .{core_hash.id},
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
            .items = list.toOwnedSlice(),
        };
    }

    pub const HashWithBlob = struct {
        id: i64,
        hash_data: sqlite.Blob,

        pub fn toRealHash(self: @This()) Hash {
            var hash_value: [32]u8 = undefined;
            std.mem.copy(u8, &hash_value, self.hash_data.data);
            return Hash{ .id = self.id, .hash_data = hash_value };
        }
    };

    pub fn fetchNamedTag(self: *Self, text: []const u8, language: []const u8) !?Tag {
        var maybe_core_hash = try self.db.?.oneAlloc(
            HashWithBlob,
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
        id: i64,
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

            return std.fmt.format(writer, "{s}", .{&self.toHex()});
        }
    };

    pub fn createNamedTag(self: *Self, text: []const u8, language: []const u8, maybe_core: ?Hash) !Tag {
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
            const core_hash_id = (try self.db.?.one(
                i64,
                "insert into hashes (hash_data) values (?) returning id",
                .{},
                .{hash_blob},
            )).?;

            // core_hash_bytes is passed by reference here, so we don't
            // have to worry about losing it to undefined memory hell.
            core_hash = .{ .id = core_hash_id, .hash_data = core_hash_bytes };

            const core_data_blob = sqlite.Blob{ .data = &core_data };
            try self.db.?.exec(
                "insert into tag_cores (core_hash, core_data) values (?, ?)",
                .{},
                .{ core_hash.id, core_data_blob },
            );

            log.debug("created tag core with hash {s}", .{core_hash});
        }

        try self.db.?.exec(
            "insert into tag_names (core_hash, tag_text, tag_language) values (?, ?, ?)",
            .{},
            .{ core_hash.id, text, language },
        );
        log.debug("created name tag with value {s} language {s} core {s}", .{ text, language, core_hash });

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

        pub fn addTag(self: *FileSelf, core_hash: Hash) !void {
            try self.ctx.db.?.exec(
                "insert into tag_files (core_hash, file_hash) values (?, ?) on conflict do nothing",
                .{},
                .{ core_hash.id, self.hash.id },
            );
            log.debug("link file {s} (hash {s}) with tag core hash {d} {s}", .{ self.local_path, self.hash, core_hash.id, core_hash });
        }

        pub fn removeTag(self: *FileSelf, core_hash: Hash) !void {
            try self.ctx.db.?.exec(
                "delete from tag_files where core_hash = ? and file_hash = ?",
                .{},
                .{ core_hash.id, self.hash.id },
            );
            log.debug("remove file {s} (hash {s}) with tag core hash {d}", .{ self.local_path, self.hash, core_hash.id });
        }

        // Copies ownership of given new_local_path
        pub fn setLocalPath(self: *FileSelf, new_local_path: []const u8) !void {
            try self.ctx.db.?.exec(
                "update files set local_path = ? where file_hash = ? and local_path = ?",
                .{},
                .{ new_local_path, self.hash.id, self.local_path },
            );

            self.ctx.allocator.free(self.local_path);
            self.local_path = try self.ctx.allocator.dupe(u8, new_local_path);
        }

        pub fn delete(self: FileSelf) !void {
            log.info("deleted file {d} {s}", .{ self.hash.id, self.local_path });
            try self.ctx.db.?.exec(
                "delete from files where file_hash = ? and local_path = ?",
                .{},
                .{ self.hash.id, self.local_path },
            );
            // TODO only delete from hashes if it's going to be unused
            //try self.ctx.db.?.exec(
            //    "delete from hashes where id = ?",
            //    .{},
            //    .{self.hash.id},
            //);
        }

        /// Returns all tag core hashes for the file.
        pub fn fetchTags(self: FileSelf, allocator: std.mem.Allocator) ![]Hash {
            var stmt = try self.ctx.db.?.prepare(
                \\ select hashes.id, hashes.hash_data
                \\ from tag_files
                \\ join hashes
                \\ 	on tag_files.core_hash = hashes.id
                \\ where tag_files.file_hash = ?
            );
            defer stmt.deinit();

            const internal_hashes = try stmt.all(
                HashWithBlob,
                allocator,
                .{},
                .{self.hash.id},
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

            return list.toOwnedSlice();
        }

        pub fn printTagsTo(
            self: FileSelf,
            allocator: std.mem.Allocator,
            writer: anytype,
        ) !void {
            var tag_cores = try self.fetchTags(allocator);
            defer allocator.free(tag_cores);

            for (tag_cores) |tag_core| {
                var tags = try self.ctx.fetchTagsFromCore(allocator, tag_core);
                defer tags.deinit();
                for (tags.items) |tag| {
                    try writer.print(" '{s}'", .{tag});
                }
            }
        }
    };

    /// Caller owns returned memory.
    pub fn createFileFromPath(self: *Self, local_path: []const u8) !File {
        const absolute_local_path = try std.fs.realpathAlloc(self.allocator, local_path);
        var possible_file_entry = try self.fetchFileByPath(absolute_local_path);
        if (possible_file_entry) |file_entry| {
            // fetchFileByPath dupes the string so we need to free it here
            defer self.allocator.free(absolute_local_path);
            return file_entry;
        }

        var file = try std.fs.openFileAbsolute(absolute_local_path, .{ .mode = .read_only });
        defer file.close();

        var file_hash: Hash = try self.calculateHash(file, .{});
        return try self.insertFile(file_hash, absolute_local_path);
    }

    pub const CalculateHashOptions = struct {
        insert_new_hash: bool = true,
    };

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
        const maybe_hash_id = try self.db.?.one(
            i64,
            "select id from hashes where hash_data = ?",
            .{},
            .{hash_blob},
        );
        if (maybe_hash_id) |hash_id| {
            file_hash.id = hash_id;
        } else {
            if (options.insert_new_hash) {
                file_hash.id = (try self.db.?.one(
                    i64,
                    "insert into hashes (hash_data) values (?) returning id",
                    .{},
                    .{hash_blob},
                )).?;
            } else {
                file_hash.id = -1;
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
        const maybe_hash_id = try self.db.?.one(
            i64,
            "select id from hashes where hash_data = ?",
            .{},
            .{hash_blob},
        );
        if (maybe_hash_id) |hash_id| {
            hash_entry.id = hash_id;
        } else {
            if (options.insert_new_hash) {
                hash_entry.id = (try self.db.?.one(
                    i64,
                    "insert into hashes (hash_data) values (?) returning id",
                    .{},
                    .{hash_blob},
                )).?;
            } else {
                hash_entry.id = -1;
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
            .{ file_hash.id, absolute_local_path },
        );
        log.debug("created file entry hash={s} path={s}", .{
            absolute_local_path,
            file_hash,
        });

        return File{
            .ctx = self,
            .local_path = absolute_local_path,
            .hash = file_hash,
        };
    }

    pub fn createFileFromDir(self: *Self, dir: std.fs.Dir, dir_path: []const u8) !File {
        var file = try dir.openFile(dir_path, .{ .mode = .read_only });
        defer file.close();
        const absolute_local_path = try dir.realpathAlloc(self.allocator, dir_path);

        var possible_file_entry = try self.fetchFileByPath(absolute_local_path);
        if (possible_file_entry) |file_entry| {
            // fetchFileByPath dupes the string so we need to free it here
            defer self.allocator.free(absolute_local_path);
            return file_entry;
        }

        var file_hash: Hash = try self.calculateHash(file, .{});
        return try self.insertFile(file_hash, absolute_local_path);
    }

    // TODO create fetchFileFromHash that receives full hash object and automatically
    // prefers hash instead of id-search
    pub fn fetchFile(self: *Self, hash_id: i64) !?File {
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
            .{hash_id},
        );

        if (maybe_local_path) |*local_path| {
            // string memory is passed to client
            defer self.allocator.free(local_path.hash_data.data);

            const almost_good_hash = HashWithBlob{
                .id = hash_id,
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

    pub fn fetchFileExact(self: *Self, hash_id: i64, given_local_path: []const u8) !?File {
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
            .{ hash_id, given_local_path },
        );

        if (maybe_local_path) |*local_path| {
            // string memory is passed to client
            defer self.allocator.free(local_path.hash_data.data);

            const almost_good_hash = HashWithBlob{
                .id = hash_id,
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
                hash_id: i64,
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
                    .id = local_path.hash_id,
                    .hash_data = hash_data,
                },
            };
        } else {
            return null;
        }
    }

    pub fn fetchFileByPath(self: *Self, absolute_local_path: []const u8) !?File {
        var maybe_hash = try self.db.?.oneAlloc(
            HashWithBlob,
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

    pub fn createTagParent(self: *Self, child_tag: Tag, parent_tag: Tag) !void {
        try self.db.?.exec(
            "insert into tag_implications (child_tag, parent_tag) values (?, ?)",
            .{},
            .{
                child_tag.core.id,
                parent_tag.core.id,
            },
        );
    }

    fn processSingleFileIntoTagTree(self: *Self, file_hash: i64, treemap: TagTreeMap) !void {
        var file = (try self.fetchFile(file_hash)).?;
        defer file.deinit();

        const TagSet = std.AutoHashMap(i64, void);
        var tags_to_add = TagSet.init(self.allocator);
        defer tags_to_add.deinit();

        var tag_cores = try file.fetchTags(self.allocator);
        defer self.allocator.free(tag_cores);

        while (true) {
            const old_tags_to_add_len = tags_to_add.count();

            for (tag_cores) |tag_core| {
                var maybe_parents = treemap.get(tag_core.id);
                if (maybe_parents) |parents| {
                    for (parents) |parent| {
                        try tags_to_add.put(parent, {});
                    }
                }
            }

            var tags_iter = tags_to_add.iterator();
            while (tags_iter.next()) |entry| {
                var maybe_parents = treemap.get(entry.key_ptr.*);
                if (maybe_parents) |parents| {
                    for (parents) |parent| {
                        try tags_to_add.put(parent, {});
                    }
                }
            }

            const new_tags_to_add_len = tags_to_add.count();
            if (old_tags_to_add_len == new_tags_to_add_len) break;
        }

        var tags_iter = tags_to_add.iterator();
        while (tags_iter.next()) |entry| {
            // don't need to readd tags that are already in
            // (prevent db locking i/o)
            var already_has_it = false;
            for (tag_cores) |core| {
                if (entry.key_ptr.* == core.id) already_has_it = true;
            }
            if (already_has_it) continue;

            try file.addTag(.{ .id = entry.key_ptr.*, .hash_data = undefined });
        }
    }

    const ProcessTagTreeOptions = struct {
        /// Only process the given file ids.
        ///
        /// Useful if you are ainclude(1) and don't want to process the entire
        /// file database.
        files: ?[]const i64 = null,
    };
    const TagTreeMap = std.AutoHashMap(i64, []i64);

    pub fn processTagTree(self: *Self, options: ProcessTagTreeOptions) !void {
        log.info("processing tag tree...", .{});

        var tree_stmt = try self.db.?.prepare(
            "select child_tag, parent_tag from tag_implications",
        );
        defer tree_stmt.deinit();
        var tree_rows = try tree_stmt.all(
            struct { child_tag: i64, parent_tag: i64 },
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
            const maybe_parents = treemap.get(tree_row.child_tag);
            if (maybe_parents) |parents| {
                // realloc
                var new_parents = try self.allocator.alloc(i64, parents.len + 1);
                std.mem.copy(i64, new_parents, parents);
                new_parents[new_parents.len - 1] = tree_row.parent_tag;
                self.allocator.free(parents);
                try treemap.put(tree_row.child_tag, new_parents);
            } else {
                var new_parents = try self.allocator.alloc(i64, 1);
                new_parents[0] = tree_row.parent_tag;
                try treemap.put(tree_row.child_tag, new_parents);
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
                file_hash: i64,
            };
            var iter = try stmt.iterator(
                FileRow,
                .{},
            );

            while (try iter.next(.{})) |file_row| {
                const file_hash = file_row.file_hash;
                try self.processSingleFileIntoTagTree(file_hash, treemap);
            }
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
        log.info("db version: {d}", .{current_version});

        // before running migrations, copy the database over

        if (self.db_path) |db_path| {
            const backup_db_path = try std.fs.path.resolve(
                self.allocator,
                &[_][]const u8{ self.home_path.?, ".awtf.before-migration.db" },
            );
            defer self.allocator.free(backup_db_path);
            log.info("starting transaction for backup from {s} to {s}", .{ db_path, backup_db_path });

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

            log.info("copying database to {s}", .{backup_db_path});
            try std.fs.copyFileAbsolute(db_path, backup_db_path, .{});
        }

        {
            var savepoint = try self.db.?.savepoint("migrations");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            inline for (MIGRATIONS) |migration_decl| {
                const decl_version = migration_decl.@"0";
                const decl_name = migration_decl.@"1";
                const decl_sql = migration_decl.@"2";

                if (current_version < decl_version) {
                    log.info("running migration {d}", .{decl_version});
                    var diags = sqlite.Diagnostics{};
                    self.db.?.execMulti(decl_sql, .{ .diags = &diags }) catch |err| {
                        log.err("unable to prepare statement, got error {s}. diagnostics: {s}", .{ err, diags });
                        return err;
                    };

                    try self.db.?.exec(
                        "INSERT INTO migration_logs (version, applied_at, description) values (?, ?, ?);",
                        .{},
                        .{
                            .version = decl_version,
                            .applied_at = std.time.timestamp(),
                            .description = decl_name,
                        },
                    );
                }
            }
        }

        const val = try self.db.?.one(i64, "PRAGMA integrity_check", .{}, .{});
        log.debug("integrity check returned {d}", .{val});
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
    log.info("sqlite logged level={d} msg={s}", .{ level, message });
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        log.err("failed to configure: {d} '{s}'", .{
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
        log.err("action argument is required", .{});
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
        log.err("unknown action {s}", .{action});
        return error.UnknownAction;
    }
}

pub var test_db_path_buffer: [std.os.PATH_MAX]u8 = undefined;

pub fn makeTestContext() !Context {
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

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file");
    defer indexed_file.deinit();

    try std.testing.expect(std.mem.endsWith(u8, indexed_file.local_path, "/test_file"));

    // also try to create indexed file via absolute path
    const full_tmp_file = try tmp.dir.realpathAlloc(std.testing.allocator, "test_file");
    defer std.testing.allocator.free(full_tmp_file);
    var path_indexed_file = try ctx.createFileFromPath(full_tmp_file);
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

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file");
    defer indexed_file.deinit();

    var tag = try ctx.createNamedTag("test_tag", "en", null);

    // add tag
    try indexed_file.addTag(tag.core);

    var tag_cores = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(tag_cores);

    var saw_correct_tag_core = false;
    for (tag_cores) |core| {
        if (std.mem.eql(u8, &tag.core.hash_data, &core.hash_data))
            saw_correct_tag_core = true;
    }
    try std.testing.expect(saw_correct_tag_core);

    // remove tag
    try indexed_file.removeTag(tag.core);

    var tag_cores_after_removal = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(tag_cores_after_removal);
    for (tag_cores_after_removal) |core| {
        if (std.mem.eql(u8, &tag.core.hash_data, &core.hash_data))
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
    var ctx = try makeTestContext();
    defer ctx.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file");
    defer indexed_file.deinit();

    var child_tag = try ctx.createNamedTag("child_test_tag", "en", null);
    try indexed_file.addTag(child_tag.core);

    // only add this through inferrence
    var parent_tag = try ctx.createNamedTag("parent_test_tag", "en", null);
    var parent_tag2 = try ctx.createNamedTag("parent_test_tag2", "en", null);
    var parent_tag3 = try ctx.createNamedTag("parent_test_tag3", "en", null);
    try ctx.createTagParent(child_tag, parent_tag);
    try ctx.createTagParent(child_tag, parent_tag2);
    try ctx.createTagParent(parent_tag2, parent_tag3);
    try ctx.processTagTree(.{});

    // assert both now exist

    var tag_cores = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(tag_cores);

    var saw_child = false;
    var saw_parent = false;
    var saw_parent2 = false;
    var saw_parent3 = false;

    for (tag_cores) |core| {
        if (core.id == parent_tag.core.id) saw_parent = true;
        if (core.id == parent_tag2.core.id) saw_parent2 = true;
        if (core.id == parent_tag3.core.id) saw_parent3 = true;
        if (core.id == child_tag.core.id) saw_child = true;
    }

    try std.testing.expect(saw_parent);
    try std.testing.expect(saw_parent2);
    try std.testing.expect(saw_parent3);
    try std.testing.expect(saw_child);
}

test "everyone else" {
    std.testing.refAllDecls(@import("./include_main.zig"));
    std.testing.refAllDecls(@import("./rename_watcher_main.zig"));
    std.testing.refAllDecls(@import("./find_main.zig"));
    std.testing.refAllDecls(@import("./ls_main.zig"));
    std.testing.refAllDecls(@import("./rm_main.zig"));
    std.testing.refAllDecls(@import("./hydrus_api_main.zig"));
    std.testing.refAllDecls(@import("./tags_main.zig"));
}
