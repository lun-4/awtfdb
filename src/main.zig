const std = @import("std");
const sqlite = @import("sqlite");

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
        \\     core_hash text primary key,
        \\     core_data blob not null
        \\ );
        \\ 
        \\ -- files that are imported by bimport/badd are here
        \\ -- this is how we learn that a certain path means a certain hash without
        \\ -- having to recalculate the hash over and over.
        \\ create table files (
        \\     file_hash text primary key not null,
        \\     local_path text not null,
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

const Context = struct {
    args_it: *std.process.ArgIterator,
    stdout: std.fs.File,
    /// Always call loadDatabase before using this attribute.
    db: ?sqlite.Db = null,

    const Self = @This();

    pub fn loadDatabase(self: *Self) !void {
        // try to create the file always. this is done because
        // i give up. tried a lot of things to make sqlite create the db file
        // itself but it just hates me (SQLITE_CANTOPEN my beloathed).

        // TODO other people do exist! (use HOME env var)
        const path = "/home/luna/boorufs.db";
        var file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        var diags: sqlite.Diagnostics = undefined;
        self.db = try sqlite.Db.init(.{
            .mode = sqlite.Db.Mode{ .File = path },
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

    pub fn createCommand(self: *Self) !void {
        try self.loadDatabase();
        try self.migrateCommand();
    }

    pub fn migrateCommand(self: *Self) !void {
        try self.loadDatabase();

        // migration log table is forever
        try self.executeOnce(MIGRATION_LOG_TABLE);

        const current_version: i32 = (try self.fetchValue(i32, "select max(version) from migration_logs")) orelse 0;
        std.log.debug("db version: {d}", .{current_version});

        {
            // this is actually a pretty dably way to express transactions
            // in zig. wrap it all in a block, with defer/errdefer for the
            // end state of such. thx zig
            try self.executeOnce("BEGIN TRANSACTION");
            defer _ = self.executeOnce("COMMIT") catch |err| {
                std.log.err("failed to commit inside migration: {s}", .{@errorName(err)});
            };
            errdefer self.executeOnce("ROLLBACK") catch |err| {
                std.log.err("failed to rollback inside migration: {s}", .{@errorName(err)});
            };

            inline for (MIGRATIONS) |migration_decl| {
                const decl_version = migration_decl.@"0";
                const decl_name = migration_decl.@"1";
                const decl_sql = migration_decl.@"2";

                if (current_version < decl_version) {
                    try self.db.?.runMulti(decl_sql, .{});

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
export fn sqliteLog(_: ?*anyopaque, level: c_int, message: ?[*:0]const u8) callconv(.C) void {
    std.log.info("sqlite log {d} {s}", .{ level, message });
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
        .args_it = &args_it,
        .stdout = stdout,
        .db = undefined,
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

test "basic test" {
    try std.testing.expectEqual(10, 3 + 7);
}
