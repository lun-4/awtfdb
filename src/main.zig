const std = @import("std");
const sqlite = @import("sqlite3");

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
        1,
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
    db: ?*sqlite.c.sqlite3 = undefined,

    const Self = @This();

    pub fn loadDatabase(self: *Self) !void {
        // TODO other people do exist! (use HOME env var)
        const flags = sqlite.c.SQLITE_OPEN_READWRITE | sqlite.c.SQLITE_OPEN_CREATE | sqlite.c.SQLITE_OPEN_EXRESCODE;
        const rc = sqlite.c.sqlite3_open_v2("/home/luna/boorufs.db", &self.db, flags, null);
        if (rc != sqlite.c.SQLITE_OK) {
            std.log.err("can't open database: {d} '{s}' '{s}'", .{
                rc, sqlite.c.sqlite3_errstr(rc), if (self.db != null) sqlite.c.sqlite3_errmsg(self.db) else "out of memory",
            });
            return error.OpenFail;
        }

        // ensure our database functions work
        var result = try self.fetchValue(i32, "select 123;");
        if (result != 123) {
            std.log.err("error on test statement: expected 123, got {d}", .{result});
            return error.TestStatementFailed;
        }
    }

    fn executeAny(self: *Self, statement: []const u8) !*sqlite.c.sqlite3_stmt {
        var maybe_stmt: ?*sqlite.c.sqlite3_stmt = null;

        var rc = sqlite.c.sqlite3_prepare_v2(self.db.?, statement.ptr, @intCast(c_int, statement.len), &maybe_stmt, null);
        if (rc != sqlite.c.SQLITE_OK) {
            std.log.err("error compiling statement ({s}): {s}", .{ statement, sqlite.c.sqlite3_errstr(rc) });
            return error.StatementPrepareFail;
        } else if (maybe_stmt) |stmt| {
            rc = sqlite.c.sqlite3_step(stmt);
            if (rc != sqlite.c.SQLITE_ROW and rc != sqlite.c.SQLITE_DONE) {
                std.log.err("error evaluating '{s}': {d} {s}", .{ statement, rc, sqlite.c.sqlite3_errstr(rc) });
                return error.EvaluationFail;
            }

            return stmt;
        } else {
            unreachable;
        }
    }

    fn executeOnce(self: *Self, statement: []const u8) !void {
        var stmt = try self.executeAny(statement);
        defer _ = sqlite.c.sqlite3_finalize(stmt);
    }

    fn fetchValue(self: *Self, comptime T: type, statement: []const u8) !T {
        var stmt = try self.executeAny(statement);
        defer _ = sqlite.c.sqlite3_finalize(stmt);

        if (T == i32) {
            var result = sqlite.c.sqlite3_column_int(stmt, 0);
            return @as(i32, result);
        } else {
            @compileError("Unsupported type " ++ @typeName(T));
        }
    }

    pub fn deinit(self: *Self) void {
        if (self.db != null) {
            defer _ = sqlite.c.sqlite3_close(self.db);
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

        const last_ran_migration = try self.fetchValue(i32, "select max(version) from migration_logs");
        std.log.debug("last migration: {d}", .{last_ran_migration});
    }

    pub fn statsCommand(self: *Self) !void {
        try self.loadDatabase();
    }

    pub fn jobsCommand(self: *Self) !void {
        try self.loadDatabase();
    }
};

pub fn main() anyerror!void {
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
