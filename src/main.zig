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

const Context = struct {
    args_it: *std.process.ArgIterator,
    stdout: std.fs.File,
    /// Always call loadDatabase before using this attribute.
    db: *sqlite.c.sqlite3 = undefined,

    const Self = @This();

    pub fn loadDatabase(self: *Self) !void {
        var maybe_db: ?*sqlite.c.sqlite3 = null;

        if (sqlite.c.sqlite3_open("/home/luna/boorufs.db", &maybe_db) != 0) {
            std.log.err("can't open database: {s}", .{sqlite.c.sqlite3_errmsg(maybe_db)});
            return error.DatabaseError;
        }
        self.db = maybe_db.?;
    }

    pub fn deinit(self: *Self) void {
        defer _ = sqlite.c.sqlite3_close(self.db);
    }

    pub fn createCommand(self: *Self) !void {
        try self.loadDatabase();

        var maybe_stmt: ?*sqlite.c.sqlite3_stmt = null;
        defer _ = sqlite.c.sqlite3_finalize(maybe_stmt);
        var rc = sqlite.c.sqlite3_prepare_v2(self.db, "select 123;", 128, &maybe_stmt, null);
        if (rc != sqlite.c.SQLITE_OK) {
            std.log.err("error executing 'select 1' statement on database: {s}", .{sqlite.c.sqlite3_errstr(rc)});
            return error.TestStatementFailed;
        } else if (maybe_stmt) |stmt| {
            rc = sqlite.c.sqlite3_step(stmt);
            if (rc != sqlite.c.SQLITE_ROW) {
                std.log.err("error fetching 'select 1' statement on database: {d} {s}", .{ rc, sqlite.c.sqlite3_errstr(rc) });
                return error.TestStatementFailed;
            }

            var result = sqlite.c.sqlite3_column_int(stmt, 0);
            if (result != 123) {
                std.log.err("error fetching 'select 1' statement on database: expected 123, got {d}", .{result});
                return error.TestStatementFailed;
            }
        } else {
            return error.InvalidTestStatementState;
        }
    }

    pub fn migrateCommand(self: *Self) !void {
        try self.loadDatabase();
        self.db;
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
