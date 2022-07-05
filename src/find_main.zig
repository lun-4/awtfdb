const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const log = std.log.scoped(.afind);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ afind: execute queries on the awtfdb index
    \\
    \\ usage:
    \\  afind [options...] query
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\ 	-L, --link			creates a temporary folder with
    \\ 					symlinks to the resulting files from
    \\ 					the query. deletes the folder on
    \\ 					CTRL-C.
    \\ 					(linux only)
    \\
    \\ query examples:
    \\ 	afind 'mytag1'
    \\ 		search all files with mytag1
    \\ 	afind 'mytag1 mytag2'
    \\ 		search all files with mytag1 AND mytag2
    \\ 	afind 'mytag1 | mytag2'
    \\ 		search all files with mytag1 OR mytag2
    \\ 	afind '"mytag1" | "mytag2"'
    \\ 		search all files with mytag1 OR mytag2 (raw tag syntax)
    \\ 		not all characters are allowed in non-raw tag syntax
    \\ 	afind '"mytag1" -"mytag2"'
    \\ 	afind 'mytag1 -mytag2'
    \\ 		search all files with mytag1 but they do NOT have mytag2
;

pub fn main() anyerror!void {
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, manage_main.sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        std.log.err("failed to configure: {d} '{s}'", .{
            rc, sqlite.c.sqlite3_errstr(rc),
        });
        return error.ConfigFail;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var args_it = std.process.args();
    _ = args_it.skip();

    const StringList = std.ArrayList([]const u8);
    const Args = struct {
        help: bool = false,
        version: bool = false,
        link: bool = false,
        query: StringList,
        pub fn deinit(self: *@This()) void {
            self.query.deinit();
        }
    };

    var given_args = Args{ .query = StringList.init(allocator) };
    defer given_args.deinit();
    var arg_state: enum { None, MoreTags } = .None;

    while (args_it.next()) |arg| {
        switch (arg_state) {
            .None => {},
            .MoreTags => {
                try given_args.query.append(arg);
                // once in MoreTags state, all next arguments are part
                // of the query.
                continue;
            },
        }
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "-L") or std.mem.eql(u8, arg, "--link")) {
            given_args.link = true;
        } else {
            arg_state = .MoreTags;
            try given_args.query.append(arg);
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.query.items.len == 0) {
        std.log.err("query is a required argument", .{});
        return error.MissingQuery;
    }
    const query = try std.mem.join(allocator, " ", given_args.query.items);
    defer allocator.free(query);

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    // afind tag (all files with tag)
    // afind 'tag1 tag2' (tag1 AND tag2)
    // afind 'tag1 | tag2' (tag1 OR tag2)
    // afind '(tag1 | tag2) tag3' (tag1 OR tag2, AND tag3)
    // afind '"tag3 2"' ("tag3 2" is a tag, actually)

    var giver = try SqlGiver.init();
    defer giver.deinit();
    const wrapped_result = try giver.giveMeSql(allocator, query);
    defer wrapped_result.deinit();

    const result = switch (wrapped_result) {
        .Ok => |ok_body| ok_body,
        .Error => |error_body| {
            log.err("error at character {d}: {s}", .{ error_body.character, error_body.error_type });
            return error.ParseErrorHappened;
        },
    };

    var resolved_tag_cores = std.ArrayList(i64).init(allocator);
    defer resolved_tag_cores.deinit();

    for (result.tags) |tag_text| {
        const maybe_tag = try ctx.fetchNamedTag(tag_text, "en");
        if (maybe_tag) |tag| {
            try resolved_tag_cores.append(tag.core.id);
        } else {
            log.err("unknown tag '{s}'", .{tag_text});
            return error.UnknownTag;
        }
    }

    var stmt = try ctx.db.?.prepareDynamic(result.query);
    defer stmt.deinit();

    log.debug("generated query: {s}", .{result.query});
    log.debug("found tag cores: {any}", .{resolved_tag_cores.items});

    var it = try stmt.iterator(i64, resolved_tag_cores.items);
    var stdout = std.io.getStdOut();
    var stderr = std.io.getStdErr();

    var returned_files = std.ArrayList(Context.File).init(allocator);
    defer {
        for (returned_files.items) |file| file.deinit();
        returned_files.deinit();
    }

    while (try it.next(.{})) |file_hash| {
        var file = (try ctx.fetchFile(file_hash)).?;
        // if we use --link, we need the full list of files to make
        // symlinks out of, so this block doesn't own the lifetime of the
        // file entity anymore.
        try returned_files.append(file);

        try stdout.writer().print("{s}", .{file.local_path});
        try file.printTagsTo(allocator, stderr.writer());
        try stdout.writer().print("\n", .{});
    }

    log.info("found {d} files", .{returned_files.items.len});

    if (given_args.link) {
        var PREFIX = "/tmp/awtf/afind-";
        var template = "/tmp/awtf/afind-XXXXXXXXXX";
        var tmp_path: [template.len]u8 = undefined;
        std.mem.copy(u8, &tmp_path, PREFIX);
        var fill_here = tmp_path[PREFIX.len..];

        const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
        var r = std.rand.DefaultPrng.init(seed);
        for (fill_here) |*el| {
            const ascii_idx = @intCast(u8, r.random().uintLessThan(u5, 24));
            const letter: u8 = @as(u8, 65) + ascii_idx;
            el.* = letter;
        }

        log.debug("attempting to create folder '{s}'", .{tmp_path});
        std.fs.makeDirAbsolute("/tmp/awtf") catch |err| if (err != error.PathAlreadyExists) return err else {};
        try std.fs.makeDirAbsolute(&tmp_path);
        var tmp = try std.fs.openDirAbsolute(&tmp_path, .{});

        defer {
            tmp.deleteTree(&tmp_path) catch |err| {
                log.err(
                    "error happened while deleting '{s}': {s}, ignoring.",
                    .{ &tmp_path, @errorName(err) },
                );
            };
            tmp.close();
        }

        for (returned_files.items) |file| {
            const joined_symlink_path = try std.fs.path.join(allocator, &[_][]const u8{
                &tmp_path,
                std.fs.path.basename(file.local_path),
            });
            defer allocator.free(joined_symlink_path);
            log.info("symlink '{s}' to '{s}'", .{ file.local_path, joined_symlink_path });
            try tmp.symLink(file.local_path, joined_symlink_path, .{});
        }

        log.info("successfully created symlinked folder at", .{});
        try stdout.writer().print("{s}\n", .{tmp_path});

        const self_pipe_fds = try std.os.pipe();
        maybe_self_pipe = .{
            .reader = .{ .handle = self_pipe_fds[0] },
            .writer = .{ .handle = self_pipe_fds[1] },
        };
        defer {
            maybe_self_pipe.?.reader.close();
            maybe_self_pipe.?.writer.close();
        }

        // configure signal handler that's going to push data to the selfpipe
        var mask = std.os.empty_sigset;
        std.os.linux.sigaddset(&mask, std.os.SIG.TERM);
        std.os.linux.sigaddset(&mask, std.os.SIG.INT);
        var sa = std.os.Sigaction{
            .handler = .{ .sigaction = signal_handler },
            .mask = mask,
            .flags = 0,
        };

        try std.os.sigaction(std.os.SIG.TERM, &sa, null);
        try std.os.sigaction(std.os.SIG.INT, &sa, null);

        const PollFdList = std.ArrayList(std.os.pollfd);
        var sockets = PollFdList.init(allocator);
        defer sockets.deinit();

        try sockets.append(std.os.pollfd{
            .fd = maybe_self_pipe.?.reader.handle,
            .events = std.os.POLL.IN,
            .revents = 0,
        });

        // we don't need to do 'while (true) { sleep(1000); }' because
        // we can poll on the selfpipe trick!

        log.info("press ctrl-c to delete the temporary folder...", .{});
        var run: bool = true;
        while (run) {
            log.debug("polling for signals...", .{});
            const available = try std.os.poll(sockets.items, -1);
            try std.testing.expect(available > 0);
            for (sockets.items) |pollfd| {
                log.debug("fd {d} has revents {d}", .{ pollfd.fd, pollfd.revents });
                if (pollfd.revents == 0) continue;

                if (pollfd.fd == maybe_self_pipe.?.reader.handle) {
                    while (run) {
                        const signal_data = maybe_self_pipe.?.reader.reader().readStruct(SignalData) catch |err| switch (err) {
                            error.EndOfStream => break,
                            else => return err,
                        };

                        log.info("exiting! with signal {d}", .{signal_data.signal});
                        run = false;
                    }
                }
            }
        }
    }
}

const Pipe = struct {
    reader: std.fs.File,
    writer: std.fs.File,
};

var zig_segfault_handler: fn (i32, *const std.os.siginfo_t, ?*const anyopaque) callconv(.C) void = undefined;
var maybe_self_pipe: ?Pipe = null;

const SignalData = extern struct {
    signal: c_int,
    info: std.os.siginfo_t,
    uctx: ?*const anyopaque,
};
const SignalList = std.ArrayList(SignalData);

fn signal_handler(
    signal: c_int,
    info: *const std.os.siginfo_t,
    uctx: ?*const anyopaque,
) callconv(.C) void {
    if (maybe_self_pipe) |self_pipe| {
        const signal_data = SignalData{
            .signal = signal,
            .info = info.*,
            .uctx = uctx,
        };
        self_pipe.writer.writer().writeStruct(signal_data) catch return;
    }
}

pub const SqlGiver = struct {
    pub const ErrorType = enum {
        UnexpectedCharacter,
    };

    const Result = union(enum) {
        Error: struct {
            character: usize,
            error_type: ErrorType,
        },
        Ok: struct {
            allocator: std.mem.Allocator,
            query: []const u8,
            tags: [][]const u8,
        },

        pub fn deinit(self: @This()) void {
            switch (self) {
                .Ok => |ok_body| {
                    ok_body.allocator.free(ok_body.query);
                    ok_body.allocator.free(ok_body.tags);
                },
                .Error => {},
            }
        }
    };

    operators: [5]libpcre.Regex,
    const Self = @This();

    pub const CaptureType = enum(usize) { Or = 0, Not, And, Tag, RawTag };

    pub fn init() !Self {
        var or_operator = try libpcre.Regex.compile("( +)?\\|( +)?", .{});
        var not_operator = try libpcre.Regex.compile("( +)?-( +)?", .{});
        var and_operator = try libpcre.Regex.compile(" +", .{});
        var tag_regex = try libpcre.Regex.compile("[a-zA-Z-_0-9:;&\\*\\(\\)]+", .{});
        var raw_tag_regex = try libpcre.Regex.compile("\".*?\"", .{});

        return Self{ .operators = [_]libpcre.Regex{
            or_operator,
            not_operator,
            and_operator,
            tag_regex,
            raw_tag_regex,
        } };
    }

    pub fn deinit(self: Self) void {
        for (self.operators) |regex| regex.deinit();
    }

    pub fn giveMeSql(
        self: Self,
        allocator: std.mem.Allocator,
        query: []const u8,
    ) (libpcre.Regex.CompileError || libpcre.Regex.ExecError)!Result {
        var index: usize = 0;

        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();

        var tags = std.ArrayList([]const u8).init(allocator);
        defer tags.deinit();

        if (query.len == 0) {
            try list.writer().print("select distinct file_hash from tag_files", .{});
        } else {
            try list.writer().print("select file_hash from tag_files where", .{});
        }

        while (true) {
            // try to match on every regex with that same order:
            // tag_regex, raw_tag_regex, or_operator, and_operator
            // if any of those match first, emit the relevant SQL for that
            // type of tag.

            // TODO paren support "(" and ")"

            const query_slice = query[index..];
            if (query_slice.len == 0) break;

            var maybe_captures: ?[]?libpcre.Capture = null;
            var captured_regex_index: ?CaptureType = null;
            for (self.operators) |regex, current_regex_index| {
                log.debug("try regex {d} on query '{s}'", .{ current_regex_index, query_slice });
                maybe_captures = try regex.captures(allocator, query_slice, .{});
                captured_regex_index = @intToEnum(CaptureType, current_regex_index);
                log.debug("raw capture? {any}", .{maybe_captures});
                if (maybe_captures) |captures| {
                    const capture = captures[0].?;
                    if (capture.start != 0) {
                        allocator.free(captures);
                        maybe_captures = null;
                    } else {
                        log.debug("captured!!! {any}", .{maybe_captures});
                        break;
                    }
                }
            }

            if (maybe_captures) |captures| {
                defer allocator.free(captures);

                const full_match = captures[0].?;
                var match_text = query[index + full_match.start .. index + full_match.end];
                index += full_match.end;

                switch (captured_regex_index.?) {
                    .Or => try list.writer().print(" or", .{}),
                    .Not => {
                        // this edge case is hit when queries start with '-TAG'
                        // since we already printed a select, we need to add
                        // some kind of condition before it's a syntax error
                        if (tags.items.len == 0) {
                            try list.writer().print(" true", .{});
                        }
                        try list.writer().print(" except", .{});
                        try list.writer().print(" select file_hash from tag_files where", .{});
                    },
                    .And => {
                        try list.writer().print(" intersect", .{});
                        try list.writer().print(" select file_hash from tag_files where", .{});
                    },
                    .Tag, .RawTag => {
                        try list.writer().print(" core_hash = ?", .{});
                        // if we're matching raw_tag_regex (tags that have
                        // quotemarks around them), index forward and backward
                        // so that we don't pass those quotemarks to query
                        // processors.
                        if (captured_regex_index.? == .RawTag) {
                            match_text = match_text[1 .. match_text.len - 1];
                        }
                        try tags.append(match_text);
                    },
                }
            } else {
                return Result{ .Error = .{ .character = index, .error_type = .UnexpectedCharacter } };
            }
        }

        return Result{ .Ok = .{
            .allocator = allocator,
            .query = list.toOwnedSlice(),
            .tags = tags.toOwnedSlice(),
        } };
    }
};

test "sql parser" {
    const allocator = std.testing.allocator;
    var giver = try SqlGiver.init();
    defer giver.deinit();
    const wrapped_result = try giver.giveMeSql(allocator, "a b | \"cd\"|e");
    defer wrapped_result.deinit();

    const result = wrapped_result.Ok;

    try std.testing.expectEqualStrings(
        "select file_hash from tag_files where core_hash = ? intersect select file_hash from tag_files where core_hash = ? or core_hash = ? or core_hash = ?",
        result.query,
    );

    try std.testing.expectEqual(@as(usize, 4), result.tags.len);

    const expected_tags = .{ "a", "b", "cd", "e" };

    inline for (expected_tags) |expected_tag, index| {
        try std.testing.expectEqualStrings(expected_tag, result.tags[index]);
    }
}

test "sql parser errors" {
    const allocator = std.testing.allocator;
    var giver = try SqlGiver.init();
    defer giver.deinit();
    const wrapped_result = try giver.giveMeSql(allocator, "a \"cd");
    defer wrapped_result.deinit();

    const error_data = wrapped_result.Error;

    try std.testing.expectEqual(@as(usize, 2), error_data.character);
    try std.testing.expectEqual(SqlGiver.ErrorType.UnexpectedCharacter, error_data.error_type);
}

test "sql parser batch test" {
    const allocator = std.testing.allocator;

    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var giver = try SqlGiver.init();
    defer giver.deinit();

    const TEST_DATA = .{
        .{ "a b c", .{ "a", "b", "c" } },
        .{ "a bc d", .{ "a", "bc", "d" } },
        .{ "a \"bc\" d", .{ "a", "bc", "d" } },
        .{ "a \"b c\" d", .{ "a", "b c", "d" } },
        .{ "a \"b c\" -d", .{ "a", "b c", "d" } },
        .{ "-a \"b c\" d", .{ "a", "b c", "d" } },
        .{ "-a -\"b c\" -d", .{ "a", "b c", "d" } },
        .{ "-d", .{"d"} },
    };

    inline for (TEST_DATA) |test_case, test_case_index| {
        const input_text = test_case.@"0";
        const expected_tags = test_case.@"1";

        const wrapped_result = try giver.giveMeSql(allocator, input_text);
        defer wrapped_result.deinit();

        const result = wrapped_result.Ok;

        var stmt = ctx.db.?.prepareDynamic(result.query) catch |err| {
            const detailed_error = ctx.db.?.getDetailedError();
            std.debug.panic(
                "unable to prepare statement test case {d} '{s}', error: {}, message: {s}\n",
                .{ test_case_index, result.query, err, detailed_error },
            );
        };
        defer stmt.deinit();

        try std.testing.expectEqual(@as(usize, expected_tags.len), result.tags.len);
        inline for (expected_tags) |expected_tag, index| {
            try std.testing.expectEqualStrings(expected_tag, result.tags[index]);
        }
    }
}
