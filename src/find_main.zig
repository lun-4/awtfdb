const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const log = std.log.scoped(.awtfdb_watcher);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ afind: execute queries on the awtfdb index
    \\
    \\ usage:
    \\  afind query
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
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

    const Args = struct {
        help: bool = false,
        version: bool = false,
        query: ?[]const u8 = null,
    };

    var given_args = Args{};

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            given_args.query = arg;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.query == null) {
        std.log.err("query is a required argument", .{});
        return error.MissingQuery;
    }
    const query = given_args.query.?;

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

    const result = try SqlGiver.giveMeSql(allocator, query);
    defer allocator.free(result.query);
    defer allocator.free(result.tags);
}

const SqlGiver = struct {
    const Result = struct {
        query: []const u8,
        tags: [][]const u8,
    };

    pub fn giveMeSql(allocator: std.mem.Allocator, query: []const u8) !Result {
        var or_operator = try libpcre.Regex.compile("( +)?\\|( +)?", .{});
        var and_operator = try libpcre.Regex.compile(" +", .{});
        var tag_regex = try libpcre.Regex.compile("[a-zA-Z-_]+", .{});
        var raw_tag_regex = try libpcre.Regex.compile("\".*?\"", .{});

        const capture_order = [_]*libpcre.Regex{
            &or_operator,
            &and_operator,
            &tag_regex,
            &raw_tag_regex,
        };

        var index: usize = 0;

        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();

        var tags = std.ArrayList([]const u8).init(allocator);
        defer tags.deinit();

        try list.writer().print("select file_hash from tag_files where", .{});

        while (true) {
            // try to match on every regex with that same order:
            // tag_regex, raw_tag_regex, or_operator, and_operator
            // if any of those match first, emit the relevant SQL for that
            // type of tag.

            // TODO paren support "(" and ")"
            // TODO NOT operator support (-tag means NOT tag)

            const query_slice = query[index..];
            if (query_slice.len == 0) break;

            var maybe_captures: ?[]?libpcre.Capture = null;
            var captured_regex_index: usize = 0;
            for (capture_order) |regex, current_regex_index| {
                log.debug("try regex {d} on query '{s}'", .{ current_regex_index, query_slice });
                maybe_captures = try regex.captures(allocator, query_slice, .{});
                captured_regex_index = current_regex_index;
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

                switch (captured_regex_index) {
                    0 => try list.writer().print(" or", .{}),
                    1 => try list.writer().print(" and", .{}),
                    2, 3 => {
                        try list.writer().print(" core_hash = ?", .{});
                        // if we're matching raw_tag_regex (tags that have
                        // quotemarks around them), index forward and backward
                        // so that we don't pass those quotemarks to query
                        // processors.
                        if (captured_regex_index == 3) {
                            match_text = match_text[1 .. match_text.len - 1];
                        }
                        try tags.append(match_text);
                    },
                    else => unreachable,
                }
            } else {
                // TODO add better parse errors (maybe return an union on
                // Result? and add relevant crash info for the ParseError part)
                return error.UnexpectedCharacters;
            }
        }

        return Result{ .query = list.toOwnedSlice(), .tags = tags.toOwnedSlice() };
    }
};

test "sql parser" {
    const allocator = std.testing.allocator;
    const result = try SqlGiver.giveMeSql(allocator, "a b | \"cd\"|e");
    defer allocator.free(result.query);
    defer allocator.free(result.tags);

    try std.testing.expectEqualStrings(
        "select file_hash from tag_files where core_hash = ? and core_hash = ? or core_hash = ? or core_hash = ?",
        result.query,
    );

    try std.testing.expectEqual(@as(usize, 4), result.tags.len);

    const expected_tags = .{ "a", "b", "cd", "e" };

    inline for (expected_tags) |expected_tag, index| {
        try std.testing.expectEqualStrings(expected_tag, result.tags[index]);
    }

    // TODO expectEqualStrings on tags contents
}
