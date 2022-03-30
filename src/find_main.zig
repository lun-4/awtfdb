const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
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

    var scanner = Scanner.init(query);
    while (true) {
        var token = scanner.next() catch |err| {
            log.err("error parsing query. around '{s}': {s}", .{ scanner.currentLexeme(), @errorName(err) });
            return error.ParseError;
        };

        log.info("{s}", .{token});
    }
}

pub const ScannerError = error{
    Unexpected,
    Unterminated,
};

pub const TokenType = enum {
    LeftParen,
    RightParen,
    Dot,
    Pipe,
    Space,
    Tag,
    EOF,
};

pub const Token = struct {
    typ: TokenType,
    lexeme: []const u8,
    source_start_character: usize,
};

pub const Scanner = struct {
    source: []const u8,

    start: usize = 0,
    current: usize = 0,

    pub fn init(source: []const u8) Scanner {
        return Scanner{ .source = source };
    }

    pub fn reset(self: *Scanner) void {
        self.start = 0;
        self.current = 0;
    }

    fn isAtEnd(self: Scanner) bool {
        return self.current >= self.source.len;
    }

    fn advance(self: *Scanner) u8 {
        self.current += 1;
        return self.source[self.current - 1];
    }

    fn rollback(self: *Scanner) void {
        self.current -= 1;
    }

    pub fn currentLexeme(self: Scanner) []const u8 {
        return self.source[self.start..self.current];
    }

    fn makeToken(self: Scanner, ttype: TokenType) Token {
        return Token{
            .typ = ttype,
            .lexeme = self.currentLexeme(),
            .source_start_character = self.current,
        };
    }

    fn makeTokenLexeme(self: Scanner, ttype: TokenType, lexeme: []const u8) Token {
        return Token{
            .typ = ttype,
            .lexeme = lexeme,
            .source_start_character = self.current,
        };
    }

    /// Peek at the current character in the scanner
    fn peek(self: Scanner) u8 {
        if (self.isAtEnd()) return 0;
        if (self.current == 0) return 0;
        return self.source[self.current - 1];
    }

    /// Peek at the next character in the scanner
    fn peekNext(self: Scanner) u8 {
        if (self.current + 1 > self.source.len) return 0;
        return self.source[self.current];
    }

    /// Consume a string. stop_char is used to determine
    /// if the string is a single quote or double quote string
    fn doString(self: *Scanner, stop_char: u8) !Token {
        // consume entire string
        while (self.peekNext() != stop_char and !self.isAtEnd()) {
            _ = self.advance();
        }

        // unterminated string.
        if (self.isAtEnd()) {
            return error.NonTerminatedString;
        }

        // the closing character of the string
        _ = self.advance();

        // remove the starting and ending chars of the string
        const lexeme = self.currentLexeme();
        return self.makeTokenLexeme(
            .Tag,
            lexeme[1 .. lexeme.len - 1],
        );
    }

    fn doIdentifier(self: *Scanner) Token {
        while (std.ascii.isAlNum(self.peek())) {
            _ = self.advance();
        }

        if (self.peekNext() != 0) {
            self.rollback(); // ugly hack
        }

        return self.makeToken(.Tag);
    }

    pub fn next(self: *Scanner) !Token {
        self.start = self.current;

        if (self.isAtEnd()) return self.makeToken(.EOF);

        var c = self.advance();
        if (std.ascii.isAlNum(c)) return self.doIdentifier();

        return switch (c) {
            '(' => self.makeToken(.LeftParen),
            ')' => self.makeToken(.RightParen),
            '.' => self.makeToken(.Dot),

            // '\'' => try self.doString('\''),
            '"' => try self.doString('"'),

            ' ' => self.makeToken(.Space),
            //'\r', '\t'=>null,
            //'\n' => blk: {
            //    self.line += 1;
            //    break :blk null;
            //},

            else => return error.UnexpectedCharacter,
        };
    }
};

fn expectFollowingTokens(scanner: *Scanner, expected: anytype) !void {
    inline for (expected) |expected_element| {
        var token = try scanner.next();
        try std.testing.expectEqual(expected_element.@"0", token.typ);
        try std.testing.expectEqualStrings(expected_element.@"1", token.lexeme);
    }
}

fn expectSameTokenFromExpr(queries: anytype, expected: anytype) !void {
    inline for (queries) |query| {
        var scanner = Scanner.init(query);
        try expectFollowingTokens(&scanner, expected);
    }
}

test "scanner basics" {
    try expectSameTokenFromExpr(.{
        "a b c",
        "a \"b\" c",
        "a \"b\" \"c\"",
        "\"a\" \"b\" \"c\"",
    }, .{
        .{ TokenType.Tag, "a" },
        .{ TokenType.Space, " " },
        .{ TokenType.Tag, "b" },
        .{ TokenType.Space, " " },
        .{ TokenType.Tag, "c" },
    });
}
