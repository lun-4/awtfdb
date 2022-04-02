const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const log = std.log.scoped(.atags);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ atags: manage your tags
    \\
    \\ usage:
    \\ 	atags action [arguments...]
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\
    \\ examples:
    \\ 	atags create tag
    \\ 	atags create --core lkdjfalskjg tag
    \\ 	atags search tag
    \\ 	atags remove --tag tag
    \\ 	atags remove --core dslkjfsldkjf
;

const ActionConfig = union(enum) {
    Create: CreateAction.Config,
    Remove: RemoveAction.Config,
    Search: SearchAction.Config,
};

const CreateAction = struct {
    pub const Config = struct {
        tag_core: ?[]const u8 = null,
        tag: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator) !ActionConfig {
        var config = Config{};

        const ArgState = enum { None, NeedTagCore };
        var state: ArgState = .None;
        while (args_it.next()) |arg| {
            if (state == .NeedTagCore) {
                config.tag_core = arg;
                state = .None;
            } else if (std.mem.eql(u8, arg, "--core")) {
                state = .NeedTagCore;
            } else {
                config.tag = arg;
            }
        }
        return ActionConfig{ .Create = config };
    }

    ctx: *Context,
    config: Config,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config) !Self {
        return Self{ .ctx = ctx, .config = config };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        _ = self;

        var stdout = std.io.getStdOut().writer();

        var maybe_core: ?Context.Hash = null;
        var raw_core_hash_buffer: [32]u8 = undefined;

        if (self.config.tag_core) |tag_core_hex_string| {
            maybe_core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
        }

        const tag = try self.ctx.createNamedTag(self.config.tag.?, "en", maybe_core);

        try stdout.print(
            "created tag with core '{s}' name '{s}'\n",
            .{ tag.core, tag },
        );
    }
};

fn consumeCoreHash(ctx: *Context, raw_core_hash_buffer: *[32]u8, tag_core_hex_string: []const u8) !Context.Hash {
    if (tag_core_hex_string.len != 64) {
        log.err("hashes myst be 64 bytes long, got {d}", .{tag_core_hex_string.len});
        return error.InvalidHashLength;
    }
    var raw_core_hash = try std.fmt.hexToBytes(raw_core_hash_buffer, tag_core_hex_string);

    const hash_blob = sqlite.Blob{ .data = raw_core_hash };
    const hash_id = (try ctx.db.?.one(
        i64,
        \\ select hashes.id
        \\ from hashes
        \\ join tag_cores
        \\  on tag_cores.core_hash = hashes.id
        \\ where hashes.hash_data = ?
    ,
        .{},
        .{hash_blob},
    )) orelse {
        return error.UnknownTagCore;
    };

    log.debug("found hash_id for the given core: {d}", .{hash_id});
    return Context.Hash{ .id = hash_id, .hash_data = raw_core_hash_buffer.* };
}

const RemoveAction = struct {
    pub const Config = struct {
        tag_core: ?[]const u8 = null,
        tag: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator) !ActionConfig {
        var config = Config{};

        const ArgState = enum { None, NeedTagCore, NeedTag };
        var state: ArgState = .None;
        while (args_it.next()) |arg| {
            if (state == .NeedTagCore) {
                config.tag_core = arg;
                state = .None;
            } else if (state == .NeedTag) {
                config.tag = arg;
                state = .None;
            } else if (std.mem.eql(u8, arg, "--core")) {
                state = .NeedTagCore;
            } else if (std.mem.eql(u8, arg, "--tag")) {
                state = .NeedTag;
            } else {
                return error.InvalidArgument;
            }
        }
        return ActionConfig{ .Remove = config };
    }

    ctx: *Context,
    config: Config,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config) !Self {
        return Self{ .ctx = ctx, .config = config };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        _ = self;

        var stdout = std.io.getStdOut().writer();
        var stdin = std.io.getStdIn().reader();

        var raw_core_hash_buffer: [32]u8 = undefined;

        var amount: usize = 0;
        try stdout.print("the following tags will be removed:\n", .{});

        if (self.config.tag_core) |tag_core_hex_string| {
            var core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);

            // to delete the core, we need to delete every tag that references this tag core
            //
            // since this is a VERY destructive operation, we print the tag
            // names that are affected by this command, requiring user
            // confirmation to continue.

            var stmt = try self.ctx.db.?.prepare(
                "select tag_text, tag_language from tag_names where core_hash = ?",
            );
            defer stmt.deinit();

            var it = try stmt.iteratorAlloc(
                struct {
                    tag_text: []const u8,
                    tag_language: []const u8,
                },
                self.ctx.allocator,
                .{core.id},
            );

            while (try it.nextAlloc(self.ctx.allocator, .{})) |tag_name| {
                defer {
                    self.ctx.allocator.free(tag_name.tag_text);
                    self.ctx.allocator.free(tag_name.tag_language);
                }
                try stdout.print(" {s}", .{tag_name.tag_text});
                amount += 1;
            }
            try stdout.print("\n", .{});
        } else if (self.config.tag) |tag_text| {
            var maybe_tag = try self.ctx.fetchNamedTag(tag_text, "en");
            if (maybe_tag) |tag| {
                try stdout.print(" {s}", .{tag.kind.Named.text});
                amount += 1;
            } else {
                return error.NamedTagNotFound;
            }
            try stdout.print("\n", .{});
        }

        var outcome: [1]u8 = undefined;
        try stdout.print("do you want to remove {d} tags (y/n)? ", .{amount});
        _ = try stdin.read(&outcome);

        if (!std.mem.eql(u8, &outcome, "y")) return error.NotConfirmed;

        var deleted_count: i64 = undefined;

        if (self.config.tag_core) |tag_core_hex_string| {
            var core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            deleted_count = (try self.ctx.db.?.one(
                i64,
                "delete from tag_names where core_hash = ? returning count(*) as deleted_count",
                .{},
                .{core.id},
            )).?;
            try self.ctx.db.?.exec("delete from tag_cores where core_hash = ?", .{}, .{core.id});
            try self.ctx.db.?.exec("delete from hashes where id = ?", .{}, .{core.id});
        } else if (self.config.tag) |tag_text| {
            deleted_count = (try self.ctx.db.?.one(
                i64,
                "delete from tag_names where tag_text = ? and tag_language = ? returning (select count(*) from tag_names where tag_text = ? and tag_language = ?)as deleted_count",
                .{},
                .{ tag_text, "en", tag_text, "en" },
            )).?;
        }
        try stdout.print("deleted {d} tags\n", .{deleted_count});
    }
};

const SearchAction = struct {
    pub const Config = struct {
        query: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator) !ActionConfig {
        var config = Config{};
        config.query = args_it.next() orelse return error.MissingQuery;
        return ActionConfig{ .Search = config };
    }

    ctx: *Context,
    config: Config,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config) !Self {
        return Self{ .ctx = ctx, .config = config };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var stdout = std.io.getStdOut().writer();

        var stmt = try self.ctx.db.?.prepare(
            \\ select tag_text, tag_language, core_hash, hashes.hash_data
            \\ from tag_names
            \\ join hashes
            \\  on hashes.id = tag_names.core_hash
            \\ where tag_text LIKE '%' || ? || '%'
        );
        defer stmt.deinit();

        var tag_names = try stmt.all(
            struct {
                tag_text: []const u8,
                tag_language: []const u8,
                core_hash: i64,
                hash_data: sqlite.Blob,
            },
            self.ctx.allocator,
            .{},
            .{self.config.query.?},
        );

        defer {
            for (tag_names) |tag| {
                self.ctx.allocator.free(tag.tag_text);
                self.ctx.allocator.free(tag.tag_language);
                self.ctx.allocator.free(tag.hash_data.data);
            }
            self.ctx.allocator.free(tag_names);
        }

        for (tag_names) |tag_name| {
            const fake_hash = Context.HashWithBlob{
                .id = tag_name.core_hash,
                .hash_data = tag_name.hash_data,
            };
            var related_tags = try self.ctx.fetchTagsFromCore(
                self.ctx.allocator,
                fake_hash.toRealHash(),
            );
            defer related_tags.deinit();

            const full_tag_core = related_tags.items[0].core;
            try stdout.print("{s}", .{full_tag_core});
            for (related_tags.items) |tag| {
                try stdout.print(" '{s}'", .{tag});
            }
            try stdout.print("\n", .{});
        }
    }
};

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
        action_config: ?ActionConfig = null,
    };

    var given_args = Args{};

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            if (std.mem.eql(u8, arg, "search")) {
                given_args.action_config = try SearchAction.processArgs(&args_it);
            } else if (std.mem.eql(u8, arg, "create")) {
                given_args.action_config = try CreateAction.processArgs(&args_it);
            } else if (std.mem.eql(u8, arg, "remove")) {
                given_args.action_config = try RemoveAction.processArgs(&args_it);
            }
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.action_config == null) {
        std.log.err("action is a required argument", .{});
        return error.MissingAction;
    }
    const action_config = given_args.action_config.?;

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    switch (action_config) {
        .Search => |search_config| {
            var self = try SearchAction.init(&ctx, search_config);
            defer self.deinit();
            try self.run();
        },
        .Create => |create_config| {
            var self = try CreateAction.init(&ctx, create_config);
            defer self.deinit();
            try self.run();
        },
        .Remove => |remove_config| {
            var self = try RemoveAction.init(&ctx, remove_config);
            defer self.deinit();
            try self.run();
        },
    }
}
