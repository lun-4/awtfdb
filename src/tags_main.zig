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
    \\ 	--no-confirm			do not ask for confirmation on remove
    \\ 					commands.
    \\
    \\ examples of tag operations::
    \\ 	atags create tag
    \\ 	atags create --core lkdjfalskjg tag
    \\ 	atags search tag
    \\ 	atags remove --tag tag
    \\ 	atags remove --core dslkjfsldkjf
    \\ 	atags remove --only-tag-name mytag --> only deleted name, no actual tag cores deleted
    \\
    \\ tag parent operations:
    \\ 	atags parent create child_tag parent_tag
    \\ 	atags parent list
    \\ 	atags parent remove id
    \\
    \\ pool operations:
    \\ 	atags pool create "my pool title"
    \\ 	atags pool search "my"
    \\ 	atags pool fetch id
    \\ 	atags pool remove id
;

const ActionConfig = union(enum) {
    Create: CreateAction.Config,
    Remove: RemoveAction.Config,
    Search: SearchAction.Config,

    CreateParent: CreateParent.Config,
    ListParent: void,
    RemoveParent: RemoveParent.Config,

    CreatePool: CreatePool.Config,
    FetchPool: FetchPool.Config,
    SearchPool: SearchPool.Config,
    RemovePool: RemovePool.Config,
};

const CreateAction = struct {
    pub const Config = struct {
        tag_core: ?[]const u8 = null,
        tag_alias: ?[]const u8 = null,
        tag: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        var config = Config{};

        const ArgState = enum { None, NeedTagCore, NeedTagAlias };
        var state: ArgState = .None;
        while (args_it.next()) |arg| {
            if (state == .NeedTagCore) {
                config.tag_core = arg;
                state = .None;
            } else if (state == .NeedTagAlias) {
                config.tag_alias = arg;
                state = .None;
            } else if (std.mem.eql(u8, arg, "--core")) {
                state = .NeedTagCore;
            } else if (std.mem.eql(u8, arg, "--alias")) {
                state = .NeedTagAlias;
            } else {
                config.tag = arg;
            }

            if (config.tag_core != null and config.tag_alias != null) {
                log.err("only one of --core or --alias may be provided", .{});
                return error.OnlyOneAliasOrCore;
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

        var raw_core_hash_buffer: [32]u8 = undefined;
        var maybe_core: ?Context.Hash = null;

        if (self.config.tag_core) |tag_core_hex_string| {
            maybe_core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
        } else if (self.config.tag_alias) |tag_core_hex_string| {
            // tag aliasing is a process where you have two separate tags
            // and you want them both to refer to the same core, in a non
            // destructive manner, by relinking files from the tag that's going
            // to become the alias.
            //
            // for purposes of explanation, we'll consider that we have
            // tag A and tag B, and we want B to be an alias of A
            //
            // to do so, we need to
            //  - find all files that are linked to B
            //  - link them to A
            //  - delete tag B
            //  - create tag B, with core set to A

            var savepoint = try self.ctx.db.?.savepoint("tag_aliasing");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            var tag_to_be_aliased_to = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            var tag_to_be_aliased_from = if (try self.ctx.fetchNamedTag(self.config.tag.?, "en")) |tag_text|
                tag_text
            else
                return error.UnknownTag;

            if (tag_to_be_aliased_from.core.id == tag_to_be_aliased_to.id) {
                log.err(
                    "tag {s} already is pointing to core {s}, making a new alias of an existing alias is a destructive operation",
                    .{ self.config.tag.?, tag_to_be_aliased_to },
                );
                return error.TagAlreadyAliased;
            }

            // find all tags with that single tag (tag_to_be_aliased_from)
            const SqlGiver = @import("./find_main.zig").SqlGiver;

            var giver = try SqlGiver.init();
            defer giver.deinit();

            // always wrap given tag text in quotemarks so that its
            // properly parsed by SqlGiver
            var find_query_text = try std.fmt.allocPrint(self.ctx.allocator, "\"{s}\"", .{self.config.tag.?});
            defer self.ctx.allocator.free(find_query_text);

            var wrapped_sql_result = try giver.giveMeSql(self.ctx.allocator, find_query_text);
            defer wrapped_sql_result.deinit();

            const sql_result = switch (wrapped_sql_result) {
                .Ok => |ok_body| ok_body,
                .Error => |error_body| {
                    log.err("parse error at character {d}: {}", .{ error_body.character, error_body.error_type });
                    return error.ParseErrorHappened;
                },
            };

            if (sql_result.tags.len != 1) {
                log.err("expected 1 tag to bind from find query: '{s}', got {d}", .{ self.config.tag.?, sql_result.tags.len });
                return error.ExpectedSingleTag;
            }

            std.debug.assert(std.mem.eql(u8, sql_result.tags[0], self.config.tag.?));

            // execute query and bind to tag_to_be_aliased_from
            var stmt = try self.ctx.db.?.prepareDynamic(sql_result.query);
            defer stmt.deinit();
            var args = [1]i64{tag_to_be_aliased_from.core.id};
            var it = try stmt.iterator(i64, args);

            // add tag_to_be_aliased_to to all returned files
            while (try it.next(.{})) |file_hash_id| {
                var file = (try self.ctx.fetchFile(file_hash_id)).?;
                defer file.deinit();
                try file.addTag(tag_to_be_aliased_to, .{});

                try stdout.print("relinked {s}", .{file.local_path});
                try file.printTagsTo(self.ctx.allocator, stdout);
                try stdout.print("\n", .{});
            }

            // delete tag_to_be_aliased_from
            const deleted_tag_names = try tag_to_be_aliased_from.deleteAll(&self.ctx.db.?);
            log.info("deleted {d} tag names", .{deleted_tag_names});

            // and create the proper alias (can only be done after deletion)
            const aliased_tag = try self.ctx.createNamedTag(self.config.tag.?, "en", tag_to_be_aliased_to);
            log.info("full tag info: {}", .{aliased_tag});

            return;
        }

        const tag = try self.ctx.createNamedTag(self.config.tag.?, "en", maybe_core);

        try stdout.print(
            "created tag with core '{s}' name '{s}'\n",
            .{ tag.core, tag },
        );
    }
};

test "create action" {
    const config = CreateAction.Config{
        .tag_core = null,
        .tag = "test tag",
    };

    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var action = try CreateAction.init(&ctx, config);
    defer action.deinit();

    try action.run();

    _ = (try ctx.fetchNamedTag("test tag", "en")) orelse return error.ExpectedTag;
}

test "create action (aliasing)" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tag1 = try ctx.createNamedTag("test tag1", "en", null);
    var tag2_before_alias = try ctx.createNamedTag("test tag2", "en", null);

    try std.testing.expect(tag2_before_alias.core.id != tag1.core.id);

    const tag1_core = tag1.core.toHex();

    // turn tag2 into an alias of tag1
    const config = CreateAction.Config{
        .tag_core = null,
        .tag_alias = &tag1_core,
        .tag = "test tag2",
    };

    var action = try CreateAction.init(&ctx, config);
    defer action.deinit();

    try action.run();

    // tag1 must still exist
    // tag2 must still exist, but with same core now

    var tag1_after_alias = (try ctx.fetchNamedTag("test tag1", "en")).?;
    var tag2_after_alias = (try ctx.fetchNamedTag("test tag2", "en")).?;
    try std.testing.expectEqual(tag1.core.id, tag1_after_alias.core.id);
    try std.testing.expectEqual(tag1.core.id, tag2_after_alias.core.id);
}

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
        only_tag_name: ?[]const u8 = null,
        given_args: *const Args,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        var config = Config{ .given_args = given_args };

        const ArgState = enum { None, NeedTagCore, NeedTag, NeedTagName };
        var state: ArgState = .None;
        while (args_it.next()) |arg| {
            if (state == .NeedTagCore) {
                config.tag_core = arg;
                state = .None;
            } else if (state == .NeedTag) {
                config.tag = arg;
                state = .None;
            } else if (state == .NeedTagName) {
                config.only_tag_name = arg;
                state = .None;
            } else if (std.mem.eql(u8, arg, "--core")) {
                state = .NeedTagCore;
            } else if (std.mem.eql(u8, arg, "--tag")) {
                state = .NeedTag;
            } else if (std.mem.eql(u8, arg, "--only-tag-name")) {
                state = .NeedTagName;
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
        var core_hash_id: ?i64 = null;
        try stdout.print("the following tags will be removed:\n", .{});

        if (self.config.tag_core) |tag_core_hex_string| {
            var core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            core_hash_id = core.id;

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
                core_hash_id = tag.core.id;
                amount += 1;
            } else {
                return error.NamedTagNotFound;
            }
            try stdout.print("\n", .{});
        } else if (self.config.only_tag_name) |only_tag_name| {
            // only delete a singular tag name. do not delete any files.
            // tag core will be garbage collected in a janitor run

            _ = (try self.ctx.fetchNamedTag(only_tag_name, "en")) orelse {
                log.err("named tag not found '{s}'", .{only_tag_name});
                return error.NamedTagNotFound;
            };

            if (self.config.given_args.ask_confirmation) {
                var outcome: [1]u8 = undefined;
                try stdout.print("do you want to remove this tag? no files will have relationships removed (y/n)? ", .{});
                _ = try stdin.read(&outcome);

                if (!std.mem.eql(u8, &outcome, "y")) return error.NotConfirmed;
            }

            const deleted_name_count = (try self.ctx.db.?.one(
                i64,
                \\ delete from tag_names
                \\ where tag_text = ?
                \\ and tag_language = ?
                \\ returning (
                \\ 	select count(*)
                \\ 	from tag_names
                \\ 	where tag_text = ? and tag_language = ?
                \\ ) as deleted_count
            ,
                .{},
                .{ only_tag_name, "en", only_tag_name, "en" },
            )).?;

            log.info("deleted {} tag names", .{deleted_name_count});
            return;
        } else {
            unreachable;
        }

        {
            const referenced_files = (try self.ctx.db.?.one(
                i64,
                "select count(*) from tag_files where core_hash = ?",
                .{},
                .{core_hash_id},
            )) orelse 0;
            try stdout.print("{d} files reference this tag.\n", .{referenced_files});
        }

        if (self.config.given_args.ask_confirmation) {
            var outcome: [1]u8 = undefined;
            try stdout.print("do you want to remove {d} tags (y/n)? ", .{amount});
            _ = try stdin.read(&outcome);

            if (!std.mem.eql(u8, &outcome, "y")) return error.NotConfirmed;
        }

        var deleted_count: ?i64 = null;

        if (self.config.tag_core) |tag_core_hex_string| {
            var core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            // TODO fix deleted_count here
            deleted_count = (try self.ctx.db.?.one(
                i64,
                \\ delete from tag_names
                \\ where core_hash = ?
                \\ returning (
                \\ 	select count(*)
                \\ 	from tag_names
                \\ 	where core_hash = ?
                \\ ) as deleted_count
            ,
                .{},
                .{ core.id, core.id },
            )).?;
            try self.ctx.db.?.exec("delete from tag_cores where core_hash = ?", .{}, .{core.id});
            try self.ctx.db.?.exec("delete from hashes where id = ?", .{}, .{core.id});
        } else if (self.config.tag) |tag_text| {
            deleted_count = (try self.ctx.db.?.one(
                i64,
                \\ delete from tag_names
                \\ where tag_text = ? and tag_language = ?
                \\ returning (
                \\ 	select count(*)
                \\ 	from tag_names
                \\ 	where tag_text = ? and tag_language = ?
                \\ ) as deleted_count
            ,
                .{},
                .{ tag_text, "en", tag_text, "en" },
            )).?;
        }
        try stdout.print("deleted {d} tags\n", .{deleted_count.?});
    }
};

test "remove action" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tag = try ctx.createNamedTag("test tag", "en", null);
    var tag2 = try ctx.createNamedTag("test tag2", "en", tag.core);
    _ = tag2;
    var tag3 = try ctx.createNamedTag("test tag3", "en", null);
    _ = tag3;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");
    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file");
    defer indexed_file.deinit();

    // setup file tags to 1, 2, 3
    try indexed_file.addTag(tag.core, .{});
    try indexed_file.addTag(tag3.core, .{});

    const tag1_core = tag.core.toHex();
    const args = Args{ .ask_confirmation = false };

    const config = RemoveAction.Config{
        .tag_core = &tag1_core,
        .tag = null,
        .given_args = &args,
    };

    var action = try RemoveAction.init(&ctx, config);
    defer action.deinit();

    try action.run();

    // tag must be gone
    var maybe_tag1 = try ctx.fetchNamedTag("test tag1", "en");
    try std.testing.expectEqual(@as(?Context.Tag, null), maybe_tag1);
    var maybe_tag2 = try ctx.fetchNamedTag("test tag2", "en");
    try std.testing.expectEqual(@as(?Context.Tag, null), maybe_tag2);
    var maybe_tag3 = try ctx.fetchNamedTag("test tag3", "en");
    try std.testing.expect(maybe_tag3 != null);

    // file should only have tag3
    var tag_cores = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(tag_cores);

    try std.testing.expectEqual(@as(usize, 1), tag_cores.len);
    try std.testing.expectEqual(tag3.core.id, tag_cores[0].id);
}

const SearchAction = struct {
    pub const Config = struct {
        query: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
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
            \\ select distinct core_hash core_hash, hashes.hash_data
            \\ from tag_names
            \\ join hashes
            \\  on hashes.id = tag_names.core_hash
            \\ where tag_text LIKE '%' || ? || '%'
            \\ order by hashes.id asc
        );
        defer stmt.deinit();

        var tag_names = try stmt.all(
            struct {
                core_hash: i64,
                hash_data: sqlite.Blob,
            },
            self.ctx.allocator,
            .{},
            .{self.config.query.?},
        );

        defer {
            for (tag_names) |tag| {
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

const CreateParent = struct {
    pub const Config = struct {
        child_tag: ?[]const u8 = null,
        parent_tag: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        var config = Config{};

        const ArgState = enum { None, NeedChildTag, NeedParentTag };
        var state: ArgState = .NeedChildTag;
        while (args_it.next()) |arg| {
            if (state == .NeedChildTag) {
                config.child_tag = arg;
                state = .NeedParentTag;
            } else if (state == .NeedParentTag) {
                config.parent_tag = arg;
                state = .None;
            } else {
                log.err("invalid argument '{s}'", .{arg});
                return error.InvalidArgument;
            }
        }

        if (config.child_tag == null) {
            log.err("child tag is required", .{});
            return error.ChildTagRequired;
        }

        if (config.parent_tag == null) {
            log.err("parent tag is required", .{});
            return error.ParentTagRequired;
        }

        return ActionConfig{ .CreateParent = config };
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
        const child_tag = (try self.ctx.fetchNamedTag(self.config.child_tag.?, "en")) orelse {
            log.err("expected '{s}' to be a named tag", .{self.config.child_tag.?});
            return error.ChildTagNotFound;
        };
        const parent_tag = (try self.ctx.fetchNamedTag(self.config.parent_tag.?, "en")) orelse {
            log.err("expected '{s}' to be a named tag", .{self.config.parent_tag.?});
            return error.ParentTagNotFound;
        };

        try self.ctx.createTagParent(child_tag, parent_tag);
        try stdout.print(
            "created tag parent where every file with '{s}' is also '{s}'\nprocessing new parents...\n",
            .{ child_tag, parent_tag },
        );

        // now that the relationship is created, we must go through all files
        // and process new implications
        try self.ctx.processTagTree(.{});
    }
};

const ListParent = struct {
    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        _ = args_it;
        return ActionConfig{ .ListParent = {} };
    }

    ctx: *Context,
    config: void,

    const Self = @This();

    pub fn init(ctx: *Context, config: void) !Self {
        _ = config;
        return Self{ .ctx = ctx, .config = {} };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var raw_stdout = std.io.getStdOut().writer();

        var stmt = try self.ctx.db.?.prepare(
            \\ select rowid,
            \\  parent_tag,
            \\ 	(select tag_text from tag_names where core_hash = parent_tag),
            \\ 	child_tag,
            \\ 	(select tag_text from tag_names where core_hash = child_tag)
            \\ from tag_implications
        );
        defer stmt.deinit();
        var entries = try stmt.all(struct {
            rowid: i64,
            parent_tag_id: i64,
            parent_tag: []const u8,
            child_tag_id: i64,
            child_tag: []const u8,
        }, self.ctx.allocator, .{}, .{});
        defer {
            for (entries) |entry| {
                self.ctx.allocator.free(entry.child_tag);
                self.ctx.allocator.free(entry.parent_tag);
            }
            self.ctx.allocator.free(entries);
        }

        const BufferedFileWriter = std.io.BufferedWriter(4096, std.fs.File.Writer);
        var buffered_stdout = BufferedFileWriter{ .unbuffered_writer = raw_stdout };
        var stdout = buffered_stdout.writer();

        for (entries) |tree_row| {
            try stdout.print(
                "{d}: {d} {s} -> {d} {s}\n",
                .{
                    tree_row.rowid,
                    tree_row.child_tag_id,
                    tree_row.child_tag,
                    tree_row.parent_tag_id,
                    tree_row.parent_tag,
                },
            );
        }

        try buffered_stdout.flush();
    }
};

const RemoveParent = struct {
    pub const Config = struct {
        given_args: *Args,
        rowid: ?i64 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        var config = Config{
            .given_args = given_args,
            .rowid = try std.fmt.parseInt(i64, args_it.next() orelse return error.NeedParentId, 10),
        };

        return ActionConfig{ .RemoveParent = config };
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
        var stdin = std.io.getStdIn().reader();

        var parent_relationship = (try self.ctx.db.?.one(
            struct { child_tag: i64, parent_tag: i64 },
            "select child_tag, parent_tag from tag_implications where rowid = ?",
            .{},
            .{self.config.rowid.?},
        )) orelse return error.InvalidParentId;

        try stdout.print(
            "the parent relationship is between tags {d} -> {d}\n",
            .{ parent_relationship.parent_tag, parent_relationship.child_tag },
        );

        if (self.config.given_args.ask_confirmation) {
            try stdout.print("do you wish to remove it? (press y) ", .{});
            var outcome: [1]u8 = undefined;
            _ = try stdin.read(&outcome);
            if (!std.mem.eql(u8, &outcome, "y")) return error.NotConfirmed;
        }

        try self.ctx.db.?.exec(
            "delete from tag_implications where rowid = ?",
            .{},
            .{self.config.rowid.?},
        );

        try stdout.print("deleted parent id {d}\n", .{self.config.rowid.?});
    }
};

const CreatePool = struct {
    pub const Config = struct {
        title: []const u8,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        var config = Config{
            .title = args_it.next() orelse return error.ExpectedPoolTitle,
        };
        return ActionConfig{ .CreatePool = config };
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

        var pool = try self.ctx.createPool(self.config.title);
        defer pool.deinit();

        std.debug.print("pool created with id ", .{});
        try stdout.print("{d}\n", .{pool.hash});
    }
};

const FetchPool = struct {
    pub const Config = struct {
        pool_id: i64,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;

        const pool_id_str = args_it.next() orelse return error.ExpectedPoolTitle;
        var config = Config{
            .pool_id = try std.fmt.parseInt(i64, pool_id_str, 10),
        };
        return ActionConfig{ .FetchPool = config };
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

        var pool = (try self.ctx.fetchPool(self.config.pool_id)) orelse return error.PoolNotFound;
        defer pool.deinit();

        var file_hashes = try pool.fetchFiles(self.ctx.allocator);
        defer self.ctx.allocator.free(file_hashes);

        try stdout.print(
            "pool '{s}' {s}\n",
            .{ pool.title, pool.hash },
        );

        for (file_hashes) |file_hash| {
            var file = (try self.ctx.fetchFile(file_hash.id)).?;
            defer file.deinit();

            try stdout.print("- {s}", .{file.local_path});
            try file.printTagsTo(self.ctx.allocator, stdout);
            try stdout.print("\n", .{});
        }
    }
};

const SearchPool = struct {
    pub const Config = struct {
        search_term: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        _ = given_args;
        var config = Config{
            .search_term = args_it.next() orelse return error.ExpectedSearchTerm,
        };
        return ActionConfig{ .SearchPool = config };
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
            \\ select pool_hash
            \\ from pools
            \\ where pools.title LIKE '%' || ? || '%'
        );
        defer stmt.deinit();

        var pool_hashes = try stmt.all(
            i64,
            self.ctx.allocator,
            .{},
            .{self.config.search_term.?},
        );
        defer self.ctx.allocator.free(pool_hashes);

        for (pool_hashes) |pool_hash| {
            var pool = (try self.ctx.fetchPool(pool_hash)).?;
            defer pool.deinit();

            try stdout.print(
                "pool '{s}' {s}\n",
                .{ pool.title, pool.hash },
            );
        }
    }
};

const RemovePool = struct {
    pub const Config = struct {
        given_args: *Args,
        pool_id: i64,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, given_args: *Args) !ActionConfig {
        const fetch_config = try FetchPool.processArgs(args_it, given_args);
        return ActionConfig{
            .RemovePool = Config{ .given_args = given_args, .pool_id = fetch_config.FetchPool.pool_id },
        };
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

        var pool = (try self.ctx.fetchPool(self.config.pool_id)) orelse return error.PoolNotFound;
        defer pool.deinit();

        try stdout.print(
            "pool '{s}' {s} will be removed\n",
            .{ pool.title, pool.hash },
        );

        var stdin = std.io.getStdIn();
        if (self.config.given_args.ask_confirmation) {
            var outcome: [1]u8 = undefined;
            try stdout.print("do you want to remove the pool (y/n)? ", .{});
            _ = try stdin.read(&outcome);
            if (!std.mem.eql(u8, &outcome, "y")) return error.NotConfirmed;
        }

        try pool.delete();
    }
};

const Args = struct {
    help: bool = false,
    version: bool = false,
    ask_confirmation: bool = true,
    action_config: ?ActionConfig = null,
    dry_run: bool = false,
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

    var given_args = Args{};
    var arg_state: enum { None, Parent, Pool } = .None;

    while (args_it.next()) |arg| {
        switch (arg_state) {
            .Parent => {
                if (std.mem.eql(u8, arg, "create")) {
                    given_args.action_config = try CreateParent.processArgs(&args_it, &given_args);
                } else if (std.mem.eql(u8, arg, "list")) {
                    given_args.action_config = try ListParent.processArgs(&args_it, &given_args);
                } else if (std.mem.eql(u8, arg, "remove")) {
                    given_args.action_config = try RemoveParent.processArgs(&args_it, &given_args);
                } else {
                    log.err("{s} is an invalid parent action", .{arg});
                    return error.InvalidParentAction;
                }
                arg_state = .None;
                continue;
            },

            .Pool => {
                if (std.mem.eql(u8, arg, "create")) {
                    given_args.action_config = try CreatePool.processArgs(&args_it, &given_args);
                } else if (std.mem.eql(u8, arg, "fetch")) {
                    given_args.action_config = try FetchPool.processArgs(&args_it, &given_args);
                } else if (std.mem.eql(u8, arg, "search")) {
                    given_args.action_config = try SearchPool.processArgs(&args_it, &given_args);
                } else if (std.mem.eql(u8, arg, "remove")) {
                    given_args.action_config = try RemovePool.processArgs(&args_it, &given_args);
                } else {
                    log.err("{s} is an invalid pool action", .{arg});
                    return error.InvalidPoolAction;
                }
                arg_state = .None;
                continue;
            },

            .None => {},
        }

        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "--no-confirm")) {
            given_args.ask_confirmation = false;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            given_args.dry_run = true;
        } else if (std.mem.eql(u8, arg, "search")) {
            given_args.action_config = try SearchAction.processArgs(&args_it, &given_args);
        } else if (std.mem.eql(u8, arg, "create")) {
            given_args.action_config = try CreateAction.processArgs(&args_it, &given_args);
        } else if (std.mem.eql(u8, arg, "remove")) {
            given_args.action_config = try RemoveAction.processArgs(&args_it, &given_args);
        } else if (std.mem.eql(u8, arg, "parent")) {
            arg_state = .Parent;
        } else if (std.mem.eql(u8, arg, "pool")) {
            arg_state = .Pool;
        } else {
            log.err("{s} is an invalid action", .{arg});
            return error.InvalidAction;
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
    if (given_args.dry_run) try ctx.turnIntoMemoryDb();

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
        .CreateParent => |config| {
            var self = try CreateParent.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },
        .ListParent => |config| {
            var self = try ListParent.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },
        .RemoveParent => |config| {
            var self = try RemoveParent.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },

        .CreatePool => |config| {
            var self = try CreatePool.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },

        .FetchPool => |config| {
            var self = try FetchPool.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },
        .SearchPool => |config| {
            var self = try SearchPool.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },
        .RemovePool => |config| {
            var self = try RemovePool.init(&ctx, config);
            defer self.deinit();
            try self.run();
        },
    }
}
