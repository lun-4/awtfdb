const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;
const clap = @import("clap");
const ID = manage_main.ID;

const logger = std.log.scoped(.atags);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ atags: manage your tags
    \\
    \\ usage:
    \\ \tatags action [arguments...]
    \\
    \\ options:
    \\ \t-h\tprints this help and exits
    \\ \t-V\tprints version and exits
    \\ \t--no-confirm\tdo not ask for confirmation on remove
    \\ \tcommands.
    \\
    \\ examples of tag operations::
    \\ \tatags create tag
    \\ \tatags create --core lkdjfalskjg tag
    \\ \tatags search tag
    \\ \tatags search --exact tag
    \\ \tatags remove --tag tag
    \\ \tatags remove --core dslkjfsldkjf
    \\ \tatags remove --only-tag-name mytag --> only deleted name, no actual tag cores deleted
    \\
    \\ tag parent operations:
    \\ \tatags parent create child_tag parent_tag
    \\ \tatags parent list
    \\ \tatags parent remove id
    \\ \tatags parent remove --delete-tag-file-entries id
    \\ \tremove the parent entry and clean up the files that had tags
    \\ \tadded by this parent relationship
    \\
    \\ pool operations:
    \\ \tatags pool create "my pool title"
    \\ \tatags pool search "my"
    \\ \tatags pool fetch id
    \\ \tatags pool remove id
    \\
    \\ source operations:
    \\  atags source create "deepdanbooru"
    \\  atags source list
    \\  atags source remove id
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

    CreateSource: CreateSource.Config,
    ListSource: void,
    RemoveSource: RemoveSource.Config,
};

const BufferedStdout = std.io.BufferedWriter(4096, std.fs.File.Writer);

const IOContext = struct {
    buffered_stdout: BufferedStdout,
    unbuffered_stdout: std.fs.File.Writer,
    const Self = @This();

    pub fn system() Self {
        const raw_stdout = std.io.getStdOut().writer();
        const buffered_stdout = BufferedStdout{ .unbuffered_writer = raw_stdout };
        return Self{
            .buffered_stdout = buffered_stdout,
            .unbuffered_stdout = raw_stdout,
        };
    }

    pub fn captured(target_fd: std.fs.File.Writer) Self {
        const buffered = BufferedStdout{ .unbuffered_writer = target_fd };
        return Self{
            .buffered_stdout = buffered,
            .unbuffered_stdout = target_fd,
        };
    }

    pub fn stdout(self: *Self) std.fs.File.Writer {
        return self.unbuffered_stdout;
    }

    /// Must use flushStdout afterwards.
    pub fn bufferedStdout(self: *Self) BufferedStdout.Writer {
        return self.buffered_stdout.writer();
    }

    pub fn flushStdout(self: *Self) !void {
        try self.buffered_stdout.flush();
    }
};

const CreateAction = struct {
    pub const Config = struct {
        tag_core: ?[]const u8 = null,
        tag_alias: ?[]const u8 = null,
        tag: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\--core <string>      tag core data for the new tag
            \\--alias <string>     create a tag alias based on an existing tag
            \\<string>     name of the new tag
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .tag_core = res.args.core,
            .tag_alias = res.args.alias,
            .tag = res.positionals[0] orelse return error.MissingTagName,
        };
        if (config.tag_core != null and config.tag_alias != null) {
            logger.err("only one of --core or --alias may be provided", .{});
            return error.OnlyOneAliasOrCore;
        }
        return ActionConfig{ .Create = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
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

            var savepoint = try self.ctx.db.savepoint("tag_aliasing");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            const tag_to_be_aliased_to = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            var tag_to_be_aliased_from = if (try self.ctx.fetchNamedTag(self.config.tag.?, "en")) |tag_text|
                tag_text
            else
                return error.UnknownTag;

            if (std.meta.eql(tag_to_be_aliased_from.core.id, tag_to_be_aliased_to.id)) {
                logger.err(
                    "tag {s} already is pointing to core {s}, making a new alias of an existing alias is a destructive operation",
                    .{ self.config.tag.?, tag_to_be_aliased_to },
                );
                return error.TagAlreadyAliased;
            }

            // find all tags with that single tag (tag_to_be_aliased_from)
            const SqlGiver = @import("find_main.zig").SqlGiver;

            var giver = try SqlGiver.init();
            defer giver.deinit();

            // always wrap given tag text in quotemarks so that its
            // properly parsed by SqlGiver
            const find_query_text = try std.fmt.allocPrint(self.ctx.allocator, "\"{s}\"", .{self.config.tag.?});
            defer self.ctx.allocator.free(find_query_text);

            var wrapped_sql_result = try giver.giveMeSql(self.ctx.allocator, find_query_text);
            defer wrapped_sql_result.deinit();

            const sql_result = switch (wrapped_sql_result) {
                .Ok => |ok_body| ok_body,
                .Error => |error_body| {
                    logger.err("parse error at character {d}: {}", .{ error_body.character, error_body.error_type });
                    return error.ParseErrorHappened;
                },
            };

            if (sql_result.arguments.len != 1) {
                logger.err("expected 1 tag to bind from find query: '{s}', got {d}", .{ self.config.tag.?, sql_result.arguments.len });
                return error.ExpectedSingleTag;
            }

            std.debug.assert(std.mem.eql(u8, sql_result.arguments[0].tag, self.config.tag.?));

            // execute query and bind to tag_to_be_aliased_from
            var stmt = try self.ctx.db.prepareDynamic(sql_result.query);
            defer stmt.deinit();
            const args = [1]sqlite.Text{tag_to_be_aliased_from.core.id.sql()};
            var it = try stmt.iterator(ID.SQL, args);

            // add tag_to_be_aliased_to to all returned files
            while (try it.next(.{})) |file_hash_id_sql| {
                const file_hash_id = ID.new(file_hash_id_sql);
                var file = (try self.ctx.fetchFile(file_hash_id)).?;
                defer file.deinit();
                try file.addTag(tag_to_be_aliased_to, .{});

                try self.io.stdout().print("relinked {s}", .{file.local_path});
                try file.printTagsTo(self.ctx.allocator, self.io.stdout(), .{});
                try self.io.stdout().print("\n", .{});
            }

            // delete tag_to_be_aliased_from
            const deleted_tag_names = try tag_to_be_aliased_from.deleteAll(&self.ctx.db);
            logger.info("deleted {d} tag names", .{deleted_tag_names});

            // and create the proper alias (can only be done after deletion)
            const aliased_tag = try self.ctx.createNamedTag(self.config.tag.?, "en", tag_to_be_aliased_to, .{});
            logger.info("full tag info: {}", .{aliased_tag});

            return;
        }

        const tag = try self.ctx.createNamedTag(self.config.tag.?, "en", maybe_core, .{});

        try self.io.stdout().print(
            "created tag with core '{s}' name '{s}'\n",
            .{ tag.core, tag },
        );
    }
};

const TestIO = struct {
    f: std.fs.File,
    io: IOContext,

    pub fn deinit(self: @This()) void {
        self.f.close();
    }
};

fn testIO() !TestIO {
    var tmp = std.testing.tmpDir(.{});
    // dont want to clean tmp -- has debug info

    const file = try tmp.dir.createFile("captured.txt", .{ .read = true });
    var realpath_buf: [std.fs.max_path_bytes]u8 = undefined;
    const realpath = tmp.dir.realpath("captured.txt", &realpath_buf) catch unreachable;
    std.debug.print("realpath = {s}\n", .{realpath});
    const io = IOContext.captured(file.writer());
    return .{ .f = file, .io = io };
}

test "create action" {
    const config = CreateAction.Config{
        .tag_core = null,
        .tag = "test tag",
    };

    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tio = try testIO();
    defer tio.deinit();

    var action = try CreateAction.init(&ctx, config, &tio.io);
    defer action.deinit();

    try (&tio.io).stdout().print("test!!\n", .{});

    try action.run();

    _ = (try ctx.fetchNamedTag("test tag", "en")) orelse return error.ExpectedTag;
}

test "create action (aliasing)" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tag1 = try ctx.createNamedTag("test tag1", "en", null, .{});
    const tag2_before_alias = try ctx.createNamedTag("test tag2", "en", null, .{});

    try std.testing.expect(!std.meta.eql(tag2_before_alias.core.id, tag1.core.id));

    const tag1_core = tag1.core.toHex();

    // turn tag2 into an alias of tag1
    const config = CreateAction.Config{
        .tag_core = null,
        .tag_alias = &tag1_core,
        .tag = "test tag2",
    };

    var tio = try testIO();
    defer tio.deinit();

    var action = try CreateAction.init(&ctx, config, &tio.io);
    defer action.deinit();

    try action.run();

    // tag1 must still exist
    // tag2 must still exist, but with same core now

    const tag1_after_alias = (try ctx.fetchNamedTag("test tag1", "en")).?;
    const tag2_after_alias = (try ctx.fetchNamedTag("test tag2", "en")).?;
    try std.testing.expectEqual(tag1.core.id, tag1_after_alias.core.id);
    try std.testing.expectEqual(tag1.core.id, tag2_after_alias.core.id);
}

fn consumeCoreHash(ctx: *Context, raw_core_hash_buffer: *[32]u8, tag_core_hex_string: []const u8) !Context.Hash {
    if (tag_core_hex_string.len != 64) {
        logger.err("hashes myst be 64 bytes long, got {d}", .{tag_core_hex_string.len});
        return error.InvalidHashLength;
    }
    const raw_core_hash = try std.fmt.hexToBytes(raw_core_hash_buffer, tag_core_hex_string);

    const hash_blob = sqlite.Blob{ .data = raw_core_hash };
    const hash_id = (try ctx.db.one(
        ID.SQL,
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

    logger.debug("found hash_id for the given core: {d}", .{hash_id});
    return Context.Hash{ .id = ID.new(hash_id), .hash_data = raw_core_hash_buffer.* };
}

const RemoveAction = struct {
    pub const Config = struct {
        tag_core: ?[]const u8 = null,
        tag: ?[]const u8 = null,
        only_tag_name: ?[]const u8 = null,
        given_args: *const Args,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        const params = comptime clap.parseParamsComptime(
            \\-h, --help           display this help and exit.
            \\--core <string>      remove by tag core
            \\--tag <string>       remove by tag name
            \\--only-tag-name <string>     only remove the given tag name, don't delete the tag itself
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .given_args = given_args,
            .tag_core = res.args.core,
            .tag = res.args.tag,
            .only_tag_name = res.args.@"only-tag-name",
        };
        return ActionConfig{ .Remove = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var raw_core_hash_buffer: [32]u8 = undefined;

        var amount: usize = 0;
        var core_hash_id: ?ID = null;
        try self.io.stdout().print("the following tags will be removed:\n", .{});

        if (self.config.tag_core) |tag_core_hex_string| {
            var core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            core_hash_id = core.id;

            // to delete the core, we need to delete every tag that references this tag core
            //
            // since this is a VERY destructive operation, we print the tag
            // names that are affected by this command, requiring user
            // confirmation to continue.

            var stmt = try self.ctx.db.prepare(
                "select tag_text, tag_language from tag_names where core_hash = ?",
            );
            defer stmt.deinit();

            var it = try stmt.iteratorAlloc(
                struct {
                    tag_text: []const u8,
                    tag_language: []const u8,
                },
                self.ctx.allocator,
                .{core.id.sql()},
            );

            while (try it.nextAlloc(self.ctx.allocator, .{})) |tag_name| {
                defer {
                    self.ctx.allocator.free(tag_name.tag_text);
                    self.ctx.allocator.free(tag_name.tag_language);
                }
                try self.io.stdout().print(" {s}", .{tag_name.tag_text});
                amount += 1;
            }
            try self.io.stdout().print("\n", .{});
        } else if (self.config.tag) |tag_text| {
            const maybe_tag = try self.ctx.fetchNamedTag(tag_text, "en");
            if (maybe_tag) |tag| {
                try self.io.stdout().print(" {s}", .{tag.kind.Named.text});
                core_hash_id = tag.core.id;
                amount += 1;
            } else {
                return error.NamedTagNotFound;
            }
            try self.io.stdout().print("\n", .{});
        } else if (self.config.only_tag_name) |only_tag_name| {
            // only delete a singular tag name. do not delete any files.
            // tag core will be garbage collected in a janitor run

            _ = (try self.ctx.fetchNamedTag(only_tag_name, "en")) orelse {
                logger.err("named tag not found '{s}'", .{only_tag_name});
                return error.NamedTagNotFound;
            };

            try self.config.given_args.maybeAskConfirmation(
                "do you want to remove this tag? no files will have relationships removed (y/n)? ",
                .{},
            );

            const deleted_name_count = (try self.ctx.db.one(
                usize,
                \\ delete from tag_names
                \\ where tag_text = ?
                \\ and tag_language = ?
                \\ returning (
                \\  select count(*)
                \\  from tag_names
                \\  where tag_text = ? and tag_language = ?
                \\ ) as deleted_count
            ,
                .{},
                .{ only_tag_name, "en", only_tag_name, "en" },
            )).?;

            logger.info("deleted {} tag names", .{deleted_name_count});
            return;
        } else {
            unreachable;
        }

        {
            const referenced_files = (try self.ctx.db.one(
                usize,
                "select count(*) from tag_files where core_hash = ?",
                .{},
                .{core_hash_id.?.sql()},
            )) orelse 0;
            try self.io.stdout().print("{d} files reference this tag.\n", .{referenced_files});
        }

        try self.config.given_args.maybeAskConfirmation(
            "do you want to remove {d} tags (y/n)? ",
            .{amount},
        );

        var deleted_count: ?usize = null;

        if (self.config.tag_core) |tag_core_hex_string| {
            var core = try consumeCoreHash(self.ctx, &raw_core_hash_buffer, tag_core_hex_string);
            // TODO fix deleted_count here
            deleted_count = (try self.ctx.db.one(
                usize,
                \\ delete from tag_names
                \\ where core_hash = ?
                \\ returning (
                \\  select count(*)
                \\  from tag_names
                \\  where core_hash = ?
                \\ ) as deleted_count
            ,
                .{},
                .{ core.id.sql(), core.id.sql() },
            )).?;
            try self.ctx.db.exec("delete from tag_cores where core_hash = ?", .{}, .{core.id.sql()});
            try self.ctx.db.exec("delete from hashes where id = ?", .{}, .{core.id.sql()});
        } else if (self.config.tag) |tag_text| {
            deleted_count = (try self.ctx.db.one(
                usize,
                \\ delete from tag_names
                \\ where tag_text = ? and tag_language = ?
                \\ returning (
                \\  select count(*)
                \\  from tag_names
                \\  where tag_text = ? and tag_language = ?
                \\ ) as deleted_count
            ,
                .{},
                .{ tag_text, "en", tag_text, "en" },
            )).?;
        }
        try self.io.stdout().print("deleted {d} tags\n", .{deleted_count.?});
    }
};

test "remove action" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tio = try testIO();
    defer tio.deinit();

    var tag = try ctx.createNamedTag("test tag", "en", null, .{});
    const tag2 = try ctx.createNamedTag("test tag2", "en", tag.core, .{});
    _ = tag2;
    const tag3 = try ctx.createNamedTag("test tag3", "en", null, .{});

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");
    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file", .{});
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

    var action = try RemoveAction.init(&ctx, config, &tio.io);
    defer action.deinit();

    try (&tio.io).stdout().print("HIIII\n", .{});

    try action.run();

    // tag must be gone
    const maybe_tag1 = try ctx.fetchNamedTag("test tag1", "en");
    try std.testing.expectEqual(@as(?Context.Tag, null), maybe_tag1);
    const maybe_tag2 = try ctx.fetchNamedTag("test tag2", "en");
    try std.testing.expectEqual(@as(?Context.Tag, null), maybe_tag2);
    const maybe_tag3 = try ctx.fetchNamedTag("test tag3", "en");
    try std.testing.expect(maybe_tag3 != null);

    // file should only have tag3
    const file_tags = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(file_tags);

    try std.testing.expectEqual(@as(usize, 1), file_tags.len);
    try std.testing.expectEqual(tag3.core.id, file_tags[0].core.id);
}

const SearchAction = struct {
    pub const Config = struct {
        exact: bool = false,
        show_hashes: bool = false,
        query: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help           display this help and exit.
            \\--exact              search tags by exact match
            \\--hash               show hash of tag cores on returned results
            \\<string>             search query
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .exact = res.args.exact != 0,
            .show_hashes = res.args.hash != 0,
            .query = res.positionals[0] orelse return error.MissingQuery,
        };
        return ActionConfig{ .Search = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var stmt = if (self.config.exact)
            try self.ctx.db.prepareDynamic(
                \\ select distinct core_hash core_hash, hashes.hash_data
                \\ from tag_names
                \\ join hashes
                \\  on hashes.id = tag_names.core_hash
                \\ where tag_text = ?
                \\ order by hashes.id asc
            )
        else
            try self.ctx.db.prepareDynamic(
                \\ select distinct core_hash core_hash, hashes.hash_data
                \\ from tag_names
                \\ join hashes
                \\  on hashes.id = tag_names.core_hash
                \\ where tag_text LIKE '%' || ? || '%'
                \\ order by hashes.id asc
            );

        defer stmt.deinit();

        const tag_names = try stmt.all(
            struct {
                core_hash: ID.SQL,
                hash_data: sqlite.Blob,
            },
            self.ctx.allocator,
            .{},
            .{self.config.query.?},
        );

        defer {
            self.ctx.allocator.free(tag_names);
        }

        for (tag_names) |tag_name| {
            defer self.ctx.allocator.free(tag_name.hash_data.data);
            const fake_hash = Context.HashSQL{
                .id = tag_name.core_hash,
                .hash_data = tag_name.hash_data,
            };
            var related_tags = try self.ctx.fetchTagsFromCore(
                self.ctx.allocator,
                Context.Hash{
                    .id = ID.new(fake_hash.id),
                    .hash_data = undefined,
                },
            );
            defer related_tags.deinit();

            const full_tag_core = related_tags.items[0].core;
            if (self.config.show_hashes) {
                try self.io.stdout().print("{s}", .{fake_hash.toRealHash()});
            } else {
                try self.io.stdout().print("{s}", .{full_tag_core.id});
            }
            for (related_tags.items) |tag| {
                try self.io.stdout().print(" '{s}'", .{tag});
            }
            try self.io.stdout().print("\n", .{});
        }
    }
};

const CreateParent = struct {
    pub const Config = struct {
        child_tag: ?[]const u8 = null,
        parent_tag: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\<string>       child tag
            \\<string>       parent tag
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        _ = given_args;
        var config = Config{};
        config.child_tag = res.positionals[0];
        config.parent_tag = res.positionals[1];

        if (config.child_tag == null) {
            logger.err("child tag is required", .{});
            return error.ChildTagRequired;
        }

        if (config.parent_tag == null) {
            logger.err("parent tag is required", .{});
            return error.ParentTagRequired;
        }

        return ActionConfig{ .CreateParent = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        const child_tag = (try self.ctx.fetchNamedTag(self.config.child_tag.?, "en")) orelse {
            logger.err("expected '{s}' to be a named tag", .{self.config.child_tag.?});
            return error.ChildTagNotFound;
        };
        const parent_tag = (try self.ctx.fetchNamedTag(self.config.parent_tag.?, "en")) orelse {
            logger.err("expected '{s}' to be a named tag", .{self.config.parent_tag.?});
            return error.ParentTagNotFound;
        };

        const tree_id = try self.ctx.createTagParent(child_tag, parent_tag);
        try self.io.stdout().print(
            "created tag parent where every file with '{s}' is also '{s}' (tree id {d})\nprocessing new parents...\n",
            .{ child_tag, parent_tag, tree_id },
        );

        // now that the relationship is created, we must go through all files
        // and process new implications
        try self.ctx.processTagTree(.{});
    }
};

const ListParent = struct {
    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = allocator;
        _ = given_args;
        _ = args_it;
        return ActionConfig{ .ListParent = {} };
    }

    ctx: *Context,
    config: void,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: void, io: *IOContext) !Self {
        _ = config;
        return Self{ .ctx = ctx, .config = {}, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var stmt = try self.ctx.db.prepare(
            \\ select rowid,
            \\  parent_tag,
            \\  (select tag_text from tag_names where core_hash = parent_tag),
            \\  child_tag,
            \\  (select tag_text from tag_names where core_hash = child_tag)
            \\ from tag_implications
        );
        defer stmt.deinit();
        const entries = try stmt.all(struct {
            rowid: i64,
            parent_tag_id: ID.SQL,
            parent_tag: []const u8,
            child_tag_id: ID.SQL,
            child_tag: []const u8,
        }, self.ctx.allocator, .{}, .{});
        defer {
            for (entries) |entry| {
                self.ctx.allocator.free(entry.child_tag);
                self.ctx.allocator.free(entry.parent_tag);
            }
            self.ctx.allocator.free(entries);
        }

        for (entries) |tree_row| {
            try self.io.stdout().print(
                "{d}: {d} {s} -> {d} {s}\n",
                .{
                    tree_row.rowid,
                    ID.new(tree_row.child_tag_id),
                    tree_row.child_tag,
                    ID.new(tree_row.parent_tag_id),
                    tree_row.parent_tag,
                },
            );
        }

        try self.io.flushStdout();
    }
};

const RemoveParent = struct {
    pub const Config = struct {
        given_args: *Args,
        rowid: i64,
        delete_file_entries: bool = false,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\--delete-file-entries     if we should remove the tag relationships created by this tag parent
            \\<i64>     id of the tag parent relationship
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .given_args = given_args,
            .rowid = res.positionals[0] orelse return error.NeedParentId,
            .delete_file_entries = res.args.@"delete-file-entries" != 0,
        };
        return ActionConfig{ .RemoveParent = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        // parent_relationship is only used on that stdout call as
        // information for the user, so it can't be tested until we have
        // stdout capturing.
        const parent_relationship = (try self.ctx.db.one(
            struct { child_tag: ID.SQL, parent_tag: ID.SQL },
            "select child_tag, parent_tag from tag_implications where rowid = ?",
            .{},
            .{self.config.rowid},
        )) orelse return error.InvalidParentId;

        try self.io.stdout().print(
            "the parent relationship is between tags {s} -> {s}\n",
            .{ parent_relationship.parent_tag, parent_relationship.child_tag },
        );

        const tag_file_count = (try self.ctx.db.one(
            usize,
            "select count(*) from tag_files where parent_source_id = ?",
            .{},
            .{self.config.rowid},
        )).?;

        if (self.config.delete_file_entries) {
            try self.io.stdout().print("tag entries in files that were made by this relationship will be removed ({d} entries)\n", .{tag_file_count});
        } else {
            try self.io.stdout().print("tag entries in files that were made by this relationship will be retained but their relationship metadata will be removed. ({d} entries)\n", .{tag_file_count});
        }

        try self.config.given_args.maybeAskConfirmation(
            "do you wish to remove it? (press y) ",
            .{},
        );

        {
            var savepoint = try self.ctx.db.savepoint("parent_removal");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            const rowid = self.config.rowid;

            if (self.config.delete_file_entries) {
                logger.info("REMOVING all tag file entries that were made by this parent...", .{});
                const deleted_tag_file_count = (try self.ctx.db.one(
                    usize,
                    \\ delete from tag_files
                    \\ where
                    \\  parent_source_id = ?
                    \\  and tag_source_type = 0
                    \\  and tag_source_id = 1
                    \\ returning (
                    \\  select count(*)
                    \\  from tag_files
                    \\ where
                    \\  parent_source_id = ?
                    \\  and tag_source_type = 0
                    \\  and tag_source_id = 1
                    \\ ) as updated_count
                ,
                    .{},
                    .{ rowid, rowid },
                )).?;

                logger.info("deleted {d} tag_files entries", .{deleted_tag_file_count});
            } else {
                logger.info("UPDATING all tag file entries that were made by this parent and setting to null...", .{});
                const updated_tag_file_count = (try self.ctx.db.one(
                    usize,
                    \\ update tag_files
                    \\ set
                    \\  parent_source_id = null,
                    \\  tag_source_type = 0,
                    \\  tag_source_id = 0
                    \\ where
                    \\  parent_source_id = ?
                    \\  and tag_source_type = 0
                    \\  and tag_source_id = 1
                    \\ returning (
                    \\  select count(*)
                    \\  from tag_files
                    \\ where
                    \\  parent_source_id = ?
                    \\  and tag_source_type = 0
                    \\  and tag_source_id = 1
                    \\ ) as updated_count
                ,
                    .{},
                    .{ rowid, rowid },
                )).?;

                logger.info("updated {d} tag_files entries", .{updated_tag_file_count});
            }

            try self.ctx.db.exec(
                "delete from tag_implications where rowid = ?",
                .{},
                .{self.config.rowid},
            );
        }

        try self.io.stdout().print("deleted parent id {d}\n", .{self.config.rowid});
    }
};

test "remove parent (no entry deletion)" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    var tio = try testIO();
    defer tio.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file", .{});
    defer indexed_file.deinit();

    const ids = try parentTestSetup(&ctx, &indexed_file, &tio);

    // attempt to run command with delete_file_entries = false

    var args = Args{ .ask_confirmation = false };
    const config = RemoveParent.Config{
        .given_args = &args,
        // remove relationship child_tag -> parent_tag
        .rowid = ids.tag_tree_entry_id,
        .delete_file_entries = false,
    };

    var action = try RemoveParent.init(&ctx, config, &tio.io);
    defer action.deinit();

    try action.run();

    const file_tags = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(file_tags);
    try std.testing.expectEqual(@as(usize, 4), file_tags.len);

    var saw_parent_tag_without_source = false;

    for (file_tags) |file_tag| {
        if (std.meta.eql(file_tag.core.id, ids.parent_tag_core_id)) {
            try std.testing.expectEqual(manage_main.TagSourceType.system, file_tag.source.kind);
            try std.testing.expectEqual(@as(i64, @intFromEnum(manage_main.SystemTagSources.manual_insertion)), file_tag.source.id);
            try std.testing.expectEqual(@as(?i64, null), file_tag.parent_source_id);
            saw_parent_tag_without_source = true;
        }
    }
    try std.testing.expect(saw_parent_tag_without_source);
}

const ParentTestSetupResult = struct {
    tag_tree_entry_id: i64,
    tag_tree_entry2_id: i64,
    tag_tree_entry3_id: i64,
    parent_tag_core_id: ID,
    parent_tag2_core_id: ID,
    parent_tag3_core_id: ID,
};

fn parentTestSetup(
    ctx: *Context,
    indexed_file: *Context.File,
    tio: *TestIO,
) !ParentTestSetupResult {
    const child_tag = try ctx.createNamedTag("child_test_tag", "en", null, .{});
    try indexed_file.addTag(child_tag.core, .{});

    // only add this through inferrence
    // child_tag -> parent_tag, parent_tag2
    // parent_tag2 -> parent_tag3
    const parent_tag = try ctx.createNamedTag("parent_test_tag", "en", null, .{});
    const parent_tag2 = try ctx.createNamedTag("parent_test_tag2", "en", null, .{});
    const parent_tag3 = try ctx.createNamedTag("parent_test_tag3", "en", null, .{});
    const tag_tree_entry_id = try ctx.createTagParent(child_tag, parent_tag);
    const tag_tree_entry2_id = try ctx.createTagParent(child_tag, parent_tag2);
    const tag_tree_entry3_id = try ctx.createTagParent(parent_tag2, parent_tag3);
    try ctx.processTagTree(.{});

    // always run ListParent to ensure that tag parenting worked
    var action = try ListParent.init(ctx, {}, &tio.io);
    defer action.deinit();
    try action.run();

    try tio.f.seekTo(0);
    var buf: [8192]u8 = undefined;
    const bytes = try tio.f.readAll(&buf);
    const stdout_sent = buf[0..bytes];
    try std.testing.expect(std.mem.containsAtLeast(u8, stdout_sent, 1, parent_tag.core.id.str()));
    try std.testing.expect(std.mem.containsAtLeast(u8, stdout_sent, 1, parent_tag2.core.id.str()));
    try std.testing.expect(std.mem.containsAtLeast(u8, stdout_sent, 1, parent_tag3.core.id.str()));

    return ParentTestSetupResult{
        .tag_tree_entry_id = tag_tree_entry_id,
        .tag_tree_entry2_id = tag_tree_entry2_id,
        .tag_tree_entry3_id = tag_tree_entry3_id,
        .parent_tag_core_id = parent_tag.core.id,
        .parent_tag2_core_id = parent_tag2.core.id,
        .parent_tag3_core_id = parent_tag3.core.id,
    };
}

test "remove parent (with entry deletion)" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();
    var tio = try testIO();
    defer tio.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile("test_file", .{});
    defer file.close();
    _ = try file.write("awooga");

    var indexed_file = try ctx.createFileFromDir(tmp.dir, "test_file", .{});
    defer indexed_file.deinit();

    const ids = try parentTestSetup(&ctx, &indexed_file, &tio);

    var args = Args{ .ask_confirmation = false };
    const config = RemoveParent.Config{
        .given_args = &args,
        // remove relationship child_tag -> parent_tag
        .rowid = ids.tag_tree_entry_id,
        .delete_file_entries = true,
    };

    var action = try RemoveParent.init(&ctx, config, &tio.io);
    defer action.deinit();

    try action.run();

    {
        try tio.f.seekTo(0);
        var buf: [8192]u8 = undefined;
        const bytes = try tio.f.readAll(&buf);
        const stdout_sent = buf[0..bytes];
        try std.testing.expect(bytes > 0);
        try std.testing.expect(std.mem.containsAtLeast(u8, stdout_sent, 1, "the parent relationship is between tags"));
        try std.testing.expect(std.mem.containsAtLeast(u8, stdout_sent, 1, ids.parent_tag_core_id.str()));
    }

    const file_tags = try indexed_file.fetchTags(std.testing.allocator);
    defer std.testing.allocator.free(file_tags);
    try std.testing.expectEqual(@as(usize, 3), file_tags.len);

    for (file_tags) |file_tag| {
        if (std.meta.eql(file_tag.core.id, ids.parent_tag_core_id)) {
            return error.ShouldNotFindOriginalParentIdHere;
        }
    }
}

const CreatePool = struct {
    pub const Config = struct {
        title: []const u8,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\<string>     title of the pool
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .title = res.positionals[0] orelse return error.ExpectedPoolTitle,
        };
        return ActionConfig{ .CreatePool = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var pool = try self.ctx.createPool(self.config.title);
        defer pool.deinit();

        std.debug.print("pool created with id {d}", .{pool.hash.id});
        try self.io.stdout().print("{d}\n", .{pool.hash});
    }
};

const FetchPool = struct {
    pub const Config = struct {
        pool_id: ID,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\<string>     id of the pool
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .pool_id = ID.fromString(res.positionals[0] orelse return error.MissingPoolID),
        };
        return ActionConfig{ .FetchPool = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var pool = (try self.ctx.fetchPool(self.config.pool_id)) orelse return error.PoolNotFound;
        defer pool.deinit();

        const file_hashes = try pool.fetchFiles(self.ctx.allocator);
        defer self.ctx.allocator.free(file_hashes);

        try self.io.stdout().print(
            "pool '{s}' {s}\n",
            .{ pool.title, pool.hash },
        );

        for (file_hashes) |file_hash| {
            var file = (try self.ctx.fetchFile(file_hash.id)).?;
            defer file.deinit();

            try self.io.stdout().print("- {s}", .{file.local_path});
            try file.printTagsTo(self.ctx.allocator, self.io.stdout(), .{});
            try self.io.stdout().print("\n", .{});
        }
    }
};

const SearchPool = struct {
    pub const Config = struct {
        search_term: ?[]const u8 = null,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\<string>     search term
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .search_term = res.positionals[0] orelse return error.ExpectedSearchTerm,
        };
        return ActionConfig{ .SearchPool = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var stmt = try self.ctx.db.prepare(
            \\ select pool_hash
            \\ from pools
            \\ where pools.title LIKE '%' || ? || '%'
        );
        defer stmt.deinit();

        const pool_hashes = try stmt.all(
            ID.SQL,
            self.ctx.allocator,
            .{},
            .{self.config.search_term.?},
        );
        defer self.ctx.allocator.free(pool_hashes);

        for (pool_hashes) |pool_hash| {
            var pool = (try self.ctx.fetchPool(ID.new(pool_hash))).?;
            defer pool.deinit();

            try self.io.stdout().print(
                "pool '{s}' {s}\n",
                .{ pool.title, pool.hash },
            );
        }
    }
};

const RemovePool = struct {
    pub const Config = struct {
        given_args: *Args,
        pool_id: ID,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        const fetch_config = try FetchPool.processArgs(args_it, allocator, given_args);
        return ActionConfig{
            .RemovePool = Config{ .given_args = given_args, .pool_id = fetch_config.FetchPool.pool_id },
        };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var pool = (try self.ctx.fetchPool(self.config.pool_id)) orelse return error.PoolNotFound;
        defer pool.deinit();

        try self.io.stdout().print(
            "pool '{s}' {s} will be removed\n",
            .{ pool.title, pool.hash },
        );

        try self.config.given_args.maybeAskConfirmation(
            "do you want to remove the pool (y/n)? ",
            .{},
        );

        try pool.delete();
    }
};

const CreateSource = struct {
    pub const Config = struct {
        title: []const u8,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\<string>     title of the new tag source
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        const config = Config{
            .title = res.positionals[0] orelse return error.ExpectedSourceTitle,
        };
        return ActionConfig{ .CreateSource = config };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        const source = try self.ctx.createTagSource(self.config.title, .{});
        std.debug.print("source created with id {d}", .{source.id});
        try self.io.stdout().print("{d}\n", .{source.id});
    }
};

const RemoveSource = struct {
    pub const Config = struct {
        id: i64,
    };

    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        const params = comptime clap.parseParamsComptime(
            \\-h, --help   display this help and exit.
            \\<i64>     id of the tag source to remove
        );

        var diag = clap.Diagnostic{};
        var res = clap.parseEx(clap.Help, &params, clap.parsers.default, args_it, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            diag.report(std.io.getStdErr().writer(), err) catch {};
            return err;
        };
        defer res.deinit();

        if (res.args.help != 0) {
            try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
            return error.NoArgs;
        }

        return ActionConfig{ .RemoveSource = Config{
            .id = res.positionals[0] orelse return error.RequiredId,
        } };
    }

    ctx: *Context,
    config: Config,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: Config, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        const source =
            (try self.ctx.fetchTagSource(.external, self.config.id)) orelse return error.SourceNotFound;

        try source.delete();
        try self.io.stdout().print("ok\n", .{});
    }
};

const ListSource = struct {
    pub fn processArgs(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
        _ = given_args;
        _ = allocator;
        _ = args_it;
        return ActionConfig{ .ListSource = {} };
    }

    ctx: *Context,
    config: void,
    io: *IOContext,

    const Self = @This();

    pub fn init(ctx: *Context, config: void, io: *IOContext) !Self {
        return Self{ .ctx = ctx, .config = config, .io = io };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn run(self: *Self) !void {
        var stmt = try self.ctx.db.prepare(
            \\ select type, id, name
            \\ from tag_sources
        );
        defer stmt.deinit();
        const entries = try stmt.all(struct { type: i64, id: i64, name: []const u8 }, self.ctx.allocator, .{}, .{});
        defer {
            for (entries) |entry| {
                self.ctx.allocator.free(entry.name);
            }
            self.ctx.allocator.free(entries);
        }

        for (entries) |row| {
            try self.io.bufferedStdout().print(
                "type={d} id={d}: name={s}\n",
                .{ row.type, row.id, row.name },
            );
        }

        try self.io.flushStdout();
    }
};

const Args = struct {
    help: bool = false,
    version: bool = false,
    ask_confirmation: bool = true,
    action_config: ?ActionConfig = null,
    dry_run: bool = false,
    cli_v1: bool = true,

    pub fn maybeAskConfirmation(self: @This(), comptime fmt: []const u8, args: anytype) !void {
        var stdin = std.io.getStdIn().reader();
        var stdout = std.io.getStdOut().writer();

        if (self.ask_confirmation) {
            var outcome: [1]u8 = undefined;
            try stdout.print(fmt, args);
            _ = try stdin.read(&outcome);
            if (!std.mem.eql(u8, &outcome, "y")) return error.NotConfirmed;
        }
    }
};

pub var current_log_level: std.log.Level = .info;
pub const std_options = struct {
    pub const log_level = .debug;
    pub const logFn = manage_main.log;
};

fn parentMain(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
    const Modes = enum {
        create,
        list,
        remove,
    };

    const custom_parsers = .{
        .string = clap.parsers.string,
        .u8 = clap.parsers.int(u8, 0),
        .mode = clap.parsers.enumeration(Modes),
    };
    const params = comptime clap.parseParamsComptime(
        \\-h, --help   display this help and exit.
        \\<mode>       action (create, list, remove)
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, custom_parsers, args_it, .{
        .diagnostic = &diag,
        .allocator = allocator,
        .terminating_positional = 0,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return error.NoArgs;
    }

    return switch (res.positionals[0] orelse return error.MissingMode) {
        .create => try CreateParent.processArgs(args_it, allocator, given_args),
        .list => try ListParent.processArgs(args_it, allocator, given_args),
        .remove => try RemoveParent.processArgs(args_it, allocator, given_args),
    };
}

fn sourceMain(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
    const Modes = enum {
        create,
        list,
        remove,
    };

    const custom_parsers = .{
        .string = clap.parsers.string,
        .u8 = clap.parsers.int(u8, 0),
        .mode = clap.parsers.enumeration(Modes),
    };
    const params = comptime clap.parseParamsComptime(
        \\-h, --help   display this help and exit.
        \\<mode>       action (create, list, remove)
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, custom_parsers, args_it, .{
        .diagnostic = &diag,
        .allocator = allocator,
        .terminating_positional = 0,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return error.NoArgs;
    }

    return switch (res.positionals[0] orelse return error.MissingMode) {
        .create => try CreateSource.processArgs(args_it, allocator, given_args),
        .list => try ListSource.processArgs(args_it, allocator, given_args),
        .remove => try RemoveSource.processArgs(args_it, allocator, given_args),
    };
}

fn poolMain(args_it: *std.process.ArgIterator, allocator: std.mem.Allocator, given_args: *Args) !ActionConfig {
    const Modes = enum {
        create,
        fetch,
        search,
        remove,
    };

    const custom_parsers = .{
        .string = clap.parsers.string,
        .u8 = clap.parsers.int(u8, 0),
        .mode = clap.parsers.enumeration(Modes),
    };
    const params = comptime clap.parseParamsComptime(
        \\-h, --help   display this help and exit.
        \\<mode>       action (create, fetch, search, remove)
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, custom_parsers, args_it, .{
        .diagnostic = &diag,
        .allocator = allocator,
        .terminating_positional = 0,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return error.NoArgs;
    }

    return switch (res.positionals[0] orelse return error.MissingMode) {
        .create => try CreatePool.processArgs(args_it, allocator, given_args),
        .fetch => try FetchPool.processArgs(args_it, allocator, given_args),
        .search => try SearchPool.processArgs(args_it, allocator, given_args),
        .remove => try RemovePool.processArgs(args_it, allocator, given_args),
    };
}

pub fn main() anyerror!void {
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, manage_main.sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        logger.err("failed to configure: {d} '{s}'", .{
            rc, sqlite.c.sqlite3_errstr(rc),
        });
        return error.ConfigFail;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var given_args = Args{};

    const SubCommands = enum {
        // tags
        create,
        search,
        remove,
        // sub: parent
        parent,
        // sub: pool
        pool,
        // sub: source
        source,
    };

    const custom_parsers = .{
        .command = clap.parsers.enumeration(SubCommands),
    };

    const params = comptime clap.parseParamsComptime(
        \\-h, --help                  display this help and exit.
        \\-V, --version               print version and exit.
        \\-v, --verbose               enable debug logs.
        \\--no-confirm                do not ask for confirmation on remove commands
        \\--dry-run                   do not modify the index file
        \\--v1                        cli v1 mode (useful for scripts)
        \\<command>                   action (for tags: create, search, remove. there's parent, pool, source)
        \\
        \\ atags: manage tags, tag parents, pools, and tag sources
    );

    var iter = try std.process.ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();

    _ = iter.next(); // skip args[0] as that's exec name

    // from https://github.com/Hejsil/zig-clap/blob/master/example/subcommands.zig
    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, custom_parsers, &iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
        .terminating_positional = 0,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    given_args.help = res.args.help != 0;
    given_args.version = res.args.version != 0;
    if (res.args.verbose != 0) current_log_level = .debug;
    given_args.cli_v1 = res.args.v1 != 0;

    given_args.ask_confirmation = res.args.@"no-confirm" != 0;
    given_args.dry_run = res.args.@"dry-run" != 0;

    if (given_args.help) {
        return try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    } else if (given_args.version) {
        std.debug.print("atags {s}\n", .{VERSION});
        return;
    }

    const command = res.positionals[0] orelse return error.MissingCommand;
    given_args.action_config = switch (command) {
        .create => CreateAction.processArgs(&iter, allocator, &given_args),
        .search => SearchAction.processArgs(&iter, allocator, &given_args),
        .remove => RemoveAction.processArgs(&iter, allocator, &given_args),
        .parent => parentMain(&iter, allocator, &given_args),
        .pool => poolMain(&iter, allocator, &given_args),
        .source => sourceMain(&iter, allocator, &given_args),
    } catch |err| switch (err) {
        error.NoArgs => return {},
        else => return err,
    };

    if (given_args.action_config == null) {
        logger.err("action is a required argument", .{});
        return error.MissingAction;
    }
    const action_config = given_args.action_config.?;
    var ctx = try manage_main.loadDatabase(allocator, .{});
    defer ctx.deinit();
    if (given_args.dry_run) try ctx.turnIntoMemoryDb();

    var default_io = IOContext.system();

    errdefer ctx.logLastError();
    switch (action_config) {
        .Search => |search_config| {
            var self = try SearchAction.init(&ctx, search_config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .Create => |create_config| {
            var self = try CreateAction.init(&ctx, create_config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .Remove => |remove_config| {
            var self = try RemoveAction.init(&ctx, remove_config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .CreateParent => |config| {
            var self = try CreateParent.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .ListParent => |config| {
            var self = try ListParent.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .RemoveParent => |config| {
            var self = try RemoveParent.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },

        .CreatePool => |config| {
            var self = try CreatePool.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .FetchPool => |config| {
            var self = try FetchPool.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .SearchPool => |config| {
            var self = try SearchPool.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .RemovePool => |config| {
            var self = try RemovePool.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },

        .CreateSource => |config| {
            var self = try CreateSource.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .ListSource => |config| {
            var self = try ListSource.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
        .RemoveSource => |config| {
            var self = try RemoveSource.init(&ctx, config, &default_io);
            defer self.deinit();
            try self.run();
        },
    }
}
