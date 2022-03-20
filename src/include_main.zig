const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const Context = manage_main.Context;

const log = std.log.scoped(.ainclude);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ ainclude: include a file/folder into the awtfdb
    \\
    \\ usage:
    \\ 	ainclude [options..] <file/folder path...>
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\ 	-v				turns on verbosity (debug logging)
    \\ 	--tag <tag>			add the following tag to the given path
    \\ 					 (if its a folder, add the tag to all files in the folder)
    \\ 	--infer-more-tags <inferrer>	infer tags using a processor
    \\ 					 (available processors: TODO)
    \\
    \\ example, adding a single file:
    \\  ainclude --tag format:mp4 --tag "meme:what the dog doing" /downloads/funny_meme.mp4
    \\
    \\ example, adding a batch of files:
    \\  ainclude --tag format:mp4 --tag "meme:what the dog doing" /downloads/funny_meme.mp4 /download/another_dog_meme.mp4 /downloads/butter_dog.mp4
    \\
    \\ example, adding a media library:
    \\  ainclude --tag type:music --infer-more-tags media /my/music/collection
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
    const HashList = std.ArrayList([64]u8);

    const Args = struct {
        help: bool = false,
        verbose: bool = false,
        version: bool = false,
        default_tags: StringList,
        wanted_inferrers: StringList,
        include_paths: StringList,

        pub fn deinit(self: *@This()) void {
            self.default_tags.deinit();
            self.wanted_inferrers.deinit();
            self.include_paths.deinit();
        }
    };

    const ArgState = enum { None, FetchTag, InferMoreTags };

    var state: ArgState = .None;

    var given_args = Args{
        .default_tags = StringList.init(allocator),
        .wanted_inferrers = StringList.init(allocator),
        .include_paths = StringList.init(allocator),
    };
    defer given_args.deinit();

    while (args_it.next()) |arg| {
        switch (state) {
            .FetchTag => {
                try given_args.default_tags.append(arg);
                state = .None;
                continue;
            },
            .InferMoreTags => {
                try given_args.wanted_inferrers.append(arg);
                state = .None;
                continue;
            },
            .None => {},
        }

        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            given_args.verbose = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "--tag")) {
            state = .FetchTag;
        } else if (std.mem.eql(u8, arg, "--infer-more-tags")) {
            state = .InferMoreTags;
        } else {
            try given_args.include_paths.append(arg);
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.verbose) {
        std.debug.todo("aa");
    }

    if (given_args.include_paths.items.len == 0) {
        std.log.err("at least one include path needs to be given", .{});
        return error.MissingArgument;
    }

    var ctx = Context{
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase();

    std.log.info("args: {}", .{given_args});

    // map tag names to their relevant cores in db
    var default_tag_cores = HashList.init(allocator);
    defer default_tag_cores.deinit();
    for (given_args.default_tags.items) |named_tag_text| {
        const maybe_tag = try ctx.fetchNamedTag(named_tag_text, "en");
        if (maybe_tag) |tag| {
            log.debug(
                "tag '{s}' is core {s}",
                .{ named_tag_text, tag.core },
            );
            try default_tag_cores.append(tag.core);
        } else {
            // TODO support ISO 639-2
            var new_tag = try ctx.createNamedTag(named_tag_text, "en", null);
            log.debug(
                "(created!) tag '{s}' with core {s}",
                .{ named_tag_text, new_tag.core },
            );
            try default_tag_cores.append(new_tag.core);
        }
    }

    for (given_args.wanted_inferrers.items) |inferrer_text| {
        _ = inferrer_text;
        std.debug.todo("add any inferrer logic");
    }

    for (given_args.include_paths.items) |path_to_include| {
        var dir: ?std.fs.Dir = std.fs.cwd().openDir(path_to_include, .{ .iterate = true }) catch |err| blk: {
            if (err == error.NotDir) break :blk null;
            return err;
        };
        defer if (dir) |*unpacked_dir| unpacked_dir.close();

        if (dir == null) {
            var file = try ctx.createFileFromPath(path_to_include);
            defer file.deinit();
            log.debug("adding file '{s}'", .{file.local_path});

            var savepoint = try ctx.db.?.savepoint("tags");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            for (default_tag_cores.items) |tag_core| {
                try file.addTag(tag_core);
            }
        } else {
            var walker = try dir.?.walk(allocator);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                switch (entry.kind) {
                    .File, .SymLink => {
                        // TODO use std.fs.path.join here
                        log.debug("adding child path '{s}/{s}'", .{ path_to_include, entry.path });

                        var file = try ctx.createFileFromDir(entry.dir, entry.basename);
                        defer file.deinit();

                        var savepoint = try ctx.db.?.savepoint("tags");
                        errdefer savepoint.rollback();
                        defer savepoint.commit();

                        for (default_tag_cores.items) |tag_core| {
                            try file.addTag(tag_core);
                        }
                    },
                    else => {},
                }
            }
        }
    }
}
