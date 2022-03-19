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
    \\ 	ainclude [options..] <file/folder path>
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

    const Args = struct {
        help: bool = false,
        verbose: bool = false,
        version: bool = false,
        default_tags: StringList,
        wanted_inferrers: StringList,
        include_path: ?[]const u8 = null,

        pub fn deinit(self: *@This()) void {
            self.default_tags.deinit();
            self.wanted_inferrers.deinit();
        }
    };

    const ArgState = enum { None, FetchTag, InferMoreTags };

    var state: ArgState = .None;

    var given_args = Args{
        .default_tags = StringList.init(allocator),
        .wanted_inferrers = StringList.init(allocator),
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
            given_args.include_path = arg;
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

    if (given_args.include_path == null) {
        std.log.err("include path is required", .{});
        return error.MissingArgument;
    }

    var ctx = Context{
        .args_it = undefined,
        .stdout = undefined,
        .db = undefined,
    };
    defer ctx.deinit();

    try ctx.loadDatabase();

    std.log.info("{}", .{given_args});
}
