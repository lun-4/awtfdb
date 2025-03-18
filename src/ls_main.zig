const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const clap = @import("clap");
const Context = manage_main.Context;
const ID = manage_main.ID;

const logger = std.log.scoped(.als);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ als: list file tags
    \\
    \\ usage:
    \\ \tals [options] [path]
    \\
    \\ options:
    \\ \t-h\tprints this help and exits
    \\ \t-V\tprints version and exits
    \\ \t--id\tprint file id
    \\  --show-sources    show tag sources
    \\
    \\ examples:
    \\ \tals path/to/file
    \\ \tshows tags about a single file
    \\ \tals path/to/directory
    \\ \tshows files and their respective tags inside a directory
    \\  als @1234
    \\  \tlist file by id
;

pub var current_log_level: std.log.Level = .info;
pub const std_options = struct {
    pub const log_level = .debug;
    pub const logFn = manage_main.log;
};

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

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             display this help and exit.
        \\-V, --version          print version and exit.
        \\-v, --verbose          enable debug logs.
        \\-f, --force            force resolution of the file even if it doesnt exist in the os.
        \\--id                   show file ids.
        \\--show-sources         show tag sources alongside the tags.
        \\<str>...
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        // Report useful error and exit.
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    const StringList = std.ArrayList([]const u8);

    const Args = struct {
        help: bool = false,
        version: bool = false,
        force: bool = false,
        show_id: bool = false,
        paths: StringList,
    };

    var print_tag_options = Context.File.PrintTagOptions{};

    var given_args = Args{ .paths = StringList.init(allocator) };
    defer given_args.paths.deinit();

    if (res.args.help != 0)
        given_args.help = true;

    given_args.version = res.args.version != 0;
    if (res.args.verbose != 0)
        current_log_level = .debug;
    given_args.force = res.args.force != 0;

    given_args.show_id = res.args.id != 0;
    print_tag_options.show_sources = res.args.@"show-sources" != 0;

    for (res.positionals[0]) |pos|
        try given_args.paths.append(pos);

    if (given_args.paths.items.len == 0) {
        try given_args.paths.append(".");
    }

    if (given_args.help) {
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }
    var ctx = try manage_main.loadDatabase(allocator, .{});
    defer ctx.deinit();

    var stdout = std.io.getStdOut().writer();

    for (given_args.paths.items) |query| {
        if (std.mem.startsWith(u8, query, "@")) {
            // direct file id fetch
            var it = std.mem.splitSequence(u8, query, "@");
            _ = it.next();
            const file_hash_as_str = it.next() orelse return error.InvalidFileIdSyntax;
            const file_hash = ID.fromString(file_hash_as_str);

            const maybe_file = try ctx.fetchFile(file_hash);
            if (maybe_file) |file| {
                defer file.deinit();
                const id_text = if (given_args.show_id) file.hash.id.str() else "";

                try stdout.print("- {s}{s}", .{ id_text, file.local_path });
                try file.printTagsTo(allocator, stdout, print_tag_options);
                try stdout.print("\n", .{});
            }
            continue;
        }

        if (given_args.force) {
            var maybe_inner_file = try ctx.fetchFileByPath(query);
            if (maybe_inner_file) |*file| {
                const id_text = if (given_args.show_id) file.hash.id.str() else "";
                try stdout.print("- {s}{s}", .{ id_text, query });
                defer file.deinit();
                try file.printTagsTo(allocator, stdout, print_tag_options);
            } else {
                try stdout.print("- {s}", .{query});
            }

            continue;
        }

        const maybe_dir: ?std.fs.Dir = std.fs.cwd().openDir(query, .{ .iterate = true }) catch |err| blk: {
            switch (err) {
                error.FileNotFound => {
                    logger.warn("path not found: {s}", .{query});
                    return err;
                },
                error.NotDir => {
                    break :blk null;
                },
                else => return err,
            }
        };

        if (maybe_dir) |dir| {
            var it = dir.iterate();
            while (try it.next()) |entry| {
                // TODO get stat?
                switch (entry.kind) {
                    .file => try stdout.print("-", .{}),
                    .directory => try stdout.print("d", .{}),
                    else => try stdout.print("-", .{}),
                }
                try stdout.print(" {s}", .{entry.name});
                if (entry.kind == .file) {
                    var realpath_buf: [std.posix.PATH_MAX]u8 = undefined;
                    const full_path = try dir.realpath(entry.name, &realpath_buf);
                    var maybe_inner_file = try ctx.fetchFileByPath(full_path);
                    if (maybe_inner_file) |*file| {
                        const id_text = if (given_args.show_id) file.hash.id.str() else "";
                        try stdout.print("{s}", .{id_text});

                        defer file.deinit();
                        try file.printTagsTo(allocator, stdout, print_tag_options);
                    }
                }
                try stdout.print("\n", .{});
            }
        } else {
            var realpath_buf: [std.posix.PATH_MAX]u8 = undefined;
            const full_path = try std.fs.cwd().realpath(query, &realpath_buf);

            const maybe_file = try ctx.fetchFileByPath(full_path);
            try stdout.print("- {s}", .{query});
            if (maybe_file) |file| {
                const id_text = if (given_args.show_id) file.hash.id.str() else "";
                try stdout.print(" {s}", .{id_text});

                defer file.deinit();
                try file.printTagsTo(allocator, stdout, print_tag_options);
            }
            try stdout.print("\n", .{});
        }
    }
}
