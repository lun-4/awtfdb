const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const libpcre = @import("libpcre");
const Context = manage_main.Context;

const log = std.log.scoped(.awtfdb_janitor);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ awtfdb-janitor: investigate the semantic consistency of the index file
    \\
    \\ usage:
    \\ 	awtfdb-janitor
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\ 	--repair			attempt to repair consistency
    \\ 					(this operation may be destructive to
    \\ 					the index file, only run this manually)
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
        repair: bool = false,
    };

    var given_args = Args{};

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "--repair")) {
            given_args.repair = true;
        } else {
            return error.InvalidArgument;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("awtfdb-janitor {s}\n", .{VERSION});
        return;
    }

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    var stmt = try ctx.db.?.prepare(
        \\ select file_hash, local_path
        \\ from files
        \\ order by file_hash asc
    );
    defer stmt.deinit();

    const FileRow = struct {
        file_hash: i64,
        local_path: []const u8,
    };
    var iter = try stmt.iterator(
        FileRow,
        .{},
    );

    var not_found_count: usize = 0;
    var repairable_not_found_count: usize = 0;
    var unrepairable_count: usize = 0;

    while (try iter.nextAlloc(allocator, .{})) |row| {
        defer allocator.free(row.local_path);

        var file = std.fs.openFileAbsolute(row.local_path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => {
                log.err("file {s} not found", .{row.local_path});
                not_found_count += 1;

                const repeated_count = (try ctx.db.?.one(
                    i64,
                    \\ select count(*)
                    \\ from files
                    \\ where file_hash = ?
                ,
                    .{},
                    .{row.file_hash},
                )).?;

                std.debug.assert(repeated_count != 0);

                if (repeated_count > 1) {
                    // repair action: delete old entry to keep index consistent
                    log.warn(
                        "found {d} files with same hash, assuming a file move happened for {d}",
                        .{ repeated_count, row.file_hash },
                    );

                    repairable_not_found_count += 1;

                    if (given_args.repair) {
                        const indexed_file = (try ctx.fetchFile(row.file_hash)) orelse return error.InconsistentIndex;
                        defer indexed_file.deinit();
                        try indexed_file.delete();
                    }
                } else if (repeated_count == 1) {
                    log.err(
                        "can not repair {s} as it is not indexed, please index a file with same contents or remove it manually from the index",
                        .{row.local_path},
                    );

                    unrepairable_count += 1;

                    if (given_args.repair) {
                        return error.ManualInterventionRequired;
                    }
                }

                continue;
            },
            else => return err,
        };

        defer file.close();
        log.info("path {s} ok", .{row.local_path});
    }

    log.info("{d} files were not found", .{not_found_count});
    log.info("{d} files were not found and can be repaired", .{repairable_not_found_count});
    log.info("{d} files can NOT be automatically repaired", .{unrepairable_count});
}
