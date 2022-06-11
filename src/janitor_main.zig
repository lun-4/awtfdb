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
    \\ 	--full				validate hashes of all files (very slow)
    \\ 	--only <path>			only run full validation on given path
    \\ 	--repair			attempt to repair consistency
    \\ 					(this operation may be destructive to
    \\ 					the index file, only run this manually)
;

pub fn main() anyerror!u8 {
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
        repair: bool = false,
        full: bool = false,
        only: StringList,
    };

    var given_args = Args{ .only = StringList.init(allocator) };
    defer {
        for (given_args.only.items) |path| allocator.free(path);
        given_args.only.deinit();
    }

    var state: enum { None, Only } = .None;

    while (args_it.next()) |arg| {
        switch (state) {
            .Only => {
                try given_args.only.append(try std.fs.path.resolve(
                    allocator,
                    &[_][]const u8{arg},
                ));
                state = .None;
                continue;
            },
            .None => {},
        }
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "--repair")) {
            given_args.repair = true;
        } else if (std.mem.eql(u8, arg, "--full")) {
            given_args.full = true;
        } else if (std.mem.eql(u8, arg, "--only")) {
            state = .Only;
        } else {
            return error.InvalidArgument;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return 1;
    } else if (given_args.version) {
        std.debug.print("awtfdb-janitor {s}\n", .{VERSION});
        return 1;
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

    const Counter = struct { total: usize = 0, unrepairable: usize = 0 };

    var counters: struct {
        file_not_found: Counter = .{},
        incorrect_hash_files: Counter = .{},
        incorrect_hash_cores: Counter = .{},
        unused_hash: Counter = .{},
    } = .{};

    var savepoint = try ctx.db.?.savepoint("janitor");
    errdefer savepoint.rollback();
    defer savepoint.commit();

    while (try iter.nextAlloc(allocator, .{})) |row| {
        defer allocator.free(row.local_path);

        const indexed_file = (try ctx.fetchFileExact(row.file_hash, row.local_path)) orelse return error.InconsistentIndex;
        defer indexed_file.deinit();

        var file = std.fs.openFileAbsolute(row.local_path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => {
                log.err("file {s} not found", .{row.local_path});
                counters.file_not_found.total += 1;

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

                    if (given_args.repair) {
                        try indexed_file.delete();
                    }
                } else if (repeated_count == 1) {
                    log.err(
                        "can not repair {s} as it is not indexed, please index a file with same contents or remove it manually from the index",
                        .{row.local_path},
                    );

                    counters.file_not_found.unrepairable += 1;

                    if (given_args.repair) {
                        return error.ManualInterventionRequired;
                    }
                }

                continue;
            },
            else => return err,
        };
        defer file.close();

        if (given_args.full) {
            var can_do_full_hash: bool = false;
            if (given_args.only.items.len > 0) {
                for (given_args.only.items) |prefix| {
                    if ((!can_do_full_hash) and std.mem.startsWith(u8, row.local_path, prefix)) {
                        can_do_full_hash = true;
                    }
                }
            } else {
                can_do_full_hash = true;
            }

            if (!can_do_full_hash) continue;

            var calculated_hash = try ctx.calculateHash(file, .{ .insert_new_hash = false });

            if (!std.mem.eql(u8, &calculated_hash.hash_data, &indexed_file.hash.hash_data)) {
                // repair option: fuck

                counters.incorrect_hash_files.total += 1;

                log.err(
                    "hashes are incorrect for file {d}",
                    .{row.file_hash},
                );

                if (given_args.repair) {
                    return error.ManualInterventionRequired;
                }
                continue;
            }
        }
        log.info("path {s} ok", .{row.local_path});
    }

    // calculate hashes for tag_cores
    var cores_stmt = try ctx.db.?.prepare(
        \\ select core_hash, core_data
        \\ from tag_cores
        \\ order by core_hash asc
    );
    defer cores_stmt.deinit();
    var cores_iter = try cores_stmt.iterator(struct {
        core_hash: i64,
        core_data: sqlite.Blob,
    }, .{});
    while (try cores_iter.nextAlloc(allocator, .{})) |core_with_blob| {
        defer allocator.free(core_with_blob.core_data.data);

        const calculated_hash = try ctx.calculateHashFromMemory(
            core_with_blob.core_data.data,
            .{ .insert_new_hash = false },
        );

        var hash_with_blob = (try ctx.db.?.oneAlloc(
            Context.HashWithBlob,
            allocator,
            \\ select id, hash_data
            \\ from hashes
            \\ where id = ?
        ,
            .{},
            .{core_with_blob.core_hash},
        )).?;
        defer allocator.free(hash_with_blob.hash_data.data);

        const upstream_hash = hash_with_blob.toRealHash();

        if (!std.mem.eql(u8, &calculated_hash.hash_data, &upstream_hash.hash_data)) {
            counters.incorrect_hash_cores.total += 1;
            counters.incorrect_hash_cores.unrepairable += 1;

            log.err(
                "hashes are incorrect for tag core {d} ({s} != {s})",
                .{ core_with_blob.core_hash, calculated_hash, upstream_hash },
            );

            if (given_args.repair) {
                return error.ManualInterventionRequired;
            }

            continue;
        }

        // TODO validate if there's any tag names to the core
    }

    // garbage collect unused entires in hashes table

    var hashes_stmt = try ctx.db.?.prepare(
        \\ select id
        \\ from hashes
        \\ order by id asc
    );
    defer hashes_stmt.deinit();
    var hashes_iter = try hashes_stmt.iterator(i64, .{});
    while (try hashes_iter.nextAlloc(allocator, .{})) |hash_id| {
        const core_count = (try ctx.db.?.one(
            i64,
            \\ select count(*) from tag_cores
            \\ where core_hash = ?
        ,
            .{},
            .{hash_id},
        )).?;

        if (core_count > 0) continue;

        const file_count = (try ctx.db.?.one(
            i64,
            \\ select count(*) from files
            \\ where file_hash = ?
        ,
            .{},
            .{hash_id},
        )).?;

        if (file_count > 0) continue;

        log.warn("unused hash in table: {d}", .{hash_id});

        counters.unused_hash.total += 1;

        if (given_args.repair) {
            try ctx.db.?.exec(
                \\ delete from hashes
                \\ where id = ?
            ,
                .{},
                .{hash_id},
            );
            log.info("deleted hash {d}", .{hash_id});
        }
    }

    const CountersTypeInfo = @typeInfo(@TypeOf(counters));

    var total_problems: usize = 0;
    inline for (CountersTypeInfo.Struct.fields) |field| {
        const total = @field(counters, field.name).total;

        log.info("problem {s}, {d} found, {d} unrepairable", .{
            field.name,
            total,
            @field(counters, field.name).unrepairable,
        });

        total_problems += total;
    }

    if ((!given_args.repair) and total_problems > 0) {
        log.info("this database has identified problems, please run --repair", .{});
        return 2;
    }
    return 0;
}
