const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const Context = manage_main.Context;

const log = std.log.scoped(.awtfdb_watcher);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ awtfdb-watcher: watch the entire operating system for renames,
    \\  updating the database with such
    \\
    \\ currently only supports linux with bpftrace installed.
    \\
    \\ MUST be run as root.
    \\
    \\ usage:
    \\  awtfdb-watcher [options...] path_to_home_directory
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
;

fn waiterThread(pipe_fd: std.os.fd_t, proc: *std.ChildProcess) !void {
    var pipe_writer = std.fs.File{ .handle = pipe_fd };

    const term_result = proc.wait() catch |err| blk: {
        log.err(
            "failed to wait for process ({s}), attempting forceful exit of daemon.",
            .{@errorName(err)},
        );
        break :blk std.ChildProcess.Term{ .Exited = 0 };
    };

    const exit_code: u32 = switch (term_result) {
        .Exited => |term_code| @as(u32, term_code),
        .Signal, .Stopped, .Unknown => |term_code| blk: {
            break :blk term_code;
        },
    };

    try pipe_writer.writer().writeIntNative(u32, exit_code);
}

const PidTid = struct { pid: std.os.pid_t, tid: std.os.pid_t };
const StringAsList = std.ArrayList(u8);
const ChunkedName = struct { state: enum { NeedMore, Complete }, data: StringAsList };
const ChunkedNameMap = std.AutoHashMap(PidTid, ChunkedName);
const NameMap = std.AutoHashMap(PidTid, []const u8);

const RenameContext = struct {
    allocator: std.mem.Allocator,
    oldnames: *ChunkedNameMap,
    newnames: *ChunkedNameMap,
    cwds: *NameMap,
    ctx: *Context,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.cwds.deinit();
        self.oldnames.deinit();
        self.newnames.deinit();
    }

    pub fn processLine(self: *Self, line: []const u8) !void {
        var line_it = std.mem.split(u8, line, ":");

        const version_string = line_it.next().?;
        const is_v1_message = std.mem.eql(u8, version_string, "v1");
        if (!is_v1_message) return;

        const message_type = line_it.next().?;

        const pid_string = line_it.next().?;
        const tid_string = line_it.next().?;
        const pid = try std.fmt.parseInt(std.os.pid_t, pid_string, 10);
        const tid = try std.fmt.parseInt(std.os.pid_t, tid_string, 10);
        const pid_tid_key = PidTid{ .pid = pid, .tid = tid };

        const is_oldname_message = std.mem.eql(u8, message_type, "oldname");
        const is_newname_message = std.mem.eql(u8, message_type, "newname");

        if (std.mem.eql(u8, message_type, "execve")) {
            var cwd_proc_path = try std.fmt.allocPrint(self.allocator, "/proc/{d}/cwd", .{pid});
            defer self.allocator.free(cwd_proc_path);

            var cwd_path = std.fs.realpathAlloc(self.allocator, cwd_proc_path) catch |err| switch (err) {
                error.AccessDenied, error.FileNotFound => {
                    log.debug("can't access cwd for {d}, ignoring rename", .{pid});
                    return;
                },
                else => return err,
            };

            try self.cwds.put(pid_tid_key, cwd_path);
        } else if (std.mem.eql(u8, message_type, "exit_execve")) {
            const return_value_as_string = line_it.next().?;

            // if unsuccessful execve, remove cwd
            if (!std.mem.eql(u8, return_value_as_string, "0")) {
                const cwd_path = self.cwds.get(pid_tid_key);
                defer if (cwd_path) |unpacked| self.allocator.free(unpacked);
                _ = self.cwds.remove(pid_tid_key);
            }
        } else if (std.mem.eql(u8, message_type, "exit_process")) {
            const cwd_path = self.cwds.get(pid_tid_key);
            defer if (cwd_path) |unpacked| self.allocator.free(unpacked);
            _ = self.cwds.remove(pid_tid_key);
        } else if (is_oldname_message or is_newname_message) {
            // i do this to account for paths that have the : character
            // in them. do not use line_it after this, or, use it very cautiously
            const chunk_data = line[(version_string.len + 1 + message_type.len + 1 + pid_string.len + 1 + tid_string.len + 1)..line.len];
            var map_to_put_in: *ChunkedNameMap =
                if (is_oldname_message) self.oldnames else self.newnames;

            var maybe_chunk = map_to_put_in.getPtr(pid_tid_key);

            if (maybe_chunk) |chunk| {
                switch (chunk.state) {
                    .NeedMore => {
                        const written_bytes = try chunk.data.writer().write(chunk_data);
                        std.debug.assert(written_bytes == chunk_data.len);
                        if (chunk_data.len < 200) {
                            chunk.state = .Complete;
                        }
                    },
                    .Complete => {},
                }
            } else {
                var chunk = ChunkedName{
                    .state = .NeedMore,
                    .data = StringAsList.init(self.allocator),
                };

                const written_bytes = try chunk.data.writer().write(chunk_data);
                std.debug.assert(written_bytes == chunk_data.len);
                if (chunk_data.len < 200) {
                    chunk.state = .Complete;
                }

                try map_to_put_in.put(
                    pid_tid_key,
                    chunk,
                );
            }
            std.debug.assert(map_to_put_in.count() > 0);
        } else if (std.mem.eql(u8, message_type, "exit_rename")) {
            // got a return from one of the rename syscalls,
            // we must (try to) resolve it
            const return_value_as_string = line_it.next().?;

            const old_name = self.oldnames.get(pid_tid_key);
            const new_name = self.newnames.get(pid_tid_key);
            const maybe_cwd = self.cwds.get(pid_tid_key);

            std.debug.assert(self.oldnames.count() > 0);
            std.debug.assert(self.newnames.count() > 0);

            if (std.mem.eql(u8, return_value_as_string, "0")) {
                defer _ = self.oldnames.remove(pid_tid_key);
                defer _ = self.newnames.remove(pid_tid_key);
                defer _ = self.cwds.remove(pid_tid_key);

                defer old_name.?.data.deinit();
                defer new_name.?.data.deinit();
                defer if (maybe_cwd) |cwd| self.allocator.free(cwd);

                try self.handleSucessfulRename(pid_tid_key, old_name.?.data.items, new_name.?.data.items, maybe_cwd);
            }
        }
    }

    fn handleSucessfulRename(
        self: *Self,
        pidtid_pair: PidTid,
        relative_old_name: []const u8,
        relative_new_name: []const u8,
        maybe_cwd: ?[]const u8,
    ) !void {
        const pid = pidtid_pair.pid;

        const is_oldname_absolute = std.fs.path.isAbsolute(relative_old_name);
        const is_newname_absolute = std.fs.path.isAbsolute(relative_new_name);

        var cwd_path: ?[]const u8 = null;
        if (maybe_cwd) |unpacked| {
            cwd_path = unpacked;
            // if neither paths are absolute, construct cwd_path and use it later
        } else if (!(is_oldname_absolute or is_newname_absolute)) {
            // if we don't have it already, try to fetch it from procfs
            // as this might be a process we didn't know about before

            var cwd_proc_path = try std.fmt.allocPrint(self.allocator, "/proc/{d}/cwd", .{pid});
            defer self.allocator.free(cwd_proc_path);

            cwd_path = std.fs.realpathAlloc(self.allocator, cwd_proc_path) catch |err| switch (err) {
                error.AccessDenied, error.FileNotFound => {
                    log.debug("can't access cwd for {d}, ignoring rename", .{pid});
                    return;
                },
                else => return err,
            };
        }

        // if we didn't receive maybe_cwd, that means we had to allocate
        // cwd_path ourselves by reading from /proc. so we own the lifetime here
        defer if (maybe_cwd == null and cwd_path != null)
            self.allocator.free(cwd_path.?);

        // applying cwd_path if the path is already absolute is incorrect behavior.
        var oldpath = if (!is_oldname_absolute)
            try std.fs.path.join(self.allocator, &[_][]const u8{
                cwd_path.?,
                relative_old_name,
            })
        else
            relative_old_name;
        defer if (!is_oldname_absolute) self.allocator.free(oldpath);
        var newpath = if (!is_newname_absolute)
            try std.fs.path.join(self.allocator, &[_][]const u8{
                cwd_path.?,
                relative_new_name,
            })
        else
            relative_new_name;
        defer if (!is_newname_absolute) self.allocator.free(newpath);

        const is_old_in_home = std.mem.startsWith(u8, oldpath, self.ctx.home_path.?);
        const is_new_in_home = std.mem.startsWith(u8, newpath, self.ctx.home_path.?);

        if (!(is_new_in_home or is_old_in_home)) {
            log.debug("{d}: neither {s} or {s} are in home", .{ pid, oldpath, newpath });
            return;
        }

        log.info("{d}: relevant rename: {s} -> {s}", .{ pid, oldpath, newpath });

        var is_directory_move = false;
        {
            var dir: ?std.fs.Dir = std.fs.cwd().openDir(newpath, .{}) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => null,
                else => return err,
            };
            defer if (dir) |*unpacked_dir| unpacked_dir.close();
            is_directory_move = dir != null;
        }

        if (is_directory_move) std.debug.todo("todo folders");

        // TODO use ? || '%' for the where clause in the case we're trying
        // to access the directory but it was already deleted
        var stmt = try self.ctx.db.?.prepare("select file_hash, local_path from files where local_path = ?");
        defer stmt.deinit();

        const maybe_file = try stmt.oneAlloc(
            struct {
                file_hash: Context.Blake3HashHex,
                local_path: []const u8,
            },
            self.allocator,
            .{},
            .{ .local_path = oldpath },
        );
        defer {
            if (maybe_file) |file| {
                self.allocator.free(file.local_path);
            }
        }
        if (maybe_file) |file| {
            log.info(
                "File {s} was renamed from {s} to {s}",
                .{ &file.file_hash, oldpath, newpath },
            );
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
        home_path: ?[]const u8 = null,
    };

    var given_args = Args{};
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            given_args.home_path = arg;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("awtfdb-watcher {s}\n", .{VERSION});
        return;
    }

    if (given_args.home_path == null) {
        std.debug.print("home path is a required argument", .{});
        return;
    }

    var ctx = Context{
        .home_path = given_args.home_path,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase();

    std.log.info("args: {}", .{given_args});

    const bpftrace_program = @embedFile("./rename_trace.bt");

    var proc = try std.ChildProcess.init(
        &[_][]const u8{ "bpftrace", "-e", bpftrace_program },
        allocator,
    );

    var envmap = std.BufMap.init(allocator);
    defer envmap.deinit();
    try envmap.put("BPFTRACE_STRLEN", "200");
    proc.env_map = &envmap;

    defer proc.deinit();

    proc.stdout_behavior = .Pipe;
    proc.stderr_behavior = .Pipe;
    try proc.spawn();

    var wait_pipe = try std.os.pipe();
    defer std.os.close(wait_pipe[0]);
    defer std.os.close(wait_pipe[1]);

    var pipe_receiver = std.fs.File{ .handle = wait_pipe[0] };

    var waiter_thread = try std.Thread.spawn(.{}, waiterThread, .{ wait_pipe[1], proc });
    waiter_thread.detach();

    var sockets = [_]std.os.pollfd{
        .{ .fd = proc.stdout.?.handle, .events = std.os.POLL.IN, .revents = 0 },
        .{ .fd = proc.stderr.?.handle, .events = std.os.POLL.IN, .revents = 0 },
        .{ .fd = wait_pipe[0], .events = std.os.POLL.IN, .revents = 0 },
    };

    var oldnames = ChunkedNameMap.init(allocator);
    var newnames = ChunkedNameMap.init(allocator);
    var cwds = NameMap.init(allocator);

    var rename_ctx = RenameContext{
        .allocator = allocator,
        .oldnames = &oldnames,
        .newnames = &newnames,
        .cwds = &cwds,
        .ctx = &ctx,
    };
    defer rename_ctx.deinit();

    while (true) {
        const available = try std.os.poll(&sockets, -1);
        if (available == 0) {
            log.info("timed out, retrying", .{});
            continue;
        }

        // have a max of 16kb per thing given by bpftrace
        var line_buffer: [16 * 1024]u8 = undefined;

        for (sockets) |pollfd| {
            if (pollfd.revents == 0) continue;

            if (proc.stdout != null and pollfd.fd == proc.stdout.?.handle) {
                const line = proc.stdout.?.reader().readUntilDelimiter(&line_buffer, '\n') catch |err| {
                    log.err("error reading from stdout {s}", .{@errorName(err)});
                    switch (err) {
                        // process might have died while we're in the middle of a read
                        error.NotOpenForReading, error.EndOfStream => {
                            proc.stdout = null;
                            continue;
                        },
                        else => return err,
                    }
                };
                try rename_ctx.processLine(line);
            } else if (proc.stderr != null and pollfd.fd == proc.stderr.?.handle) {
                const buffer_offset = proc.stderr.?.reader().readAll(&line_buffer) catch |err| {
                    log.err("error reading from stderr {s}", .{@errorName(err)});
                    switch (err) {
                        // process might have died while we're in the middle of a read
                        error.NotOpenForReading => {
                            proc.stderr = null;
                            continue;
                        },
                        else => return err,
                    }
                };

                const line = line_buffer[0..buffer_offset];
                log.warn("got stderr: {s}", .{line});
            } else if (pollfd.fd == pipe_receiver.handle) {
                const exit_code = pipe_receiver.reader().readIntNative(u32);
                log.err("bpftrace exited with {d}", .{exit_code});
                return;
            }
        }
    }
}
