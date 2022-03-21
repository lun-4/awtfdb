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
const NameMap = std.AutoHashMap(PidTid, []const u8);

const RenameContext = struct {
    oldnames: *NameMap,
    newnames: *NameMap,

    const Self = @This();

    pub fn deinit(self: *Self) void {
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

        if (is_oldname_message or is_newname_message) {
            // i do this to account for paths that have the : character
            // in them. do not use line_it after this
            const path = line[(version_string.len + 1 + message_type.len + 1 + pid_string.len + 1 + tid_string.len + 1)..line.len];
            var map_to_put_in: *NameMap =
                if (is_oldname_message) self.oldnames else self.newnames;

            try map_to_put_in.put(
                pid_tid_key,
                try map_to_put_in.allocator.dupe(u8, path),
            );
            std.debug.assert(map_to_put_in.count() > 0);
        } else if (std.mem.eql(u8, message_type, "ret")) {
            // got a return from one of the rename syscalls,
            // we must (try to) resolve it
            const return_value_as_string = line_it.next().?;

            const old_name = self.oldnames.get(pid_tid_key);
            const new_name = self.newnames.get(pid_tid_key);

            std.debug.assert(self.oldnames.count() > 0);
            std.debug.assert(self.newnames.count() > 0);

            if (std.mem.eql(u8, return_value_as_string, "0")) {
                defer _ = self.oldnames.remove(pid_tid_key);
                defer _ = self.newnames.remove(pid_tid_key);

                defer self.oldnames.allocator.free(old_name.?);
                defer self.newnames.allocator.free(new_name.?);

                log.info("successful rename by {d},{d}: {s} -> {s}", .{ pid, tid, old_name.?, new_name.? });
            }
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
    };

    var given_args = Args{};
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            std.debug.print("unknown argument: {s}", .{arg});
            return error.UnknownArgument;
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("awtfdb-watcher {s}\n", .{VERSION});
        return;
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

    const bpftrace_program = @embedFile("./rename_trace.bt");

    var proc = try std.ChildProcess.init(
        &[_][]const u8{ "bpftrace", "-e", bpftrace_program },
        allocator,
    );
    defer proc.deinit();
    errdefer _ = proc.kill() catch |err| {
        log.err("attempted to kill bpftrace process, got {s}", .{@errorName(err)});
    };

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

    var oldnames = NameMap.init(allocator);
    var newnames = NameMap.init(allocator);

    var rename_ctx = RenameContext{
        .oldnames = &oldnames,
        .newnames = &newnames,
    };
    defer rename_ctx.deinit();

    while (true) {
        const available = try std.os.poll(&sockets, -1);
        if (available == 0) {
            log.info("timed out, retrying", .{});
            continue;
        }

        var stdout_buffer: [16 * 1024]u8 = undefined;

        for (sockets) |pollfd| {
            if (pollfd.revents == 0) continue;

            if (proc.stdout != null and pollfd.fd == proc.stdout.?.handle) {
                // have a max of 16kb per line given by bpftrace
                //
                // TODO maybe we shouldn't use heap memory for this since its
                // the hot path? (i should learn how to profile those things)
                const line = try proc.stdout.?.reader().readUntilDelimiter(&stdout_buffer, '\n');
                //log.warn("got stdout: {s}", .{line});

                try rename_ctx.processLine(line);
            } else if (proc.stderr != null and pollfd.fd == proc.stderr.?.handle) {
                // max(usize) yolo
                const line = try proc.stderr.?.reader().readAllAlloc(allocator, std.math.maxInt(usize));
                defer allocator.free(line);
                log.warn("got stderr: {d} {s}", .{ line.len, line });
            } else if (pollfd.fd == pipe_receiver.handle) {
                const exit_code = pipe_receiver.reader().readIntNative(u32);
                log.err("bpftrace exited with {d}", .{exit_code});
                return error.BpfTraceExit;
            }
        }
    }
}
