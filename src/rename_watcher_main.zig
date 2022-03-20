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

    const NameMap = std.AutoHashMap(struct { pid: std.os.pid_t, tid: std.os.pid_t }, []const u8);

    var rename_ctx = struct {
        oldnames: NameMap,
        newnames: NameMap,
    }{
        .oldnames = NameMap.init(allocator),
        .newnames = NameMap.init(allocator),
    };
    _ = rename_ctx;

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

    while (true) {
        const available = try std.os.poll(&sockets, -1);
        if (available == 0) {
            log.info("timed out, retrying", .{});
            continue;
        }

        for (sockets) |pollfd| {
            if (pollfd.revents == 0) continue;

            if (pollfd.fd == proc.stdout.?.handle) {
                // have a max of 16kb per line given by bpftrace
                const line = try proc.stdout.?.reader().readUntilDelimiterAlloc(allocator, '\n', 16 * 1024);
                log.warn("got stdout: {s}", .{line});
            } else if (pollfd.fd == proc.stderr.?.handle) {
                // max(usize) yolo
                const line = try proc.stdout.?.reader().readAllAlloc(allocator, std.math.maxInt(usize));
                log.warn("got stderr: {s}", .{line});
            } else if (pollfd.fd == pipe_receiver.handle) {
                const exit_code = pipe_receiver.reader().readIntNative(u32);
                log.err("bpftrace exited with {d}", .{exit_code});
                return error.BpfTraceExit;
            }
        }
    }
}
