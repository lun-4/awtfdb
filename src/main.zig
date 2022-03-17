const std = @import("std");

const HELPTEXT =
    \\ awtfdb-manage: main program for awtfdb file management
    \\
    \\ usage:
    \\ 	awtfdb-manage [global options..] <action> [action options...]
    \\
    \\ global options:
    \\  -h		prints this help and exits
    \\ 	-V		prints version and exits
    \\ 	-v		turns on verbosity (debug logging)
    \\
    \\ creating an awtfdb file:
    \\  awtfdb-manage create
    \\
    \\ getting statistics:
    \\  awtfdb-manage stats
    \\
    \\ current running jobs:
    \\  awtfdb-manage jobs
;

const Context = struct {
    args_it: *std.process.ArgIterator,
    stdout: std.io.File,

    const Self = @This();

    pub fn createCommand(self: *Self) !void {}
    pub fn statsCommand(self: *Self) !void {}
    pub fn jobsCommand(self: *Self) !void {}
};

pub fn main() anyerror!void {
    const args_it = std.process.args();
    _ = args_it.skip();
    const action = args_it.next();
    const stdout = std.io.getStdOut();

    const Args = struct {
        help: bool = false,
        verbose: bool = false,
        version: bool = false,
        maybe_action: ?[]const u8 = null,
    };

    var arg_state: usize = 0;
    var given_args = Args{};
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            given_args.verbose = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else {
            given_args.maybe_action = arg;
        }
    }

    if (given_args.help) {
        try stdout.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        try stdout.print("awtfdb-manage 0.0.1\n", .{});
        return;
    }

    if (given_args.verbose) {
        std.debug.todo("lmao help");
    }

    if (given_args.maybe_action == null) {
        std.log.err("action argument is required");
        return error.MissingActionArgument;
    }

    var ctx = Context{
        .args_it = args_it,
        .stdout = stdout,
    };

    const action = given_args.maybe_action.?;
    if (std.mem.eql(u8, action, "create")) {
        ctx.createCommand();
    } else {
        std.log.err("unknown action {s}", .{action});
        return error.UnknownAction;
    }
}

test "basic test" {
    try std.testing.expectEqual(10, 3 + 7);
}
