const std = @import("std");
const builtin = @import("builtin");

const EXECUTABLES = .{
    .{ "awtfdb-manage", @import("main.zig").main },
    .{ "ainclude", @import("include_main.zig").main },
    .{ "afind", @import("find_main.zig").main },
    .{ "als", @import("ls_main.zig").main },
    .{ "arm", @import("rm_main.zig").main },
    .{ "atags", @import("tags_main.zig").main },
    .{ "awtfdb-metrics", @import("metrics_main.zig").main },
} ++ switch (builtin.os.tag) {
    .linux => .{
        .{ "awtfdb-watcher", @import("rename_watcher_main.zig").main },
    },
    else => .{},
};

pub fn main() anyerror!u8 {
    var it = std.process.args();
    const exec_name = std.fs.path.basename(it.next().?);
    inline for (EXECUTABLES) |executable| {
        if (std.mem.eql(u8, exec_name, executable.@"0")) {
            const main_type = @typeInfo(@TypeOf(executable.@"1"));
            const ret_type = @typeInfo(main_type.Fn.return_type.?);
            const payload_type = ret_type.ErrorUnion.payload;
            if (payload_type == u8) {
                return executable.@"1"();
            } else {
                try executable.@"1"();
                return 0;
            }
        }
    }

    @panic("invalid executable name");
}
