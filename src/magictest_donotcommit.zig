const std = @import("std");

const logger.= std.log.scoped(.shit);

const c = @cImport({
    @cInclude("magic.h");
});

const MimeResult = struct {
    cookie: c.magic_t,
    result: []const u8,

    pub fn deinit(self: @This()) void {
        c.magic_close(self.cookie);
    }
};

fn inferMimetype(path: []const u8, allocator: std.mem.Allocator) !MimeResult {
    var cookie = c.magic_open(
        c.MAGIC_MIME | c.MAGIC_CHECK | c.MAGIC_SYMLINK | c.MAGIC_ERROR,
    ) orelse return error.MagicCookieFail;

    if (c.magic_check(cookie, "/usr/share/misc/magic") == -1) {
        const magic_error_value = c.magic_error(cookie);
        logger.err("failed to check magic file: {s}", .{magic_error_value});
        return error.MagicFileFail;
    }

    if (c.magic_load(cookie, "/usr/share/misc/magic") == -1) {
        const magic_error_value = c.magic_error(cookie);
        logger.err("failed to load magic file: {s}", .{magic_error_value});
        return error.MagicFileFail;
    }

    const local_path_cstr = try std.cstr.addNullByte(allocator, path);
    defer allocator.free(local_path_cstr);
    logger.warn("test: {s}", .{local_path_cstr});

    const mimetype = c.magic_file(cookie, local_path_cstr) orelse {
        const magic_error_value = c.magic_error(cookie);
        logger.err("failed to infer mimetype: {s}", .{magic_error_value});
        return error.MimetypeFail;
    };
    return MimeResult{
        .cookie = cookie,
        .result = std.mem.span(mimetype),
    };
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    const result = try inferMimetype("/home/luna/git/awtfdb/src/test_vectors/audio_test_vector.mp3", allocator);
    defer result.deinit();

    logger.info("SHIT DID IT WORK {s}", .{result.result});
}
