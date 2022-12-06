const std = @import("std");

// This is my own scheme so that it both has large enough time limits
// and enough randomness to prevent collisions
// AND it fits in sqlite rowids (64 bit signed ints)
//
// 50 bits for timestamp in seconds
// 13 random bits
//
// (1 bit goes away to the sign, so this is a 63 bit id scheme)

const Fields = packed struct {
    timestamp: u50,
    random_bits: u13,
};

pub const AnimeSnowflake = packed union {
    value: u63,
    fields: Fields,

    const Self = @This();

    pub fn fromTimestamp(timestamp: u50) Self {
        var rng = std.rand.DefaultPrng.init(
            @truncate(u64, @intCast(u128, std.time.nanoTimestamp())),
        );
        const random = rng.random();
        const random_bits = random.int(u13);
        return Self{ .fields = .{ .timestamp = timestamp, .random_bits = random_bits } };
    }
};

comptime {
    std.debug.assert(@sizeOf(AnimeSnowflake) == @sizeOf(u63));
    std.debug.assert(@bitSizeOf(AnimeSnowflake) == 63);
    std.debug.assert(@bitSizeOf(Fields) == 63);

    const timestamp: i64 = 1669493613473;
    const random_bits: u13 = 315;
    const snowflake = AnimeSnowflake{ .fields = .{
        .timestamp = @intCast(u50, timestamp),
        .random_bits = random_bits,
    } };

    const snowflake_int = snowflake.value;
    const data2 = (AnimeSnowflake{ .value = snowflake_int }).fields;
    std.debug.assert(timestamp == data2.timestamp);
    std.debug.assert(random_bits == data2.random_bits);

    const bitwised = snowflake_int & std.math.maxInt(u63) >> 13;
    std.debug.assert(timestamp == bitwised);
}

test "snowflake max" {
    const timestamp: i64 = std.math.maxInt(u50);
    const random_bits: u13 = std.math.maxInt(u13);

    const snowflake = AnimeSnowflake{ .fields = .{
        .timestamp = @intCast(u50, timestamp),
        .random_bits = random_bits,
    } };

    const snowflake_int = snowflake.value;

    const data = (AnimeSnowflake{ .value = snowflake_int }).fields;
    try std.testing.expectEqual(timestamp, data.timestamp);
    try std.testing.expectEqual(random_bits, data.random_bits);
}

test "snowflake time" {
    const timestamp: i64 = std.time.timestamp();

    const random_bits: u13 = 69;

    const snowflake = AnimeSnowflake{ .fields = .{
        .timestamp = @intCast(u50, timestamp),
        .random_bits = random_bits,
    } };

    try std.testing.expectEqual(timestamp, snowflake.fields.timestamp);
    try std.testing.expectEqual(timestamp, (AnimeSnowflake{ .value = snowflake.value }).fields.timestamp);

    const bitwised = snowflake.value & std.math.maxInt(u63) >> 13;
    //@compileLog(std.math.maxInt(u63));
    const data = (AnimeSnowflake{ .value = snowflake.value }).fields;
    try std.testing.expectEqual(timestamp, data.timestamp);
    try std.testing.expectEqual(timestamp, bitwised);
    try std.testing.expectEqual(random_bits, data.random_bits);
}
