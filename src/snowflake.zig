const std = @import("std");

// This is my own scheme so that it both has large enough time limits
// and enough randomness to prevent collisions
//
// 50 bits for timestamp in seconds
// 13 random bits

fn binaryMask(comptime bit_start: usize, comptime bit_end: usize) i64 {
    comptime var mask: i64 = 0;
    comptime {
        var count = bit_start;
        while (count <= bit_end) : (count += 1) {
            const set_bit = 1 << count;
            mask |= set_bit;
        }
    }

    return mask;
}

const Fields = packed struct {
    timestamp: u50,
    random_bits: u13,
};

pub const AnimeSnowflake = packed union {
    value: u63,
    fields: Fields,
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
