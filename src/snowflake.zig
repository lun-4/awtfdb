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

pub const AnimeSnowflake = packed struct {
    timestamp: u50,
    random_bits: u13,

    const Self = @This();

    fn toInt(self: Self) i64 {
        const asbytes = std.mem.asBytes(&self);
        return @ptrCast(*const i64, asbytes).*;
    }

    fn fromInt(value: i64) AnimeSnowflake {
        const asbytes = std.mem.asBytes(&value);
        return @ptrCast(*const Self, asbytes).*;
    }
};

test "snowflake" {
    const timestamp: i64 = 1669493613473;
    const random_bits: u13 = 315;
    const snowflake = AnimeSnowflake{
        .timestamp = @intCast(u50, timestamp),
        .random_bits = random_bits,
    };

    const snowflake_int = snowflake.toInt();

    const CORRECT_SNOWFLAKE: i64 = 354660140149040033;
    try std.testing.expectEqual(CORRECT_SNOWFLAKE, snowflake_int);

    const data = AnimeSnowflake.fromInt(snowflake_int);
    try std.testing.expectEqual(timestamp, data.timestamp);
    try std.testing.expectEqual(random_bits, data.random_bits);
}

test "snowflake max" {
    const timestamp: i64 = std.math.maxInt(u50);
    const random_bits: u13 = std.math.maxInt(u13);
    const snowflake = AnimeSnowflake{
        .timestamp = @intCast(u50, timestamp),
        .random_bits = random_bits,
    };

    const snowflake_int = snowflake.toInt();

    const data = AnimeSnowflake.fromInt(snowflake_int);
    try std.testing.expectEqual(timestamp, data.timestamp);
    try std.testing.expectEqual(random_bits, data.random_bits);
}
