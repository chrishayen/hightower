const std = @import("std");
const crypto = std.crypto;

const adjectives = [_][]const u8{
    "fierce",
    "ruthless",
    "relentless",
    "unstoppable",
    "vicious",
    "savage",
    "brutal",
    "ferocious",
    "merciless",
    "furious",
    "wild",
    "violent",
    "intense",
    "aggressive",
    "explosive",
    "devastating",
    "thunderous",
    "supreme",
    "dominant",
    "legendary",
    "epic",
    "glorious",
    "triumphant",
    "bold",
    "fearless",
};

const nouns = [_][]const u8{ "warrior", "commando", "predator", "terminator", "destroyer", "berserker", "gladiator", "spartan", "samurai", "ninja", "viking", "crusader", "centurion", "titan", "juggernaut", "warlord", "champion", "hunter", "reaper", "renegade", "maverick", "vanguard", "sentinel", "guardian", "avenger", "house" };

pub const NameGeneratorError = error{
    EmptyPrefix,
    OutOfMemory,
};

/// Generates a random name in the format: prefix-adjective-noun-xxxx
/// where xxxx is a 4-character random hex string
pub fn generate(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    if (prefix.len == 0) {
        return NameGeneratorError.EmptyPrefix;
    }

    var random_bytes: [2]u8 = undefined;
    crypto.random.bytes(&random_bytes);

    const adjective = adjectives[crypto.random.intRangeAtMost(usize, 0, adjectives.len - 1)];
    const noun = nouns[crypto.random.intRangeAtMost(usize, 0, nouns.len - 1)];

    return std.fmt.allocPrint(
        allocator,
        "{s}-{s}-{s}-{x:0>4}",
        .{ prefix, adjective, noun, std.mem.readInt(u16, &random_bytes, .little) },
    );
}
