const std = @import("std");
const c = @cImport({
    @cInclude("stdbool.h");
    @cInclude("stdint.h");
    @cInclude("scap_savefile.h");
    @cInclude("scap_const.h");
    @cInclude("scap_procs.h");
    @cInclude("scap_redefs.h");
});

const ppm_events = @cImport({
    @cInclude("ppm_events_public.h");
});

const block_names = std.ComptimeStringMap([:0]const u8, .{
    .{ "SHB", "Section Header" },
    .{ "MI", "Machine Info" },
    .{ "PL", "Process List" },
    .{ "FDL", "FD LIst" },
    .{ "EV", "Event" },
    .{ "IL", "Interface List" },
    .{ "UL", "User List" },
    .{ "EVF", "Event with Flags" },
});

pub export fn get_block_desc(block_type: u32) ?[*:0]const u8 {
    @setEvalBranchQuota(30000); // If you exceed the branch quota then bump it

    inline for (@typeInfo(c).Struct.decls) |decl| {
        const is_block_type = comptime std.mem.containsAtLeast(u8, decl.name, 1, "_BLOCK_TYPE");
        if (is_block_type) {
            const block_name = comptime blk: {
                const n = std.mem.indexOfScalar(u8, decl.name, '_').?;
                const prefix = decl.name[0..n];
                break :blk block_names.get(prefix) orelse {
                    @compileError("Unrecognized block type prefix: " ++ prefix ++ ", found in: " ++ decl.name);
                };
            };

            if (block_type == @as(u32, @intCast(@field(c, decl.name)))) {
                return block_name.ptr;
            }
        }
    }

    return "";
}

export fn print_event_line(event: *const c.event_header) void {
    print_event_line_impl(event) catch |err| {
        @panic(@errorName(err));
    };
}

fn get_event_type_str(event_type: u32) ?[]const u8 {
    @setEvalBranchQuota(20000); // If you exceed the branch quota then bump it

    return inline for (@typeInfo(ppm_events).Struct.decls) |decl| {
        const is_ppme = comptime std.mem.startsWith(u8, decl.name, "PPME_") and
            std.meta.trait.isNumber(@TypeOf(@field(ppm_events, decl.name)));
        if (is_ppme) {
            if (event_type == @field(ppm_events, decl.name))
                break decl.name;
        }
    } else null;
}

fn print_event_line_impl(event: *const c.event_header) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll("\tEvent type=");
    if (get_event_type_str(event.type)) |type_str|
        try stdout.print("{s}, ", .{type_str})
    else
        try stdout.print("{}, ", .{event.type});

    try stdout.print("ts={}, tid={}, len={}\n", .{
        event.ts_ns,
        event.tid,
        event.len,
    });
}
