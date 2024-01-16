const std = @import("std");
const scap = @import("scap.zig");
const ProcessTree = @import("ProcessTree.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .stack_trace_frames = 20,
    }){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();
    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2)
        return error.InvalidArgs;

    const file_path = args[1];
    std.log.info("file path: {s}", .{file_path});
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var proc_lists = std.ArrayList(scap.ProcList).init(allocator);
    {
        errdefer {
            for (proc_lists.items) |*list| list.deinit(allocator);
            proc_lists.deinit();
        }

        var buffered = std.io.bufferedReader(file.reader());

        // collect processes from the scap file
        var scap_reader = try scap.init_reader(buffered.reader());
        while (true) {
            var block = try scap_reader.next(allocator) orelse break;
            switch (block) {
                .proc_list => |proc_list| {
                    try proc_lists.append(proc_list);
                    continue;
                },
                else => {},
            }
            defer block.deinit(allocator);
        }
    }

    var tree = try ProcessTree.init(allocator, proc_lists);
    defer tree.deinit();

    const stdout = std.io.getStdOut().writer();
    for (tree.cgroups.keys(), tree.cgroups.values()) |cgroup_name, children| {
        var sorted_children = try tree.gpa.dupe(*const scap.ThreadInfo, children.items);
        defer tree.gpa.free(sorted_children);

        std.mem.sortUnstable(*const scap.ThreadInfo, sorted_children, {}, @import("ps.zig").thread_info_less_than);

        try stdout.print("{s}\n", .{cgroup_name});
        for (sorted_children) |process| {
            const comm: [*:0]const u8 = @ptrCast(&process.comm);
            try stdout.print("  {} {s}\n", .{ process.tid, comm });
        }

        try stdout.writeByte('\n');
    }
}
