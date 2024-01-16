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

    // keep track of what's printed, this will let us know if there were any
    // processes with multiple parents, which _should_ be impossible.
    var visited = Visited.init(allocator);
    defer visited.deinit();

    const stdout = std.io.getStdOut().writer();
    var sorted_process_lineage = try allocator.dupe(*const scap.ThreadInfo, tree.process_lineage.keys());
    defer allocator.free(sorted_process_lineage);

    std.mem.sortUnstable(*const scap.ThreadInfo, sorted_process_lineage, {}, thread_info_less_than);

    for (sorted_process_lineage) |process| {
        if (visited.contains(process))
            continue;

        const depth: u32 = 0;
        try recursive_print_lineage(tree, &visited, process, depth, stdout);
    }
}
const Visited = std.AutoHashMap(*const scap.ThreadInfo, void);

pub fn thread_info_less_than(_: void, lhs: *const scap.ThreadInfo, rhs: *const scap.ThreadInfo) bool {
    return lhs.tid < rhs.tid;
}

const RecursivePrintError = error{
    OutOfMemory,
    AccessDenied,
    Unexpected,
    SystemResources,
    FileTooBig,
    NoSpaceLeft,
    DeviceBusy,
    WouldBlock,
    InputOutput,
    OperationAborted,
    BrokenPipe,
    ConnectionResetByPeer,
    DiskQuota,
    InvalidArgument,
    NotOpenForWriting,
    LockViolation,
};

fn recursive_print_lineage(tree: ProcessTree, visited: *Visited, process: *const scap.ThreadInfo, depth: u32, writer: anytype) RecursivePrintError!void {
    if (visited.contains(process))
        return;

    try visited.putNoClobber(process, {});
    try writer.writeByteNTimes(' ', depth);
    const comm: [*:0]const u8 = @ptrCast(&process.comm);
    const cgroups: [*:0]const u8 = @ptrCast(&process.cgroups);
    try writer.print("{} {s}: {s}\n", .{ process.tid, comm, cgroups });

    var sorted_children = try tree.gpa.dupe(*const scap.ThreadInfo, if (tree.process_lineage.get(process)) |list| list.items else &.{});
    defer tree.gpa.free(sorted_children);

    std.mem.sortUnstable(*const scap.ThreadInfo, sorted_children, {}, thread_info_less_than);
    for (sorted_children) |child|
        try recursive_print_lineage(tree, visited, child, depth + 1, writer);
}
