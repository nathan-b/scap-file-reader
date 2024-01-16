gpa: Allocator,
// place to stuff string copies
arena: std.heap.ArenaAllocator,
proc_lists: std.ArrayList(scap.ProcList),
tid_to_threads: TidToThreads,
threads: ThreadSet,
processes: ThreadSet,
thread_lineage: ThreadMapping,
process_lineage: ThreadMapping,
// maps to processes
cgroups: std.StringArrayHashMap(std.ArrayListUnmanaged(*const scap.ThreadInfo)),

const ProcessTree = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;

const scap = @import("scap.zig");

const ThreadSet = std.AutoArrayHashMap(*const scap.ThreadInfo, void);
const ThreadMap = std.AutoArrayHashMap(*const scap.ThreadInfo, *const scap.ThreadInfo);
const ThreadMapping = std.AutoArrayHashMap(*const scap.ThreadInfo, std.ArrayListUnmanaged(*const scap.ThreadInfo));
const TidToThreads = std.AutoArrayHashMap(u64, std.ArrayListUnmanaged(*const scap.ThreadInfo));

/// takes ownership of lists
pub fn init(allocator: Allocator, proc_lists: std.ArrayList(scap.ProcList)) !ProcessTree {
    var tree = ProcessTree{
        .gpa = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .proc_lists = proc_lists,
        .tid_to_threads = TidToThreads.init(allocator),
        .threads = ThreadSet.init(allocator),
        .processes = ThreadSet.init(allocator),
        .thread_lineage = ThreadMapping.init(allocator),
        .process_lineage = ThreadMapping.init(allocator),
        .cgroups = std.StringArrayHashMap(std.ArrayListUnmanaged(*const scap.ThreadInfo)).init(allocator),
    };
    errdefer tree.deinit();

    for (proc_lists.items) |proc_list| {
        var it = proc_list.items.first;
        while (it != null) : (it = it.?.next) {
            try tree.threads.putNoClobber(&it.?.data, {});

            const result = try tree.tid_to_threads.getOrPut(it.?.data.tid);
            if (!result.found_existing)
                result.value_ptr.* = .{};

            try result.value_ptr.append(allocator, &it.?.data);
        }
    }

    // Processes are threads who's pid == tid
    for (tree.threads.keys()) |thread| {
        const tid: i64 = @bitCast(thread.tid);
        const pid: i64 = @bitCast(thread.pid);
        if (pid != -1 and tid == pid)
            try tree.processes.putNoClobber(thread, {});
    }

    // Temporary mapping to make lookups easier
    var thread_to_group_leader = ThreadMap.init(allocator);
    defer thread_to_group_leader.deinit();

    for (tree.threads.keys()) |thread| {
        const pid: i64 = @bitCast(thread.pid);
        if (pid == -1)
            continue;

        const thread_group_leader = tree.find_thread(pid, thread.clone_ts) orelse continue;
        if (!tree.processes.contains(thread_group_leader))
            return error.ThreadGroupLeaderNotProcess;

        try thread_to_group_leader.putNoClobber(thread, thread_group_leader);
        const result = try tree.thread_lineage.getOrPut(thread_group_leader);
        if (!result.found_existing)
            result.value_ptr.* = .{};

        try result.value_ptr.append(allocator, thread);
    }

    for (tree.processes.keys()) |process| {
        const ptid: i64 = @bitCast(process.ptid);
        const parent_thread = tree.find_thread(ptid, process.clone_ts) orelse continue;
        const thread_group_leader = thread_to_group_leader.get(parent_thread) orelse continue;
        if (!tree.processes.contains(thread_group_leader))
            return error.ThreadGroupLeaderNotProcess;

        {
            const result = try tree.process_lineage.getOrPut(thread_group_leader);
            if (!result.found_existing)
                result.value_ptr.* = .{};

            try result.value_ptr.append(allocator, process);
        }

        {
            // add it to a cgroup if it has any
            //
            // Not sure why it's always cpuset, but let's go with that for now
            const cgroup_name = try get_cgroup_name(tree.arena.allocator(), "cpuset", process) orelse continue;
            const result = try tree.cgroups.getOrPut(cgroup_name);
            if (!result.found_existing)
                result.value_ptr.* = .{};

            try result.value_ptr.append(allocator, process);
        }
    }

    return tree;
}

fn get_cgroup_name(allocator: Allocator, expected_key: []const u8, process: *const scap.ThreadInfo) !?[]u8 {
    const cgroup_str: [*:0]const u8 = @ptrCast(&process.cgroups);
    const cgroup_slice = std.mem.span(cgroup_str);
    const count = std.mem.count(u8, cgroup_slice, "=");
    if (count > 1)
        @panic("TODO: multiple cgroups");

    if (count == 0)
        return null;

    const index = std.mem.indexOfScalar(u8, cgroup_slice, '=').?;
    const key = cgroup_slice[0..index];
    if (!std.mem.eql(u8, key, expected_key)) {
        std.log.err("unexpected key: {s}", .{key});
    }

    return try allocator.dupe(u8, cgroup_slice[index + 1 ..]);
}

fn find_thread(tree: ProcessTree, needle_tid: i64, clone_ts: u64) ?*const scap.ThreadInfo {
    if (needle_tid <= 0)
        return null;

    return if (tree.tid_to_threads.get(@intCast(needle_tid))) |list|
        for (list.items) |thread| {
            const tid: i64 = @bitCast(thread.tid);
            if (tid != @as(i64, @intCast(needle_tid)))
                continue;

            if (thread.clone_ts < clone_ts)
                continue;

            break thread;
        } else null
    else
        null;
}

pub fn deinit(tree: *ProcessTree) void {
    for (tree.proc_lists.items) |*list| list.deinit(tree.gpa);
    tree.proc_lists.deinit();

    for (tree.tid_to_threads.values()) |*list| list.deinit(tree.gpa);
    tree.tid_to_threads.deinit();

    for (tree.thread_lineage.values()) |*children| children.deinit(tree.gpa);
    tree.thread_lineage.deinit();

    for (tree.process_lineage.values()) |*children| children.deinit(tree.gpa);
    tree.process_lineage.deinit();

    for (tree.cgroups.values()) |*children| children.deinit(tree.gpa);
    tree.cgroups.deinit();

    tree.threads.deinit();
    tree.processes.deinit();
    tree.arena.deinit();
}
