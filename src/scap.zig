const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const utils = @import("main.zig");

const c = @cImport({
    @cInclude("stdbool.h");
    @cInclude("stdint.h");
    @cInclude("scap_savefile.h");
    @cInclude("scap_redefs.h");
});

pub const ThreadInfo = c.scap_threadinfo;

pub const ProcList = struct {
    items: std.TailQueue(ThreadInfo),

    pub const Node = std.TailQueue(ThreadInfo).Node;

    pub fn deinit(proc_list: *ProcList, allocator: Allocator) void {
        while (proc_list.items.pop()) |node| allocator.destroy(node);
    }

    pub fn from_reader(
        allocator: Allocator,
        bytes: []const u8,
        block_type: u32,
    ) !ProcList {
        var fbs = std.io.fixedBufferStream(bytes);
        var counting = std.io.countingReader(fbs.reader());
        const reader = counting.reader();
        const version: u32 = switch (block_type) {
            c.PL_BLOCK_TYPE_V1, c.PL_BLOCK_TYPE_V1_INT => 1,
            c.PL_BLOCK_TYPE_V2, c.PL_BLOCK_TYPE_V2_INT => 2,
            c.PL_BLOCK_TYPE_V3, c.PL_BLOCK_TYPE_V3_INT => 3,
            c.PL_BLOCK_TYPE_V4 => 4,
            c.PL_BLOCK_TYPE_V5 => 5,
            c.PL_BLOCK_TYPE_V6 => 6,
            c.PL_BLOCK_TYPE_V7 => 7,
            c.PL_BLOCK_TYPE_V8 => 8,
            c.PL_BLOCK_TYPE_V9 => 9,
            else => @panic("Unhandled Block Version"),
        };

        var items = std.TailQueue(ThreadInfo){};
        errdefer while (items.pop()) |node| allocator.destroy(node);

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var sub_begin: usize = 0;

        while (bytes.len - counting.bytes_read >= 4) {

            // assumes that versions later than 9 will be backwards compatible
            const sub_len: u32 = switch (version) {
                1...8 => 0,
                9 => try reader.readIntLittle(u32),
                else => unreachable,
            };

            const tid = try reader.readIntLittle(u64);
            const pid = try reader.readIntLittle(u64);
            const ptid = try reader.readIntLittle(u64);
            const sid: ?u64 = switch (version) {
                1...5 => null,
                6...9 => try reader.readIntLittle(u64),
                else => unreachable,
            };

            const vpgid: ?u64 = switch (version) {
                1...7 => null,
                8...9 => try reader.readIntLittle(u64),
                else => unreachable,
            };

            const comm = try read_varlen(arena.allocator(), reader);
            const exe = try read_varlen(arena.allocator(), reader);
            const exepath: ?[:0]const u8 = switch (version) {
                1...6 => null,
                7...9 => try read_varlen(arena.allocator(), reader),
                else => unreachable,
            };
            const args = try read_varlen(arena.allocator(), reader);
            const cwd = try read_varlen(arena.allocator(), reader);
            const fdlimit = try reader.readIntLittle(i64);
            const flags = try reader.readIntLittle(u32);
            const uid = try reader.readIntLittle(u32);
            const gid = try reader.readIntLittle(u32);

            const vmsize_kb: ?u32 = if (version >= 2) try reader.readIntLittle(u32) else null;
            const vmrss_kb: ?u32 = if (version >= 2) try reader.readIntLittle(u32) else null;
            const vmswap_kb: ?u32 = if (version >= 2) try reader.readIntLittle(u32) else null;

            const pfmajor: ?u64 = if (version >= 2)
                try reader.readIntLittle(u64)
            else
                null;

            const pfminor = if (version >= 2)
                try reader.readIntLittle(u64)
            else
                null;

            const env: ?[]const u8 = if (version >= 3)
                try read_varlen(arena.allocator(), reader)
            else
                null;

            const vtid: ?i64 = if (version >= 4)
                try reader.readIntLittle(i64)
            else
                null;

            const vpid: ?i64 = if (version >= 4)
                try reader.readIntLittle(i64)
            else
                null;

            const cgroups: ?[:0]const u8 = if (version >= 4)
                try read_varlen(arena.allocator(), reader)
            else
                null;

            const root: ?[:0]const u8 = if (version >= 5)
                try read_varlen(arena.allocator(), reader)
            else
                null;

            //const init_count = counting.bytes_read;
            const loginuid: ?i32 = if (sub_len > 0 and counting.bytes_read + @sizeOf(i32) <= sub_len)
                try reader.readIntLittle(i32)
            else
                null;

            const exe_writable: ?bool = if (sub_len > 0 and counting.bytes_read + @sizeOf(bool) <= sub_len) blk: {
                const raw = try reader.readIntLittle(u8);
                break :blk switch (raw) {
                    0 => false,
                    1 => true,
                    else => return error.InvalidBool,
                };
            } else null;

            const cap_inheritable: ?u64 = if (sub_len > 0 and counting.bytes_read + @sizeOf(u64) <= sub_len)
                try reader.readIntLittle(u64)
            else
                null;

            const cap_permitted: ?u64 = if (sub_len > 0 and counting.bytes_read + @sizeOf(u64) <= sub_len)
                try reader.readIntLittle(u64)
            else
                null;

            const cap_effective: ?u64 = if (sub_len > 0 and counting.bytes_read + @sizeOf(u64) <= sub_len)
                try reader.readIntLittle(u64)
            else
                null;

            try reader.skipBytes(sub_len - (counting.bytes_read - sub_begin), .{});
            sub_begin += sub_len;

            var node = try allocator.create(Node);
            errdefer allocator.destroy(node);

            node.data = ThreadInfo{
                .tid = tid,
                .pid = pid,
                .ptid = ptid,
                .sid = sid orelse std.math.maxInt(u64),
                .vpgid = vpgid orelse std.math.maxInt(u64),
                .comm = undefined,
                .exe = undefined,
                .exepath = undefined,
                .exe_writable = exe_writable orelse false,
                .args = undefined,
                .args_len = @intCast(args.len),
                .env = undefined,
                .env_len = if (env) |e| @intCast(e.len) else 0,
                .cwd = undefined,
                .fdlimit = fdlimit,
                .flags = flags,
                .uid = uid,
                .gid = gid,
                .cap_permitted = cap_permitted orelse 0,
                .cap_effective = cap_effective orelse 0,
                .cap_inheritable = cap_inheritable orelse 0,
                .vmsize_kb = vmsize_kb orelse 0,
                .vmrss_kb = vmrss_kb orelse 0,
                .vmswap_kb = vmswap_kb orelse 0,
                .pfmajor = pfmajor orelse 0,
                .pfminor = pfminor orelse 0,
                .vtid = vtid orelse -1,
                .vpid = vpid orelse -1,
                .cgroups = undefined,
                .cgroups_len = if (cgroups) |cg| @intCast(cg.len) else 0,
                .root = undefined,
                .fdlist = null,
                .loginuid = loginuid orelse -1,

                // fields not serialized it seems, going to initialize to zero
                .exe_upper_layer = false,
                .exe_ino = 0,
                .exe_ino_ctime = 0,
                .exe_ino_mtime = 0,
                .exe_ino_ctime_duration_clone_ts = 0,
                .exe_ino_ctime_duration_pidns_start = 0,
                .pidns_init_start_ts = 0,
                .filtered_out = 0,
                .clone_ts = 0,
                .tty = 0,
                .exe_from_memfd = false,
            };

            try copy_null_terminated(&node.data.comm, comm);
            try copy_null_terminated(&node.data.exe, exe);
            try copy_null_terminated(&node.data.exepath, exepath);
            try copy_null_terminated(&node.data.cwd, cwd);
            try copy_null_terminated(&node.data.cgroups, cgroups);
            try copy_null_terminated(&node.data.root, root);

            items.append(node);
        }

        return ProcList{
            .items = items,
        };
    }

    // caller owns memory via allocator, not very efficient because we allocate
    // temporary memory then immediately copy it, but it's a bit easier to keep
    // track of fields
    fn read_varlen(allocator: Allocator, reader: anytype) ![:0]u8 {
        const len = try reader.readIntLittle(u16);

        var buf = try allocator.allocSentinel(u8, len, 0);
        errdefer allocator.free(buf);

        const n = try reader.readAll(buf[0..]);
        if (n != len)
            return error.EndOfStream;

        return buf;
    }
};

fn copy_null_terminated(buf: []u8, str: ?[:0]const u8) !void {
    if (str) |s| {
        if (buf.len < s.len + 1)
            return error.TooLong;

        @memcpy(buf[0 .. s.len + 1], s[0 .. s.len + 1]);
    } else buf[0] = 0;
}

pub const Event = struct {
    impl: c.event_section_header_flags,
    pub fn deinit(event: Event, allocator: Allocator) void {
        _ = event;
        _ = allocator;
    }
};

pub const EventNoFlags = struct {
    impl: c.event_section_header_no_flags,

    pub fn deinit(event: EventNoFlags, allocator: Allocator) void {
        _ = event;
        _ = allocator;
    }
};

pub const MachineInfo = struct {
    pub fn deinit(machine_info: MachineInfo, allocator: Allocator) void {
        _ = machine_info;
        _ = allocator;
    }
};

pub const InterfaceList = struct {
    pub fn deinit(interface_list: InterfaceList, allocator: Allocator) void {
        _ = interface_list;
        _ = allocator;
    }
};

pub const UserList = struct {
    pub fn deinit(user_list: UserList, allocator: Allocator) void {
        _ = user_list;
        _ = allocator;
    }
};

pub const FdList = struct {
    pub fn deinit(fd_list: FdList, allocator: Allocator) void {
        _ = fd_list;
        _ = allocator;
    }
};

pub const Block = union(enum) {
    event: Event,
    event_no_flags: EventNoFlags,
    proc_list: ProcList,
    machine_info: MachineInfo,
    interface_list: InterfaceList,
    user_list: UserList,
    fd_list: FdList,

    pub fn deinit(block: *Block, allocator: Allocator) void {
        switch (block.*) {
            inline else => |*variant| variant.deinit(allocator),
        }
    }

    pub fn format(
        block: Block,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (block) {
            .event => |event| try writer.print("event: {}", .{event.impl}),
            .event_no_flags => |event_no_flags| try writer.print("event_no_flags: {}", .{event_no_flags.impl}),
            .proc_list => |proc_list| try writer.print("proc_list: {}", .{proc_list}),
            .machine_info => |machine_info| try writer.print("machine_info: {}", .{machine_info}),
            .interface_list => |interface_list| try writer.print("interface_list: {}", .{interface_list}),
            .user_list => |user_list| try writer.print("user_list: {}", .{user_list}),
            .fd_list => |fd_list| try writer.print("fd_list: {}", .{fd_list}),
        }
    }
};

pub fn init_reader(reader: anytype) !Reader(@TypeOf(reader)) {
    return Reader(@TypeOf(reader)).init(reader);
}

pub fn Reader(comptime InnerReader: type) type {
    return struct {
        block_header: c.block_header,
        section_header: c.section_header_block,
        block_trailer: u32,
        inner: InnerReader,

        const Self = @This();

        pub fn init(inner: InnerReader) !Self {
            // read the section header block
            return Self{
                .block_header = try inner.readStruct(c.block_header),
                .section_header = try inner.readStruct(c.section_header_block),
                .block_trailer = try inner.readIntLittle(u32),
                .inner = inner,
            };
        }

        pub fn next(self: *Self, allocator: Allocator) !?Block {
            // read block header
            const block_header = self.inner.readStruct(c.block_header) catch |err| {
                return if (err == error.EndOfStream)
                    null
                else
                    err;
            };

            const expected_len = block_header.block_total_length - @sizeOf(c.block_header) - @sizeOf(u32);
            var buf = try std.ArrayList(u8).initCapacity(allocator, expected_len);
            defer buf.deinit();

            try buf.appendNTimes(undefined, expected_len);
            const n = try self.inner.readAll(buf.items);
            if (n != expected_len) {
                std.log.err("Could not read block (expected length of {}, got length of {})", .{
                    expected_len,
                    n,
                });
                return error.InvalidBlock;
            }

            // trailer
            _ = try self.inner.readIntLittle(u32);
            return switch (block_header.block_type) {
                c.EVF_BLOCK_TYPE,
                c.EVF_BLOCK_TYPE_V2,
                c.EVF_BLOCK_TYPE_V2_LARGE,
                => Block{
                    .event = .{
                        .impl = @as(*c.event_section_header_flags, @alignCast(@ptrCast(buf.items.ptr))).*,
                    },
                },
                c.EV_BLOCK_TYPE,
                c.EV_BLOCK_TYPE_V2,
                c.EV_BLOCK_TYPE_V2_LARGE,
                => Block{
                    .event_no_flags = .{
                        .impl = @as(*c.event_section_header_no_flags, @alignCast(@ptrCast(buf.items.ptr))).*,
                    },
                },
                c.MI_BLOCK_TYPE => Block{
                    .machine_info = .{},
                },
                c.IL_BLOCK_TYPE,
                c.IL_BLOCK_TYPE_V2,
                => Block{
                    .interface_list = .{},
                },
                c.UL_BLOCK_TYPE,
                c.UL_BLOCK_TYPE_V2,
                => Block{
                    .user_list = .{},
                },
                c.FDL_BLOCK_TYPE,
                c.FDL_BLOCK_TYPE_V2,
                => Block{
                    .fd_list = .{},
                },
                c.PL_BLOCK_TYPE_V1,
                c.PL_BLOCK_TYPE_V2,
                c.PL_BLOCK_TYPE_V3,
                c.PL_BLOCK_TYPE_V4,
                c.PL_BLOCK_TYPE_V5,
                c.PL_BLOCK_TYPE_V6,
                c.PL_BLOCK_TYPE_V7,
                c.PL_BLOCK_TYPE_V8,
                c.PL_BLOCK_TYPE_V9,
                c.PL_BLOCK_TYPE_V1_INT,
                c.PL_BLOCK_TYPE_V2_INT,
                c.PL_BLOCK_TYPE_V3_INT,
                => blk: {
                    break :blk Block{
                        .proc_list = try ProcList.from_reader(allocator, buf.items, block_header.block_type),
                    };
                },
                else => |block_type| blk: {
                    std.log.err("unhandled block type: {}: {?s}", .{ block_type, utils.get_block_desc(block_type) });
                    break :blk error.UnrecognizeBlockType;
                },
            };
        }
    };
}
