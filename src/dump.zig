const std = @import("std");
const scap = @import("scap.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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
    defer {
        for (proc_lists.items) |*list| list.deinit(allocator);
        proc_lists.deinit();
    }

    const stdout = std.io.getStdOut().writer();

    // collect processes from the scap file
    var scap_reader = try scap.Reader(std.fs.File.Reader).init(file.reader());
    while (true) {
        var block = try scap_reader.next(allocator) orelse break;
        defer block.deinit(allocator);

        try stdout.print("{}\n", .{block});
    }
}
