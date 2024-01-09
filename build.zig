const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zlib_dep = b.dependency("zlib", .{
        .target = target,
        .optimize = optimize,
    });

    const block_types = b.addStaticLibrary(.{
        .name = "block_types",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    block_types.addIncludePath(.{ .path = "deps/falco-libs/userspace/libscap" });
    block_types.addIncludePath(.{ .path = "deps/falco-libs/driver" });
    block_types.addIncludePath(.{ .path = "." });

    const scap_read = b.addExecutable(.{
        .name = "scap_read",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    scap_read.addIncludePath(.{ .path = "deps/falco-libs/userspace/libscap" });
    scap_read.addIncludePath(.{ .path = "deps/falco-libs/userspace/libscap/engine/savefile" });
    scap_read.addCSourceFiles(&.{
        "scap_read.c",
        "read_proclist.c",
        "bufscap.c",
        "largest_block.c",
    }, &.{
        "-fno-sanitize=all", // UB sanitization using traps is on by default,
        // hit these and don't want to deal with them atm
        // so turn them off for now.
    });
    scap_read.linkLibrary(block_types);
    scap_read.linkLibrary(zlib_dep.artifact("z"));
    b.installArtifact(scap_read);

    const scap_read_run = b.addRunArtifact(scap_read);
    if (b.args) |args|
        scap_read_run.addArgs(args);

    const run_step = b.step("run", "Run scap reader");
    run_step.dependOn(&scap_read_run.step);
}
