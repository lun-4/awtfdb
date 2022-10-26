const std = @import("std");
const deps = @import("./deps.zig");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);
    deps.addAllTo(exe_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);

    const manage_exe = b.addExecutable("awtfdb-manage", "src/main.zig");
    manage_exe.setTarget(target);
    manage_exe.setBuildMode(mode);
    manage_exe.install();
    deps.addAllTo(manage_exe);

    const watcher_exe = b.addExecutable("awtfdb-watcher", "src/rename_watcher_main.zig");
    watcher_exe.setTarget(target);
    watcher_exe.setBuildMode(mode);
    watcher_exe.install();

    deps.addAllTo(watcher_exe);

    const include_exe = b.addExecutable("ainclude", "src/include_main.zig");
    include_exe.setTarget(target);
    include_exe.setBuildMode(mode);
    include_exe.install();

    deps.addAllTo(include_exe);

    const find_exe = b.addExecutable("afind", "src/find_main.zig");
    find_exe.setTarget(target);
    find_exe.setBuildMode(mode);
    find_exe.install();

    deps.addAllTo(find_exe);

    const ls_exe = b.addExecutable("als", "src/ls_main.zig");
    ls_exe.setTarget(target);
    ls_exe.setBuildMode(mode);
    ls_exe.install();

    deps.addAllTo(ls_exe);

    const tags_exe = b.addExecutable("atags", "src/tags_main.zig");
    tags_exe.setTarget(target);
    tags_exe.setBuildMode(mode);
    tags_exe.install();
    deps.addAllTo(tags_exe);

    const rm_exe = b.addExecutable("arm", "src/rm_main.zig");
    rm_exe.setTarget(target);
    rm_exe.setBuildMode(mode);
    rm_exe.install();
    deps.addAllTo(rm_exe);

    const janitor_exe = b.addExecutable("awtfdb-janitor", "src/janitor_main.zig");
    janitor_exe.setTarget(target);
    janitor_exe.setBuildMode(mode);
    janitor_exe.install();
    deps.addAllTo(janitor_exe);

    const metrics_exe = b.addExecutable("awtfdb-metrics", "src/metrics_main.zig");
    metrics_exe.setTarget(target);
    metrics_exe.setBuildMode(mode);
    metrics_exe.install();

    // this is required for metrics so that the queries don't take too long
    //metrics_exe.build_mode = .ReleaseSafe;
    deps.addAllTo(metrics_exe);
}
