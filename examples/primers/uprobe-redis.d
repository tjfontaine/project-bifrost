#!/usr/bin/env bifrost
/*
 * uprobe-redis.d — user-space probe in a guest binary
 *
 * `bifrost:guest_user:<binary>:<symbol>:entry` attaches a uprobe
 * inside the guest. The host CLI parses the probe spec, walks the
 * guest binary's ELF symbol table to resolve `<symbol>` to a file
 * offset, and ships the resolved (binary, offset) into the guest
 * via the BFR7 LOAD_PROG trailer. The guest driver then walks
 * `for_each_process` to find the target task and registers the
 * uprobe via the in-kernel bifrost helper.
 *
 * The boot-order race (uprobe registration vs virtiofs mount) is
 * handled by the kern_path retry path in linux-bifrost commit
 * 0041 (`bifrost-uprobe-kern_path-retry`).
 *
 * Run (assumes redis is the workload — adjust the binary and
 * symbol for other targets):
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/uprobe-redis.d
 *   sudo examples/primers/uprobe-redis.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 */

#pragma D option quiet

bifrost:guest_user:redis-server:processCommand:entry
{
    @cmds = count();
}
