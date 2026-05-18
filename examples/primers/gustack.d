#!/usr/bin/env bifrost
/*
 * gustack.d — guest user-space stack walk
 *
 * `gustack()` (guest user stack) walks the guest's userspace frame
 * pointers from the kernel side, then symbolicates each address
 * against the right ELF in the guest rootfs. The host renderer
 * matches PCs against per-(tgid, exec_id) VMA tables published by
 * the in-kernel bifrost driver and demangles glibc / vDSO / static-
 * PIE binaries.
 *
 * Frame-pointer-default rootfs is required (Ubuntu 24.04+, Fedora
 * 38+, Arch, AlmaLinux 10+). Alpine + musl produces truncated
 * stacks because musl strips frame pointers.
 *
 * Run:
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/gustack.d
 *   sudo examples/primers/gustack.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 *
 * Expected output: each fire is followed by a stack of frames like
 *   redis-server!processCommand+0xa52d0
 *   redis-server!aeProcessEvents+0x...
 *   libc.so.6!__libc_start_main+0x...
 */

#pragma D option quiet

bifrost::do_sys_openat2:entry
{
    gustack();
}
