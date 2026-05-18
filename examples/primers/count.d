#!/usr/bin/env bifrost
/*
 * count.d — proof of life
 *
 * The smallest possible bifrost demo. The single bifrost: clause
 * compiles to eBPF on the macOS host, ships through the SHM control
 * plane into the guest kernel, JIT'd, and attached as a kprobe on
 * `do_sys_openat2` (the kernel entry path for openat(2)). Every
 * fire crosses back to the host's libdtrace consumer.
 *
 * What proves the pipeline works:
 *   • `bifrost -p <pid> -s examples/primers/count.d` writes a BFR7 wrapper
 *   • Observer attach succeeds, LOAD_PROG queues the program
 *   • Records appear on stdout for any file open inside the guest
 *
 * Run:
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/count.d
 *   sudo examples/primers/count.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 */

#pragma D option quiet

bifrost::do_sys_openat2:entry { x = 1; }
