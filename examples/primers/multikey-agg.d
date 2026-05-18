#!/usr/bin/env bifrost
/*
 * multikey-agg.d — multi-key aggregation
 *
 * Aggregation keyed on a tuple `(pid, execname)`. The lowering
 * pass packs both keys into the BPF map's key slot; the snapshot
 * path unpacks them on read so the libdtrace consumer sees one
 * row per (pid, execname) pair.
 *
 * `execname` is the guest task's comm (16 bytes max); reading it
 * uses the bifrost guest helper `bifrost_kfunc_current_comm` since
 * task->comm is not directly accessible from user-loaded BPF
 * programs without the bifrost verifier shim. The host renderer
 * labels the pid field as `gpid=` in output.
 *
 * Run:
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/multikey-agg.d
 *   sudo examples/primers/multikey-agg.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 */

#pragma D option quiet

bifrost::do_sys_openat2:entry
{
    @[pid, execname] = count();
}
