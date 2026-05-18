#!/usr/bin/env bifrost
/*
 * per-pid-opens.d — file opens grouped by guest PID
 *
 * Demonstrates user-defined globals (`@count[gpid]`) lowered to a
 * BPF HASH map keyed on var_id, with the snapshot path materializing
 * the map contents on dtrace consumer exit.
 *
 * The D-source variable `pid` lowers to a BPF helper call
 * (`bpf_get_current_pid_tgid()` masked to 32 bits). The host
 * renderer labels the resulting field as `gpid=` to make it
 * unambiguous which side of the boundary the PID belongs to.
 *
 * Expected output on exit (one row per guest PID seen):
 *   233     2456
 *   234       17
 *   ...
 *
 * Run:
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/per-pid-opens.d
 *   sudo examples/primers/per-pid-opens.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 */

#pragma D option quiet

bifrost::do_sys_openat2:entry
{
    @count[pid] = count();
}
