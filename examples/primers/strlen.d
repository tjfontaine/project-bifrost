#!/usr/bin/env bifrost
/*
 * strlen.d — `strlen(s)` for user-space strings.
 *
 * Wraps `bpf_probe_read_user_str` behind a kfunc that caps reads
 * at 256 bytes. Returns 0 on NULL or unreadable input — matches
 * DTrace's "no fault, just zero" semantics. Real fault routing
 * to a `dtrace:::ERROR` clause is handled by fault accounting.
 *
 *   sudo bifrost -p $PID -s examples/primers/strlen.d
 *
 * Reports the strlen of each opened path. Length-0 entries mean
 * the kfunc could not read the userspace pointer (e.g. probe
 * fired in interrupt context where the user mm wasn't pinned).
 */

#pragma D option quiet

syscall::openat:entry
{
    printf("open path_len=%d\n", strlen(copyinstr(arg1)));
}
