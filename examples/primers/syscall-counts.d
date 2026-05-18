#!/usr/bin/env bifrost
/*
 * syscall-counts.d — count syscall entries per execname via the
 * stable `syscall::` provider catalog.
 *
 * `syscall::<name>:entry` is rewritten by the bifrost CLI's
 * `rewrite_per_syscall` source-pass into the underlying raw
 * tracepoint
 * `tracepoint:guest:syscalls:sys_enter_<name>`.  The user-visible
 * script uses the stable DTrace name; the underlying Linux
 * tracepoint can be renamed/restructured without breaking the
 * script.
 *
 * Same idea for `syscall:::entry` (all syscalls) — see
 * STABLE_PROVIDERS in host/bifrost/src/cli/source_rewrite.rs.
 *
 *   sudo bifrost -p $PID -s examples/primers/syscall-counts.d
 *
 * Expected output after ^C:
 *
 *   @[execname]
 *           <some_proc>           <count>
 *           ...
 */

#pragma D option quiet

syscall::openat:entry
{
    @[execname] = count();
}
