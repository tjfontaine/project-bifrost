#!/usr/bin/env bifrost
/*
 * error-clause.d — dtrace:::ERROR and Bifrost fault visibility.
 *
 * Two sides of the same coin:
 *
 *   1.  Host-side: libdtrace fires `dtrace:::ERROR` whenever
 *       its own probes (here: `syscall::openat:entry`) fault.
 *       The deliberately-broken `copyin(0x1, 16)` below feeds
 *       0x1 (unreadable user memory) so the ERROR clause has
 *       something to do; printed `arg2/arg3/arg5` give the
 *       faulting probe id, action index, and errno.
 *
 *   2.  Guest-side: Bifrost-owned probes (`fbt:guest:...`,
 *       `bifrost:guest_kernel:...`, `uprobe:guest:...`) bump
 *       the per-CPU `BIFROST_DROP_CLASS_DBLERR` counter
 *       whenever a fault-prone kfunc (`copyin`, `copyinstr`,
 *       `strlen`, `strchr`, `strrchr`, `strstr`, `strjoin`,
 *       `substr`, `progenyof`) returns its zero/NULL sentinel
 *       on an unreadable input.  The host CLI's drop summary
 *       renders this as `dblerr=N` so the user sees the
 *       fault rate even when no `dtrace:::ERROR` clause is
 *       registered.
 *
 *   sudo bifrost -p $PID -s examples/primers/error-clause.d
 *
 * Expected output: one "[primer] ERROR fired" line per
 * faulting openat plus a non-zero `dblerr=N` in the final
 * `[bifrost] guest-ring drop summary:` line when a
 * Bifrost-owned probe with a fault-prone kfunc call is also
 * loaded.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("[primer] arming a deliberately-faulting copyin\n");
}

syscall::openat:entry
{
    /* copyin(0x1) — 0x1 is unreadable user memory; libdtrace
     * fires the ERROR clause with the faulting probe id +
     * action index + errno. */
    trace(copyin(0x1, 16));
}

dtrace:::ERROR
{
    printf("[primer] ERROR fired: probe_id=%d action=%d errno=%d\n",
           arg2, arg3, arg5);
}
