#!/usr/bin/env bifrost
/*
 * probe.d — redis processCommand uprobe trace
 *
 * The first end-to-end demo that exercises the BFR7 uprobe trailer
 * path.  bifrost: `guest_user:redis-server:processCommand:entry`
 * resolves redis-server's processCommand symbol to a file offset
 * via the host CLI's ELF parse, ships the (binary, offset) tuple
 * into the guest via LOAD_PROG's BFR7 wrapper, and the in-kernel
 * bifrost driver registers a uprobe on the running redis pid.
 *
 * Two aggregations + a gustack() to surface the redis call chain:
 *
 *   @cmds[pid]    — per-pid command counts.  redis is single-
 *                   threaded by default; the postmaster pid
 *                   dominates.
 *
 *   @cmd_lat      — processCommand entry → return latency,
 *                   quantize.  Real PING traffic fills the
 *                   sub-microsecond bucket; under load with
 *                   richer commands you would see a long tail.
 *
 *   gustack()     — entry-time guest user stack.  Frame-pointer
 *                   build of redis-server walks cleanly into
 *                   processCommand and its caller chain
 *                   (call() → processInputBuffer →
 *                   readQueryFromClient → aeProcessEvents).
 *
 * Pair with: examples/redis-uprobe/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/redis-uprobe/probe.d
 */

#pragma D option quiet
#pragma D option aggsize=8m

dtrace:::BEGIN
{
    printf("redis processCommand uprobe trace - Ctrl-C to dump\n");
    printf("    @cmds:    per-pid command count.  redis is single-\n");
    printf("              threaded by default; one pid dominates.\n");
    printf("    @cmd_lat: processCommand entry->return latency,\n");
    printf("              quantize.  PING is sub-microsecond.\n");
    printf("    gustack:  redis call chain at processCommand entry\n");
    printf("              (frame pointers walk into call(),\n");
    printf("              processInputBuffer, etc.)\n\n");
}

uprobe:guest:redis-server:processCommand:entry
{
    @cmds[pid] = count();
    self->t0 = timestamp;
    gustack();
}

uprobe:guest:redis-server:processCommand:return
/self->t0/
{
    @cmd_lat = quantize(timestamp - self->t0);
    self->t0 = 0;
}
