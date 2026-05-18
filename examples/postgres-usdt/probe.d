#!/usr/bin/env bifrost
/*
 * probe.d — postgres USDT trace via .note.stapsdt
 *
 * The first end-to-end demo of the bifrost USDT provider.  Earlier
 * postgres demos hooked `do_sys_openat2` (kernel syscall fbt),
 * which under steady-state pgbench load mostly fires on shared-
 * buffer cache misses — interesting once but bursty and noisy.
 *
 * USDT puts probes at the level postgres reasoning happens:
 *
 *   postgresql:query__start    — every SQL statement entering exec
 *   postgresql:query__done     — every SQL statement returning
 *   postgresql:transaction__commit / __abort
 *
 * The Debian-built postgres:16 image (PGDG packages) is compiled
 * with `--enable-dtrace`, so the binary ships 56 unique probe sites
 * under provider `postgresql`.  The bifrost host CLI ferries
 * (basename, provider, probe) in the BFR7 LOAD_PROG trailer; the
 * guest driver walks `.note.stapsdt` from task->exe_file, finds the
 * matching note, and registers a uprobe at the recorded pc with
 * ref_ctr_offset = semaphore so the SDT probe body actually fires
 * (postgres uses semaphore-gated probes — without ref_ctr the body
 * short-circuits and the NOP never executes).
 *
 * Pair with: examples/postgres-usdt/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/postgres-usdt/probe.d
 */

#pragma D option quiet
#pragma D option aggsize=8m

dtrace:::BEGIN
{
    printf("postgres USDT trace - Ctrl-C to dump\n");
    printf("    @queries:    per-pid query__start count.  postgres forks one\n");
    printf("                 backend per pgbench client; each backend pid\n");
    printf("                 surfaces here.\n");
    printf("    @qlat:       query__start -> query__done latency, quantize.\n");
    printf("                 Captures full SQL execution including planner +\n");
    printf("                 executor + result emit.\n");
    printf("    @txn:        transaction__commit / __abort counts.  Ratio\n");
    printf("                 surfaces transaction failure rate under load.\n\n");
}

usdt:guest:postgres:postgresql:query__start
{
    @queries[pid] = count();
    self->q0 = timestamp;
}

usdt:guest:postgres:postgresql:query__done
/self->q0/
{
    @qlat = quantize(timestamp - self->q0);
    self->q0 = 0;
}

usdt:guest:postgres:postgresql:transaction__commit
{
    @txn["commit"] = count();
}

usdt:guest:postgres:postgresql:transaction__abort
{
    @txn["abort"] = count();
}
