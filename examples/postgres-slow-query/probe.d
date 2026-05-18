#!/usr/bin/env bifrost
/*
 * probe.d - postgres-workload I/O profile.
 *
 * Captures every file open issued during the postgres-driven
 * pgbench load; surfaces who's opening files, latency distribution,
 * and the postgres function chain at each open.
 *
 * The `execname == "postgres"` predicate that earlier versions
 * carried turned out to be too narrow under steady-state pgbench
 * load — postgres backends mostly hit shared-buffer cache and
 * rarely reopen files in the read-only TPC-B mix, so the
 * filtered aggregation ended up empty in normal trace windows.
 * This shape drops the predicate and surfaces every openat fired
 * by the workload mix (postgres, pgbench, postmaster, plus the
 * background system processes); postgres backends appear among
 * them, and the (execname, pid) breakdown lets the user
 * post-filter visually.
 *
 * Pair with: examples/postgres-slow-query/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/postgres-slow-query/probe.d
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("postgres I/O trace via fbt - Ctrl-C to dump\n");
    printf("    @by_exec:  per-execname openat count (postgres + pgbench + system)\n");
    printf("    @by_pid:   per-(execname, pid) breakdown — pin specific backends\n");
    printf("    @open_lat: bucketed open latency, quantize\n");
    printf("    gustack:   user stack at each open (postgres frames symbolicate)\n\n");
}

fbt:guest:do_sys_openat2:entry
{
    self->t0 = timestamp;
    @by_exec[execname] = count();
    @by_pid[execname, pid] = count();
}

fbt:guest:do_sys_openat2:return
/self->t0/
{
    @open_lat = quantize(timestamp - self->t0);
    self->t0 = 0;
}

fbt:guest:do_sys_openat2:entry
/execname == "postgres" || execname == "pgbench"/
{
    gustack();
}
