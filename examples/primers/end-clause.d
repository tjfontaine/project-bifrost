#!/usr/bin/env bifrost
/*
 * end-clause.d — proof that dtrace:::BEGIN and dtrace:::END clauses
 * run on the host-side libdtrace consumer and can fire alongside
 * guest-side bifrost: probes.
 *
 * BEGIN/END are identifier-only DTrace probes (no provider:module:
 * function:name tuple). Bifrost's parser keeps them in the host_d
 * stream so libdtrace fires BEGIN once at attach time and END once
 * at consumer-exit time (Ctrl-C, SIGTERM, or --duration-seconds
 * elapse). The clauses can use host-side dtrace built-ins
 * (`printf`, `printa`) and reference any aggregations the
 * libdtrace consumer accumulates from native macOS clauses on the
 * same script.
 *
 * Cross-domain aggregations (`@by_tool[execname]`) defined inside
 * `bifrost:`-targeted clauses live in guest-side BPF maps; their
 * snapshot dump happens through the xagg path on consumer
 * shutdown, NOT inside the END clause. The END clause here just
 * prints a sentinel line so you can confirm the dispatch fired.
 *
 *   sudo bifrost -p $PID -s examples/primers/end-clause.d
 *
 * Expected output on a fresh attach + Ctrl-C:
 *
 *   [primer] BEGIN fired
 *   <guest-side records as cc1 / openat workload runs>
 *   [primer] END fired
 *   <xagg dump for @opens>
 *
 * The two `[primer] …` lines bracket the run, proving the
 * BEGIN/END dispatch fires exactly once each through libdtrace.
 */

#pragma D option quiet

BEGIN
{
    printf("[primer] BEGIN fired\n");
}

fbt:guest:do_sys_openat2:entry
{
    @opens[execname] = count();
}

END
{
    printf("[primer] END fired\n");
}
