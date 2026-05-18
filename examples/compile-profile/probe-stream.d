#!/usr/bin/env bifrost
/*
 * probe-stream.d — non-aggregating variant of probe.d.
 *
 * The default probe.d uses `count()` aggregations that buffer
 * guest-side and only emit on agg flush, so the per-fire stream
 * looks suspiciously sparse. This variant emits a printf record
 * for every do_sys_openat2 entry — useful for measuring real
 * throughput across the bifrost record pipeline (guest probe →
 * SHMEM → libkrun → bifrost_event_received → libdtrace).
 *
 * Pair with the same setup.sh — same workload, just a different
 * recording strategy. Compare line counts vs probe.d to see how
 * much of the rate goes into aggregation buffers.
 */

#pragma D option quiet

fbt:guest:do_sys_openat2:entry
{
    printf("openat execname=%s pid=%d\n", execname, pid);
}
