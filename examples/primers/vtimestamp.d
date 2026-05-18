#!/usr/bin/env bifrost
/*
 * vtimestamp.d — per-thread CPU-time clock.
 *
 * `vtimestamp` returns the total amount of time the current
 * thread has been running on a CPU, in nanoseconds, as tracked
 * by the kernel scheduler (`task_struct.se.sum_exec_runtime`).
 * Distinct from `timestamp` which advances at wall-clock rate
 * regardless of whether the thread was on-CPU.
 *
 * An earlier implementation aliased `ktime_get_ns()` —
 * same as `timestamp` — so deltas between consecutive reads
 * matched wall-clock and silently broke any script that
 * relied on the "thread CPU time" semantic.  Now the
 * delta tracks scheduler runtime, so the @vt sum advances at a
 * different rate than @ts (typically slower for non-CPU-bound
 * workloads).
 *
 * Uses `sched:sched_switch` so the aggs populate reliably
 * without an external workload.
 *
 *   sudo bifrost -p $SMOLVM_PID -s examples/primers/vtimestamp.d
 *
 * Expected rendered output (both aggs visible at end of run):
 *   @vt
 *               key        value
 *                 0  <vtimestamp sum>
 *   @ts
 *               key        value
 *                 0  <timestamp sum>
 *
 * The ratio `@vt / @ts` is typically well below 1 for
 * non-CPU-bound workloads — the rendered numbers will differ
 * meaningfully if the vtimestamp implementation is wired correctly.
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch
{
    @vt = sum(vtimestamp);
    @ts = sum(timestamp);
}
