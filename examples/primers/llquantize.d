#!/usr/bin/env bifrost
/*
 * llquantize.d — W5c primer.
 *
 * `llquantize(value, factor, low_mag, high_mag, steps_per_mag)`
 * builds a log-linear-bucket histogram.  Standard
 * "latency in nanoseconds" shape:
 *   factor=10, low_mag=0, high_mag=6, steps_per_mag=10
 *   → 1, 2, 3, ..., 9, 10, 20, ..., 1k, ..., 1M
 *
 * This primer buckets the low 16 bits of the next-task PID at
 * every context switch.  Uses `sched:sched_switch` so the
 * histogram populates reliably without external workload.
 *
 *   sudo bifrost -p $SMOLVM_PID -s examples/primers/llquantize.d
 *
 * Expected rendered output:
 *   @pid (llquantize)
 *                 value ------------- Distribution -------------    count
 *                   1 |@@@                                            ...
 *                   2 |@@@@                                           ...
 *                  (etc.)
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch
{
    @pid = llquantize((arg2 & 0xffff), 10, 0, 6, 10);
}
