#!/usr/bin/env bifrost
/*
 * lquantize.d — W5b primer.
 *
 * `lquantize(value, base, upper, step)` builds a linear-bucket
 * histogram with `(upper - base) / step` in-range buckets plus
 * one underflow and one overflow bucket.  This primer buckets
 * the low byte of the next-task PID at every context switch
 * into [0, 1000) step 100.
 *
 * Uses `sched:sched_switch` rather than a syscall path so the
 * histogram populates reliably without an external workload —
 * `arg2` of the tracepoint is the next-task pid.
 *
 *   sudo bifrost -p $SMOLVM_PID -s examples/primers/lquantize.d
 *
 * Expected rendered output:
 *   @pid (lquantize)
 *                 value ------------- Distribution -------------    count
 *                  < 0  |                                                0
 *                    0  |@@@@@@@@@@@@                                  100
 *                  100  |@@@@                                           30
 *                  ...
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch
{
    @pid = lquantize((arg2 & 0xff), 0, 1000, 100);
}
