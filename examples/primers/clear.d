/*
 * clear.d — aggregation primer.
 *
 * Demonstrates `clear(@agg)` zeroing the per-CPU slots of an
 * aggregation map.  The clause fires on every context switch
 * (a continuously-firing probe), bumps a counter keyed by
 * next-task pid byte, then clears the entire map.  With the
 * clear in place, the rendered xagg output stays near zero —
 * never accumulating because each fire wipes the prior count.
 *
 * Run:
 *   sudo bifrost -s examples/primers/clear.d -p $SMOLVM_PID
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch
{
    @switches[arg2 & 0xff] = count();
    clear(@switches);
}
