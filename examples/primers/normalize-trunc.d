#!/usr/bin/env bifrost
/*
 * normalize-trunc.d — W5d primer.
 *
 * Demonstrates `normalize(@agg, divisor)`, `denormalize(@agg)`,
 * and `trunc(@agg, N)` as render-time hints applied to
 * guest-side aggregations.
 *
 * The bifrost CLI walks every clause body at compile time and
 * registers the lib-action hints on the agg's name (see
 * `cli::xagg::collect_libact_hints`).  At dump time,
 * `dump_xagg_state_inner` divides each rendered value by the
 * registered divisor and caps the row count at the registered
 * trunc N.
 *
 * Uses `sched:sched_switch` so the histogram populates reliably
 * without an external workload.
 *
 *   sudo bifrost -p $SMOLVM_PID -s examples/primers/normalize-trunc.d
 *
 * Expected output:
 *   @switches (normalize=100) (trunc=5)
 *      <up to 5 rows, each value divided by 100>
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch
{
    @switches[arg2 & 0xff] = count();
}

END
{
    /* Render-time hints — both apply when the xagg dump runs.
     * The lib-actions are skipped on the BPF side; the bifrost
     * source rewriter registers them in xagg_state. */
    normalize(@switches, 100);
    trunc(@switches, 5);
}
