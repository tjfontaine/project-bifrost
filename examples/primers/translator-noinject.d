#!/usr/bin/env bifrost
/*
 * translator-noinject.d — false-positive regression net.
 *
 * An earlier translator implementation ran the typed-translator
 * rewrite as a `String::replace` on the *whole* D source *before*
 * `parse::parse` split clauses, which meant string-literal mentions
 * of the canonical needle got clobbered too:
 * `printf("args[0]->prev->comm")` in any clause (host BEGIN/END,
 * host syscall clause, guest probe) became `printf("arg0")`.  That's
 * a silent corruption — there was no compile error or runtime warning.
 *
 * The current translator moves the expansion past `parse::parse` and
 * only touches `bifrost:` clauses, with a body walker that respects
 * string literals.  This primer pins both invariants:
 *
 *   1. A `BEGIN` clause (routes to native libdtrace) whose
 *      printf carries the canonical needle as a literal — the
 *      old rewrite would have clobbered it; the current translator
 *      must leave it intact.
 *
 *   2. A `tracepoint:` clause (routes to bifrost eBPF) that
 *      keeps counting so the run actually produces records and
 *      the BEGIN printf line lands in the same output stream.
 *
 * Old behavior: rendered output starts with "arg0".
 * Current behavior: rendered output starts with the literal
 * "args[0]->prev->comm" line.
 *
 * Uses `sched:sched_switch` so the counter fires reliably
 * without an external workload.
 */

#pragma D option quiet

BEGIN
{
    printf("args[0]->prev->comm\n");
}

tracepoint:guest:sched:sched_switch
{
    @switches = count();
}
