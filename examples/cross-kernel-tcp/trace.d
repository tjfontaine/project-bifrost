/*
 * Cross-kernel TCP killer demo.
 *
 * Probes a kernel-agnostic event — a TCP segment arrives on a VM's
 * loopback nginx listener — through each kernel's native provider.
 * The planner uses TraceTarget::route_probe to send the
 * tracepoint clause to the Linux target and the fbt clause to the
 * FreeBSD target, and the merged renderer interleaves both streams
 * on host wall-clock with a configurable lookback.
 *
 * The cross-target `@rx` aggregation keyed by `target` produces one
 * row per kernel; the side-by-side `quantize()` histograms in the
 * END clause are the one-screen visual nothing else in the DTrace
 * ecosystem produces today.
 *
 * Clock alignment.  Each guest's `timestamp` DIF builtin reads its
 * own kernel monotonic clock — VM A's `timestamp` and VM B's are
 * not directly comparable (each kernel chose its own boot moment
 * as origin).  We stash `self->t0 = timestamp` in BEGIN so the
 * quantize() histograms run over a per-target delta rather than an
 * absolute kernel time; cross-target wall-clock ordering of the
 * per-record stream is handled by the host orchestrator's merge
 * key independently.
 */

BEGIN
{
    self->t0 = timestamp;
}

tracepoint:guest:net:netif_receive_skb
{
    @rx["linux"] = count();
    @arrival["linux"] = quantize(timestamp - self->t0);
}

fbt:kernel:tcp_input:entry
{
    @rx["freebsd"] = count();
    @arrival["freebsd"] = quantize(timestamp - self->t0);
}

profile:::tick-1sec
{
    printf("linux rx=%@d  freebsd rx=%@d\n", @rx["linux"], @rx["freebsd"]);
}

END
{
    printa("%-10s %@d\n", @rx);
    printa("%-10s %@d\n", @arrival);
}
