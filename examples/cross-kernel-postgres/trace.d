/*
 * Cross-kernel Postgres demo.
 *
 * Different probe surface from cross-kernel-tcp:
 *   - Linux side: USDT probes from postgres's `.note.stapsdt` —
 *     postgres:::query__start surfaces every query through the
 *     bifrost USDT path (Linux-eBPF backend).
 *   - FreeBSD side: a kernel-side fbt probe on VOP_OPEN — every
 *     vnode open including postgres's storage manager opening
 *     relation files.  Native FreeBSD DTrace backend.
 *
 * One pgbench run, one merged record stream.
 *
 * Clock alignment.  `BEGIN { self->t0 = timestamp; }` anchors the
 * quantize() histograms to a per-target delta, since each kernel's
 * `timestamp` builtin is its own monotonic clock origin.
 */

BEGIN
{
    self->t0 = timestamp;
}

usdt:guest:postgres:postgresql:query__start
{
    @starts["linux"] = count();
    @arrival["linux"] = quantize(timestamp - self->t0);
}

fbt:kernel:VOP_OPEN:entry
{
    @opens["freebsd"] = count();
    @arrival["freebsd"] = quantize(timestamp - self->t0);
}

END
{
    printa("linux  query__start %@d\n", @starts);
    printa("freebsd VOP_OPEN     %@d\n", @opens);
    printa("%-10s %@d\n", @arrival);
}
