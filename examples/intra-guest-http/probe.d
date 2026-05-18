#!/usr/bin/env bifrost
/*
 * probe-fbt.d — fbt-attached counterpart to probe.d.
 *
 * Identical clause shape — same target (`tcp_v4_do_rcv`), same
 * predicate, same actions.  The only thing that changes is the
 * provider: `fbt::` attaches via the BPF trampoline (FENTRY for
 * :entry, FEXIT for :return) instead of via kprobe.
 *
 * Both `:return` clauses across our demos use only `timestamp`
 * (kernel-helper builtin) and thread-local `self->t0` set by the
 * matching :entry — they don't read the function's return value
 * — so the existing DIF lowering works unchanged on FEXIT.
 *
 * Pair with: examples/intra-guest-http/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/intra-guest-http/probe-fbt.d
 */

#pragma D option quiet
#pragma D option aggsize=8m

dtrace:::BEGIN
{
    printf("intra-guest HTTP trace via fbt - Ctrl-C to dump\n");
    printf("    @reqs:    per-pid tcp_v4_do_rcv segment count.\n");
    printf("    @rcv_lat: per-segment guest TCP processing latency,\n");
    printf("              quantize.  Tight fast-path peak vs long tail.\n");
    printf("    gustack:  guest user stack at each fire.\n\n");
}

fbt:guest:tcp_v4_do_rcv:entry
{
    @reqs[pid] = count();
    self->t0 = timestamp;
    gustack();
}

fbt:guest:tcp_v4_do_rcv:return
/self->t0/
{
    @rcv_lat = quantize(timestamp - self->t0);
    self->t0 = 0;
}
