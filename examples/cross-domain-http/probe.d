#!/usr/bin/env bifrost
/*
 * cross-domain-http probe.
 *
 * The workload runs nginx and ab inside one guest netns so the
 * guest TCP receive path is observable. Host-side ab over TSI is
 * intentionally not used here: host ab is outside the attached
 * libdtrace target pid, and TSI does not traverse tcp_v4_do_rcv.
 *
 * The :return clause uses only `timestamp` and thread-local
 * `self->t0` — no return-value access — so existing DIF lowering
 * covers it on FEXIT.
 *
 * Pair with: examples/cross-domain-http/run.sh
 *
 * Run manually:
 *   sudo bifrost -p $PID -s examples/cross-domain-http/probe.d
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("cross-domain HTTP trace - Ctrl-C to dump\n");
    printf("    @reqs:    per-pid guest tcp_v4_do_rcv segment count\n");
    printf("    @rcv_lat: per-segment guest TCP processing time, quantize\n");
    printf("    xstack:   sampled host+guest call chains at 997 Hz\n\n");
}

fbt:guest:tcp_v4_do_rcv:entry
{
    @reqs[pid] = count();
    self->t0 = timestamp;
}

fbt:guest:tcp_v4_do_rcv:return
/self->t0/
{
    @rcv_lat = quantize(timestamp - self->t0);
    self->t0 = 0;
}

fbt:guest:tcp_v4_do_rcv:entry
{
    xstack(SAMPLE, 32);
}
