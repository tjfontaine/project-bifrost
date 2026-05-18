#!/usr/bin/env bifrost
/*
 * quantize.d — power-of-two latency histogram
 *
 * Captures entry timestamp in a thread-local (`self->t0`), reads it
 * back at return time, and feeds the delta into `quantize()` which
 * lowers to a BPF ARRAY map of bucketed counters. The histogram is
 * rendered in libdtrace's standard ASCII art form on consumer exit.
 *
 * The thread-local lowering is a HASH map keyed on
 * `(pid_tgid << 32) | var_id`, with `bifrost_kfunc_*` helpers
 * providing kernel-side allocation and lookup.
 *
 * Run:
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/quantize.d
 *   sudo examples/primers/quantize.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 */

#pragma D option quiet

bifrost::do_sys_openat2:entry
{
    self->t0 = timestamp;
}

bifrost::do_sys_openat2:return
/self->t0/
{
    @lat = quantize(timestamp - self->t0);
    self->t0 = 0;
}
