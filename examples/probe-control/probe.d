#!/usr/bin/env bifrost
/*
 * probe-fbt.d — fbt-attached counterpart to probe.d.
 *
 * Identical clause shape to probe.d, but the `do_sys_openat2:entry`
 * fire site attaches via the BPF trampoline (`fbt::`) rather than
 * a kprobe int3 (`bifrost::`).  Same target function, same per-fire
 * action — the only thing that changes is the attach mechanism.
 *
 * Pair with probe.d for a side-by-side per-fire-cost comparison
 * against the same workload (the `ls /etc` loop driven by
 * setup.sh).  Because the fire site, predicate, and action are all
 * identical, any throughput delta in the rendered aggregations
 * traces back to the kprobe-vs-fentry attach path and dispatch
 * stub overhead.
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/probe-control/probe-fbt.d
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("probe-control fbt variant - fentry attach via BPF trampoline\n");
    printf("    target:     do_sys_openat2 (same as probe.d)\n");
    printf("    attach:     fbt:: -> bpf_trampoline_link_prog\n\n");
}

fbt:guest:do_sys_openat2:entry
{
    @opens[execname] = count();
}

dtrace:::END
{
    printf("\nprobe-control fbt: trace ended\n");
    printa("    %-16s %@d\n", @opens);
}
