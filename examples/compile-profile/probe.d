#!/usr/bin/env bifrost
/*
 * probe-fbt.d — fbt-attached counterpart to probe.d.
 *
 * Identical clause shape — same target (`do_sys_openat2`), same
 * predicates, same actions.  Provider swaps from `bifrost::`
 * (kprobe) to `fbt::` (FENTRY for :entry, FEXIT for :return).
 *
 * The :return clause uses only `timestamp` and thread-local
 * `self->t0` — no return-value access — so existing DIF lowering
 * covers it on FEXIT.
 *
 * Pair with: examples/compile-profile/run.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/compile-profile/probe-fbt.d
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("compile profile via fbt - Ctrl-C to dump aggregations\n");
    printf("    @by_tool:  file-open counts per toolchain subprocess\n");
    printf("    @by_pid:   per-(execname, pid) breakdown\n");
    printf("    @open_lat: cc1 open latency quantize\n");
    printf("    gustack:   guest user stack at each cc1 open\n\n");
}

fbt:guest:do_sys_openat2:entry
{
    @by_tool[execname] = count();
    @by_pid[execname, pid] = count();
}

fbt:guest:do_sys_openat2:entry
/execname == "cc1"/
{
    self->t0 = timestamp;
    gustack();
}

fbt:guest:do_sys_openat2:return
/self->t0/
{
    @open_lat = quantize(timestamp - self->t0);
    self->t0 = 0;
}
