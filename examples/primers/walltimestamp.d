#!/usr/bin/env bifrost
/*
 * walltimestamp.d — wall-clock-since-epoch timestamps.
 *
 * `walltimestamp` returns CLOCK_REALTIME nanoseconds since the
 * Unix epoch — the same clock `date +%s%N` reads. An earlier
 * implementation aliased `bpf_ktime_get_boot_ns` (monotonic since
 * boot), so scripts comparing against absolute wall time silently
 * saw bogus values. It is now wired to a dedicated kfunc
 * (`bifrost_kfunc_walltime_ns`) that calls `ktime_get_real_ns()`.
 *
 *   sudo bifrost -p $PID -s examples/primers/walltimestamp.d
 *
 * The printed wall-clock seconds should match `date +%s` within
 * a second. If you see values starting at ~tens-of-thousands
 * instead of seconds-since-1970, the wall-clock lowering did not land
 * (still aliasing boot ns).
 */

#pragma D option quiet

profile:::profile-1
{
    /* Divide by 1e9 to convert ns → s for easy compare. */
    printf("walltimestamp_sec=%d\n", walltimestamp / 1000000000);
    exit(0);
}
