#!/usr/bin/env bifrost
/*
 * stddev.d — population standard-deviation aggregation.
 *
 * `@lat = stddev(timestamp - self->t0)` lowers to a per-CPU
 * 24-byte slot `[n:u64, sum:u64, sum_of_squares:u64]`. The BPF
 * program increments n, adds the value to sum, and adds value*value
 * to sum_of_squares on every fire. The host snapshot pump reduces
 * across CPUs via `bifrost_map_lookup_stddev_u64` and ships the
 * triple in a per-row variable-width agg-snapshot entry. The CLI's
 * xagg renderer computes
 *
 *     stddev = sqrt((sum_sq * n - sum*sum) / (n * (n-1)))
 *
 * at render time.
 *
 *   sudo bifrost -p $PID -s examples/primers/stddev.d
 *
 * On a steady cc1 workload the @open_lat row should report a
 * non-zero stddev measuring the spread of open() latencies
 * around the mean.
 */

#pragma D option quiet

fbt:guest:do_sys_openat2:entry
/execname == "cc1"/
{
    self->t0 = timestamp;
}

fbt:guest:do_sys_openat2:return
/self->t0/
{
    @open_lat = stddev(timestamp - self->t0);
    self->t0 = 0;
}
