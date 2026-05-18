#!/usr/bin/env bifrost
/*
 * speculate.d — speculation primer.
 *
 * Demonstrates speculative tracing: every fire on
 * `do_sys_openat2:entry` opens a speculation lane on the
 * current CPU and stages a record into a per-CPU side buffer.
 * On `do_sys_openat2:return` the script inspects `retval` —
 * negative (an error) commits the lane (records replay into
 * the principal sub-ring); zero/positive discards (records
 * dropped).
 *
 * Result: the user sees a record stream containing only the
 * failing opens, even though every open emitted a record at
 * entry time.  Without speculation the script would have to
 * predicate on `retval` at exit time, requiring the same
 * `arg0` to be reconstructed from a thread-local across the
 * entry/return pair.
 *
 *   sudo bifrost -p $SMOLVM_PID -s examples/primers/speculate.d
 *
 * Implementation: `bifrost_kfunc_speculation` allocates a
 * per-CPU lane id (1); `bifrost_kfunc_speculate(1)` flips the
 * per-CPU active flag so subsequent
 * `bifrost_shmem_reserve_kernel_class` calls route into the
 * side buffer; `bifrost_kfunc_commit(1)` replays the buffer;
 * `bifrost_kfunc_discard(1)` zeroes it.
 *
 * Per-CPU side buffer is sized for 16 records × 1 KB each
 * (`BIFROST_SPEC_RECORDS_PER_CPU` × `BIFROST_SPEC_RECORD_MAX`).
 */

#pragma D option quiet

fbt:guest:do_sys_openat2:entry
{
    self->spec_id = speculation();
    speculate(self->spec_id);
    trace(arg0);
}

fbt:guest:do_sys_openat2:return
/self->spec_id != 0 && retval < 0/
{
    commit(self->spec_id);
    self->spec_id = 0;
}

fbt:guest:do_sys_openat2:return
/self->spec_id != 0/
{
    discard(self->spec_id);
    self->spec_id = 0;
}
