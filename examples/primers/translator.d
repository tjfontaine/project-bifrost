#!/usr/bin/env bifrost
/*
 * translator.d — BTF-driven translator generalisation.
 *
 * Reads `task_struct.se.sum_exec_runtime` off the `prev` task
 * pointer on every `sched_switch` firing via the
 * BTF-resolved translator chain:
 *
 *   args[0]->prev->se.sum_exec_runtime
 *
 * The host CLI resolves the chain through the vmlinux BTF,
 * emits one CORE_OFFSETOF sentinel per hop, and lowers the
 * read to a single `bpf_probe_read_kernel(dst, 8, prev_task +
 * total_off)`.  The libkrun-side BTF patcher re-resolves the
 * sentinels against the running kernel so the read survives
 * cross-kernel field-offset drift.
 *
 * Records carry the resolved u64 nanosecond runtime in the
 * `arg0` slot of the rendered output:
 *
 *   guest_kernel:sched_switch:entry vmid=… probe_id=1 … value=0x…
 *
 * Phase-B contract: the records are produced (i.e. the BTF
 * chain compiled cleanly + loaded into the verifier + fired)
 * and the value field is non-zero (i.e. the read landed within
 * task_struct, not in unmapped memory).
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch
{
    trace(args[0]->prev->se.sum_exec_runtime);
}
