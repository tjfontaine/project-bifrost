#!/usr/bin/env bifrost
/*
 * stable-providers.d — proof that the DTrace stable-provider
 * catalog (`syscall:::`, `proc:::`, `sched:::`, `io:::`,
 * `tcp:::`, `signal:::`) maps to the underlying Linux raw
 * tracepoints transparently.
 *
 * `host/bifrost/src/cli/source_rewrite.rs` carries a static
 * (needle, replacement) catalog plus a dynamic per-syscall
 * rewrite, so D scripts written against the stable DTrace probe
 * names compile against the matching Linux tracepoint without
 * the user touching tracepoint names. If a future kernel renames
 * `block_rq_issue → block_rq_*`, we update one entry in the
 * catalog and every script keeps working.
 *
 *   sudo bifrost -p $PID -s examples/primers/stable-providers.d
 *
 * Compile path (visible via `--emit-ebpf`):
 *
 *   syscall::openat:entry   → tracepoint:guest:syscalls:sys_enter_openat
 *   syscall:::entry         → tracepoint:guest:raw_syscalls:sys_enter
 *   sched:::switch          → tracepoint:guest:sched:sched_switch
 *   io:::start              → tracepoint:guest:block:block_rq_issue
 *   proc:::exec             → tracepoint:guest:sched:sched_process_exec
 *
 * Run alongside a live guest workload to see records flow.
 */

#pragma D option quiet

syscall::openat:entry
{
    @opens[execname] = count();
}

sched:::switch
{
    @switches = count();
}

proc:::exec
{
    @execs[execname] = count();
}
