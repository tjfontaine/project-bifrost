#!/usr/bin/env bifrost
/*
 * probe.d — guest scheduler activity, attached at the
 *           `sched_switch` tracepoint.
 *
 * `sched_switch` fires on every voluntary or preemption-driven
 * context switch — the canonical scheduler-observability shape
 * (also what DTrace's `sched:::on-cpu` / `off-cpu` providers
 * surface on Solaris, what bpftrace ships in `runqlat.bt`).
 *
 * This shape replaces the prior `fbt:guest:try_to_wake_up:entry`
 * stand-in, which only saw wakeups (not preemption-driven
 * switches).  Tracepoints sit on dedicated kernel hook points —
 * no ftrace-nop dependency — so they reach `__schedule`-class
 * functions that are deliberately marked `notrace` to prevent
 * ftrace recursion in scheduler hot paths.
 *
 * One aggregation:
 *
 *   @switches[pid]
 *     Per-pid context-switch count.  Under steady stress-ng load
 *     this surfaces the workload tasks (workers, kthreads), with
 *     pid 0 (per-CPU swapper / idle task) typically dominating
 *     the long tail when CPUs go idle between bursts.
 *
 * Pair with: examples/scheduler-offcpu/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/scheduler-offcpu/probe.d
 */

#pragma D option quiet
#pragma D option aggsize=8m

dtrace:::BEGIN
{
    printf("scheduler activity trace - Ctrl-C to dump aggregation\n");
    printf("    @switches: per-pid context-switch count from\n");
    printf("               sched:sched_switch tracepoint.\n");
    printf("               pid 0 = per-CPU swapper, then your\n");
    printf("               workload tasks.\n\n");
}

tracepoint:guest:sched:sched_switch
{
    @switches[pid] = count();
}
