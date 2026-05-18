#!/usr/bin/env bifrost
/*
 * probe.d — multi-tracepoint scheduler activity profile.
 *
 * Demonstrates two raw-tracepoint clauses in a single script
 * plus tracepoint-context arg access (arg0 from sched_switch's
 * `bool preempt` parameter).  Each clause produces its own
 * aggregation against the canonical scheduler events:
 *
 *   sched_switch  — fires on every context switch.  Args:
 *     arg0 = bool preempt           (true = preemption, false = voluntary)
 *     arg1 = struct task_struct *prev   (pointer; deref needs typed-arg
 *                                        lowering — see Limitations)
 *     arg2 = struct task_struct *next   (pointer; same)
 *     arg3 = unsigned int prev_state    (TASK_RUNNING=0, TASK_INTERRUPTIBLE=1,
 *                                        TASK_UNINTERRUPTIBLE=2, ...)
 *
 *   sched_wakeup  — fires whenever a task is being made runnable.
 *     arg0 = struct task_struct *p   (pointer)
 *
 * `pid` builtin in each clause gives the CURRENT task at fire
 * time — for sched_switch that's the prev task (about to lose
 * the CPU), for sched_wakeup that's the waker.
 *
 * Aggregations:
 *
 *   @preempted[pid]   tasks that lost the CPU to preemption
 *                     (sched_switch with preempt=true).
 *   @blocked[pid]     tasks that voluntarily gave up the CPU
 *                     (sched_switch with preempt=false — they
 *                     went to sleep, called blocking syscall, etc).
 *   @wakers[pid]      tasks that woke other tasks
 *                     (sched_wakeup, current-task = waker).
 *
 * Together these surface the workload's scheduler personality:
 * who gets preempted vs who blocks vs who's the busy waker.
 *
 * Pair with: examples/sched-multi/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/sched-multi/probe.d
 */

/*
 * Limitations (followups, not blockers):
 *   - arg1/arg2 in sched_switch are task_struct pointers.  The
 *     canonical "wakeup-to-switch latency" pattern wants
 *     `args[1]->pid` / `args[2]->pid` — typed-arg deref against
 *     vmlinux BTF — which the lowering doesn't yet support for
 *     tracepoint context.  Adding that is the unblock for the
 *     full sched-runqlat shape.
 *   - prev_state is in arg3; predicate `arg3 != 0` would
 *     differentiate TASK_RUNNING (preempt-bumped, still runnable)
 *     from blocked.  Today's `arg0` (preempt) split is a
 *     reasonable approximation — preempt=true correlates with
 *     prev_state=0 in practice.
 */

#pragma D option quiet
#pragma D option aggsize=8m

dtrace:::BEGIN
{
    printf("multi-tracepoint scheduler trace - Ctrl-C to dump\n");
    printf("    @preempted: per-pid preempt-driven switch-out count.\n");
    printf("    @blocked:   per-pid voluntary switch-out count.\n");
    printf("    @wakers:    per-pid task-waking count.\n\n");
}

tracepoint:guest:sched:sched_switch
/arg0/
{
    @preempted[pid] = count();
}

tracepoint:guest:sched:sched_switch
/!arg0/
{
    @blocked[pid] = count();
}

tracepoint:guest:sched:sched_wakeup
{
    @wakers[pid] = count();
}
