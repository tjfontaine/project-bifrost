# sched-multi

Multi-tracepoint scheduler activity profile.  Demonstrates two
raw-tracepoint clauses in a single script (`sched_switch` +
`sched_wakeup`) plus tracepoint-context arg access (`arg0` from
`sched_switch` to split preemption-driven vs voluntary switches).

This is the natural follow-on to `scheduler-offcpu` (which uses
just `sched_switch` for a flat per-pid switch count): same
workload, richer breakdown, exercises a wider slice of the
tracepoint provider surface.

## What it shows

Three aggregations from two tracepoints:

| agg | tracepoint | predicate | meaning |
|---|---|---|---|
| `@preempted[pid]` | `sched_switch` | `arg0` (preempt=true) | task lost CPU to preemption |
| `@blocked[pid]`   | `sched_switch` | `!arg0` (preempt=false) | task voluntarily gave up CPU |
| `@wakers[pid]`    | `sched_wakeup` | (none) | task was the *waker* of another task |

`pid` builtin in each clause = the **current task** at fire time:

- For `sched_switch` that's the task being switched OUT (prev).
- For `sched_wakeup` that's the **waker**, not the task being
  woken — `arg0` would be the wakee's `task_struct *` if
  typed-arg deref were available.

Under the default `stress-ng --cpu 2 --io 2 --fork 1` workload:

- `@preempted` is dominated by the long-lived stress-ng workers
  getting timer-tick preempted off the CPU.
- `@blocked` is dominated by IO workers and short-lived
  fork-children that exit / wait.
- `@wakers` includes kthreads (kworker, ksoftirqd) and stress-ng
  workers waking each other.

## Run

Two shells.

```sh
# shell 1 — boots smolvm + stress-ng workload
examples/sched-multi/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself
sudo bifrost -p $PID -s examples/sched-multi/probe.d
```

## Files

- [`setup.sh`](setup.sh) — boots smolvm + stress-ng (CPU + IO + fork mix)
- [`probe.d`](probe.d) — three aggs from two tracepoints

## Limitations / future work

The canonical "wakeup-to-switch latency" pattern wants to
correlate `sched_wakeup`'s wakee task with `sched_switch`'s next
task — both passed as `task_struct *` pointers (`arg0` in
sched_wakeup, `arg2` in sched_switch).  That requires
**typed-arg dereferencing** in the lowering: read `task_struct->pid`
from a kernel pointer arg using BTF-resolved offsets +
`bpf_probe_read_kernel`.  Today the lowering reads `argN` as a
flat u64 — fine for scalar args (preempt flag, prev_state) but
not for pointer derefs.

When that lowering lands, this demo extends to the canonical
shape:

```d
tracepoint:guest:sched:sched_wakeup {
    sleep_t[args[0]->pid] = timestamp;
}
tracepoint:guest:sched:sched_switch /sleep_t[args[2]->pid]/ {
    @lat[args[2]->comm] = quantize(timestamp - sleep_t[args[2]->pid]);
    sleep_t[args[2]->pid] = 0;
}
```
