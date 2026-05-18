# scheduler-offcpu

Guest scheduler activity surfaced through a kprobe on
`__schedule` — the scheduler's entry point that every voluntary
or preemption-driven context switch funnels through.

The four other demos all attach to syscall- or device-layer
kprobes (`do_sys_openat2`, `tcp_v4_do_rcv`) or userspace uprobes
(`processCommand`). This one attaches deeper — to the scheduler
core path itself — and surfaces a different shape of data: per-
pid context-switch counts under a real workload mix.

> **Why `__schedule` and not `finish_task_switch`.** The compiler
> interprocedurally specializes `finish_task_switch` into
> `finish_task_switch.isra.0` (a local symbol with a synthetic
> `.isra.0` suffix), so `kprobe-by-name` against the unsuffixed
> name finds nothing and the probe never fires.  `__schedule` is
> stable across kernel builds and fires once per scheduler
> invocation.

The demo splits into two halves:

- [`setup.sh`](setup.sh) boots `ubuntu:24.04` in smolvm,
  apt-installs `stress-ng`, and runs it as the entrypoint with a
  mix of CPU + IO + fork workers. Default settings produce
  ~5-10 K context switches per second in the guest.
- You run bifrost yourself in another shell, dtrace-style.

## What it shows

One aggregation:

- **`@switches[pid]` per-pid context-switch count.** Surfaces
  the workload's task mix.  `pid 0` (the per-CPU swapper) shows
  idle accounting; the stress-ng workers show as a small handful
  of long-lived pids; the fork-stress generates a long tail of
  short-lived forked children with one or two switches each.

> **Why pid keys, not execname.**  Two BPF-side gaps surfaced
> running this demo, deliberately worked around to keep the
> shape simple and shipping:
>
> 1. `bpf_get_current_comm()` from inside a `__schedule` kprobe
>    doesn't aggregate cleanly (works fine on syscall-entry
>    kprobes — see `compile-profile`'s `@by_tool[execname]`).
>    Likely a recursion / scheduler-hot-path restriction.
>
> 2. Multi-action entry clauses (count + thread-local
>    timestamp store) lose most BPF-prog firings on
>    `__schedule` under stress: `@switches[pid] = count()`
>    standalone aggregates ~thousands per second; adding
>    `self->t0 = timestamp` drops the count rate ~150×.  This
>    blocked the originally-planned matching `:return /self->t0/`
>    `@sw_lat = quantize(...)` clause for entry→return latency.
>
> Both are tracked as the next demo-driven steps.

## Run

Two shells.

```sh
# shell 1 — boots smolvm + runs stress-ng until ^C
examples/scheduler-offcpu/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself.
sudo bifrost -p $PID -s examples/scheduler-offcpu/probe.d
```

Three equivalent forms — pick whichever you prefer:

```sh
# 1. -s flag, like dtrace
sudo bifrost -p $PID -s examples/scheduler-offcpu/probe.d

# 2. inline D expression with -n
sudo bifrost -p $PID \
    -n 'bifrost::__schedule:entry { @[pid] = count(); }'

# 3. self-executing script
sudo examples/scheduler-offcpu/probe.d -p $PID
```

Override knobs on `setup.sh`:

```sh
STRESS_CPU=4 STRESS_FORK=2 examples/scheduler-offcpu/setup.sh
```

## Files

- [`setup.sh`](setup.sh) — boots smolvm + stress-ng workload mix
- [`probe.d`](probe.d) — `fbt::try_to_wake_up:entry` + per-pid
  agg.  Note: this demo's natural target would be `__schedule`
  (every context switch), but `__schedule` is `notrace` and so
  not fbt-attachable.  `try_to_wake_up` is the closest
  fbt-reachable substitute — the metric shifts from per-pid
  context-switch count to per-pid wakeup count, related but
  distinct.  Tracepoints (`sched:::switch`) will eventually
  give the canonical context-switch-count shape; that remains
  the unblocking work.

## What's not here yet (next demo-driven step)

A fuller dtrace-style off-cpu profile would key by tid (not
pid) and compute per-task off-cpu duration:

```d
/* off-cpu: timestamp on the task that just left the CPU */
bifrost::__schedule:entry {
    off_t[arg0->pid] = timestamp;       /* needs BTF struct field access */
}

/* on-cpu: delta from stored timestamp for the task taking the CPU */
bifrost::__schedule:return {
    @offcpu[pid] = sum(timestamp - off_t[curtid]);
    off_t[curtid] = 0;
}
```

This needs:
- **Multi-action entry clauses on __schedule.**  Adding the
  thread-local store currently drops the count rate ~150× (see
  the inline note above).  Same shape works on syscall kprobes;
  the bug is specific to the scheduler hot path.
- **BTF struct field access** on `task_struct->pid`, which
  bifrost doesn't yet expose to D scripts.  Once both land,
  this demo can extend to the canonical "who's spending the
  most time blocked" view that bpftrace's `offcputime.bt`
  ships.

Other natural extensions documented for later:
- Wakeup-latency (`try_to_wake_up:entry → __schedule:return`)
- Per-runqueue-CPU off-cpu breakdowns
- Stack-keyed off-cpu (gustack at off-cpu time, accumulate per
  unique stack — bpftrace's classic flame-graph input)

## Captured output

A real ~25 s run against ubuntu:24.04 + apt-installed stress-ng
(`STRESS_CPU=2 STRESS_IO=2 STRESS_FORK=1`):

```
[bifrost] prog #0: 46 insns, target='__schedule:entry', schema=5 fields (32-byte records), 1 map(s)
```

`@switches[pid]` table at exit — heavy hitters first, then a
long tail of short-lived stress-ng-fork children:

```
  @switches
                             key        value
                               0         6005   ← swapper (per-CPU idle)
                             228         3473   ← stress-ng worker
                             227         3267   ← stress-ng worker
                              30         2601   ← kworker
                             229         2219   ← stress-ng worker
                              19           73   ← kthread
                              16           16
                             225           13
                             226            9
                           18389            2   ← short-lived fork child
                           18398            2
                           18385            2
                           18374            1
                           18358            1
                           ... [~80 short-lived pids @ 1-2 switches each] ...
```

The shape matches what `dtrace -n 'sched:::on-cpu'` would surface
on Solaris: a small handful of long-lived workload pids
dominating, fork-stress generating an isra-style long tail of
ephemeral children.
