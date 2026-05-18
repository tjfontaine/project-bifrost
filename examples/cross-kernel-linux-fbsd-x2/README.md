# cross-kernel-linux-fbsd-x2 — the north-star demo

One `bifrost orchestrate` invocation, one D source, **two kernels**.
A Linux smolvm and a FreeBSD QEMU guest boot in parallel; both
target's clauses fire into the merged record stream; a shared
`@latency = quantize()` aggregation folds bucket counts across the
two kernels into one cross-target histogram.

This is the demo the rest of the bifrost stack exists to enable.

## Quick start

```
# First-run on a fresh M-series Mac:
scripts/first-run.sh

# Dry-run the plan + D source (cheap, no VMs):
examples/cross-kernel-linux-fbsd-x2/run.sh

# Boot smolvm + FreeBSD, run the full demo end-to-end:
BIFROST_LIVE=1 examples/cross-kernel-linux-fbsd-x2/run.sh
```

## Pass criteria

```
✓ both targets accepted their sessions
✓ merged record stream carried records from both targets
  linux-a records: ≥1
  fbsd-b  records: ≥1
✓ cross-target aggregation table rendered
```

The cross-target `@latency` row visibly references BOTH `linux-a`
and `fbsd-b` in its contributors map — that's what makes this
"merged" instead of "two demos running side by side."

## How it works

```
                              orchestrate
                              ┌────────────┐
plan.yaml ───── route_clauses ─┤ launcher  │── smolvm-launch.sh ── linux smolvm
                              │            │
trace.d   ────── per-OS lower─┤ N=2 drain │── qemu-launch-freebsd.sh ── fbsd qemu
                              │            │
                              │ MergedRing │── stdout (one merged record stream)
                              │            │
                              │ CrossTargetAggReducer │── @latency = quantize{…}
                              └────────────┘
```

* `plan.yaml` declares two targets, each with its own `launcher:
  kind:` and an empty `pid: 0` slot that the launcher subprocess
  fills in via `CONDUIT_BACKEND_PID_FILE`.
* `trace.d` carries ONE shared clause: `profile:::tick-100ms { …
  }`.  As of Track B P0 #6 the Linux backend attaches it via
  `perf_event_create_kernel_counter` + `perf_event_set_bpf_prog`
  (`PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`,
  `sample_period = period_ns`).  FreeBSD attaches it via the
  kernel's native `profile` provider.
* `route_clauses` (`host/bifrost/src/plan.rs`) fans the clause
  out to every accepting target.  The kernel-agnostic frontend
  intentionally has zero per-OS branches.
* The orchestrator's drain loop reads each target's data SHM,
  feeds `AGG_SNAPSHOT` records into
  `merge::CrossTargetAggReducer`, and emits per-fire records
  through `merge::MergedRing` in host wall-clock order.
* At session END the reducer's quantize buckets are folded across
  both kernels and rendered through `cli::printa::render_end_printa`.

## Three-kernels sibling

For the three-kernel variant (macOS host + Linux smolvm + FreeBSD
QEMU), see [`../three-kernels`](../three-kernels/README.md) — same
shape, third target.
