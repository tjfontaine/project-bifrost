# three-kernels — the original bifrost thesis

One `bifrost orchestrate` invocation, one D source, **three kernels**:
macOS host + Linux smolvm + FreeBSD QEMU.  All three contribute to
the same merged record stream and the same cross-target
aggregation row.

This is the original bifrost thesis ("trace macOS and the guest in
one D script") finally landing in the demo flow, with FreeBSD
joining as a peer.  No Slack channel, no "and then you SSH into this
VM," no host-vs-guest split.

## Quick start

```
# First-run on a fresh M-series Mac:
scripts/first-run.sh

# Dry-run the plan + D source (cheap, no VMs):
examples/three-kernels/run.sh

# Boot smolvm + FreeBSD + spawn macOS-host dtrace; full demo:
BIFROST_LIVE=1 examples/three-kernels/run.sh
```

## Pass criteria

```
✓ all three targets accepted their sessions
✓ merged record stream carried records from all three targets
  macos-host records: ≥1
  linux-a    records: ≥1
  fbsd-b     records: ≥1
✓ cross-target @triplet["all"] row contributors map names ALL THREE
  target ids (`macos-host`, `linux-a`, `fbsd-b`).
```

## How it works

```
                              orchestrate
                              ┌────────────────┐
plan.yaml ─── route_clauses ──┤ launcher (N=2) ├── smolvm-launch.sh ─── linux smolvm
                              │                ├── qemu-launch-freebsd.sh ── fbsd qemu
                              │                │
trace.d   ── per-OS lower  ───┤ macos-host ────┴── /usr/sbin/dtrace (child)
                              │                │
                              │ MergedRing     ── stdout (one merged record stream)
                              │                │
                              │ CrossTargetAggReducer ── xagg @triplet["all"] = N
                              └────────────────┘
```

* `plan.yaml` declares THREE targets.  The macos-host entry omits
  `conduit:` and uses `launcher: { kind: macos-host-dtrace }`.
* `trace.d` carries one shared agg name (`@triplet["all"]`) hit by
  per-OS clauses.  The frontend stays kernel-agnostic; each
  backend picks up only the clauses it can attach (see
  `host/bifrost/src/plan.rs` `route_clauses`).
* The macos-host launcher (`host/bifrost/src/cli/macos_host.rs`)
  spawns `sudo -n /usr/sbin/dtrace -q -n '<routed source>'`.  A
  reader thread tokenizes the child's stdout into per-fire records
  + scalar agg-row updates and feeds them into the same
  `MergedRing` / `CrossTargetAggReducer` the SHM-conduit targets
  use.
* At END the synthetic `printa("\1bf-mhx\1count\1<name>\1%s\1%@d\n",
  @<name>)` clause our orchestrator appends emits a
  marker-prefixed agg row the reader thread parses cleanly without
  having to format-decode dtrace's default histogram renderer.

## Why one shared key works

Each per-OS clause writes into `@triplet["all"] = count();` —
all three contributors share the same key tuple (`"all"`).  The
cross-target reducer (`merge::CrossTargetAggReducer`) keys on
`(agg_name, key_tuple)` and folds contributions additively, so the
sum and the contributor list both surface in one row.

## Per-fire stream caveat

`dtrace(1) -q` writes `trace(value)` bytes back-to-back with no
separator between fires.  To make the per-fire stream parseable,
`cli::macos_host::assemble_routed_source` appends `printf("\n");`
to every clause body before passing the source to dtrace.  Users
who write their own `printf()` calls inside the body are
unaffected.

## Sibling demo

For the two-kernel (Linux + FreeBSD) variant — simpler, no macOS
host arm — see [`../cross-kernel-linux-fbsd-x2`](../cross-kernel-linux-fbsd-x2/README.md).
