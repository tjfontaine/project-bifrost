# cross-kernel-fbsd-x2 — Live N=2 orchestrate proof

The smallest end-to-end acceptance run: two independent
FreeBSD QEMU instances driven by **one** `bifrost orchestrate`
invocation, with one D source fanned out via `route_clauses` to
both targets and the merged renderer emitting target-tagged
records from both kernels in `gns` order.

This demo proves N=2 transport plumbing and the merged renderer
with target_id stamping live, without needing the
Linux eBPF lowering pipeline integration that the parent
`cross-kernel-tcp` demo also depends on. Same N=2 orchestration
shape, just N=2 of one OS.

## Run

```
guest/freebsd-bifrost/build-module.sh
guest/freebsd-bifrost/stage-module-disk.sh
host/runtime/stage-conduit-backend.sh
QEMU=/private/tmp/qemu-11.0.0/build/qemu-system-aarch64 \
    examples/cross-kernel-fbsd-x2/run.sh
```

## Pass criteria

```
✓ both targets accepted their sessions
✓ merged record stream carried records from both targets
  fbsd-a records: ≥1
  fbsd-b records: ≥1
orchestrate: drained N records across 2 target(s) (0 flushed at session end)
```

`drained N records` with each target contributing is the
N=2 acceptance shape. `0 flushed at session end` means every
record was emitted inside the lookback window — no orphan records
needed final reconciliation.
