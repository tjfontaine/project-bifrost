# redis-smoke-test

The end-to-end smoke test for the Bifrost cross-domain pipeline.
Single-shot script: boot a Redis guest, attach Bifrost, collect
records, summarize, and tear down.

## What It Shows

The probe attaches to the guest raw `sched_switch` tracepoint while
`redis:7-alpine` is running in smolvm. It does not depend on host port
publishing, which keeps the release smoke gate focused on the Bifrost
path:

```text
macOS bifrost CLI -> SHM -> smolvm libkrun -> guest kernel
-> bifrost driver -> eBPF JIT -> raw tracepoint -> SHMEM ringbuf
-> libkrun shmem consumer -> CLI auto-injected sink -> stdout
```

This proves the BFR7 wrapper transport, kernel-side attach path, SHMEM
record delivery, and host renderer are wired together.

## Run

```sh
examples/redis-smoke-test/run.sh
```

Override the trace duration:

```sh
TRACE_SECONDS=20 examples/redis-smoke-test/run.sh
```

Manual equivalent:

```sh
sudo bifrost -p "$PID" -s examples/redis-smoke-test/probe.d
```

## Files

- `probe.d` — raw `sched_switch` tracepoint, trivial `x = 1` action.
- `run.sh` — one-shot harness.

## Expected Output

Successful runs print records like:

```text
guest_kernel:sched_switch:entry vmid=1 probe_id=1 gns=0x281b0a632 gpid=0 value=0x1
```

The summary reports the observed record count and exits 0 when at
least one record was delivered:

```text
[redis-smoke-test] records observed in CLI output: 273
[redis-smoke-test] ✓ end-to-end cross-domain trace working
```
