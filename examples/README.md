# Bifrost examples

A working set of D scripts plus paired workload-driving harness
scripts that exercise the bifrost feature surface against real
Ubuntu-base Docker images.

The shipping examples are Linux-backend demos unless explicitly
named otherwise.  `freebsd-dtrace-smoke/` is the FreeBSD-first
kernel-only portability proof: it boots a stock FreeBSD image with
the generic conduit attached, and in preload mode proves the
FreeBSD kernel conduit attaches and publishes DATA_SHM_READY without
a guest userspace helper or guest `dtrace(1)` in the tracing path;
the same preload gate now sends a host proof control payload, runs a
host-supplied DOF fixture through the FreeBSD kernel DTrace wrapper, and
verifies the resulting record through the existing host-visible data
SHM.

The examples split into two tiers:

- **Pattern primers** (`primers/`) — small, single-feature
  scripts. Useful as building blocks to copy into your own D
  scripts. None of these drives a workload; you point them at
  any running smolvm process and watch records on stdout.
- **Self-contained demos** — each in its own directory. Most
  follow a two-shell shape: a `setup.sh` boots the workload and
  drives load continuously while you run bifrost manually in
  another shell, dtrace-style. `redis-smoke-test` is a
  single-shot integration test that drives load and runs bifrost
  end-to-end in one go.

## Self-contained demos

| Demo | What it shows | Driver |
|---|---|---|
| [`redis-smoke-test/`](redis-smoke-test/) | The smallest end-to-end test: a raw `sched_switch` tracepoint emits records while a Redis guest is alive. | `run.sh` (one-shot) |
| [`freebsd-dtrace-smoke/`](freebsd-dtrace-smoke/) | FreeBSD-first native-DTrace portability proof. v0 boots stock FreeBSD with `conduit-backend`; v1 preloads the kernel-only FreeBSD conduit and verifies DATA_SHM_READY; v2 drives a host-selected DOF session and renders the native `trace()` record through Bifrost schema output. | `run.sh` (one-shot) |
| [`cross-domain-http/`](cross-domain-http/) | HTTP workload demo over the cross-domain Bifrost path: in-guest nginx plus in-guest `ab`, guest `tcp_v4_do_rcv` count/latency, and sampled `xstack(SAMPLE, 32)`. | `run.sh` / `setup.sh` |
| [`postgres-slow-query/`](postgres-slow-query/) | Manual diagnostic for Postgres file-open latency. Steady-state pgbench usually stays in cache, so this is not part of the automated sweep until it gets a workload that deliberately causes file opens. | `setup.sh` (two-shell) |
| [`compile-profile/`](compile-profile/) | Anatomy of a real C compile: opens grouped by toolchain subprocess (cc1 / as) with `gustack()` and quantized open latency. Driven by a continuous in-guest `gcc -c` loop. No port-forward needed. | `setup.sh` (two-shell) |
| [`intra-guest-http/`](intra-guest-http/) | TCP receive-side latency via fbt FENTRY+FEXIT on `tcp_v4_do_rcv`, quantized per-pid. Driven by in-guest `ab` against in-guest `nginx` (no port-forward; isolates the receive path from the cross-domain hop). | `setup.sh` (two-shell) |
| [`probe-control/`](probe-control/) | Controlled comparison demo on `do_sys_openat2`. Same workload (`ls /etc` loop), same predicate, same action — exists to surface attach-path / dispatch-stub overhead deltas isolated from fire-site differences. | `setup.sh` (two-shell) |
| [`failed-opens/`](failed-opens/) | System-wide failed-open profile via `fbt::do_sys_openat2:return` with `retval` access and a multi-key agg `@errs[execname, retval]`. Driven by an alice-vs-shadow workload. Demonstrates retval lowering through the FEXIT context slot. | `setup.sh` (two-shell) |
| [`redis-uprobe/`](redis-uprobe/) | User-space attach: `uprobe:guest:redis-server:processCommand:entry` + `:return` for per-command latency. Demonstrates the uprobe-by-symbol path (ELF symtab lookup + VMA resolution). | `setup.sh` (two-shell) |
| [`scheduler-offcpu/`](scheduler-offcpu/) | Off-CPU profile via the `tracepoint:guest:sched:sched_switch` raw tracepoint. Per-pid context-switch count with task-state breakdown. | `setup.sh` (two-shell) |
| [`sched-multi/`](sched-multi/) | Multi-tracepoint scheduler activity profile: `sched_switch` + `sched_wakeup` in one D script, three aggs (preempted / blocked / wakers). Exercises raw-tracepoint provider beyond a single hookpoint. | `setup.sh` (two-shell) |

### Two-shell shape

In one shell, boot the workload and start the load loop:

```sh
examples/cross-domain-http/setup.sh
# or postgres-slow-query/setup.sh, compile-profile/setup.sh
```

`setup.sh` prints the smolvm pid and the exact `bifrost` command
to type next.

In a second shell, run bifrost yourself, dtrace-style:

```sh
sudo bifrost -p $PID \
    -s examples/cross-domain-http/probe.d
```

Or with an inline D expression — equivalent of `dtrace -n`:

```sh
sudo bifrost -p $PID \
    -n 'fbt::tcp_v4_do_rcv:entry { @[pid] = count(); }'
```

When you have enough samples, ^C the bifrost CLI to dump
aggregations, then ^C `setup.sh` to tear down smolvm + the load
driver.

### One-shot shape (redis-smoke-test only)

```sh
examples/redis-smoke-test/run.sh
```

This boots smolvm, attaches the bifrost trace, drives 10
seconds of guest scheduler activity, captures records, and summarises
in one go.

## Pattern primers

Single-feature D scripts you can point at any running smolvm:

| Primer | Pattern |
|---|---|
| [`primers/count.d`](primers/count.d) | proof of life — single kprobe fire |
| [`primers/per-pid-opens.d`](primers/per-pid-opens.d) | user-defined globals (`@count[pid]`) |
| [`primers/quantize.d`](primers/quantize.d) | thread-locals + power-of-two histogram |
| [`primers/multikey-agg.d`](primers/multikey-agg.d) | multi-key aggregation `@[pid, execname]` |
| [`primers/gustack.d`](primers/gustack.d) | guest user-stack walk |
| [`primers/xstack.d`](primers/xstack.d) | cross-domain stitched call chain |
| [`primers/uprobe-redis.d`](primers/uprobe-redis.d) | user-space probe in a guest binary |

Run any primer against a running smolvm:

```sh
examples/redis-smoke-test/run.sh &     # background a workload
PID=$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || \
      pgrep -f '_boot-vm.*boot-config' | tail -1)
sudo bifrost -p "$PID" -s examples/primers/per-pid-opens.d
```

## Why Ubuntu base images

The `gustack()` and `xstack()` user-side stack chases are pure
frame-pointer walks (the kernel's `arch_stack_walk_user`). Distros
that strip frame pointers — Alpine + musl, Debian stable, RHEL 8/9
— produce truncated stacks with most of the call chain missing.

Ubuntu 24.04+ builds the toolchain and the official `ubuntu/*`
container images with `-fno-omit-frame-pointer` everywhere, which
is why the demos use them specifically. Fedora 38+, Arch, and
AlmaLinux 10+ are also frame-pointer-default and would work
equivalently if you swap the image.

## Validation

The demos are the VM-bound tier of the release-validation
checklist documented in [`DEVELOPMENT.md`](../DEVELOPMENT.md).

Cheap local gates run first (no VM boot — see DEVELOPMENT.md
"Cheap local gates"). After they pass, the demo sweep is the
end-to-end VM-bound gate:

```sh
examples/run-full-sweep.sh
```

The sweep boots each demo's smolvm, applies the demo's
`probe.d`, drives the workload, and tears down between demos. It
must report `failures=0` in its summary. Each demo whose
`run.sh` wraps `[demo-harness] PASS / FAIL` must report `PASS`;
`redis-smoke-test` must observe records and print
"end-to-end cross-domain trace working".

All `.d` files also compile cleanly with the current bifrost CLI
(BFR7 wrapper, BTF-resolved kfunc names, valid eBPF):

```sh
for f in examples/primers/*.d examples/*/probe.d; do
    sudo bifrost -s "$f" --emit-ebpf /tmp/check.bfr7
done
```

That loop is a fast smoke test you can run without a smolvm
running.

## Notes

- All examples set `#pragma D option quiet` so libdtrace doesn't
  print column headers for empty record schemas. Records still
  reach stdout — bifrost auto-injects a default record sink.
- Aggregations (`@[…] = count()`, `quantize(…)`, etc.) dump on
  consumer exit (Ctrl-C). Use the non-aggregating variants for
  fire-by-fire output.
- `pid` and `execname` resolve to **guest** task properties since
  the probe runs in the guest. The host renderer labels the
  rendered field as `gpid=` to disambiguate from any host-side
  `pid` field.
