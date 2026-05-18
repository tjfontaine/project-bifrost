# probe-control

The "what's missing" demo. Every action below is part of the
canonical DTrace surface; bifrost lowers some today
(`DTRACEACT_DIFEXPR`, `_PRINTF`, `_USTACK`, `_STACK`) and rejects
the rest with `DTRACEACT kind 0x... not yet lowered to eBPF`.
This demo exercises every form so the failure surface is concrete
and demo-driven development can close the gaps one at a time.

The four other demos (compile-profile, postgres-slow-query,
cross-domain-http, intra-guest-http) all rely on Ctrl-C to dump
aggregations. probe-control is the demo that wants to programmatically
end the trace via `exit()`, format an aggregation explicitly via
`printa()`, and react to BEGIN/END clauses — none of which are
fully wired today.

## What's exercised (what works / what doesn't)

| D source | DTRACEACT kind | Lowered? | Notes |
| --- | --- | --- | --- |
| `printf("...", ...)` | `_PRINTF` (3) | ✓ yes | the workhorse output action |
| `@agg[key] = count()` | (agg via `_DIFEXPR` 1) | ✓ yes | aggregations land in BPF maps |
| `gustack()` / `ustack()` | `_USTACK` (0x101) | ✓ yes | guest user-stack walk |
| `stack()` | `_STACK` (0x401) | ✓ yes | guest kernel-stack walk |
| variable assignment (`n_seen++`) | `_DIFEXPR` (1) | ✓ yes | global / thread-local lowering |
| `BEGIN` / `END` clauses (printf-only) | (libdtrace BEGIN/END) | ✓ yes | routed to the in-process libdtrace consumer; printf bodies fire on attach (BEGIN) and on Ctrl-C (END) |
| `exit(N)` in `bifrost:` clause | `_EXIT` (2) | ⚠ partial | per-fire BPF prog returns early via bpf_exit; trace as a whole keeps running until Ctrl-C. Full DTrace exit-the-trace semantics need a SHM control-plane KIND_EXIT_REQUEST follow-up to signal the host consumer's drain loop. |
| `printa("...", @guest_agg)` | `_PRINTA` (4) | ⚠ partial | libdtrace now accepts `printa(@guest_agg, ...)` — the bifrost CLI auto-injects a never-firing `BEGIN /0/ { @<name>[<dummy_key>] = count(); }` stub so the symbol resolves and the type signature matches.  The agg stays empty from libdtrace's perspective (the stub body never runs), so printa() formats nothing; the real guest-side data renders through bifrost's own xagg dump on Ctrl-C.  Wiring guest-side data back into libdtrace's agg state is a follow-up. |
| `clear(@agg)` | `_LIBACT` cleardepth | ✗ not lowered | periodic agg reset for top-N rolling windows. |
| `trunc(@agg, n)` | `_LIBACT` truncdepth | ✗ not lowered | keep top-N entries only. |
| `system("...")` | `_SYSTEM` | ✗ not lowered | shell out at trace exit. |
| `freopen("...")` | `_FREOPEN` | ✗ not lowered | redirect printf sink. |
| `stop()` | `_STOP` | ✗ not lowered | SIGSTOP the firing task. |
| `raise(SIG)` | `_RAISE` | ✗ not lowered | post-SIGNAL to firing task. |

The probe.d compiles a clause-per-action so every gap fires its
own libdtrace error. The first error aborts the trace, so
expect to ^C and re-run after each fix.

## Run

Two shells.

```sh
# shell 1 — boots smolvm and drives `ls /etc` continuously
examples/probe-control/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself.
sudo bifrost -p $PID -s examples/probe-control/probe.d
```

Three equivalent forms — pick whichever you prefer:

```sh
# 1. -s flag, like dtrace
sudo bifrost -p $PID -s examples/probe-control/probe.d

# 2. inline D expression with -n
sudo bifrost -p $PID \
    -n 'dtrace:::BEGIN { printf("hi"); }
        bifrost::do_sys_openat2:entry { @[execname] = count(); }
        dtrace:::END { printa("%-16s %@d\n", @); }'

# 3. self-executing script
sudo examples/probe-control/probe.d -p $PID
```

When the trace ends (either by ^C or once `exit(0)` is wired up,
once n_seen reaches 200), aggregations dump.

## Files

- [`setup.sh`](setup.sh) — boots smolvm + drives in-guest `ls /etc` loop
- [`probe.d`](probe.d) — exercises BEGIN, END, printa, exit,
  global counter.  Attaches via the BPF trampoline.

## Why this demo exists

The other demos are "things that work, here's the captured output."
This one is "things that should work, here's how the failure
looks today." Each missing action is a half-day to a day of
lowering work in `host/bifrost/src/lower/action.rs`; a fully
green table above is the bar for closing the demo-driven
development series.

## Captured output

A real ~25 s run against ubuntu:24.04 with `ls /etc` firing
through the in-guest exec loop.  Both progs JIT cleanly with
the `exit()` lowering, and libdtrace accepts `printa(@opens)` in
the END clause via the auto-injected stub:

```
[bifrost] stubbed guest-only aggs for libdtrace: @opens
[bifrost] prog #0: 54 insns, target='do_sys_openat2:entry', schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #1: 52 insns, target='do_sys_openat2:entry', schema=5 fields (32-byte records), 2 map(s)
[bifrost] LOAD_PROG acked; programs queued
[bifrost] auto-injected host D (715 bytes); attaching libdtrace in-process
```

`dtrace:::BEGIN` header fires (libdtrace path):

```
probe-control demo - exercises trace-control actions
    BEGIN/END:  clause hooks at trace start/end
    n_seen:     global counter incremented per fire
    exit(0):    stop the trace after 200 fires
    printa():   explicitly format @opens at END
```

prog #1 is the predicate-gated `exit(0)` clause — before this
patch, it rejected with `DTRACEACT kind 0x2 not yet lowered to
eBPF`; with `_EXIT` lowered to `bpf_exit`, the clause loads as
a 52-insn prog and runs cleanly.

Drops summary (always present in stderr):

```
[bifrost] dtrace summary: drops=0 (principal=0 agg=0 dyn=0 rinse=0 dirty=0 spec=0 stkstr=0 dblerr=0) errs=0
```
