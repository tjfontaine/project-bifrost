# Primers

Short, single-clause D scripts that demonstrate one DTrace
feature each.  Each primer compiles cleanly under
`sudo bifrost --emit-ebpf …` and renders the expected
per-feature output when attached to a running smolvm.

The runtime sweep `examples/primers/sweep.sh` exercises every
primer end-to-end against a live smolvm + redis workload and
reports per-primer PASS/FAIL based on rendered output markers.

## Aggregations

| Primer | Demonstrates |
|---|---|
| [`count.d`](count.d) | `@a[k] = count();` per-key counter |
| [`quantize.d`](quantize.d) | `quantize()` power-of-two histogram |
| [`stddev.d`](stddev.d) | `stddev()` aggregation via per-CPU `[n, sum, sum_of_squares]` |
| [`lquantize.d`](lquantize.d) | `lquantize(value, base, upper, step)` linear histogram |
| [`llquantize.d`](llquantize.d) | `llquantize(value, factor, low_mag, high_mag, steps_per_mag)` log-linear histogram |
| [`clear.d`](clear.d) | `clear(@agg)` zeroes every per-CPU map slot |
| [`normalize-trunc.d`](normalize-trunc.d) | `normalize` / `denormalize` / `trunc` render-time hints |
| [`multikey-agg.d`](multikey-agg.d) | `@a[k1, k2] = count();` composite key |
| [`per-pid-opens.d`](per-pid-opens.d) | per-pid `count()` keyed across multiple probes |

## DIF subroutines / built-ins

| Primer | Demonstrates |
|---|---|
| [`strlen.d`](strlen.d) | `strlen(s)` on a user string pointer |
| [`copyinstr.d`](copyinstr.d) | `copyinstr(uaddr)` per-CPU scratch user-string copy |
| [`strchr.d`](strchr.d) | `strchr(s, c)` |
| [`strings.d`](strings.d) | `strstr`, `index`, `strjoin`, `substr` family |
| [`tracemem.d`](tracemem.d) | `tracemem(addr, len)` raw byte capture + libdtrace-style hex/ASCII dump |
| [`walltimestamp.d`](walltimestamp.d) | `walltimestamp` via `ktime_get_real_ns()` (CLOCK_REALTIME) |
| [`vtimestamp.d`](vtimestamp.d) | `vtimestamp` via `task->se.sum_exec_runtime` (per-thread CPU runtime) |
| [`progeny.d`](progeny.d) | `progenyof(pid)` ancestor-chain walk |

## Probe surface

| Primer | Demonstrates |
|---|---|
| [`gustack.d`](gustack.d) | `gustack()` guest user-stack capture with ELF symbolisation |
| [`xstack.d`](xstack.d) | `xstack()` cross-domain (host + guest) stitched stack |
| [`uprobe-redis.d`](uprobe-redis.d) | `uprobe:guest:<binary>:<sym>:entry` attach |
| [`stable-providers.d`](stable-providers.d) | `sched:::switch`, `tcp:::send`, `signal:::send`, etc. translated to Linux raw tracepoints |
| [`syscall-counts.d`](syscall-counts.d) | `syscall:::entry` per-syscall counter via raw_syscalls:sys_enter |

## Identifier-only probes

| Primer | Demonstrates |
|---|---|
| [`end-clause.d`](end-clause.d) | `dtrace:::END` fires at consumer-exit |
| [`error-clause.d`](error-clause.d) | libdtrace `dtrace:::ERROR` for its own probes + Bifrost-owned probes' fault counter surfaces as `dblerr=N` in the drop summary |

## Speculative tracing

| Primer | Demonstrates |
|---|---|
| [`speculate.d`](speculate.d) | `speculation()` / `speculate(id)` / `commit(id)` / `discard(id)` — buffer records into a per-CPU side lane until commit/discard |

## Runtime sweep

```sh
examples/primers/sweep.sh
```

Boots one smolvm + redis, starts an in-guest `find /etc`
workload, then runs each primer through
`bifrost-trace.sh --duration-seconds=8` and greps the captured
log for the per-primer marker.  Exits 0 when every primer's
marker is found.  Per-primer logs land under
`/tmp/bifrost-primer-sweep-<timestamp>/`.

## See also

- [`docs/dtrace-compatibility.md`](../../docs/dtrace-compatibility.md)
  — feature-by-feature support matrix.
- [`docs/dtrace-roadmap.md`](../../docs/dtrace-roadmap.md) — feature
  landing history.
