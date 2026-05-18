# Cross-domain `pair()` primitive — scoping note

A first-class DTrace primitive that joins paired events across the
host↔guest boundary. Today bifrost can run `@<name>` aggregations on
each side independently (Plan B / `bifrost_xdomain.d`); this is the
longer-term "Plan C" that produces a single quantize histogram of
inter-event latency from a host open-leg + guest close-leg pair.

This doc is the output of a research pass; treat it as a design
sketch, not a committed plan.

## Prior art landscape

No existing tracer ships a first-class cross-domain pair-matching
primitive; everyone reinvents it from two lower-level building
blocks.

- **DTrace itself** has only the thread-local idiom:
  `entry { self->t = timestamp; }` /
  `return /self->t/ { @lat = quantize(timestamp - self->t); self->t = 0; }`.
  Pairing is implicit in `self->`, scoped to one thread, one
  kernel.
- **bpftrace** does the same with `@start[tid] = nsecs` /
  `@lat = hist(nsecs - @start[tid]); delete(@start[tid])` — explicit
  map keyed on tid.
- **Perfetto** punts pairing to post-hoc SQL via `SPAN_JOIN` over
  `(ts, dur, partition)` rows.
- **Distributed tracing** (Zipkin/Jaeger/OpenTelemetry) propagates
  an explicit `trace_id` + `parent_span_id` in-band — pairing is a
  join on those IDs at the collector.
- **Magic-trace** doesn't pair at all — captures one ring per
  snapshot.
- **Academic VM tracing** (Nemati 2019, vPSD/HEC) builds host↔guest
  correlation by joining `kvm_entry` / `kvm_exit` against guest
  sched events offline, post-hoc.

The one syntactic primitive the field actually has is `self->`;
everything else is JOIN, mostly outside the trace runtime.

## Proposed D syntax

Treat `pair` as an aggregation constructor that takes two probe
sites and a key expression:

```d
/* (a) implicit gpid pairing — host send to guest receive */
pair @rtt = (host_pid$target:libkrun*:bifrost_event_send:entry,
             bifrost:guest_kernel:bifrost_agent_recv:entry)
            on key=arg0 expire=10ms;

host_pid$target:libkrun*:bifrost_event_send:entry { @rtt[probefunc] = pair_open(arg0); }
bifrost:guest_kernel:bifrost_agent_recv:entry      { @rtt = pair_close(quantize, arg0); }
```

```d
/* (b) sugar form — single-site bracket, like self-> but cross-domain */
@cmd_lat = pair[gpid, sequence_id](
    open: syscall::sendto:entry  /execname=="bifrost"/ ,
    close: bifrost:guest_user:agent::cmd_done
) -> quantize;
```

```d
/* (c) explicit user-supplied tag, for bring-your-own-correlation */
syscall::write:entry  /args[0]==self->agent_fd/ { pair_open(@e2e, this->req_id); }
bifrost:guest_kernel:tcp_v4_rcv:entry           { pair_close(@e2e, args[0]->req_id, timestamp); }
```

## Matching mechanism

Storage is one BPF hash map per `pair` aggregation:

- key = correlation tag (u64 or hashed tuple)
- value = `{ open_ts: u64, open_cpu/tid: u32, slot_gen: u32 }`

Default key tuple is `(gpid, user_tag)` where `gpid` is already
plumbed and `user_tag` defaults to `arg0` of the open probe. On
`pair_close` we look up, compute `now - open_ts`, feed the result
into the wrapped agg (`quantize`/`avg`/`hist`), and `delete` the
slot.

Two correctness knobs:

1. `expire=` TTL on each open slot, swept on a 1Hz interval probe
   so a dropped close doesn't pin memory.
2. Bounded slot count (e.g. 64K) with reservoir-style eviction —
   overflow increments `@drops`.

Wire cost: one extra u64 in the host record's `correlation_tag`
field; the SHMEM ringbuf already carries gpid.

## Implementation phases

**Phase 0** (sugar over today's primitives). Compile `pair[k]` to
the existing thread-local pattern *when both legs are on the same
side* — no new runtime. Pure DIF/lower work. Lands the syntax
without yet reaching across the boundary.

**Phase 1** (cross-side, host-resident matcher). When legs span
domains, do the join in `bifrost-cli` at demux time: open-leg
parks records in a Rust `HashMap<key, OpenSlot>`, close-leg drains
and folds into the agg. Both sides emit ordinary records. No
verifier work, no map plumbing — just the host correlator and a
new `pair_open`/`pair_close` builtin pair the lowerer recognises.

**Phase 2** (in-kernel pairing). Promote the matcher into the guest
BPF program backed by `BPF_MAP_TYPE_HASH` with `BPF_F_NO_PREALLOC`;
needed only when the close-leg fires faster than the ringbuf
drains, which we don't see today (~860 rec/s).

**Phase 3** (typed correlation builders). `pair_by_gpid_seq()`,
`pair_by_socket()`, `pair_by_kfd()` — sugar on top of phase 1/2.

## Complexity & biggest unknowns

Phase 0 + Phase 1 is ~2 weeks: parser changes in `parse.rs`, two
new builtins in `schema.rs`, lowering thunks in `lower.rs`, and
~200 lines of correlator in the bifrost CLI.

The biggest unknown is **clock semantics on the open leg**: the
wallclock anchor is computed at first-record arrival, but the
open-side timestamp is taken at probe-fire time. For an MVP we
record host `mach_absolute_time` and guest `bpf_ktime_get_ns` and
convert through the existing skew table (`bifrost_skew.d` already
exercises this). If skew drifts mid-run we get negative latencies;
the answer is to renew the anchor on every Nth pair, not per-fire.

The other unknown is whether users actually want pair semantics or
relation semantics (one open, many closes — like a fanout RPC);
recommend explicitly rejecting many-to-one for v1 and emitting a
diagnostic.

## MVP that captures most of the value

Ship **only Phase 1 with the explicit-tag form** (script (c)
above) and a single new builtin `pair_quantize(@agg, key, ts)`.
No new syntax, no new aggregation type — `@agg` is an ordinary
`quantize` aggregation; the builtin just resolves the open/close
internally.

The user writes `pair_open` in one clause and `pair_quantize` in
the other. ~1 week of work, gives 90% of the use cases (host-
syscall→guest-kprobe latency, send→receive RTT, command-dispatch
end-to-end), and defers the harder questions (sugar syntax,
in-kernel matcher, fanout semantics, lifetime management) until
real scripts demand them.

A connect→guest-recv roundtrip script is the natural first
proof — pair the host-side `connect` with the guest-side
`recvmsg` (or equivalent) and run
`pair_quantize(@e2e, agent_fd, walltimestamp)` across the two
clauses.

## Relevant files

- `host/bifrost/src/parse.rs` (clause + agg parsing)
- `host/bifrost/src/schema.rs` (record schema; new
  `pair_open`/`pair_close` builtins)
- `host/bifrost/src/lower/` (DIF→eBPF lowering thunks; 7-file
  module — `mod.rs` is the entry, `dif.rs`/`emit.rs`/`agg.rs`/
  `action.rs`/`state.rs`/`branch.rs`/`tests.rs` cover specifics)

## Sources

- [DTrace Thread-Local Variables (Oracle)](https://docs.oracle.com/cd/E19253-01/817-6223/chp-variables-3/index.html)
- [DTrace pid Provider return (Brendan Gregg)](https://www.brendangregg.com/blog/2011-02-14/dtrace-pid-provider-return.html)
- [A thorough introduction to bpftrace (Brendan Gregg)](https://www.brendangregg.com/blog/2019-08-19/bpftrace.html)
- [bpftrace docs 0.22](https://bpftrace.org/docs/0.22)
- [Getting Started with PerfettoSQL](https://perfetto.dev/docs/analysis/perfetto-sql-getting-started)
- [Perfetto Trace Processor (C++)](https://perfetto.dev/docs/analysis/trace-processor)
- [Magic-trace: Diagnosing tricky performance issues (Jane Street)](https://blog.janestreet.com/magic-trace/)
- [OpenTelemetry Traces concepts](https://opentelemetry.io/docs/concepts/signals/traces/)
- [OpenTelemetry trace_id vs span_id (SigNoz)](https://signoz.io/comparisons/opentelemetry-trace-id-vs-span-id/)
- [CrossTrace: cross-thread/service span correlation (arXiv 2508.11342)](https://arxiv.org/html/2508.11342v1)
- [VM Flow Analysis Using Host Kernel Tracing (Nemati, Polytechnique Montréal)](https://publications.polymtl.ca/3902/1/2019_HaniNemati.pdf)
- [Host-Based VM Workload Characterization Using Hypervisor Trace Mining (ACM TOMPECS)](https://dl.acm.org/doi/10.1145/3460197)
