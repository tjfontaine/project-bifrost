# DTrace parity roadmap

> **DOF-generic rebuild update — 2026-05-17.**
> The lowering pipeline has been inverted: the host emits one
> `DTRACE_SESSION_V1` envelope per session
> (`host/bifrost-wire/src/session_envelope.rs`) carrying a DOF blob;
> each guest decodes the same envelope against
> `crates/bifrost-dtrace-lower` (no_std) and drives a local
> `KernelAdapter` against its native tracing engine. Records flow
> back as SHMEM v6 semantic envelopes
> (`host/bifrost-wire/src/shmem_v6.rs`). The Linux-specific
> BFR7/LOAD_PROG path is being retired; the new gate
> `scripts/check-no-active-bfr7.sh --strict` enforces that no live
> host call site emits BFR7 anymore once the migration completes.

This document tracks the DTrace parity work — what has landed and
what remains. The headline data-plane and aggregation items have
landed: per-CPU principal buffers (50× drop reduction at
`FIRE_GAP=0.05`) and `stddev()` (per-CPU `[n, sum, sum_of_squares]`
slot pattern with a wire-format extension).

Each section below names the files involved, the structural
blockers that make remaining work multi-session, the rough landing
order, and the validation artifact each item should produce.

The current-state audit of which DTrace features Bifrost supports
today lives in
[`dtrace-compatibility.md`](dtrace-compatibility.md); pickup
pointers here cross-link back to it for context.

## Per-CPU principal buffer in the guest driver

**Status:** Landed (SHMEM_VERSION 4). 6 MB ringbuf carved into N
per-CPU sub-rings with dedicated producer/consumer/drop cache
lines, delivering a 50× drop reduction on compile-profile. Below
entry preserved for context only.

**Why it matters:** A single 16 MB SHMEM ring with one
producer/consumer cursor pair is the practical throughput ceiling
under hot workloads: every guest CPU CAS-claims into the same
`producer_pos`, and the compile-profile demo at `FIRE_GAP=0.05`
drops 1.7M records per 16 s window because of cross-CPU cache-
line contention. Per-CPU buffers eliminate the contention and
unblock speculation, which is naturally per-CPU.

**Files involved:**

- `third_party/linux-bifrost/kernel/bpf/helpers.c` —
  `bifrost_shmem_ringbuf_hdr` struct currently has one
  `producer_pos` / `consumer_pos` / `dropped_records` /
  `dropped_bytes` set. Needs N copies (`BIFROST_MAX_CPUS = 16`).
  `bifrost_shmem_reserve` / `bifrost_shmem_submit` /
  `bifrost_shmem_kick` index into the per-CPU sub-region.
- `third_party/linux-bifrost/drivers/bifrost/shmem_layout.rs` —
  carve `SHMEM_RINGBUF_LEN` into N sub-rings; publish
  per-CPU offsets.
- `third_party/linux-bifrost/drivers/bifrost/shmem_init.rs` —
  stamp per-CPU sub-ring headers at SHMEM_INIT time.
- `third_party/linux-bifrost/drivers/bifrost/record_writer.rs` —
  per-CPU writer state.
- `third_party/linux-bifrost/drivers/bifrost/agg_snapshot.rs` —
  emit snapshots into the local CPU's sub-ring.
- `host/bifrost/src/control_shmem.rs` — `DataShmSnapshot` grows
  per-CPU arrays for producer/consumer cursors.
- `host/bifrost/src/cli/runtime.rs` — direct-render thread
  round-robins drain across N rings (or spawn N worker threads;
  start with the simpler round-robin).
- `host/bifrost-wire/src/lib.rs` — pin `BIFROST_MAX_CPUS` and
  the per-CPU sub-region offset constants for the drift script.
- `host/virtio-conduit/src/lib.rs` — the virtio shared-memory
  region size stays at 16 MB; the sub-region carve is owned by
  the guest driver.

**Structural blockers:**

1. `bifrost_shmem_ringbuf_hdr` is a `#[repr(C)]` struct that's
   wire-stable between guest and host. Changing it bumps the
   SHMEM_VERSION; old libkrunfw bundles can't read the new
   layout, so the kernel + libkrunfw + host need to land
   simultaneously.
2. The agg snapshot encoder reads a single producer_pos to
   decide where to write. With N rings, each snapshot needs to
   land in the writer's CPU's ring — straightforward but means
   touching every kfunc entry point that emits a record.
3. The CLI renderer's `records_between` walks one ring with
   one busy-record spin budget. Round-robining over N rings
   needs careful fairness so a hot CPU's ring doesn't starve
   the others.
4. The renderer recovery branch (the "advance to
   `producer - ring_len/2` when lapped" path) needs per-ring
   state.

**Validate:**

- A new `examples/per-cpu-throughput/` micro-demo fires a tight
  scalar trace on every CPU for 5 s and reports per-CPU record
  rates within 10 % of each other (proves the load actually
  spreads).
- `examples/compile-profile/run.sh` at `FIRE_GAP=0.05` shows
  ≥ 10× reduction in total `dropped_records` versus the
  single-ring baseline (1.7M / 16 s).
- `examples/run-full-sweep.sh` continues to report
  `failures=0`.
- Existing cheap-local gates still exit 0 (in particular
  `scripts/check-proto-drift.sh` — `BIFROST_MAX_CPUS` and the
  per-CPU sub-region offsets need pinning across guest + host
  + bifrost-wire constants).

## Cross-process wake

**Status:** The 250 µs wake-aware poll has landed; FIFO-backed
true cross-process wake also landed (see below). Original deferral
notes preserved for context.

**Why it matters:** The poll cadence is below the per-record decode
cost for typical workloads, so the user-visible latency floor is no
longer the wait. The cross-process Condvar buys a marginal latency
win for low-rate scripts and matters more once per-CPU buffers
reduce decode cost.

**Files involved:**

- `host/virtio-conduit/src/control.rs` — publish a wake FIFO or
  named POSIX semaphore alongside `data_wake_counter`. macOS
  lacks `sem_timedwait`; use a UNIX FIFO (`/tmp/bifrost-wake-
  <pid>`) and `kqueue`/`EVFILT_READ` on the read fd.
- `host/virtio-conduit/src/shmem/consumer.rs` — `sem_post` (or
  `write(fd, &b, 1)`) after each `increment_data_wake_counter`.
- `host/bifrost/src/control_shmem.rs` — discovery: pick up the
  wake-FIFO path from the control SHM header (new u64 offset
  field).
- `host/bifrost/src/cli/runtime.rs` — renderer subscribes
  (`open(path, O_RDONLY | O_NONBLOCK)`) and `poll(fd, 1 ms)`.

**Structural blockers:**

1. Cross-process notification on macOS doesn't have a single
   primitive; kqueue + FIFO is the most portable.
2. The conduit is supposed to be generic. A wake-eventfd is
   defensible (it's a transport primitive); but the FIFO path
   needs to be a generic-conduit feature, not Bifrost-specific.

**Validate:**

- A `host/bifrost/tests/wake_driven_latency.rs` fixture
  attaches to a synthetic producer and measures the time
  between `producer_pos` increment and CLI render. Median
  ≤ 200 µs under a low-rate workload.

## `dtrace:::ERROR`

**Status:** Landed (May 14, 2026). Every fault-prone
Bifrost kfunc (`copyin`, `copyinstr`, `strlen`, `strchr`,
`strrchr`, `strstr`, `progenyof`) calls
`bifrost_kfunc_note_fault()` on its error path; the per-CPU
`BIFROST_DROP_CLASS_DBLERR` counter increments and surfaces in
the host CLI's drop summary as `dblerr=N`. libdtrace continues
to fire `dtrace:::ERROR` clauses for its own probes via the
`host_script` passthrough. Below entry preserved for context
only.

**Why it matters:** Real D scripts use ERROR to recover from
faulting probe actions (bad `copyin`, divide by zero). Without
it, scripts that fault silently lose data.

**Files involved:**

- `host/bifrost/src/parse.rs` — recognise `dtrace:::ERROR` as
  the ERROR-handler clause; collect its body.
- `host/bifrost/src/lower/mod.rs` — emit a tail-call-style
  branch from every action that can fault: on non-zero return
  from `bpf_probe_read_user` / `bpf_probe_read_kernel`, set up
  the ERROR-clause's argN slots (probe ID, action index, error
  number) and jump to the ERROR program.
- `host/bifrost/src/cli/wrapper.rs` — the BFR7 wrapper needs an
  ERROR-program slot per parent probe; current `programs`
  vector is one-per-clause and assumes successful return.
- `third_party/linux-bifrost/drivers/bifrost/uprobe_handlers.rs`
  and friends — register the ERROR program alongside its
  parent.

**Structural blockers:**

1. Linux BPF has no native "action-fault" mechanism. The error
   has to be detected explicitly at each fault-prone helper
   call. Routing it to a separate program is a tail-call.
2. ERROR clauses share the same `arg0..arg9` namespace as
   regular probes; lowering needs to thread the action-index
   and errno separately.

**Validate:**

- A new `examples/primers/error-clause.d` defines a
  deliberately-faulting probe (e.g. `copyin(0x1)`) and an
  `ERROR` clause that prints "saw error at probe N". Run for
  2 s and confirm the trace produces ≥ 1 "saw error" line and
  no kernel splat.

## `lquantize` / `llquantize` / `clear` / `normalize` / `trunc`

**Status:** Fully landed.

- `stddev()` — per-CPU `[n, sum, sum_of_squares]` slot.
- `clear(@agg)` — real `bifrost_kfunc_clear_agg(struct bpf_map *)`
  walking PERCPU_ARRAY/HASH per-CPU value slots; lowering emits
  `bpf_ld_map_fd + kfunc_call`.
- `lquantize` — `DTRACEAGG_LQUANTIZE = 0x0708`,
  Apple's packed `(step, levels, base)` decoded from
  `action.arg`; BPF lowering, host renderer, primer.
- `llquantize` — `DTRACEAGG_LLQUANTIZE = 0x0709`,
  per-magnitude unrolled threshold-compare (capped at 8 mags);
  host renderer, primer.
- `normalize` / `denormalize` / `trunc` —
  render-time hints scanned out of every clause body at compile
  time and applied at `dump_xagg_state` time.

Below entry preserved for context only.

**Why it matters:** Power-of-two `quantize` is too coarse for
latency analysis at fine resolution. `lquantize` (linear) and
`llquantize` (log-linear) are routine in production DTrace.
`stddev`/`clear`/`normalize`/`trunc` round out the standard
agg-manipulation set.

**Files involved:**

- `host/bifrost/src/lower/agg.rs` — add `DTRACEAGG_STDDEV =
  0x0706`, `DTRACEAGG_LQUANTIZE = 0x0708`, `DTRACEAGG_LLQUANTIZE
  = 0x0709`; new emit functions; new
  `agg_map_decl_for_chain` value sizes (24 bytes for stddev,
  N×8 for lquantize).
- `host/bifrost-support/src/schema.rs` — schema field-kind for
  multi-u64 agg payloads.
- `third_party/linux-bifrost/kernel/bpf/helpers.c` — new
  `bifrost_map_lookup_stddev_u64(map, key, out_n, out_sum,
  out_sum_sq)`, `bifrost_map_lookup_lquantize_u64(...)`,
  `bifrost_map_lookup_llquantize_u64(...)`. Each kfunc reduces
  the per-CPU values into a wider output.
- `third_party/linux-bifrost/drivers/bifrost/agg_snapshot.rs` —
  emit wider value payloads for the new agg kinds.
- `host/bifrost/src/cli/xagg.rs` — render stddev (sqrt formula),
  lquantize (linear histogram), llquantize (log-linear
  histogram).

**Structural blockers:**

1. The kernel reducer's `out: *mut u64` ABI returns a single
   u64. Each new agg kind needs its own reducer with the right
   output shape.
2. The agg snapshot's wire format hardcodes 8-byte values per
   `(fd, key)`. The new agg kinds need either a length-prefixed
   value or a per-kind switch.
3. `lquantize` parameters (lower, upper, step) are embedded by
   libdtrace in the action's `arg` u64. Extracting the params
   in `emit_agg_chain_at` requires a new path in the lowering.

**Recommended landing order:**

1. `stddev` first — fixed 24-byte value, simplest.
2. `lquantize` next — parameterised, but linear bucketing is
   straightforward.
3. `llquantize` after — log-linear is `lquantize` per magnitude.
4. `clear` / `normalize` / `trunc` — pure host-side renderer
   transforms; no kernel changes.

**Validate per agg:**

- A new `examples/primers/<agg>.d` exercises the action and
  produces the expected rendered output.

## `speculate()` / `commit()` / `discard()`

**Status:** Landed (May 14, 2026).

Per-CPU `struct bifrost_spec_state` declared above
`bifrost_shmem_reserve_kernel_class` carves a 16-slot × 1 KB
side buffer. `bifrost_kfunc_speculation` allocates lane id 1
per CPU; `speculate(id)` flips the active flag;
`bifrost_shmem_reserve_kernel_class` routes into the side
buffer while a lane is active; `commit(id)` replays buffered
records back through the principal reserve+submit path;
`discard(id)` zeroes the buffer. Host action arms
`DTRACEACT_SPECULATE/_COMMIT/_DISCARD` (0x0601-0x0603) lower
to direct kfunc calls — Bifrost supports both Apple's action
encoding and OpenDTrace's DIF subr (10 / 41 / 46 / 47) form.

Cross-CPU footprint: 16 KB per CPU × `BIFROST_NUM_CPUS_MAX = 16`
≈ 256 KB. Records exceeding `BIFROST_SPEC_RECORD_MAX = 1024`
or arriving past the 16-slot cap drop into `DBLERR`.

Below entry preserved for context only.

**Why it matters:** Speculative tracing is the canonical way to
filter "interesting" events out of a hot probe stream — let
every probe buffer into a speculation, decide post-hoc whether
to commit or discard.

**Depends on per-CPU buffers** because speculations are naturally
per-CPU (each CPU's claim path needs its own side-buffer).

**Files involved:**

- `third_party/linux-bifrost/kernel/bpf/helpers.c` — new
  speculation-buffer struct + lifecycle kfuncs:
  `bifrost_kfunc_speculation()` allocates, `_speculate(id)`
  redirects subsequent reservations into that side buffer,
  `_commit(id)` / `_discard(id)` promotes or drops.
- `third_party/linux-bifrost/drivers/bifrost/shmem_layout.rs` —
  reserve per-CPU speculation sub-regions (8 active maximum).
- `host/bifrost-wire/src/lib.rs` — speculation lifecycle
  record kinds.
- `host/bifrost/src/lower/mod.rs` — lower the four built-in
  speculation calls.
- `host/bifrost/src/cli/runtime.rs` — drain speculation
  commit/discard records.

**Validate:**

- A new `examples/primers/speculate.d` traces every syscall but
  only commits on processes that exit non-zero. Run against a
  mixed workload and confirm only failing-process traces show
  up.

## `tracemem` / `copyin` / string built-ins

**Status:** Mostly landed.
- **`strlen(s)`** — `bifrost_kfunc_strlen` bounds the read
  at 256 bytes via `strncpy_from_user`; DIF_SUBR_STRLEN (id 12)
  routes through `emit_single_arg_kfunc_subr`. Primer:
  `examples/primers/strlen.d`.
- **`copyinstr(uaddr)`** — `bifrost_kfunc_copyinstr` writes
  into a `DEFINE_PER_CPU` 256-byte scratch buffer and returns
  the kernel pointer (BPF treats as `string`). Primer:
  `examples/primers/copyinstr.d`.
- **`copyin(ptr, len)`** (in progress) — uses an explicit length
  so the scratch lifetime is more tightly bound. Sketch: per-CPU
  scratch keyed on (size_class, slot) so a probe can chain
  several `copyin` calls without overwriting earlier results.
- **`tracemem(addr, len)`** — Landed. Lowering
  recognizes Apple libdtrace's `DTRACEACT_TRACEMEM` (kind 6)
  and `DTRACEACT_TRACEMEM_DYNSIZE` (kind 7); the host
  `RecordSchema::for_tracemem(max_len)` introduces a `Bytes`
  field after the standard correlation header; the action
  arm in `host/bifrost/src/lower/action.rs` lowers the addr
  DIFO and emits `bpf_probe_read_kernel(record + offset,
  len, addr)` for the byte copy. Length is read from the
  value DIFO's `rtype_size` (Apple) or `action.arg`
  (OpenDTrace) — both encodings supported. Host renderer
  in `host/bifrost/src/cli/trace_render.rs::render_bytes_dump`
  formats hex/ASCII dumps in 16-byte rows. Primer:
  `examples/primers/tracemem.d`.
- **`strstr`/`strjoin`/`substr`/`index`/`strrchr`/`strchr`** —
  each a separate kfunc + DIF_SUBR_* dispatch. Pattern matches
  `strlen` — one-line lower-side addition per subr, kfunc body
  doing the bounded scratch work.

## `walltimestamp` / `vtimestamp` / `progenyof()`

**Status:**
- **`walltimestamp`** — Landed. New kfunc
  `bifrost_kfunc_walltime_ns` calls `ktime_get_real_ns()`; DIF
  var 0x011a lowers to a kfunc reloc instead of the
  `bpf_ktime_get_boot_ns` alias. Primer:
  `examples/primers/walltimestamp.d`.
- **`progenyof(pid)`** — Landed. New kfunc
  `bifrost_kfunc_progenyof` walks `current->real_parent` up
  to init under RCU (depth-capped at 64); DIF_SUBR_PROGENYOF
  (id 11) routes through the `emit_single_arg_kfunc_subr`
  helper. Primer: `examples/primers/progeny.d`.
- **`vtimestamp`** — Landed (May 14, 2026).
  `bifrost_kfunc_vtimestamp_ns` returns
  `current->se.sum_exec_runtime` — the kernel scheduler's
  authoritative per-thread CPU-runtime counter, sourced
  directly from `task_struct.se`. Matches DTrace's "total
  amount of time the current thread has been running on a
  CPU" semantic. No PERCPU_HASH map / lowerer bracket
  machinery required — the scheduler already tracks this
  precisely on every context switch and tick, so a single
  read is both correct and cheap.

## Typed tracepoint translators

**Status:** Landed (2026-05-15). The first stage moved the
five canonical translator needles (`args[0]->prev->comm`,
`prev->pid`, `next->comm`, `next->pid`, `pr_pid`) out of the
pre-parse `String::replace` and into a parser-aware expansion
pass (`host/bifrost/src/translators.rs`) that runs after
`parse::parse` per bifrost-routed clause and respects string
literals. The second stage added BTF-driven resolution: arbitrary
chains like `args[0]->prev->se.sum_exec_runtime` resolve through
the host's vmlinux BTF, emit one CORE_OFFSETOF sentinel per hop,
and lower to a single `bpf_probe_read_kernel(dst, sizeof(T),
prev_task + total_off)`. The libkrun-side BTF patcher
re-resolves each sentinel against the running kernel so the
read survives field-offset drift.

**Caps:** chain depth ≤ 4 hops; ≤ 8 chains per clause;
scalar terminal types only (1/2/4/8-byte ints + pointers);
user-VA pointer chases rejected at host-side BTF resolve.

**Files that landed:**

- `host/bifrost/src/translators.rs` — module carrying the
  canonical-chain table, the BTF chain walker, and the
  body rewriter.
- `host/bifrost/src/btf.rs` — `member_descend` helper for
  classifying mid-chain field kinds.
- `host/bifrost/src/cli/source_rewrite.rs` — removed
  `rewrite_typed_translators` (the prior textual rewrite); the
  CORE_OFFSETOF sentinel HI moved from `0xC0FECAFE` to
  `0x7C0FCAFE` so the resulting literals fit inside int64 (the
  largest integral type libdtrace's integer-constant parser
  recognises).
- `host/bifrost/src/bin/bifrost.rs` — per-clause call to
  `expand_translators` between `parse::parse` and the existing
  rewrite chain.
- `examples/primers/translator.d` + `translator-noinject.d` —
  BTF-resolution identity primer and a textual false-positive
  regression net; both wired into the primer sweep.

**Validation:** primer sweep PASS with `failures=0` (10
primers, incl. `translator` reading non-zero
`task_struct.se.sum_exec_runtime` and `translator-noinject`
preserving the literal `args[0]->prev->comm` from a `BEGIN`
clause). Full-demo sweep PASS with `drops=0`.

## Per-class drop attribution in the kernel

**Status:** Landed. SHMEM_VERSION bumped 4→5;
each per-CPU state entry widened from 64 B to 128 B to hold
two 4-element arrays (`dropped_records[CLASS]`,
`dropped_bytes[CLASS]`) indexed by PRINCIPAL / AGG / STKSTR /
DBLERR. `bifrost_shmem_reserve_kernel_class(size, class)` is
the entry point; the BPF kfunc `bifrost_kfunc_shmem_reserve`
defaults to PRINCIPAL while in-kernel pumps pass
`SHMEM_DROP_CLASS_AGG` (agg snapshot), `SHMEM_DROP_CLASS_STKSTR`
(VMA / symtab) explicitly. Host CLI's `print_shmem_drop_summary`
reports real per-class numbers; constant_pins.rs covers the new
identifiers; cross-layer drift check at SHA pin
`1cd208e55e46653e6693daaa3817e9af1045e3886084c90f98f4b580fa704994`.

**Validation:** full sweep passed with `failures=0` /
`drops=0` across 11 demos (compile-profile alone emitted
498 808 records with 0 drops).

## Suggested landing order for remaining work

1. **Per-CPU buffers.** Unblocks speculation, simplifies the agg
   reducers, and is the biggest user-visible win.
2. **Per-class drops.** Small touch on top of per-CPU buffers
   (each per-CPU ring already tracks one counter; extend to four
   classes).
3. **Aggregations — stddev first, then lquantize, then
   llquantize.** Each builds on the per-CPU reducer pattern.
4. **ERROR clauses.** Independent of the per-CPU work.
5. **Cross-process wake.** Becomes more
   useful after per-CPU buffers because decode cost drops.
6. **Typed translators.** Pure-host.
7. **walltimestamp/vtimestamp/progenyof.** Small touch each.
8. **tracemem/copyin/strings.** Independent kfunc set.
9. **Speculation.** Depends on per-CPU buffers.

## Architectural backlog from 2026-05-15 review

Findings from a layering/ethos review that did not block release but
should land as standalone work items.

- **Conduit policy bleed (high). Landed 2026-05-15.** The conduit
  no longer decodes Bifrost op codes. Op 8 (`SHMEM_INIT`) and op 9
  (`LOAD_PROG_STATUS`) were renamed to transport-level
  `OP_DATA_SHM_READY` / `OP_CTRL_RESPONSE`; op 9 carries opaque body
  bytes and is routed verbatim to the rsp ring as
  `KIND_RSP_PAYLOAD`. The `is_guest_load_prog(op==2)` sniffer in
  `shmem/consumer.rs` is gone — request/response intent is now
  expressed by the host CLI via a new `KIND_CTRL_PAYLOAD_REQ` ring
  entry kind, which the conduit forwards with an LE seq trailer
  appended. The host CLI parses the LOAD_PROG status body itself
  (see `decode_load_prog_status` in `control_shmem.rs`). Guest
  driver wire is unchanged — it still emits op=9 with the same
  status/detail layout, which is now opaque to the conduit. See
  `docs/virtio-conduit.md` § "Event-vq opcodes" / "Control-ring
  entry kinds".

- **D source rewriting is too textual (medium).**
  `host/bifrost/src/cli/source_rewrite.rs` does string `replace()`
  for stable-provider names and typed-translator expressions before
  parsing, so it can rewrite tokens inside strings/comments/host
  clauses. The DTrace-compatibility direction is a clause-aware or
  token-aware rewrite (or moving these rewrites into the parser
  itself as alias expansion). Currently bounded by the fact that
  no shipped scripts trigger the false-positive path, but the
  textual approach won't survive contributed scripts.

- **CLI architectural pressure (low).** `cargo clippy -D warnings`
  for `host/bifrost`, `host/virtio-conduit`, `host/bifrost-wire`,
  and `host/bifrost-support` flags type-complexity / too-many-args
  / lifetime forcing / missing safety docs, concentrated in
  `cli/runtime.rs` and `cli/wrapper.rs`. Not a correctness bug —
  the signal is that the CLI runtime wants decomposition before
  the next round of features (cross-process wake, agg reducers).

## Cross-references

- [`docs/dtrace-compatibility.md`](dtrace-compatibility.md) —
  current-state audit of which DTrace features Bifrost supports.
- [`docs/architecture.md`](architecture.md) — pipeline overview.
- [`docs/architecture-shmem.md`](architecture-shmem.md) — SHMEM
  data plane (single-ring today; per-CPU carve is the planned
  evolution).
- [`docs/virtio-conduit.md`](virtio-conduit.md) — generic
  transport contract (the cross-process wake plumbs through here).
