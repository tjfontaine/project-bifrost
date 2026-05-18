# Changelog

Capability-level summary of project-bifrost. For per-commit
detail use `git log`.

## DTrace parity close-out (May 14, 2026)

Completes the DTrace feature surface with real kernel-side
implementations; no stub kfunc bodies remain.

- **`dtrace:::ERROR` fault visibility for Bifrost-owned
  probes.** `bifrost_kfunc_note_fault()` bumps the per-CPU
  `BIFROST_DROP_CLASS_DBLERR` counter from every fault-prone
  Bifrost kfunc (`copyin`, `copyinstr`, `strlen`, `strchr`,
  `strrchr`, `strstr`, `progenyof`); the host CLI's drop
  summary renders this as `dblerr=N`. libdtrace's own
  `dtrace:::ERROR` continues to handle native-probe faults via
  the `host_script` passthrough.
- **`clear(@agg)`.** `bifrost_kfunc_clear_agg(struct
  bpf_map *map__map)` routes through the verifier's
  `KF_ARG_PTR_TO_MAP` path and walks every per-CPU value slot
  (PERCPU_ARRAY by index, PERCPU_HASH via `map_get_next_key`),
  zeroing them in place. Lowering emits a 5-instruction
  standalone program: `bpf_ld_map_fd + kfunc_call`.
- **`lquantize(value, base, upper, step)`.** New
  `AGG_KIND_LQUANTIZE = 5`; Apple's packed `(step, levels,
  base)` decoded from `action.arg`; BPF lowering emits a
  guarded `(value − base) / step + 1` with underflow / overflow
  clamps; host renderer formats linear bucket labels.
- **`llquantize(value, factor, low_mag, high_mag,
  steps_per_mag)`.** New `AGG_KIND_LLQUANTIZE = 6`; lowering
  unrolls a per-magnitude threshold compare (capped at 8
  magnitudes for verifier safety) plus a linear sub-bucket
  step within each magnitude band. Host log-linear renderer.
- **`normalize` / `denormalize` / `trunc` render-time hints.**
  `xagg::collect_libact_hints` scans every clause body at
  compile time and registers the divisor / row cap on the agg
  name; `dump_xagg_state_inner` divides each row by the divisor
  and caps the row list at the trunc N.
- **Speculative tracing.** Per-CPU `struct
  bifrost_spec_state` carves a 16-slot × 1 KB side buffer;
  `bifrost_shmem_reserve_kernel_class` routes there when a
  lane is active; `commit(id)` replays buffered records back
  through the principal sub-ring; `discard(id)` zeroes the
  buffer. Host action arms for `DTRACEACT_SPECULATE` /
  `_COMMIT` / `_DISCARD` (0x0601–0x0603) lower to direct
  kfunc calls — Bifrost supports both Apple's action
  encoding and the OpenDTrace DIF subr (10 / 41 / 46 / 47).
- **`tracemem(addr, len)` action.**
  `DTRACEACT_TRACEMEM = 6` / `_DYNSIZE = 7` recognized;
  `RecordSchema::for_tracemem` lays down a `Bytes` slot;
  lowering emits `bpf_probe_read_kernel(record + offset, len,
  addr)`; host renders a libdtrace-style hex/ASCII dump.
- **`vtimestamp`.** Reads `current->se.sum_exec_runtime` —
  the kernel scheduler's authoritative per-thread CPU-runtime
  counter — instead of aliasing `ktime_get_ns()`.

Seven primers ship in `examples/primers/` (`clear.d`,
`lquantize.d`, `llquantize.d`, `normalize-trunc.d`,
`speculate.d`, `tracemem.d`, `vtimestamp.d`). The runtime
sweep `examples/primers/sweep.sh` reports
`complete: failures=0` across all seven. `examples/run-full-sweep.sh`
reports `failures=0` (11/11 baseline demos PASS).

## Provider catalog and string/time builtins (May 13, 2026)

- **Per-class kernel drop attribution.** SHMEM_VERSION
  4 → 5. Per-CPU state carries `dropped_records[CLASS]` and
  `dropped_bytes[CLASS]` for PRINCIPAL / AGG / STKSTR / DBLERR.
- **`walltimestamp` + `progenyof`.** New kfuncs
  `bifrost_kfunc_walltime_ns` (CLOCK_REALTIME via
  `ktime_get_real_ns`) and `bifrost_kfunc_progenyof` (RCU-walk
  ancestor chain, depth-capped at 64).
- **String family.** Nine new kfuncs: `strlen`,
  `copyinstr`, `strchr`, `strrchr`, `strstr`, `index`,
  `strjoin`, `substr`, plus `copyin`. Three helper emit
  functions (`emit_{single,two,three}_arg_kfunc_subr`) thread
  DIF tuple-stack args through the kfunc-call ABI.
- **Cross-process wake FIFO.** Landed in the conduit +
  renderer for sub-millisecond latency on the kick path.

## Per-CPU principal buffer + stddev (May 12, 2026)

- **Per-CPU principal buffer.** SHMEM_VERSION 3 → 4.
  6 MB ringbuf carved into N per-CPU sub-rings (cap
  `SHMEM_NUM_CPUS_MAX = 16`). 50× drop reduction at
  `FIRE_GAP=0.05` on compile-profile (1.7M drops / 16 s → 35k
  drops / 16 s) plus 9.5× throughput increase.
- **`stddev()` aggregation.** Per-CPU 24-byte slot
  `[n, sum, sum_of_squares]`; kernel reducer
  `bifrost_map_lookup_stddev_u64`; host renderer computes
  `sqrt((sum_sq * n − sum²) / (n * (n−1)))`. Wire format
  gains a per-row `u32 v_size` so variable-width agg values
  ride alongside the existing 8-byte sum / min / max / avg.

## Wake-aware renderer, drop-summary format, BEGIN/END (May 12, 2026)

- **Wake-aware CLI direct renderer.** 10 ms baseline
  poll replaced with a tight 250 µs wake-aware cycle keyed on
  `data_wake_counter`.
- **`dtrace:::BEGIN` / `dtrace:::END`.**
  Identifier-only probes route through libdtrace via
  `host_script` passthrough.
- **DTrace-style drop summary.** `[bifrost] guest-ring
  drop summary: drops=N (principal=N agg=N stkstr=N dblerr=N)
  bytes=N` matches libdtrace's class-taxonomy line.
- **Stable provider catalog.** `syscall:::entry`,
  `proc:::exec`, `sched:::switch`, `io:::start`, `tcp:::send`,
  `signal:::send` (and family) rewritten to Linux raw
  tracepoints at parse time.
- **FEXIT `retval` access.** `rewrite_retval` looks up
  the target function's arity in vmlinux BTF and rewrites
  `retval` to `arg<arity>` inside fbt `:return` clauses.

## Wire-codec and conduit hardening

- Explicit LE wire codec across host/bifrost-wire.
- virtio-conduit hardening (CAS-backed cursor advance, drop
  attribution, capability handshake).
- Renderer recovery from lapped ringbuf state.

## Foundation

The cross-domain trace pipeline (macOS host with libdtrace +
Linux guest with eBPF, joined via a 16 MB SHMEM data plane)
landed as the foundation for the work above. Highlights:

- BFR7 wrapper format with kernel-resolved kfunc BTF ids
  (replaces the BFR6 compile-time fingerprint check, eliminates
  the BTF-staleness bug class).
- All four DTrace storage classes lowered to eBPF: built-in
  globals, user globals, thread-local (`self->`), clause-local
  (`this->`).
- `gustack()` cross-binary user-stack symbolication against
  the staged guest rootfs.
- `xstack()` — host + guest stitched call chain.
- Cross-domain aggregations (`@by_pid[gpid]` joining host and
  guest probe streams on a shared key).
- USDT support via `usdt:guest:<binary>:<provider>:<probe>`
  with kernel-resolved `.note.stapsdt` walking + automatic
  `ref_ctr_offset` semaphore handling.
- Smolvm pipeline integration replacing the legacy
  `bifrost_agent` PID-1 startup path; the `bifrost_guest`
  driver builds in-tree (`drivers/bifrost/`) against the
  in-process libdtrace consumer with a per-vCPU FIFO stitcher
  for multi-vCPU correctness.
