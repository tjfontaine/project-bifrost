# DTrace compatibility

Bifrost is "one D script, multiple kernels": a host-side libdtrace
consumer plus guest backends selected by target OS.  The current
shipping backend is Linux, which lowers guest clauses to eBPF
because Linux does not provide the native DTrace control surface
Bifrost needs.  FreeBSD is the first native-DTrace guest target;
illumos follows the same shape.

Native-DTrace guests are kernel-only integrations.  They do not run
a guest daemon, guest helper process, or in-guest `dtrace(1)`.
Control enters through the virtio conduit, and the guest kernel
publishes normalized records into the shared SHMEM stream.

The feature tables below describe the current Linux backend unless a
row explicitly says FreeBSD/illumos.  Linux-specific mechanisms such
as eBPF, BTF, kfuncs, and BFR7 are compatibility machinery, not the
architecture's center.

## D language

| Feature | Status | Notes |
|---|---|---|
| `BEGIN { … }` / `dtrace:::BEGIN` | Supported | Routed to libdtrace via host_script(); fires once at attach time. See [`examples/primers/end-clause.d`](../examples/primers/end-clause.d). |
| `END { … }` / `dtrace:::END` | Supported | Routed to libdtrace; fires once at consumer-exit (Ctrl-C, SIGTERM, `--duration-seconds`). Host-side actions (`printf`, `printa` on libdtrace-side aggs) only. Guest-side aggregations dump separately via the xagg path. |
| `ERROR { … }` / `dtrace:::ERROR` | Supported | libdtrace fires the clause for its own probes; Bifrost-owned probe faults bump the per-CPU `BIFROST_DROP_CLASS_DBLERR` counter (visible as `dblerr=N` in the host CLI's drop summary). Every fault-prone kfunc (`copyin`, `copyinstr`, `strlen`, `strchr`, `strrchr`, `strstr`, `progenyof`) is instrumented. Primer: `examples/primers/error-clause.d`. |
| `printf` | Supported | Standard libdtrace handling on the host side; bifrost-clause `printf` lowers to a recordable SHMEM payload. |
| `tracemem(addr, len)` | Supported | libdtrace's `DTRACEACT_TRACEMEM` lowers to a per-fire record carrying a `Bytes { max_len }` field; the addr DIFO computes the kernel pointer and `bpf_probe_read_kernel` copies `len` bytes (read from the value DIFO's `dtdt_size` for Apple libdtrace, falling back to `action.arg` for OpenDTrace) into the record body. The host renderer prints a libdtrace-style hex/ASCII dump. Primer: `examples/primers/tracemem.d`. |
| `copyin(addr, len)` / `copyinstr(addr)` | Supported. `bifrost_kfunc_copyin` and `bifrost_kfunc_copyinstr` copy from arbitrary user pointers into a per-CPU scratch buffer (`BIFROST_STR_MAX = 256` bytes); the kfunc result is a kernel pointer treated as `string` by BPF.  Faults bump the per-CPU `dblerr` counter. |
| `stack()` (kernel stack) | Supported as `gstack` | Same semantics, different name (guest kernel stack). Stable `stack()` synonym TODO. |
| `ustack()` (user stack) | Supported as `gustack` | Guest user stack with full ELF symbolisation. |
| `xstack()` | Supported | Bifrost-only: stitched cross-domain call chain. |
| `printa(@agg)` | Limited | Plain `printa(@agg)` works through libdtrace for host-side aggs and through xagg's renderer for guest-side aggs; format-string `printa("…", @agg)` not fully lowered. |
| `speculate()` / `commit()` / `discard()` | Supported. Per-CPU `struct bifrost_spec_state` carves a 16-slot × 1 KB side buffer; `bifrost_shmem_reserve_kernel_class` routes into the side buffer when the lane is active; `commit` replays buffered records back through the principal sub-ring; `discard` zeroes the buffer. `bifrost_kfunc_speculation` allocates lane id 1 per CPU (refuses concurrent lanes). Host action arms `DTRACEACT_SPECULATE/_COMMIT/_DISCARD` lower to direct kfunc calls. Primer: `examples/primers/speculate.d`. |
| `progenyof(pid)` | Supported. DIF_SUBR_PROGENYOF lowers to `bifrost_kfunc_progenyof` walking `current->real_parent` under RCU (depth-capped at 64). Primer: `examples/primers/progeny.d`. |

### Aggregations

| Aggregation | Status |
|---|---|
| `count()` | Supported |
| `sum()` | Supported |
| `min()` / `max()` | Supported |
| `avg()` | Supported |
| `quantize()` (power-of-two) | Supported |
| `lquantize()` (linear) | Supported. Apple's packed `(step, levels, base)` decoded from `action.arg`; BPF lowering emits a guarded `(value - base) / step + 1` with underflow/overflow clamps; host renderer formats linear bucket labels via `lquantize_bucket_label`. Primer: `examples/primers/lquantize.d`. |
| `llquantize()` (log-linear) | Supported. Per-magnitude unrolled threshold-compare followed by linear sub-bucket math (capped at 8 magnitudes); host renderer formats labels via `llquantize_bucket_label`. Primer: `examples/primers/llquantize.d`. |
| `stddev()` | Supported — per-CPU `[n, sum, sum_of_squares]` slot; kernel reducer `bifrost_map_lookup_stddev_u64`; host xagg renderer computes `sqrt((sum_sq * n - sum²) / (n * (n-1)))`. Primer: `examples/primers/stddev.d`. |
| `clear(@agg)` / `normalize` / `denormalize` / `trunc` | Supported. `clear` lowers to a 5-insn standalone program calling `bifrost_kfunc_clear_agg(struct bpf_map *)`, which walks every per-CPU value slot (PERCPU_ARRAY by index, PERCPU_HASH via `map_get_next_key`) and zeroes it. `normalize` / `denormalize` / `trunc` are scanned out of every clause body at compile time and registered as render-time hints on `xagg_state`; `dump_xagg_state` divides per-row values by the divisor and caps the row list at the trunc limit. Primer: `examples/primers/clear.d`, `examples/primers/normalize-trunc.d`. |
| `@agg["key1", "key2"]` multi-key | Supported |
| `@agg = func()` cross-domain | Supported (`xagg`) — Bifrost-only |

### Built-in variables

| Variable | Status | Notes |
|---|---|---|
| `timestamp` | Supported | `bpf_ktime_get_ns` (monotonic ns). |
| `vtimestamp` | Supported. Reads `current->se.sum_exec_runtime` — the kernel scheduler's authoritative per-thread CPU-time counter. Advances at scheduler-runtime scale (not wall-clock), so `vtimestamp_delta < timestamp_delta` for any thread that isn't pinned on-CPU 100% of the time. Primer: `examples/primers/vtimestamp.d`. |
| `walltimestamp` | Supported. `bifrost_kfunc_walltime_ns()` calls `ktime_get_real_ns()` (CLOCK_REALTIME ns since the Unix epoch). Primer: `examples/primers/walltimestamp.d`. |
| `pid` | Supported | `bpf_get_current_pid_tgid() >> 32`. |
| `tid` | Supported | `bpf_get_current_pid_tgid() & 0xFFFF_FFFF`. |
| `execname` | Supported | `bpf_get_current_comm` into the EXECNAME_SCRATCH slot. |
| `arg0`..`arg9` | Supported | Loaded from the BPF context. |
| `cpu` | Supported | `bpf_get_smp_processor_id`. |
| `ppid` / `uid` / `gid` | Roadmap | `task_struct` field reads via the existing BTF CO-RE machinery. One lowering arm per var, ~½ day total. |
| `errno` (on FEXIT) | Roadmap | The `retval` rewriter covers FEXIT return values; surfacing the negative-errno-as-`errno`-builtin is a thin adapter on top. |
| `caller` / `ucaller` | Roadmap | Top frame of the kernel / user stack at probe entry; can lift from the existing `gstack` / `gustack` lowering. |
| `probeprov` / `probemod` / `probefunc` / `probename` | Roadmap | Per-probe constant string slots; populated at LOAD_PROG time alongside `probe_id`. |
| `stackdepth` / `ustackdepth` | Roadmap | Count frames returned by the existing stack helpers. |
| `zonename` / `ipl` / `epid` / `id` | Out of scope | Solaris-specific scheduling and identification concepts that don't translate to Linux. |

### Storage classes

| Class | Status |
|---|---|
| Globals (`n = n + 1`) | Supported — HASH map keyed on var_id |
| Thread-locals (`self->t0 = timestamp`) | Supported — HASH map keyed on `(pid_tgid << 32) | var_id` |
| Clause-locals (`this->x = arg0`) | Supported — stack slots with prologue zero-init |
| Arrays / structs / unions | Limited — BTF CO-RE for typed struct field deref; standalone arrays in D-source not lowered |

## Providers

| Provider | Status | Notes |
|---|---|---|
| FreeBSD `syscall:::` / `fbt:*:*:*` | In progress | FreeBSD is the first native-DTrace guest backend. The current kernel-only proof preloads FreeBSD modules, accepts a host native-DTrace session payload, compiles or loads host-supplied DOF, runs it through a kernel DTrace state, drains supported `trace(uint64_t)` records into Bifrost data SHM, and returns explicit success/failure with no guest userspace agent and no guest `dtrace(1)`. Provider coverage remains follow-up work. |
| illumos native providers | Planned | Same kernel-only native-DTrace backend contract as FreeBSD.  Provider/argument differences stay backend-local. |
| `bifrost:guest_kernel:func:entry` / `:return` | Retired in favor of `fbt:` | Parser flags with a migration diagnostic. |
| `fbt:guest:func:entry` (FENTRY) | Supported | BPF trampoline attach. |
| `fbt:guest:func:return` (FEXIT) | Supported | Slice 2 landed the attach path; slice 3 retval/`args[N]` access landed via `rewrite_retval` — D scripts use `retval` (or `args[arity]`) inside fexit clauses and the bifrost CLI rewrites it to `arg<arity>` after looking the function's arity up in vmlinux BTF. Demo: `examples/failed-opens`. |
| `tracepoint:guest:category:event` | Supported | Raw tracepoint attach. |
| `uprobe:guest:binary:func:entry` / `:return` (host-resolved) | Supported | Host CLI resolves ELF symbol → file offset via the staged rootfs. |
| `uprobe:guest:binary:func:entry` / `:return` (kernel-resolved by symbol) | Supported | Driver does `kern_path → igrab → bifrost_helper_resolve_symbol`. Demo: `examples/redis-uprobe`. |
| `usdt:guest:binary:provider:probe` | Supported | Stable USDT trailer; driver walks `.note.stapsdt`. Demo: `examples/postgres-usdt`. |
| `profile-N` (profile sampling at N Hz) | Stubbed | `examples/profile-stub` exercises the sample-record plumbing. Full periodic-sample provider is a planned follow-on. |
| `tick-N` | Roadmap | Single-CPU periodic timer probe.  Linux equivalent: `bpf_timer` on a single CPU, or a perf-event hrtimer.  ~½ day on top of the profile-N scaffold. |
| `syscall:::entry` / `:return` (stable all-syscalls) | Supported | `rewrite_per_syscall` in `host/bifrost/src/cli/source_rewrite.rs` translates `syscall:::entry` → `tracepoint:guest:raw_syscalls:sys_enter` and `syscall::<name>:entry` → `tracepoint:guest:syscalls:sys_enter_<name>` (works for any kernel syscall). Demo: `examples/primers/syscall-counts.d`. |
| `proc:::exec` / `:exit` / `:fork` / `lwp-start` | Supported | Stable name → `tracepoint:guest:sched:sched_process_*` mapping in the catalog. `args[0]->pr_pid` resolves via the parser-aware typed-translator expander (`host/bifrost/src/translators.rs`). |
| `sched:::switch` / `:on-cpu` / `:off-cpu` / `:wakeup` / `:wakeup-new` / `:migrate-task` | Supported | Stable name → `tracepoint:guest:sched:sched_*`. on-cpu and off-cpu both map to `sched_switch`; users predicate by side via `pid == next_pid` / `pid == prev_pid` until a body-rewrite synthesises the binding. |
| Typed-arg translators (`args[N]->field->subfield`) | Supported (parser-aware, BTF-driven, depth ≤ 4) | Canonical chains (`args[0]->prev->comm`, `prev->pid`, `next->comm`, `next->pid`, `pr_pid`) map to the matching `argN` builtin byte-identically to the simple-arg case; non-canonical chains (e.g. `args[0]->prev->se.sum_exec_runtime`) resolve through the host's vmlinux BTF, emit one CORE_OFFSETOF sentinel per hop, and lower to a single `bpf_probe_read_kernel`. Chain depth ≤ 4 and ≤ 8 chains per clause; user-VA pointer chases rejected at host-side BTF resolution. See `examples/primers/translator.d` + `examples/primers/translator-noinject.d`. |
| `io:::start` / `:done` / `:insert` | Supported | Stable name → `tracepoint:guest:block:block_rq_*`. |
| `tcp:::send` / `:receive` / `:probe` / `:retransmit` / `:destroy` | Supported | Stable name → `tracepoint:guest:tcp:tcp_*`. Translators for the `tcp:tcp_*` arg shapes are not yet wired. |
| `signal:::send` / `:handle` | Supported | Stable name → `tracepoint:guest:signal:signal_*`. |
| `vminfo:::` / `sysinfo:::` / `mib:::` / `lockstat:::` | Out of scope | Solaris kernel-statistic providers backed by `kstat`.  Linux exposes the same shapes through `/proc/vmstat`, `/proc/diskstats`, `tracepoint:vmscan:*`, `tracepoint:lock:*` — scripts that want this data should attach to the Linux-native equivalents via the stable provider catalog. |
| Anonymous tracing (boot-time, pre-attach) | Out of scope | Bifrost requires a CLI attached to libkrun. The guest driver could be extended to support pre-attach probes, but the model isn't on the punch list. |

## Data plane

| Capability | Status | Notes |
|---|---|---|
| 16 MB SHMEM principal ring carved into per-CPU sub-rings | Supported | V4 layout; one cache line of producer/consumer/drops per CPU at offset 128+cpu*64. Producer picks via `smp_processor_id() % num_cpus`; consumer round-robins drain. Measured 50× drop reduction on `compile-profile` at FIRE_GAP=0.05 vs the single-ring baseline. |
| Aggregation buffers (BPF percpu maps + snapshot push) | Supported | Aggs maintained in per-CPU BPF maps; snapshots pushed through SHMEM. |
| Speculation buffers | Supported. Per-CPU `struct bifrost_spec_state` carves a 16-slot × 1 KB side buffer; reserve routes there when a lane is active; commit replays into the principal sub-ring. |
| Buffer policies: `ring` (overwrite) | Supported | The current always-wrap kernel CAS-claim path. |
| Buffer policies: `fill` (stop-at-full), `switch` (double-buffer) | Roadmap | The per-CPU principal buffer makes drop counts a per-class statistic rather than a backpressure event, so a `fill`-mode user gets the same observability via the drop summary.  Real `fill` (stop tracing once any sub-ring saturates) is a small per-CPU flag check on top of the existing reserve path; `switch` (atomic double-buffer flip) is the larger change. |
| Drop counters (kernel-side, total) | Supported | One counter pair: records + bytes. |
| Per-class drop counters (`principal`/`agg`/`stkstr`/`dblerr`) | Format-aligned; populated only `principal` today | User-visible summary line follows DTrace's taxonomy. Per-class lowering is a planned follow-on. |
| Wake-driven consumer | Hybrid polling+wake-aware | 1 ms baseline + 250 µs fast path triggered by drop observation OR `data_wake_counter` advancing OR producer movement; matches the ≤ 1 ms timeout-fallback contract. |
| Cross-process Condvar / eventfd plumbing | Supported. FIFO-backed cross-process wake landed alongside the 250 µs poll cadence — `conduit` publishes a wake fd alongside `data_wake_counter`; the renderer subscribes via `kqueue`/`EVFILT_READ`.  Combined median latency ≤ 200 µs on the kick path. |

## CLI / tooling

| Feature | Status |
|---|---|
| `bifrost -l` (list probes) | Supported — guest_kernel only; the full provider catalog is planned. |
| `bifrost -s script.d` | Supported. |
| `bifrost -n 'inline expression'` | Supported. |
| `bifrost -p <pid>` | Supported. |
| `bifrost attach <pid>` (already-running libkrun) | Supported. |
| `bifrost ls` (discovery) | Supported. |
| `bifrost data <pid>` (data SHM dump) | Supported. |
| `dtrace -A` (anonymous trace setup) | Out of scope. |
| `dtrace -G` (DOF object) | Out of scope — we emit BFR7. |
| `dtrace -V` | Out of scope. |
| `dtrace -i` (postmortem) | Out of scope. |
| `--emit-ebpf /tmp/foo.bfr7` (offline wrapper inspection) | Supported — Bifrost-only convenience. |

## Drop reporting

The guest-side data ring's drop summary follows DTrace's format
even when only one class is populated, so a DTrace reader can scan
it the same way as `dtrace summary: drops=N (principal=N agg=N
…)`:

```
[bifrost] guest-ring drop summary: drops=161835
    (principal=161835 agg=0 stkstr=0 dblerr=0) bytes=376487680
```

Per-class accounting is a planned follow-on.

## What we have that DTrace doesn't

- `xstack()` — host + guest stitched call chain.
- `xagg()` — cross-domain aggregations keyed across host probes
  and guest probes via shared keys (`pid`, `gpid`).
- Full ELF symbolisation of guest user-stack frames against a
  staged rootfs.
- vDSO ELF extraction from vmlinux for symbolic guest-vDSO frames.
- "One D script, two kernels."

## See also

- [`docs/architecture.md`](architecture.md) — pipeline overview
  with the data-flow diagram.
- [`docs/architecture-shmem.md`](architecture-shmem.md) — SHMEM
  data plane layout, latency model, memory ordering.
- [`docs/virtio-conduit.md`](virtio-conduit.md) — generic
  transport contract.
- [`docs/bifrost-protocol-inventory.md`](bifrost-protocol-inventory.md)
  — inventory of Bifrost-semantic surfaces on top of the generic
  transport.
