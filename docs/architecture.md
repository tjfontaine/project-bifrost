# Architecture

The bifrost pipeline. For the deep-dive on the SHMEM data plane
specifically, see [architecture-shmem.md](architecture-shmem.md).
For the generic transport that carries the data plane between the
VMM and the application, see
[virtio-conduit.md](virtio-conduit.md).

## One rule

**DTrace DOF is the guest control-plane IR, and SHMEM is the
generic data plane.**

- The host compiles D to DOF on macOS, packages it in a
  `DTRACE_SESSION_V1` envelope (see `host/bifrost-wire/src/
  session_envelope.rs`), and ships the bytes opaquely through
  virtio-conduit.
- Each guest kernel module decodes the same envelope against
  `crates/bifrost-dtrace-lower` (a `no_std` lowering crate owned by
  this repo), then drives a local `KernelAdapter` to talk to its
  native tracing engine (eBPF on Linux, native DTrace state on
  FreeBSD/illumos).
- libkrun stays payload-opaque: it forwards SHMEM offsets, copies
  control descriptors, and delivers doorbells. No DTrace knowledge.
- Records flow back as SHMEM v6 semantic envelopes (see
  `host/bifrost-wire/src/shmem_v6.rs`): `TRACE_RECORD`,
  `AGG_SNAPSHOT`, `STATUS`, `DROP_SUMMARY`, `SYMBOL_TABLE`,
  `STACK_TABLE`, `OS_METADATA`. The transport mechanism — 16 MB
  virtio shared-memory region, per-CPU SPSC rings, doorbells — is
  unchanged; only the record vocabulary is generalized.

## Guest backend model

Bifrost is a cross-domain DTrace coordinator.  The generic part is
session planning, target routing, the DTrace session envelope, SHMEM
transport, host rendering, and cross-domain ordering.  The guest
runtime is selected by guest OS — but the *host control payload* is
the same `DTRACE_SESSION_V1` envelope for every target:

| Guest OS | Backend | Lowering location | KernelAdapter impl |
|---|---|---|---|
| Linux | DIF → eBPF compatibility backend | `crates/bifrost-dtrace-lower` in the Linux driver | `drivers/bifrost/` |
| FreeBSD | native kernel DTrace backend | DOF interpreter in the FreeBSD bridge | `guest/freebsd-bifrost/` |
| illumos | native kernel DTrace backend (planned) | DOF interpreter in the illumos bridge | future |

Linux is the unusual backend because it does not expose the native
DTrace kernel control plane Bifrost needs. Its eBPF lowering, BTF
relocations, kfuncs, and program loader are therefore Linux-specific
machinery — but they live in the **guest kernel module**, not the
host CLI, so the host stays OS-agnostic. FreeBSD is the first
native-DTrace guest target; illumos follows the same contract.

### Historical: BFR7 / LOAD_PROG

Before the DOF-generic rebuild, the host CLI lowered D to eBPF and
shipped pre-built BFR7 wrappers / LOAD_PROG_BATCH payloads
to the Linux guest. The BFR7 constants in `bifrost-wire` and the
historical fixtures under `host/bifrost-wire/tests/` are preserved
so old recordings still decode, but no live host path produces
them. `scripts/check-no-active-bfr7.sh --strict` is the gate that
enforces this; once flipped to strict in CI, any new active producer
fails the commit.

Native-DTrace guests do **not** run a guest daemon, helper process,
or in-guest `dtrace(1)`.  The guest integration point is the booted
kernel or preloaded kernel modules: a Bifrost conduit driver receives
host control messages and publishes normalized records into SHMEM.
The current FreeBSD proof accepts a host control payload, drives a
host-selected DOF session through native kernel DTrace state creation,
load/start/drain/stop/destroy, publishes supported `trace(u64)`
records with host-side schema metadata, and returns explicit
success/failure.  The root filesystem image remains unmodified.

## Ownership boundaries

Bifrost is intentionally split into four layers with explicit
responsibilities. Reviewers should be able to read the directory
tree and match it to this list:

- **`host/bifrost/`** — DTrace parsing, session planning, guest
  backend selection, Linux DIF→eBPF lowering, Linux BFR7 wrapper
  construction, backend-specific load payload construction,
  **direct data-SHM rendering**, and user-visible CLI output. Owns
  Linux vmlinux BTF resolution, ELF symbol tables, vDSO extraction,
  schema decoding, aggregation rendering. The user-facing surface.
- **`host/bifrost-wire/`** — Bifrost semantic wire constants and
  codecs (record headers, status responses, Linux BFR7 wrapper,
  field relocs). `no_std`. The single source of truth shared by the
  Linux backend; the Linux guest copy is vendored with a SHA pin
  (see `scripts/check-proto-drift.sh`) and the libkrun layer no
  longer consumes Bifrost wire bytes at all.
- **`host/bifrost-support/`** — focused shared host/libkrun support
  crate (record schema, ELF symbol table, vDSO). Same code can
  serve libkrun adapters if they ever need it; the full
  `host/bifrost` crate is forbidden from libkrun's dependency tree
  (enforced by `scripts/check-crate-graph.sh`).
- **`host/virtio-conduit/`** — **generic** virtio conduit core.
  Owns control/data shared-memory plumbing, opaque payload
  forwarding, doorbell wake accounting. Knows nothing about
  Bifrost, BFR7, schemas, BTF, kallsyms, VMA tables, or DTrace
  rendering. Full contract:
  [virtio-conduit.md](virtio-conduit.md).
- **`third_party/smolvm/libkrun/`** — VMM-side adapter. Owns
  virtio-mmio registration, shared-memory-region exposure,
  descriptor copies, IRQ signaling, and event-manager
  integration. Treats LOAD_PROG bytes as opaque. The historic
  semantic-rendering code has been removed.
- **`third_party/linux-bifrost/drivers/bifrost/`** — Linux guest
  backend. Owns BPF verification/JIT/attach, the Linux LOAD_PROG byte
  parser, and the Linux producer for the common Bifrost SHMEM record
  layout. In-tree built-in driver (no module loading).
- **`guest/freebsd-bifrost/`** — FreeBSD guest backend. Owns the
  FreeBSD virtio conduit endpoint, the kernel-only host-DOF
  `dtrace_bifrost` wrapper proof, and the planned dynamic bridge
  into FreeBSD DTrace internals. It must not depend on a guest
  userspace daemon or on running `dtrace(1)` in the guest.

## Data flow

```
                ┌────────────────────────────────────────────┐
                │           macOS dtrace -s script.d         │
                │     (host probes + bifrost: clauses)       │
                └────────────────────┬───────────────────────┘
                                     │ libdtrace compiles D → DIF
                                     ▼
┌─────────────────────────────────────────────────────────────┐
│  host/bifrost (Rust)                                         │
│   • Session planner selects a guest backend                  │
│   • Linux backend: DIF instruction stream → eBPF bytecode    │
│   • FreeBSD/illumos backend: native kernel-DTrace load state │
│   • Resolves vmlinux BTF (CO-RE for typed deref / OFFSETOF)  │
│   • Picks kfuncs (exe_path, vma_table, shmem_*) per program  │
│   • Pre-flight static checker                                │
│   • Direct data-SHM record rendering (CLI render thread)     │
└────────────────────┬────────────────────────────────────────┘
                     │ Backend load payload
                     │   Linux: BFR7-derived LOAD_PROG
                     │   FreeBSD/illumos: kernel-DTrace session payload
                     │ → host/virtio-conduit control SHM (opaque bytes)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  third_party/smolvm/libkrun (generic conduit adapter)        │
│   • virtio-mmio device (3 virtqueues + shared-memory region) │
│   • Opaque control-payload forwarding (cmd_ring → VQ_CTRL,   │
│     VQ_EVENT → rsp_ring)                                     │
│   • Doorbell EventFd → conduit wake_counter increment        │
│   • No Bifrost semantic state (no BFR7 parse, no schema, no  │
│     VMA cache, no symbol cache, no record dispatch)          │
└────────────────────┬────────────────────────────────────────┘
                     │ HVF / krunvm
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  guest Linux 6.12.76 (linux-bifrost submodule)               │
│   • In-tree built-in driver at drivers/bifrost/: virtio      │
│     driver, BPF prog patcher, kprobe/uprobe registration.    │
│     device_initcall runs before any rootfs pivot — no .ko,   │
│     no module loading.                                       │
│   • Bounded LOAD_PROG layout parser (load_prog_parse.rs);    │
│     all multi-byte wire reads use explicit LE byte copy so   │
│     odd-length string trailers don't make later u64 / map /  │
│     instruction reads unaligned.                             │
│   • BPF kfuncs in kernel/bpf/helpers.c: current_exe_path,    │
│     emit_vma_table, publish_vma_table, shmem_reserve,        │
│     shmem_submit, shmem_kick                                 │
│   • Standard kernel BPF verifier + JIT (with one custom      │
│     verifier hook for shmem_reserve's PTR_TO_MEM return)     │
└─────────────────────────────────────────────────────────────┘
                     │
             ┌───────┴────────┐
             │                │
             ▼                ▼
    ┌──────────────┐   ┌──────────────────────┐
    │  kprobe      │   │  OCI image entrypoint │
    │  on syscall  │   │  as PID 1 (e.g. redis)│
    └──────────────┘   └──────────────────────┘
```

## SHMEM data plane

A 16 MB region exposed to the guest as a **virtio shared-memory
region** (region 0, default `VIRTIO_SHM_REGION_SIZE = 16 MB`). The
libkrun adapter publishes a host-mapped pointer through
`mem.get_host_address(...)`; the guest driver maps the same range
via the virtio-mmio shared-memory-region registers. Both sides
read/write directly — **no virtqueue copies for any record payload,
BTF, kallsyms, or VMA table.**

A legacy `vmalloc`/PFN-ferry path (`SHMEM_INIT n_pages > 0`) was
the original Phase 1 transport. It is now rejected at the conduit
event handler; the guest is expected to use the virtio
shared-memory region. The legacy code path is kept only as a
documented compatibility branch and is not exercised by any
shipping configuration.

| Sub-region | Size | Use |
|---|---|---|
| Header | 4 KB | magic, version, cursor pair, sub-region offsets |
| Event ringbuf | 6 MB | gustack / printf / scalar trace records |
| BTF | 6 MB cap | vmlinux BTF (~4.6 MB used) — CO-RE relocation target |
| kallsyms | 2 MB cap | sorted (addr, name) pairs for `stack()` symbolication |
| VMA cache | ~2 MB | reserved for per-(tgid, exec_id) VMA tables |

BPF programs allocate ringbuf space via `bifrost_kfunc_shmem_reserve`
(atomic CAS on `producer_pos`), write the record body directly,
and submit via `bifrost_kfunc_shmem_submit` (release-store on a
ready bit). The host data-plane consumer thread polls
`producer_pos` and the wake_counter, walks records, dispatches each
through the renderer, and advances `consumer_pos`. Wakeup uses a
third virtqueue (`VQ_DOORBELL`) whose kick triggers an HVF MMIO
trap → libkrun signals the conduit's doorbell `EventFd` → the
conduit worker increments the control-SHM
`data_wake_counter`.

Full design rationale and protocol details:
[architecture-shmem.md](architecture-shmem.md). The transport
contract for the virtio device and control SHM is in
[virtio-conduit.md](virtio-conduit.md).

## Performance

Three latency numbers are easy to conflate. Pull them apart:

1. **HVF MMIO doorbell trap cost** — guest-side virtqueue kick to
   host-side wake. One-shot spike, 64 iterations:

   | | ns |
   |---|---|
   | min | 2 333 |
   | **median** | **3 333** |
   | avg | 3 873 |
   | max | 11 291 |

   This is the wake-latency *floor*, not the end-to-end CLI
   render latency.

2. **libkrun conduit consumer wake cadence** — the conduit's
   doorbell worker thread (`host/virtio-conduit/src/shmem/consumer.rs`)
   waits on the host-side doorbell `EventFd` with a 1 ms
   `kevent` (macOS) or `poll(2)` (Linux) timeout. On wake it
   drains the eventfd and increments the control-SHM
   `data_wake_counter` so observers know the producer has fresh
   data. Wake-counter advance latency: ~doorbell trap cost +
   syscall return = 3–15 µs in the kicked path, or up to 1 ms in
   the timeout-fallback path.

3. **CLI direct-render record visibility latency** — the user-
   visible number. The bifrost CLI render thread
   (`host/bifrost/src/cli/runtime.rs` direct-render loop) is
   wake-driven on a 250 µs polling cadence:

   - **Baseline + fast path: 250 µs.** Both tiers land at the
     same cadence today. Each iteration the renderer atomically
     loads the conduit-published `data_wake_counter` and the
     ring's `producer_pos`; either advancing triggers an
     immediate drain on the same cycle. (The two-tier branch is
     preserved in source for future per-CPU-buffer routing.)
   - **FIFO wake fast path.** The renderer also `poll(2)`s the
     conduit-published wake FIFO (`/tmp/bifrost-wake-<pid>`).
     The conduit's doorbell worker writes one byte on every
     wake-counter increment, so a burst of guest records is
     visible to the renderer in the next poll cycle without
     waiting the full timeout. If the FIFO is unavailable
     (older conduit, mkfifo race) the renderer falls back to
     plain sleep.
   - **Timeout floor: ≥ 1 ms.** `poll(2)` timeouts round up to
     a 1 ms minimum (the smallest unit `poll` accepts), which
     satisfies the "≤ 1 ms timeout fallback" contract.

   Per-cycle drain limit: 65536 records (large enough for one
   full ring at typical record sizes). The renderer never blocks
   on the doorbell directly — that wake is consumed by the
   libkrun conduit consumer one layer down, which then nudges
   the wake counter and FIFO.

   Practical implication: under steady load the user observes
   records within ≤ 1 ms of the BPF program writing them, and
   typically within one 250 µs poll cycle once the FIFO byte
   arrives. Microsecond claims for "record visibility" *still*
   describe the doorbell trap cost, not end-to-end render
   latency.

A fresh end-to-end measurement is captured alongside each
release-candidate build, recording the hardware, workload, and
timestamped numbers.

### Boot

The conduit publishes the virtio shared-memory region size and
host-side POSIX SHM name through the control SHM header. After
that, BTF (~4.6 MB) and kallsyms (~1.5 MB) are read straight out
of the data SHM — no chunked virtqueue traffic. Total boot
ctrl-plane traffic before the first `LOAD_PROG`: under one page,
versus ~6 MB across ~95 chunked virtqueue messages on the
pre-SHMEM data plane.

## Repository layout

```
project-bifrost/
├── host/
│   ├── bifrost/          # CLI + DIF → eBPF lowering + direct renderer (Rust)
│   │   ├── src/lower/          # Per-instruction lowering
│   │   ├── src/btf.rs          # vmlinux BTF parser
│   │   ├── src/elf_syms.rs     # On-disk ELF symtab parser
│   │   ├── src/vdso.rs         # vDSO ELF extraction from vmlinux
│   │   ├── src/schema.rs       # Record schema definitions
│   │   ├── src/verify.rs       # Pre-flight static checker
│   │   ├── src/control_shmem.rs # /conduit-<pid> client (attach side)
│   │   ├── src/cli/runtime.rs   # Direct data-SHM renderer thread
│   │   ├── src/cli/direct_load.rs # LOAD_PROG payload builder (LE-explicit)
│   │   └── src/bin/bifrost.rs   # CLI runner
│   ├── bifrost-wire/     # Bifrost semantic wire (no_std) — canonical
│   │                     #   protocol crate; SHA-pinned vendored copy
│   │                     #   in third_party/linux-bifrost/drivers/bifrost/
│   ├── bifrost-support/  # Focused host/libkrun shared support (schema,
│   │                     #   ELF symbol tables, vDSO)
│   ├── virtio-conduit/   # GENERIC virtio conduit core
│   │                     #   (control SHM + data SHM plumbing).
│   │                     #   Contract: docs/virtio-conduit.md
│   └── runtime/          # Shell wrappers for the bifrost CLI (NOPASSWD sudoers scope)
│       ├── bifrost              # CLI binary (cp'd from host/bifrost/target/release/)
│       │                         #   (add host/runtime/ to PATH; .envrc
│       │                         #    bundled for direnv users)
│       ├── cleanup.sh           # kill stuck bifrost / dtrace procs
│       ├── stage-smolvm.sh      # cargo build -p smolvm + entitlement re-sign
│       ├── stage-libkrun.sh     # cp + adhoc-codesign smolvm libkrun.dylib
│       └── stage-libkrunfw.sh   # cp + adhoc-codesign smolvm libkrunfw.5.dylib
├── third_party/
│   ├── linux-bifrost/    # SUBMODULE — patched 6.12.76 kernel with the
│   │                     #   bifrost driver in-tree at drivers/bifrost/
│   │                     #   plus the 0028+ commits applied as a series.
│   │                     #   Patches mirrored under
│   │                     #   third_party/smolvm/libkrunfw/patches/.
│   └── smolvm/           # SUBMODULE — vendored smolvm (canonical)
│       ├── libkrun/      # smolvm libkrun fork; thin conduit adapter at
│       │                 #   src/devices/src/virtio/conduit/.
│       ├── libkrunfw/    # smolvm libkrunfw fork (carries kernel patches)
│       ├── smolvm-sdk/   # SDK crates (crates re-export)
│       └── src/agent/    # smolvm-agent (in-guest exec helper)
├── tools/
│   └── rebuild-driver    # Atomic rebuild pipeline: linux-bifrost →
│                         #   libkrunfw → libkrun → smolvm (codesigned)
├── docs/                 # Design notes (this file, architecture-shmem.md,
│                         #   virtio-conduit.md, bifrost-protocol-inventory.md,
│                         #   kernel-patches.md, troubleshooting-rebuilds.md)
├── examples/             # D-script demos
│   ├── primers/                     # Single-feature pattern primers
│   └── <demo>/                      # Self-contained demo dirs:
│       ├── probe.d                  #   - the D source
│       ├── run.sh                   #   - workload driver
│       ├── README.md                #   - what it shows
│       └── expected-output.txt      #   - sample successful run
└── scripts/              # Misc dev helpers (verify-patches, check-*-drift)
```

Licensing: Apache-2.0 throughout `host/`. `third_party/smolvm/` is
Apache-2.0 with submodules carrying their own licenses (notably
libkrunfw patches are GPL-2.0). The Linux kernel under
`third_party/linux-bifrost/` is GPL-2.0; the bifrost driver
(`drivers/bifrost/`) is GPL-2.0 like the rest of Linux. See
[../AGENTS.md](../AGENTS.md) for the full table.
