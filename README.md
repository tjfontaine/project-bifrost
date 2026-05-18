# Project Bifrost

**One DTrace script, two kernels.**

## Quick start (fresh M-series Mac)

```sh
git clone https://github.com/tjfontaine/project-bifrost && cd project-bifrost
scripts/first-run.sh
BIFROST_LIVE=1 examples/cross-kernel-linux-fbsd-x2/run.sh
```

That's the whole install path: `first-run.sh` walks the toolchain
gates, builds the bifrost CLI + smolvm + libkrun, fetches the
FreeBSD 14.3 QCOW2, and validates the install with a plan dry-run.
The second command boots a Linux smolvm and a FreeBSD QEMU guest
in parallel, drives them from one D source, and emits a merged
record stream plus one cross-kernel `@latency` quantize histogram.

If anything fails, `scripts/diagnose.sh` names the bucket so the
fix is one paste-ready command away.

---

Bifrost lets a single D script trace both a macOS host *and* a
Linux microVM running on top of it. Host syscalls, guest kernel
kprobes, and guest userspace stacks merge into one time-ordered
output stream, surfaced through the same `dtrace` binary that
ships with macOS. macOS `dtrace` cannot see a Linux kernel.
Linux eBPF cannot see a macOS process. Bifrost stitches both,
with full symbol resolution against the guest's on-disk binaries
— including the vDSO blob embedded in vmlinux.

You'd reach for it when:

- You're debugging a containerized service from a macOS dev
  machine and want to know what it's actually doing — every
  file open, every kernel function, with full call stacks.
- You have a macOS process talking to a guest service via a
  socket and one side is silently misbehaving. You want the
  trace from "I sent the byte" to "the guest opened the wrong
  file" in one stream.
- You're profiling a microVM workload (krun, Apple Container,
  Lima) and want call-graph data for the guest binary, not the
  hypervisor's view.
- You already know D and would rather not learn bpftrace.

## Quick demo

Bifrost runs on top of vendored smolvm at `third_party/smolvm`.
No Docker required, no rootfs staging — just a stock OCI image as
PID 1 in a smolvm-launched microVM, with the bifrost CLI attaching
to the libkrun process via the SHM control plane:

```sh
# One-shot end-to-end demo: boot redis in a fresh smolvm, attach a
# raw tracepoint wrapper for sched_switch, and surface guest kernel
# records on stdout.
examples/redis-smoke-test/run.sh
# → "✓ end-to-end cross-domain trace working"
# → "records observed in CLI output: 273"
```

Each line of output looks like:
```
guest_kernel:sched_switch:entry vmid=0 probe_id=1 \
    gns=0x1c240b0c0 gpid=234 value=0x1
```
where `gpid` is the guest task PID. The full integration chain —
BTF plumbing, BFR7 wrapper format, raw tracepoint attach, and SHMEM
record delivery — is documented in [docs/architecture.md](docs/architecture.md).

## Listing available probes

`bifrost -l` is the analog of `dtrace -l`. It walks the guest
kernel's symtab on disk (no VM boot, no sudo) and emits one
probe spec per kprobe-able function:

```sh
$ bifrost -l | wc -l
   97379

$ bifrost -l 'tcp_v4_connect'
  ID   PROVIDER     MODULE                                         FUNCTION NAME
   1   bifrost      guest_kernel                             tcp_v4_connect entry
   2   bifrost      guest_kernel                             tcp_v4_connect return

$ bifrost -l 'do_sys_openat'
  ID   PROVIDER     MODULE                                         FUNCTION NAME
   1   bifrost      guest_kernel                             do_sys_openat2 entry
   2   bifrost      guest_kernel                             do_sys_openat2 return
   3   bifrost      guest_kernel                         __arm64_sys_openat entry
   4   bifrost      guest_kernel                         __arm64_sys_openat return
```

The optional pattern is a substring match against the function
name; pass a `bifrost:guest_kernel:...:entry` shape if you want
to match against the full probe spec instead.

## Writing your own probes

The [`examples/`](examples/) directory ships two tiers of D
scripts: small *pattern primers* under [`examples/primers/`](examples/primers/)
showing one feature each, and *self-contained demos* that bundle
a `probe.d`, a `run.sh` workload driver, a `README.md`, and an
`expected-output.txt` per directory.

**Pattern primers**. Run any of them against a running smolvm
(after putting `host/runtime/` on PATH; see Setup below):

```sh
PID=$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || \
      pgrep -f '_boot-vm.*boot-config' | tail -1)
sudo bifrost -p "$PID" \
    -s examples/primers/count.d

# or via the script's own shebang:
sudo examples/primers/count.d -p "$PID"
```

**Self-contained demos** — show off the headline trick (one D
script, both kernels) using realistic workloads:

| Demo | Image | What it shows |
|---|---|---|
| [`examples/redis-smoke-test/`](examples/redis-smoke-test/) | `redis:7-alpine` | The smallest end-to-end smoke test: raw `sched_switch` tracepoint records while a Redis guest is alive. |
| [`examples/cross-domain-http/`](examples/cross-domain-http/) | `localhost:5005/bifrost-bench:latest` | HTTP workload demo: in-guest nginx plus in-guest `ab`, tracing guest `tcp_v4_do_rcv` count/latency and sampled `xstack()` over the cross-domain data path. |
| [`examples/postgres-slow-query/`](examples/postgres-slow-query/) | `localhost:5005/postgres-usdt-bench:latest` | Manual diagnostic for Postgres file-open latency. It needs an I/O-heavy workload; steady-state pgbench is usually cache-hot and too weak for automated release validation. |
| [`examples/compile-profile/`](examples/compile-profile/) | `localhost:5005/bifrost-bench:latest` | `gcc -c` anatomy: opens grouped by toolchain subprocess (cc1 / as) with `gustack()` and quantized latency. No port-forward needed — workload is guest-internal. |

See [examples/README.md](examples/README.md) for the full
breakdown plus the Ubuntu-image rationale (frame pointers).

## Architecture

The bifrost pipeline takes a D script, compiles it to DOF on macOS,
wraps the DOF in a `DTRACE_SESSION_V1` envelope, and ferries that
envelope over a **generic virtio conduit** to every connected guest.
Each guest decodes the same envelope against the no_std
`crates/bifrost-dtrace-lower` crate and drives a local
`KernelAdapter` against its native tracing engine. Records flow back
as SHMEM v6 semantic envelopes through the 16 MB virtio shared-memory
region; the macOS-side libdtrace consumer interleaves guest records
with native host probes into one output stream.

The Linux guest backend's adapter compiles DIF to eBPF in-kernel
through the bifrost driver and attaches via the standard verifier/JIT
plus BTF/kfunc relocation. The FreeBSD guest backend's adapter runs
the same DOF through native kernel DTrace state creation
(`dtrace_bifrost` session wrapper) and drains records into SHMEM.
illumos follows the same KernelAdapter contract.

Historical: before the DOF-generic rebuild, the host CLI lowered D
to eBPF and shipped pre-built BFR7 / LOAD_PROG_BATCH payloads to the
Linux guest. The constants survive in `bifrost-wire` so old
recordings still decode; `scripts/check-no-active-bfr7.sh --strict`
gates against any new live producer.

Ownership boundaries (kept honest by
`scripts/check-crate-graph.sh` and
`scripts/check-no-active-bfr7.sh`):

- `host/bifrost/` — D parsing, session planning, target fanout,
  DTrace session envelope construction, direct data-SHM rendering,
  user-visible output. **No OS-specific lowering.**
- `host/bifrost-wire/` — Bifrost semantic wire constants and codecs
  (`no_std`). Includes `session_envelope` (DTRACE_SESSION_V1) and
  `shmem_v6` (semantic record kinds).
- `crates/bifrost-dtrace-lower/` — repo-owned `no_std` DOF/DIF
  parser, ECB/action walker, aggregation planner, and the
  `KernelAdapter` trait every guest implements. Apache-2.0 OR
  GPL-2.0 so the same source ships in the Linux kernel module and
  the host CLI.
- `host/virtio-conduit/` — generic transport (control/data SHM
  plumbing, opaque payload forwarding, wake accounting).
- libkrun adapter — virtio-mmio registration, shared-memory region
  exposure, descriptor copies, IRQ signaling. Treats session
  envelope bytes as opaque; no Bifrost semantic state.
- Linux guest backend (`third_party/linux-bifrost/drivers/bifrost/`) —
  consumes `bifrost-dtrace-lower`; implements the adapter as
  DIF → eBPF lowering + verifier/JIT/attach + SHMEM record producer.
- FreeBSD guest backend (`guest/freebsd-bifrost/`) — kernel-only
  conduit endpoint, host-supplied DOF DTrace session, native
  record draining, FreeBSD module/QEMU smoke scaffolding.

For the data flow diagram, performance numbers, repo layout, and
SHMEM data plane summary see
[docs/architecture.md](docs/architecture.md). The SHMEM record
protocol is in [docs/architecture-shmem.md](docs/architecture-shmem.md).
The generic transport contract is in
[docs/virtio-conduit.md](docs/virtio-conduit.md). Development and
release validation gates are in [DEVELOPMENT.md](DEVELOPMENT.md),
and the kernel patch workflow is indexed in
[docs/kernel-patches.md](docs/kernel-patches.md).

## Building

```sh
# 1. Clone with submodules.
git clone --recursive git@github.com:tjfontaine/project-bifrost.git
cd project-bifrost

# 2. Build everything: kernel → libkrunfw → libkrun → smolvm,
#    transactionally and with codesign+entitlement re-stamping.
#    Honors stamp files so re-runs skip work that is already
#    current; first run takes ~10 minutes for the kernel build.
tools/rebuild-driver

# 3. Build the bifrost CLI.
( cd host/bifrost && cargo build --release --bin bifrost )
cp host/bifrost/target/release/bifrost host/runtime/bifrost

# 4. Put the bifrost CLI on PATH so you can invoke it directly.
#    Either install direnv and run `direnv allow` (a .envrc is
#    bundled), or manually:
export PATH="$PWD/host/runtime:$PATH"

# 5. Smoke-test the whole pipeline.
examples/redis-smoke-test/run.sh
# → "✓ end-to-end cross-domain trace working"

# Optional full demo sweep.
examples/run-full-sweep.sh
```

The atomic rebuild driver (`tools/rebuild-driver`) is the
recommended entry point for any change that touches the kernel
patches or the smolvm side. It re-syncs the in-tree `bifrost`
driver into the libkrunfw kernel source, rebuilds the kernel inside
a krunvm Fedora VM, relinks `libkrunfw.5.dylib`, copies the dylibs
into `third_party/smolvm/lib/`, builds `smolvm`, and re-applies the
HVF hypervisor entitlement at codesign time (cargo build strips it
on every release build).

If you only want to rebuild the smolvm CLI without touching the
kernel, `host/runtime/stage-smolvm.sh` is a thin alias for
`cargo build --release -p smolvm` plus an entitlement check.

### Invoking bifrost

Once `host/runtime/` is on PATH, the bifrost CLI works like
dtrace. Three equivalent invocation forms:

```sh
# 1. -s flag — like `dtrace -s probe.d`
sudo bifrost -p $PID -s examples/cross-domain-http/probe.d

# 2. inline -n D expression — like `dtrace -n '...'`
sudo bifrost -p $PID \
    -n 'fbt::tcp_v4_do_rcv:entry { @[pid] = count(); }'

# 3. self-executing D script — every probe.d in this repo starts
#    with `#!/usr/bin/env bifrost` and is chmod +x
sudo examples/cross-domain-http/probe.d -p $PID
```

Find the smolvm libkrun PID with:

```sh
PID=$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || \
      pgrep -f '_boot-vm.*boot-config' | tail -1)
```

Demos under [`examples/`](examples/) follow a two-shell shape:
one `setup.sh` that boots the workload and drives a load loop, a
second shell where you run bifrost.

## Constraints

- **No guest userspace daemon.** Records originate inside the guest
  kernel backend, transit SHMEM, and are consumed by the host
  renderer thread. Linux records originate from eBPF programs;
  FreeBSD/illumos records originate from native kernel DTrace.
  The acceptance path must not require a guest daemon, helper
  process, or in-guest `dtrace(1)`.
- **libkrun on macOS HVF.** Linux KVM works in principle (the
  Linux side of the consumer wakeup uses POSIX `poll(2)`), but
  primary development is on macOS Apple Silicon.
- **Linux target guest kernel:** 6.12.76 with the full bifrost
  patch series, carried as commits on the `third_party/linux-bifrost`
  submodule. The bifrost helpers + SHMEM groundwork lives in the
  `0036-bifrost-helpers-and-shmem` commit (`3ffe13e1b31a`); the
  rest of the series adds the in-tree driver, the kprobe verifier
  ops, the uprobe `kern_path` retry, and the AF_TSI updates.
- **FreeBSD native-DTrace target:** FreeBSD 14.3 aarch64 under the
  QEMU/vhost-user conduit harness. The root image stays pristine;
  integration happens through the booted kernel or preloaded kernel
  modules under `guest/freebsd-bifrost/`.
- **Standard kernel BPF verifier.** Programs run through
  `bpf_check` before JIT — no bypass-verifier paths in shipping
  configurations. One custom `special_kfunc_list` entry in
  `kernel/bpf/verifier.c` types the SHMEM reserve kfunc's
  `void *` return as `PTR_TO_MEM`.
- **Frame-pointer-default rootfs.** Use Ubuntu 24.04+, Fedora
  38+, Arch, or AlmaLinux 10+. Alpine + musl will produce
  truncated user stacks.

## Status

The cross-domain trace works end-to-end on macOS arm64.  A
user-written D script mixing macOS probes with
`bifrost:guest_kernel:<sym>:entry { gustack(); }` produces a
single output stream with full glibc / libc / vDSO frames
symbolicated against the right ELF in the guest rootfs.

The DTrace-parity feature set is implemented end-to-end with
real kernel-side support: `dtrace:::ERROR` fault accounting,
`clear` / `lquantize` / `llquantize` / `normalize` / `trunc`
aggregations, `tracemem` action emission, speculative tracing
via `speculate` / `commit` / `discard`, and `vtimestamp`
per-thread CPU runtime.  Every primer in `examples/primers/`
PASSes the runtime sweep; the 11-demo
`examples/run-full-sweep.sh` reports `failures=0`.

Working today:

- SHMEM data plane: 16 MB shared region, ringbuf + BTF + kallsyms
  + VMA cache flat-mapped both sides (no virtqueue copies)
- gustack / gstack / typed deref / aggregations / vDSO ELF
  resolution / multi-clause D scripts / cross-binary user-stack
  symbolication
- In-process libdtrace consumer with per-vCPU FIFO stitcher —
  multi-vCPU guests stitch correctly
- `xstack()` cross-domain stitched call chain (guest fire +
  hypervisor side captured at the same instant)
- Cross-domain aggregations (host syscalls joined with guest
  events on shared keys via `@[gpid]`)
- `bifrost attach <pid>` for already-running libkrun consumers
  (Apple Container, Lima, …), with `bifrost ls` discovery and
  `--preserve` for attach-lifecycle independence
- `xstack(SAMPLE)` — non-perturbing alternative to `xstack()`
  that swaps synchronous forced vCPU exits for profile-997hz
  sampling, paired with guest fires within a ±1 ms tolerance
  window
- All four canonical D storage classes lower to eBPF: built-in
  globals (`timestamp`, `pid`, `arg0..9`, `execname`) → BPF
  helpers; user globals (`n = n + 1`) → HASH map keyed on
  var_id; thread-local (`self->`) → HASH map keyed on
  `(pid_tgid << 32) | var_id`; clause-local (`this->`) → stack
  slots with prologue zero-init
- Guest-userspace uprobes via
  `bifrost:guest_user:<binary>:<symbol>:entry|return`. Host
  pipeline is complete (parse → ELF symbol resolver against the
  staged rootfs → BFR7 trailer → libkrun forwarding into op=2
  LOAD_PROG → guest driver's `kern_path / igrab /
  uprobe_register`); the in-tree driver is built against
  `CONFIG_UPROBES=y` via the linux-bifrost submodule's `0037`
  Kconfig commit
- Patched kernel tracked as a proper git submodule at
  `third_party/linux-bifrost` (`bifrost/v6.12.76` of
  github.com/tjfontaine/linux — 35 commits on top of upstream
  Linux v6.12.76, in canonical libkrunfw order). Required:
  development on a case-sensitive filesystem (the project
  canonically lives on `/Volumes/CaseSensitive/project-bifrost`
  on macOS — APFS is case-insensitive by default and silently
  collides files like `xt_CONNMARK.h` vs `xt_connmark.h`).

Open follow-ups:

- **TSI host↔guest data leg** is half-bridged: guest→host bind +
  inbound bytes work, but the guest never produces an `op=5 RW`
  reply packet, so a macOS TCP client sees `CLOSE_WAIT` without
  receiving a byte. Confirmed broken in both directions
  (guest-internal `redis-cli` to a guest redis-server also times
  out), so TSI's post-accept data delivery is the gap.
- **Tracepoint provider** (`sched:::switch`,
  `syscalls:::sys_enter_*`) — separate BPF program type from
  fentry; needed for canonical context-switch observability
  without depending on kprobe-on-`__schedule` (which is
  `notrace`).  The `scheduler-offcpu` demo currently uses
  `fbt::try_to_wake_up:entry` as a stand-in.

Recently landed (kept for context):

- **Verifier crash in `mark_fastcall_patterns`** — root-caused to
  four layered defects (`CONFIG_BPF_JIT` missing, libkrunfw
  Makefile dep order, the `bifrost_guest` `.ko` → in-tree
  conversion, and `bpf_verifier_ops[KPROBE] = NULL`). All four
  resolved; `bifrost_count.d` runs end-to-end.
- **Smolvm pipeline integration** — bifrost runs on top of vendored
  smolvm at `third_party/smolvm`. End-to-end verified via
  [`examples/redis-smoke-test/run.sh`](examples/redis-smoke-test/run.sh).
- **Uprobe boot-order + native-init demo path** — uprobe attach
  retries until virtiofs is ready; `bifrost_agent` retired in
  favour of running the OCI image's natural entrypoint as PID 1.
- **BFR7 wrapper format** — kfunc references emitted symbolically;
  the guest kernel resolves them at `LOAD_PROG` time, eliminating
  the `btf_id`-staleness bug class entirely (replaces the BFR6
  BTF-fingerprint check).
