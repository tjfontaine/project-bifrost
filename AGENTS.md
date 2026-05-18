# AGENTS.md

Orientation for AI coding agents working on Project Bifrost.
Pair this with the root `README.md` (architecture, perf
numbers, run instructions) and `docs/architecture-shmem.md`
(SHMEM data plane design).

## What this project is

A cross-domain DTrace pipeline: a single D script spans macOS host
probes (`syscall:`, `pid$target:`) and Linux-guest probes
(`bifrost:guest_kernel:<sym>:entry`). Guest-side clauses get
compiled to DIF, lowered to eBPF on the host, ferried into a
Linux 6.12.76 microVM running under libkrun (vendored via
smolvm), JIT'd, and attached to a real kprobe. Records flow back
through a 16 MB shared-memory data plane and merge into the same
DTrace output stream.

End-to-end status: cross-domain trace works. `gustack()` resolves
guest user PCs to demangled symbols (libc, ld-musl, vDSO,
static-PIE rust). Sustained throughput ~860 rec/s, ≤1 µs
differential latency, vDSO entry resolution via vmlinux-extracted
ELF (perf-style).

## Repository layout

```
project-bifrost/
├── host/                                Apache-2.0
│   ├── bifrost/           CLI source + DIF → eBPF lowering library + utils
│   │                      Key file: src/bin/bifrost.rs (CLI entry).
│   └── runtime/           Shell wrappers (no Rust source any more):
│                            bifrost                  the release CLI binary
│                            cleanup.sh               kill stuck bifrost / dtrace procs
│                            stage-libkrun.sh         cp + adhoc-codesign smolvm libkrun.dylib
│                            stage-libkrunfw.sh       cp + adhoc-codesign smolvm libkrunfw.5.dylib
│                            stage-smolvm.sh          re-codesign smolvm w/ hypervisor entitlement
│                            smolvm.entitlements      hv + library-validation entitlement plist
├── guest/
│   └── linux-bifrost/     SUBMODULE — patched Linux 6.12.76 kernel.
│                          Carries the bifrost patch series as commits on
│                          branch `bifrost/v6.12.76`. The bifrost driver
│                          is in-tree at drivers/bifrost/bifrost.rs and
│                          built into vmlinux (no .ko, no module loading).
│                          The 0036-bifrost-helpers-and-shmem commit
│                          (3ffe13e1b31a) carries the BPF kfuncs + SHMEM
│                          plumbing; later commits add the kprobe verifier
│                          ops, uprobe kern_path retry, AF_TSI updates.
├── third_party/
│   └── smolvm/            SUBMODULE — vendored smolvm fork (canonical):
│                            libkrun/                 libkrun fork w/ bifrost virtio device
│                                                       (devices/src/virtio/bifrost/, 9 files)
│                            libkrunfw/               libkrunfw fork
│                            smolvm-sdk/              SDK crates
│                            src/agent/               smolvm-agent (in-guest exec helper —
│                                                       use this for any "run a command in
│                                                       the guest" need; replaces the
│                                                       retired bifrost_agent)
│                            Makefile.toml            cargo-make build entry points
├── scripts/               Misc helpers:
│                            check_lowering.sh        DOF → eBPF lowering smoke test
│                            sync-linux-patches.sh    apply libkrunfw/patches to fresh tree
│                            verify-patches.sh        lint: libkrunfw/patches in sync w/
│                                                       linux-bifrost (drift catcher)
├── README.md              Architecture, perf numbers, build/run.
├── LICENSE                Apache-2.0 (root).
└── .gitmodules            third_party/linux-bifrost, third_party/smolvm.
```

## Licensing

| Component | License | Why |
|---|---|---|
| Everything in `host/` | Apache-2.0 | Pure permissive code, no GPL link |
| `third_party/smolvm/` | Apache-2.0 (with submodules under their own licenses) | smolvm itself is Apache-2.0; libkrunfw patches are GPL-2.0 (Linux derivative) |
| `third_party/linux-bifrost/` | GPL-2.0 | Linux kernel source. Includes the in-tree bifrost driver at `drivers/bifrost/`, also GPL-2.0 |

Every non-trivial source file we own carries an `SPDX-License-Identifier`
header. The in-tree bifrost driver declares `MODULE_LICENSE("GPL")`,
which is required for `EXPORT_SYMBOL_GPL` linkage.

When adding new files, set the SPDX header to match the table above.

## Build setup

The project depends on smolvm being built first (which itself
builds libkrun + libkrunfw + the smolvm-agent). After
`git clone --recursive` (or
`git submodule update --init --recursive` on an existing checkout):

```sh
# 1. Build smolvm (libkrun + libkrunfw + smolvm-agent + smolvm CLI).
#    libkrunfw drives a krunvm-Fedora VM internally to compile the
#    kernel from the linux-bifrost submodule — see
#    third_party/smolvm/Makefile.toml.
cd third_party/smolvm
cargo make build-libkrunfw    # one-time, ~10 min
cargo make build-libkrun      # release dylib
cargo make build              # smolvm CLI + agent
cd ../..
sudo -n host/runtime/stage-smolvm.sh   # entitlement re-sign
                                       # (load-bearing — see below)

# 2. Build the bifrost CLI.
cd host/bifrost && cargo build --release --bin bifrost
cp target/release/bifrost ../runtime/bifrost
cd ../..

# 3. Smoke-test.
sudo -n examples/redis-smoke-test/run.sh
```

`stage-libkrun.sh` / `stage-libkrunfw.sh` copy the freshly-built
dylibs into `third_party/smolvm/lib/` and re-codesign them with
an adhoc signature. dyld rejects Cargo's linker-signed Mach-O
when loaded via `DYLD_LIBRARY_PATH`, so the adhoc re-sign is
load-bearing on macOS. The smolvm Makefile.toml runs these as
part of the build flow.

**`stage-smolvm.sh` is a sibling for the smolvm binary itself.**
`cargo build --release` on the smolvm workspace produces a binary
with NO entitlements. Without `com.apple.security.hypervisor`,
HVF refuses `hv_vm_create` and surfaces opaquely as
`krun_start_enter -22` (libc EINVAL wrapper) — boot subprocess
dies in ~30 ms with no diagnostic trail. Run `stage-smolvm.sh`
after every smolvm rebuild; it re-codesigns with the entitlements
in `host/runtime/smolvm.entitlements`.

**Frame pointers are required** for `gustack()` to produce useful
output. The kernel's `arch_stack_walk_user` is a pure FP chase;
binaries built without `-fno-omit-frame-pointer` (Alpine, Debian
stable, RHEL 8/9) produce truncated stacks. Stick to FP-default
distros: Ubuntu 24.04+, Fedora 38+, Arch, AlmaLinux 10+.

## Running

```sh
# Launch a target microVM via smolvm (no bifrost involvement yet):
smolvm machine run -d --image redis:7-alpine -- \
    redis-server --bind 0.0.0.0 --protected-mode no

# Find its libkrun pid:
PID=$(pgrep -f '_boot-vm.*boot-config' | head -1)

# Attach a trace from another shell — probe.d files use
# `fbt::funcname:entry|return` (BPF trampoline attach):
sudo bifrost -p "$PID" -s probe.d

# Full end-to-end smoke test (kicks off smolvm, attaches a kprobe,
# drives load, summarizes record count):
sudo -n examples/redis-smoke-test/run.sh
```

The bifrost binary at `host/runtime/bifrost` only links system
libs, so it can be invoked directly. Add `host/runtime/` to
`PATH` (a bundled `.envrc` does this for direnv users) and then
`sudo bifrost -p $PID -s probe.d` works. The project NOPASSWD
sudoers spec covers `/host/*/*` paths so all of the helpers
under `host/runtime/` (including `bifrost` itself and
`cleanup.sh`) work without a password prompt.

## Build & runtime gotchas

These are the load-bearing facts a fresh agent needs in muscle
memory; missing them costs an hour each.

- **Fedora is canonical for the kernel build.**
  `cargo make build-libkrunfw` drives `build_on_krunvm_fedora.sh`
  (Fedora 44 has the right rustc + bindgen + rust-src layout out
  of the box). Ubuntu 24.04 is for **OCI demo images** (frame
  pointers in apt-installed redis/nginx/postgres), NOT for the
  kernel build. If Fedora is temporarily wedged (mirror desync,
  etc.), retry rather than substituting Ubuntu.
- **After a kernel rebuild, sanity-check
  `grep ^CONFIG_BIFROST_GUEST third_party/smolvm/libkrunfw/linux-6.12.76/.config`.**
  If `make olddefconfig` couldn't satisfy `CONFIG_RUST`'s deps
  (rustc version, bindgen version, rust-src path), `RUST=n`
  cascades to `BIFROST_GUEST=n` silently — kernel builds clean,
  driver isn't in vmlinux. Symptom: bifrost CLI times out at
  `OBSERVER_ATTACH reply: None`, no `bifrost_*` lines in guest
  dmesg.
- **Uprobe target binaries go in `/workspace`.** Inside crun
  containers, `/dev/shm` is `noexec`, `/tmp` and `/usr/bin` are
  overlayfs (uprobe_write_opcode returns -EIO). `/workspace`
  (smolvm-provisioned ext4 disk) supports both exec and uprobe
  COW writes; copy the resolved binary there and exec from it.
- **`use kernel::ffi`, not `core::ffi`.** The kernel compiles
  with `-funsigned-char` so `c_char = u8`; `core::ffi::c_char`
  is platform-default (`i8` on aarch64) and breaks every
  bindgen-generated callback signature. The kernel's
  `rust/ffi.rs` already aliases the C primitives correctly —
  import from there in `drivers/bifrost/`.
- **macOS `make` is 3.81 — use `gmake`** (`brew install make`).
  The libkrunfw and kernel Makefiles both need GNU Make 4.0+.
- **No apostrophes in `bash -c '...'` comments.** A `can't` in
  a setup.sh comment inside the single-quoted block terminates
  the quote — silent breakage, the entrypoint then expands on
  the host shell. Spell it `cannot`.
- **Source comments document the code as it stands today.**
  They do not log the history of changes, reference iteration
  numbers, work-item markers (`W<N>`, `Iter-<N>`), ticket IDs,
  sprint names, reviewer names, or working-note documents.
  That information belongs in commit messages and `docs/`.
- **Comments answer "why is this code the way it is."** Hidden
  constraints, non-obvious invariants, spec quirks, memory
  ordering rationale, ABI contracts. They do not restate what
  well-named identifiers already say.
- **Complex modules carry a top-of-file block comment** stating
  the conceptual model, the invariants the module maintains,
  the data-flow context, and the constraints the
  implementation depends on. Internal architecture uses `//`
  block comments; `///` is reserved for public-API contracts.
- **Commented-out code is deleted.** Git retains it.
- **Don't run long `smolvm machine exec` calls while the
  entrypoint is alive.** Each `machine exec` spawns its own
  crun container that competes with the bg entrypoint for the
  agent's request socket; a multi-minute exec blocks every
  other agent operation (cleanup probes, status checks, even
  `machine stop`) and the cleanup script reports "PID alive
  but agent unresponsive" — looks identical to a kernel hang,
  isn't.  Pattern: drive long-running setup work (DB init,
  cache warm, dataset load) and the steady-state load loop
  *inside* the entrypoint.  setup.sh's job is launch +
  wait-for-port + idle-on-trap.  Reserve `machine exec` for
  short post-ready inspection only.  See
  examples/postgres-slow-query/setup.sh for the canonical
  shape; examples/probe-control/setup.sh's per-tick `ls /etc`
  via `machine exec` is fine because each call finishes in
  ~10 ms (short slot hold).

## Kernel patch workflow

**`third_party/linux-bifrost` is the source of truth for the kernel
patch series.** It is a full Linux 6.12.76 git tree with branch
`bifrost/v6.12.76` carrying our patches as ordinary commits on top of
upstream `master`. The mbox files in
`third_party/smolvm/libkrunfw/patches/` are GENERATED — `git
format-patch` output that `libkrunfw/Makefile` re-applies into the
extracted kernel tarball at build time.

### Why this layering

libkrunfw is an upstream-tracked submodule we rebase onto periodically;
keeping our kernel changes in *its* tree would mean redoing them every
time it advances. Instead we maintain the patches in a separate
`linux-bifrost` worktree (a normal kernel git repo) where they live as
real commits with real history, and ship them to libkrunfw as a series
of mbox patches.

### Canonical workflow for kernel changes

1. `cd third_party/linux-bifrost && git checkout bifrost/v6.12.76`.
2. Make your kernel change as one or more commits on top of HEAD.
   Keep each commit logically scoped (one feature per commit) and
   give it a `NNNN-short-slug` subject — that becomes the patch
   filename.
3. `git format-patch <prev-tip>..bifrost/v6.12.76 \
       -o ../smolvm/libkrunfw/patches/ --start-number <N>` to
   regenerate the mbox files for whatever range you added.
4. Run a libkrunfw rebuild (`gmake` inside the `bifrost-builder`
   krunvm Fedora VM, then host-side `gmake` to relink the
   `.dylib`, then `host/runtime/stage-libkrunfw.sh`) to verify the
   regenerated patches apply cleanly to a fresh tarball extract.
5. Commit the new/updated patch files in libkrunfw, then bump the
   smolvm submodule and root accordingly.

**If you amend, squash, or rebase commits on `bifrost/v6.12.76`**
(including via `git rebase -i`, `git commit --amend`, or
`git reset --hard` followed by re-applying), the corresponding
patch files in `libkrunfw/patches/` will drift.  The
`bifrost: VMA-table emit` and `bifrost: fentry/fexit support`
squashes were caught and reconciled this way; future squashes
need the same treatment.  Workflow:

1. After the squash/amend on linux-bifrost, identify each
   linux-bifrost commit whose old multi-patch breakdown is now in
   libkrunfw/patches/.
2. Delete the orphan patches: `rm libkrunfw/patches/<old-files>*`.
3. Format-patch each squashed commit alone:
   `git format-patch <commit>^..<commit> -o libkrunfw/patches/`.
4. Rename to the canonical `NNNN-...` numbering (drop the
   doubled prefix `git format-patch` produces from the
   `NNNN-slug:` subject).
5. Run `scripts/verify-patches.sh` — must report
   "OK: N commits match" before committing.

### Anti-patterns

- **Don't hand-edit files in `libkrunfw/patches/*.patch`.** Hunk
  counts and offsets drift, and `patch(1)` rejects the result on
  fresh builds. The mbox files are output, not input.
- **Don't edit `libkrunfw/linux-6.12.76/`** (the extracted tree)
  expecting the change to stick — `make` blows the tree away on a
  clean rebuild. The tree is a build artifact.
- **Don't bypass linux-bifrost.** If a change goes only into
  `libkrunfw/patches/` without a matching commit on
  `bifrost/v6.12.76`, the next kernel rebase loses it silently.

### Drift lint

`scripts/verify-patches.sh` re-runs `git format-patch` against
linux-bifrost's `bifrost/v6.12.76` and diffs the hunk content of
each generated patch against the matching file in
`libkrunfw/patches/` (matched by canonicalized subject — tolerates
the legacy `NNNN-` prefix carried in commit subjects, and merges
MIME quoted-printable subject splits so non-ASCII commit titles
canonicalize cleanly). Exits 0 on clean state, 1 on any drift
with a diagnostic per offending patch.

**Pre-commit hook** at `scripts/git-hooks/pre-commit` auto-runs
this lint when a commit touches `third_party/linux-bifrost`,
`third_party/smolvm`, or `scripts/verify-patches.sh` itself.
Wire it up once per clone:

```sh
git config core.hooksPath scripts/git-hooks
```

This is per-clone (lives in `.git/config`, not versioned), so
fresh clones must re-run that line.  Bypass for unusual
situations with `git commit --no-verify`.

### Catching up `linux-bifrost` if it has drifted

If the libkrunfw tree has changes that aren't in `bifrost/v6.12.76`
(usually because someone hand-edited a patch file):

```sh
# Compare the trees
diff -ru third_party/linux-bifrost/{drivers/bifrost,kernel/bpf} \
        third_party/smolvm/libkrunfw/linux-6.12.76/{drivers/bifrost,kernel/bpf}

# Apply the deltas as new commits on bifrost/v6.12.76
cd third_party/linux-bifrost
# (copy the post-build files into place, git add, git commit per
# logical feature)

# Regenerate the mbox tail
git format-patch <last-known-good>..bifrost/v6.12.76 \
    -o ../smolvm/libkrunfw/patches/ --start-number <N>
```

## Architectural rules

These constraints have already cost real engineering effort to
land. Don't relax them without discussion:

- **No guest userspace daemon.** Records originate inside the
  BPF program, transit SHMEM, are consumed by the host renderer
  thread. The in-tree bifrost driver is the only guest privilege.
- **macOS HVF first-class.** Linux KVM works in principle; the
  Linux-side wakeup path uses `poll(2)` while macOS uses
  `kqueue`. Primary development is Apple Silicon.
- **Standard kernel BPF verifier.** Programs run through
  `bpf_check` before JIT — no bypass-verifier paths in shipping
  configurations. One custom `special_kfunc_list` entry types
  the SHMEM reserve kfunc's `void *` return as `PTR_TO_MEM`.
- **No printf-style logging in the guest's hot paths.** State is
  designed to be observed via DTrace and lldb. The host renderer
  uses `log::` in libkrun's existing infra; that's fine.
- **SHMEM is the data plane.** No reverting to chunked virtqueue
  copies for record payloads / BTF / kallsyms / VMA tables.
  Phases 1–5 of that migration are done; the legacy `op=4`/`op=5`
  paths and BPF-ringbuf scaffolding have been deleted.

### Transport / protocol / application layering

The vhost-user transport makes the existing crate boundary
load-bearing.

- **Transport (below `ConduitCore`).** Anything that speaks
  vhost-user or libkrun-virtio descriptor copies. Lives in
  `host/conduit-backend/` or in the libkrun in-tree adapter.
  The conduit protocol must not appear here.

- **Protocol (`ConduitCore` and friends).** `host/virtio-conduit/`
  owns `KIND_*` ring entries, `OP_*` opcodes, control-SHM header
  layout, wake-counter semantics. No `vhost-user` types, no
  libkrun types.

- **Application (above `ConduitCore`).** `host/bifrost-wire/`
  and `host/bifrost/` own BFR7, `LOAD_PROG`, agg snapshots,
  CLI rendering. No conduit ring details, no transport state.

A change that crosses any of those three boundaries needs a
paragraph in the PR explaining why the layering had to bend.
The crate-graph check (`scripts/check-crate-graph.sh`) is the
mechanical guardrail; this section is the human one.

The vhost-user transport retired a layering violation: the
in-tree libkrun device used to live in libkrun's source tree
*and* know about bifrost-specific opcodes. That code is now
gone in favor of (1) a generic feature-gated vhost-user-device
shim inside libkrun (transport only) and (2) the bifrost-
specific protocol moving entirely into
`host/conduit-backend/`.

## Recent direction

The shipping core is done. Open follow-ups (in the in-tree task
list, not all of them slated):

- Syscall tracepoints (`syscalls:::sys_enter_*`).  Raw tracepoint
  attach is in (patch 0039); `sched_switch` / `sched_wakeup` work
  (`sched-multi`, `scheduler-offcpu`).  The syscalls family is
  the next target — raw tracepoints only (no kprobe fallback).
- Long-running file refactors: `host/bifrost/src/bin/bifrost.rs`
  (3.7 K lines) is the remaining monolith; CLI parsing, source
  rewriting, BFR7 wrapper construction, attach-mode runtime, and
  agg/stack/printf rendering all live in one binary entrypoint.
  The previously-monolithic libkrun virtio device and host
  `lower/` lowering pipeline have been split (9 and 7 files
  respectively).
- More BPF observability primitives (probe args, typed deref
  beyond the current CO-RE flow).

## Conventions for AI-driven work

- **Test through the real VM.** `--emit-ebpf` is a prefilter, not
  a test. End-to-end via `examples/redis-smoke-test/run.sh` (or an equivalent
  attach-mode run against a smolvm-launched libkrun) is the only
  signal that matters.
- **Re-codesign smolvm dylibs after a libkrun/libkrunfw rebuild.**
  Cargo's linker signature is rejected by dyld when loaded via
  `DYLD_LIBRARY_PATH`; `host/runtime/stage-libkrun.sh` and
  `stage-libkrunfw.sh` copy the freshly-built dylibs into
  `third_party/smolvm/lib/` with an adhoc re-sign that dyld
  accepts. The smolvm Makefile.toml flow runs these automatically;
  call them by hand only if you've rebuilt out of band.
- **One bundled commit when the change spans submodules.** Bump
  the parent repo's submodule pointers in the same commit (or
  immediately after) so reviewers don't see a half-state.
- **Recovery from a wedged HVF run is `host/runtime/cleanup.sh`,**
  not a host reboot. Back-to-back libkrun VMs sometimes hang the
  new process at 100 % CPU; this is a known interaction, not a
  code bug.
