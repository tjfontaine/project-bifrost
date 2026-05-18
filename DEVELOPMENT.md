# Development

Project Bifrost spans a parent repository plus kernel and smolvm
submodules. Treat the current checkout as a multi-repo release
candidate: verify submodule state before editing, and publish leaf
repositories before parent pointers.

## Checkout

```sh
git clone --recursive git@github.com:tjfontaine/project-bifrost.git
cd project-bifrost
git submodule update --init --recursive
```

Use a case-sensitive filesystem. Primary development and validation
run on Apple Silicon macOS with HVF.

## Build Order

The recommended path is the atomic rebuild driver:

```sh
tools/rebuild-driver
```

It walks the kernel → libkrunfw → libkrun → smolvm dependency chain
in order, with per-stage stamp files so re-runs skip work that's
already current. See the script's header comment for the stage list
and failure modes.

If you only want to rebuild the smolvm CLI binary (no kernel
changes, no libkrun changes):

```sh
host/runtime/stage-smolvm.sh
```

That is a thin alias for `cargo build --release -p smolvm` plus a
defensive re-sign with the HVF hypervisor entitlement (cargo strips
entitlements on every release build, surfacing later as
`HV_DENIED` / `krun_start_enter -22`).

After the smolvm side is built, build the bifrost CLI:

```sh
( cd host/bifrost && cargo build --release --bin bifrost )
cp host/bifrost/target/release/bifrost host/runtime/bifrost
```

The libkrunfw build uses Fedora inside a krunvm to build the patched
Linux 6.12.76 kernel. Do not substitute Ubuntu for that kernel-build
path; Ubuntu 24.04 is used for demo container images because it keeps
frame pointers by default.

## Validation Checklist

Two tiers: **cheap local gates** (always required before publishing)
and **VM-bound gates** (required for release candidates; optional
for diagnostic-only changes).

### Cheap local gates — required before publishing

```sh
scripts/check-crate-graph.sh
scripts/check-proto-drift.sh
scripts/check-kfunc-manifest.sh
scripts/verify-patches.sh
cargo test --manifest-path host/bifrost-wire/Cargo.toml --features zerocopy_repr,codec,alloc
cargo test --manifest-path host/virtio-conduit/Cargo.toml
cargo test --manifest-path host/bifrost-support/Cargo.toml
cargo test --manifest-path host/bifrost/Cargo.toml
```

Every command must exit 0. The bifrost-wire feature set is required
because the codec roundtrip + status tests live behind those
features; without them only the constant-pin tests run.

### libkrun adapter compile validation — required before publishing

The libkrun device/VMM check exercises the extracted conduit
boundary (`host/virtio-conduit` consumed through a thin adapter at
`third_party/smolvm/libkrun/src/devices/src/virtio/conduit/`):

```sh
cargo check --manifest-path third_party/smolvm/libkrun/src/vmm/Cargo.toml
cargo test --manifest-path third_party/smolvm/libkrun/src/devices/Cargo.toml \
    --lib -- --skip legacy::i8042
```

Both must exit 0. The devices crate's `build.rs` compiles
`init/init.c` into the cargo `OUT_DIR` automatically; the build is
hermetic. The optional `KRUN_INIT_BINARY_PATH` environment variable
overrides that with a pre-built init binary if a particular
checkout has staged one (production builds use the artifact emitted
by `tools/rebuild-driver`'s libkrunfw stage). On macOS,
`KRUN_INIT_BINARY_PATH` must point at a Linux ELF init — the
default `build.rs` compile path needs a Linux cross toolchain that
the bare macOS install lacks; the
`target/release/build/krun-devices-*/out/init` produced by an
earlier release build is a suitable cross-built fallback.

The `--skip legacy::i8042` exclusion is for two upstream tests
(`test_i8042_kbd`, `test_i8042_read_write_and_event`) that assume
Linux `eventfd` counter-accumulation semantics. The macOS
`utils::eventfd` shim returns counters one read at a time, which
trips those two assertions. The defect predates the bifrost work
and lives in code we do not own; we filter the tests in the
validation gate rather than carrying a patch.

### VM-bound gates — required for release candidates

Driven by the recipe under `examples/`:

```sh
sudo -n examples/redis-smoke-test/run.sh   # single-demo smoke test
examples/run-full-sweep.sh                 # serial sweep across all demos
```

The full sweep must report `failures=0` in its summary. Each
harnessed demo must report `PASS`. `redis-smoke-test` must print
"end-to-end cross-domain trace working" and observe records.
No demo should report Bifrost guest-ring drops or DTrace principal
drops unless that demo explicitly documents an intentional drop
scenario.

If a VM run wedges, use `host/runtime/cleanup.sh` before treating
the failure as a code regression.

### Optional diagnostics

These are useful when chasing a specific regression but are not
required before publishing:

- `bifrost data <pid>` — read the data SHM header and the producer/
  consumer cursors directly, with a configurable poll cadence. Used
  to confirm record traffic without rendering.
- `tools/rebuild-driver --help` — print the stage list to figure
  out which stage caches you might want to invalidate manually.
- `scripts/sync-linux-patches.sh` — preview missing patches between
  the `linux-bifrost` submodule and the libkrunfw `patches/` tree.

## Generated artifacts and submodule pointers

After kernel changes:

1. Commit the kernel change inside `third_party/linux-bifrost` on
   the `bifrost/v6.12.76` branch.
2. Regenerate the matching `third_party/smolvm/libkrunfw/patches/*.patch`
   files from that commit range (`git format-patch`).
3. Run `scripts/verify-patches.sh` and confirm a clean exit.
4. Rebuild libkrunfw + libkrun + smolvm via `tools/rebuild-driver`.
5. Confirm the kernel config still pins the bifrost driver in:

   ```sh
   grep '^CONFIG_BIFROST_GUEST' \
       third_party/smolvm/libkrunfw/linux-6.12.76/.config
   ```

   Expected: `CONFIG_BIFROST_GUEST=y`.

The patch files are **generated**: do not hand-edit them. They are
checked in so that a fresh clone can build libkrunfw without first
re-applying the `linux-bifrost` series. The `bifrost-wire`
canonical/vendored relationship is similar — the guest copy at
`third_party/linux-bifrost/drivers/bifrost/wire.rs` is a SHA-pinned
mirror of `host/bifrost-wire/src/lib.rs`; the drift script
(`scripts/check-proto-drift.sh`) catches mismatches.

## Crate boundaries

- `host/bifrost-wire` — `no_std` protocol crate with wire constants,
  typed headers, and optional codec helpers. Canonical for the
  guest's vendored copy.
- `host/bifrost-support` — shared host/libkrun support (record
  schema, ELF symbol tables, vDSO).
- `host/virtio-conduit` — generic virtio conduit core (control and
  data SHM plumbing, opaque payload forwarding, wake accounting).
  Bifrost-agnostic. Contract:
  [docs/virtio-conduit.md](docs/virtio-conduit.md).
- `host/bifrost` — full host CLI and lowering crate. libkrun must
  not depend on this crate. `scripts/check-crate-graph.sh` enforces
  the rule and also verifies that `krun-devices` depends on
  `krun-virtio-conduit`.

## Local artifacts

Do not stage scratch files, backup files, build products, or generated
VM artifacts. In this tree, watch especially for:

- `third_party/linux-bifrost/drivers/bifrost/*.bak`
- `third_party/smolvm/lib/*.so.*`
- `third_party/smolvm/libkrun/init/init.krun`
- `target/`
- `Cargo.lock` in library crates, unless intentionally tracked

Classify every dirty or untracked path before committing.

## Publishing order

Publish leaf repositories first so every parent pointer references a
SHA available from its remote:

1. `third_party/smolvm/libkrun`
2. `third_party/smolvm/libkrunfw`
3. `third_party/linux-bifrost`
4. `third_party/smolvm`
5. parent `project-bifrost`

Avoid force-pushing or destructive history rewrites unless everyone
sharing the branch has agreed to the rewrite.
