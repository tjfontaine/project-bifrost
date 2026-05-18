# Kernel Patch Workflow And Review Index

The guest kernel is Linux 6.12.76 plus the patch series in
`third_party/smolvm/libkrunfw/patches/`. The authoritative editable
history for the Bifrost-specific portion is the
`third_party/linux-bifrost` submodule on `bifrost/v6.12.76`; the
patch files are generated output consumed by the libkrunfw build.

Do not hand-edit `libkrunfw/patches/*.patch`. Make kernel changes as
commits in `third_party/linux-bifrost`, regenerate patch files with
`git format-patch`, and verify the result with:

```sh
scripts/verify-patches.sh
```

Current release-candidate verification:

```text
[verify-patches] OK: 49 commits match patches in .../third_party/smolvm/libkrunfw/patches
```

The directory currently contains 50 `.patch` files because the
libkrunfw baseline carries a historical duplicate `0023` slot. The
drift verifier compares generated patch content by canonicalized
subject and reports the 49 matching commits.

## DOF-generic adapter integration (planned)

The Linux driver will consume the
`crates/bifrost-dtrace-lower` no_std crate via Kbuild `--extern`.
The integration has three moving parts that have to land together:

1. **libkrunfw kernel-build orchestration.** The kernel is compiled
   inside a krunvm with only `libkrunfw/<sources>/` mounted, so the
   external crate must either be bind-mounted into that build root
   or vendored into the kernel tree. The current plan is to
   bind-mount `crates/bifrost-dtrace-lower/` at
   `linux/drivers/bifrost/dtrace_lower/` during the krunvm build and
   add the corresponding `rustc --extern` flag in the kernel-rust
   build rules.

2. **Driver Kbuild.** `drivers/bifrost/Makefile` adds the bound
   crate as a dependency once the orchestration above is in place;
   `dtrace_adapter.rs` switches from its inline trait mirror to
   `use bifrost_dtrace_lower::adapter::*;`.

3. **Host cutover.** `scripts/check-no-active-bfr7.sh --strict`
   flips on in CI once `host/bifrost/src/cli/direct_load.rs` and
   any other live `build_wrapper_bytes()` call sites have been
   replaced with `capability_fanout::fanout()`.

Until those three pieces land together, `dtrace_adapter.rs` mirrors
the trait surface verbatim and is audited against drift by
`scripts/check-proto-drift.sh`. The bifrost driver's existing
BFR7/LOAD_PROG path keeps working through the transition.

## Review Groups

### 0001-0027: inherited libkrunfw baseline

These patches are inherited from the smolvm/libkrunfw fork and should
be reviewed as upstream libkrunfw enablement rather than Bifrost
kernel work.

- `0001-0002`: krunfw init/reboot robustness.
- `0003-0010`: vsock datagram support and Transparent Socket
  Impersonation.
- `0011-0015`: Apple Silicon memory-model support.
- `0016-0027`: graphics, DAX, overlayfs, virtio, CAN, and related
  libkrunfw platform patches.

### 0028-0032: initial Bifrost kernel surface

These introduce the in-tree driver, Rust bindings, BPF kfuncs,
SHMEM plumbing, uprobe support, task/path helpers, and early AF_TSI
updates needed by Bifrost.

Expected upstream posture: split between Linux-driver review topics
and libkrunfw integration glue. The Bifrost driver and verifier hooks
need kernel-list quality review before any upstream submission.

### 0034-0045: data plane, attach families, and driver decomposition

These patches move the runtime toward the current public architecture:
VMA publication, fentry/fexit, raw tracepoints, sibling Rust files,
BFR7 wire vendoring, per-slot attach cleanup, and kernel-resolved USDT
provider support.

Expected upstream posture: mostly Bifrost-specific kernel support.
The raw tracepoint and trampoline attach pieces are reviewable kernel
topics; generated wire-vendor commits are project-local integration
bookkeeping.

### 0046: AF_TSI integration fix

`0046-tsi-mask-SOCK_NONBLOCK-SOCK_CLOEXEC.patch` is not Bifrost
driver code. It belongs with the AF_TSI/libkrunfw transport surface
and should be reviewed separately from the tracing patches.

### 0047-0054: release-candidate Bifrost evolution

These patches cover slot-table scaling, probe-family dispatch,
observer handshakes, kfunc manifest validation, profile/wire
scaffolding, BTF field relocations, and `LOAD_PROG` payload v3.

Expected upstream posture: Bifrost project-local until the public API
settles. The kfunc manifest check and field-reloc flow are good
review boundaries because they have clear invariants and cross-layer
tests.

## Generated Wire Re-Vendor Patches

The following patches intentionally re-vendor generated or mirrored
wire definitions into the kernel tree:

- `0042-bifrost-vendor-wire-rs-from-canonical-bifrost-wire-cr.patch`
- `0043-bifrost-re-vendor-wire-rs-with-typed-BFR7-headers.patch`
- `0050-bifrost-wire.rs-re-vendor-Phase-I-HELLO-feature-bit-.patch`
- `0052-bifrost-wire.rs-re-vendor-Phase-J-M-wire-foundation.patch`
- `0053-bifrost-wire.rs-re-vendor-Phase-N.1-BTF-field-reloc-.patch`

They are expected to look mechanical. Use
`scripts/check-proto-drift.sh` to verify the vendored kernel copy
matches the canonical `host/bifrost-wire` definitions.

## Authoring New Kernel Changes

1. `cd third_party/linux-bifrost`
2. Check out `bifrost/v6.12.76`.
3. Commit the kernel change there, with one logical change per commit.
4. Regenerate patches into `third_party/smolvm/libkrunfw/patches/`
   using `git format-patch` from the matching commit range.
5. Run `scripts/verify-patches.sh` from the parent repo.
6. Rebuild libkrunfw through the smolvm flow so the patch series is
   applied to a fresh kernel tree.
7. Commit and push leaf repositories before bumping the parent
   submodule pointers.

## Release Checks

Before publishing a parent commit that changes kernel or libkrunfw
state, run:

```sh
scripts/verify-patches.sh
scripts/check-proto-drift.sh
scripts/check-kfunc-manifest.sh
```

After a kernel rebuild, also sanity-check:

```sh
grep ^CONFIG_BIFROST_GUEST third_party/smolvm/libkrunfw/linux-6.12.76/.config
```

It must be enabled. If Rust support silently fell out of the kernel
configuration, the build can succeed while the Bifrost driver is absent
from `vmlinux`.
