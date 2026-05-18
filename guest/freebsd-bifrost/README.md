# guest/freebsd-bifrost — FreeBSD guest kernel patch set

FreeBSD-side companion to `guest/linux-bifrost`. Builds the
**guest-only** kernel modules that boot FreeBSD into Bifrost's
out-of-process conduit transport and produce native-DTrace
records without any guest userspace agent.

## Layout (mirrors the Linux model)

The FreeBSD source + bifrost patches live as a **submodule** at
`third_party/freebsd-bifrost`, tracking the `bifrost/14.3` branch
of `https://github.com/tjfontaine/freebsd-src.git`. The branch
carries every bifrost-conduit / dtrace-wrapper commit on top of
upstream `releng/14.3`, the same shape `guest/linux-bifrost` uses
against `linux-6.12.76`.

The previous patch-files-in-tree shape (`patches/*.patch` +
`fetch-freebsd-src.sh` + `check-patches.sh`) has been retired
because the submodule branch IS the patch series.

Bifrost-side commits on `bifrost/14.3` (in order):

1. **bifrost: add FreeBSD virtio conduit transport skeleton** —
   virtio driver for id `45`, 3 queues (VQ_CTRL / VQ_EVENT /
   VQ_DOORBELL), 16 MB data SHM via legacy PFN, deterministic
   `OP_CTRL_RESPONSE`.
2. **bifrost native dtrace record proof** — first native-record
   path: SDT provider `bifrost:conduit:native_dtrace:record`,
   v5 data-SHM ring layout, default-trace-shaped record at
   `probe_id=1`.
3. **bifrost dtrace kernel wrapper proof** —
   `dtrace_bifrost_run_fixed()` in patched `dtrace.ko`: creates a
   kernel DTrace state, loads a built-in fixture DOF, drives
   start / drain / stop / destroy, returns structured status.
4. **bifrost freebsd data shm doorbell** — wakes the host data
   SHM mirror after publishing the wrapper record so `bifrost
   data` and the renderer see the producer cursor advance.
5. **bifrost native dtrace host dof session** —
   `dtrace_bifrost_run_dof()` accepts a host-supplied DOF payload,
   preserves the schema probe id, drains every supported
   `trace(uint64_t)` descriptor.

## Build And Run

```
git submodule update --init --recursive third_party/freebsd-bifrost
guest/freebsd-bifrost/build-module.sh
guest/freebsd-bifrost/stage-module-disk.sh
host/runtime/stage-conduit-backend.sh
QEMU=/private/tmp/qemu-11.0.0/build/qemu-system-aarch64 \
    FREEBSD_PRELOAD_CONDUIT=1 \
    examples/freebsd-dtrace-smoke/run.sh
```

`build-module.sh` runs on macOS (`bmake` + `clang` + `ld.lld` +
`llvm-objcopy`) or on a FreeBSD build host with the native
toolchain. It produces:

- `opensolaris.ko`, patched `dtrace.ko`, `bifrost_conduit.ko` —
  the original three.
- `fbt.ko`, `systrace.ko`, `profile.ko` — provider modules
  required by the cross-kernel demos' `fbt:kernel:*` /
  `syscall::*` / `profile:::tick-*sec` probes.

The smoke test preloads the additional provider modules through
the EFI loader when they're present on the staged module disk.
Iter-9 acceptance for `fbt:kernel:vfs_read:entry` against a
freshly-booted guest is gated by the fbt-coverage step in
`examples/freebsd-dtrace-smoke/run.sh`.

The launcher exposes the staged module tree as a USB mass-storage
vvfat copy because the FreeBSD EFI loader sees that path before
kernel start. The cached root qcow2 stays pristine across runs.

## Why submodule + branch instead of patches/*.patch

Three reasons, matching `guest/linux-bifrost`:

1. **Replayable history.** Each bifrost commit on the branch has
   author / message / parent — bisectable, blame-able, rebasable
   when upstream refreshes. Patch files lose that.
2. **Single source of truth.** `build-module.sh` builds straight
   from the submodule's checked-out tree; no per-build `git apply`
   step that can silently skew between patch file and source.
3. **Drop-in for forks.** The user's existing fork pattern
   (`tjfontaine/linux.git`, `tjfontaine/smolvm.git`,
   `tjfontaine/vmm-sys-util.git`) extends naturally to
   `tjfontaine/freebsd-src.git`; the submodule URL is the only
   thing that changes.
