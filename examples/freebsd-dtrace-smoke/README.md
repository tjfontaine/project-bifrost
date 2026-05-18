# freebsd-dtrace-smoke

FreeBSD-first kernel-only DTrace portability proof. See
[`fbsd.md`](../../fbsd.md) at the repo root for the full design.

## What this example proves

Two staged claims, each gated:

| iter | claim                                                       | gated on                                  |
|------|-------------------------------------------------------------|-------------------------------------------|
| v0   | host harness can boot stock FreeBSD with conduit-backend    | nothing — works from a fresh checkout     |
| v1   | `bifrost_conduit` attaches and publishes DATA_SHM_READY     | built/preloaded guest kernel module       |
| v2   | host-selected native DOF session renders through Bifrost schema output | built/preloaded `opensolaris.ko`, `dtrace.ko`, and `bifrost_conduit.ko` |

`run.sh` exits 0 after the strongest claim proven by the boot and
backend logs and prints `[v1 PENDING]` or `[v2 PENDING]` for the
rest, so dashboards see green for what actually works and don't
falsely promote later milestones. Set `FREEBSD_PRELOAD_CONDUIT=1`
to run the v1/v2 gates; the script then fails unless the serial log
contains the `bifrost_conduit` kernel-ready marker and the backend
log contains `DATA_SHM_READY` for the 16 MB data SHM. The v2 gate
then materializes the host-selected DOF fixture and runs
`bifrost freebsd-proof <pid> --dof <fixture>`, which asks the guest
conduit to call the patched `dtrace.ko` wrapper. That wrapper
creates a kernel DTrace state, loads the host-supplied DOF, starts
and stops tracing, drains supported `trace(uint64_t)` records,
publishes Bifrost v5 data-SHM records, sends a doorbell, and returns
explicit success/failure without guest `dtrace(1)`. The CLI renders
the observed record through the normal `RecordSchema::default_trace`
path rather than a FreeBSD-specific raw-record printer.

This is not yet the full dynamic FreeBSD DTrace backend. Broad
provider coverage, argument decoding, predicates, aggregations, and
non-scalar record formatting remain follow-up work.

## Prerequisites

- Custom QEMU built with `--enable-vhost-user` (must expose
  `vhost-user-test-device-pci` and `memory-backend-shm`). Default
  path: `/private/tmp/qemu-11.0.0/build/qemu-system-aarch64`.
  Override via `QEMU=...`.
- `conduit-backend` built from `host/conduit-backend/` and on
  `PATH` (the project `.envrc` already adds `host/runtime/`).
- Optional v1/v2 artifact path:
  `guest/freebsd-bifrost/build-module.sh` followed by
  `guest/freebsd-bifrost/stage-module-disk.sh`, then run with
  `FREEBSD_PRELOAD_CONDUIT=1`.
- macOS aarch64 with HVF, or Linux aarch64 with KVM.
- Network access on first run, to download the official FreeBSD
  14.3-RELEASE aarch64 cloud QCOW2 from download.freebsd.org. The
  decompressed image lands at `artifacts/freebsd/`.

The harness does NOT modify the FreeBSD root image. The first
boot uses a stock release QCOW2 unchanged and creates a per-launch
qcow2 overlay that is removed on cleanup. The only other mutable
state is a per-launch copy of the EDK2 variable store, also removed
on cleanup. Set `FREEBSD_QCOW2_SNAPSHOT=0` only for disposable
debug images.

In preload mode the launcher copies the staged module directory to
a per-launch vvfat tree and attaches it as USB mass storage. The
FreeBSD EFI loader can see that disk as `disk1s1`, so the smoke
test can load `/boot/kernel/kernel`, preload `opensolaris.ko`,
`dtrace.ko`, and `bifrost_conduit.ko`, and boot without
modifying the cached QCOW2 or the staged module directory.

## Run

```sh
QEMU=/private/tmp/qemu-11.0.0/build/qemu-system-aarch64 \
    examples/freebsd-dtrace-smoke/run.sh
```

First run downloads ~600 MB and takes a few minutes; subsequent
runs reuse `artifacts/freebsd/FreeBSD-14.3-RELEASE-arm64-aarch64.qcow2`.

For the kernel-only transport plus host-supplied DOF wrapper proof:

```sh
guest/freebsd-bifrost/build-module.sh
guest/freebsd-bifrost/stage-module-disk.sh
host/runtime/stage-conduit-backend.sh
QEMU=/private/tmp/qemu-11.0.0/build/qemu-system-aarch64 \
    FREEBSD_PRELOAD_CONDUIT=1 \
    examples/freebsd-dtrace-smoke/run.sh
```

## Outputs

- `/tmp/bifrost-freebsd-launch.log` — full serial console of the
  FreeBSD boot plus the conduit-backend launcher diagnostics.
- `/tmp/conduit-backend-fbsd.log` — conduit-backend log only.
- `/tmp/bifrost-fbsd-data.log` — `bifrost data` output when the
  native-record gate is enabled.
