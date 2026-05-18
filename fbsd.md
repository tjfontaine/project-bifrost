**FreeBSD Kernel-Only DTrace Portability Proof**

**Summary**
- Target **FreeBSD 14.3 arm64/aarch64** under the custom QEMU at `/private/tmp/qemu-11.0.0/build/qemu-system-aarch64`.
- Keep the acceptance path **kernel-only inside the guest**: no guest daemon, no runtime `dtrace(1)`, no SSH-driven tracing loop, and no mutation of the cached root image.
- FreeBSD is first; illumos should follow the same native-DTrace backend shape once the transport and kernel-consumer boundaries are stable.

**Current validated state (2026-05-16)**
- `examples/freebsd-dtrace-smoke/run.sh` passes the FreeBSD boot, transport, and host-DOF wrapper proof when run as:
  `QEMU=/private/tmp/qemu-11.0.0/build/qemu-system-aarch64 FREEBSD_PRELOAD_CONDUIT=1 examples/freebsd-dtrace-smoke/run.sh`.
- The harness downloads/caches the official `FreeBSD-14.3-RELEASE-arm64-aarch64.qcow2`, boots it via EDK2 through a disposable qcow2 overlay, attaches `conduit-backend` through `vhost-user-test-device-pci`, preloads `opensolaris.ko`, patched `dtrace.ko`, and `bifrost_conduit.ko` from an attached USB module disk using QMP-injected EFI loader input, and reaches the FreeBSD serial `login:` prompt.
- `guest/freebsd-bifrost/patches/0001-bifrost-conduit-transport-skeleton.patch` carries the first FreeBSD kernel transport patch. It binds virtio id `45`, registers that id in FreeBSD's virtio tables, enters the virtio module build list, allocates the 3 conduit queues, posts control buffers, publishes the 16 MB data-SHM region through the legacy PFN `OP_DATA_SHM_READY` path required by stock QEMU, and returns a deterministic `OP_CTRL_RESPONSE` saying the full native DTrace bridge is pending.
- `guest/freebsd-bifrost/patches/0002-bifrost-native-dtrace-record-proof.patch` added the first native-record checkpoint: the conduit published the Bifrost v5 data-SHM ring layout and proved the host-visible FreeBSD record path.
- `guest/freebsd-bifrost/patches/0003-bifrost-dtrace-kernel-wrapper-proof.patch` moves the proof to the FreeBSD DTrace kernel itself. The patched `dtrace.ko` exposes a private wrapper that creates a kernel DTrace state, loads DOF, starts tracing, drains one `trace(uint64_t)` BEGIN record, stops, destroys the state, and returns structured status.
- `guest/freebsd-bifrost/patches/0004-bifrost-freebsd-data-shm-doorbell.patch` wakes the host data-SHM mirror after publishing the wrapper record so `bifrost data` observes the producer cursor and payload.
- `guest/freebsd-bifrost/patches/0005-bifrost-native-dtrace-host-dof-session.patch` accepts the native-DTrace backend session payload, copies host-supplied DOF in the guest kernel, preserves the host-selected schema probe id, drains supported `trace(uint64_t)` descriptors, and calls `dtrace_bifrost_run_dof()` instead of relying on the old fixed opcode.
- `guest/freebsd-bifrost/check-patches.sh` validates both patches against a sparse `releng/14.3` FreeBSD source checkout at `4f4b48e8a5478657f343953ef30ce992f2a6b68f`, rejects whitespace-dirty patches, generates the FreeBSD kernel interface headers, and runs `clang -target aarch64-unknown-freebsd14.3 -fsyntax-only` with `KDTRACE_HOOKS`.
- `guest/freebsd-bifrost/build-module.sh` builds `artifacts/freebsd/modules/opensolaris.ko`, patched `dtrace.ko`, and `bifrost_conduit.ko` locally with `bmake`, `clang -target aarch64-unknown-freebsd14.3`, `ld.lld`, and `llvm-objcopy`.
- `guest/freebsd-bifrost/stage-module-disk.sh` stages those modules under `artifacts/freebsd/module-disk/`, and `host/runtime/qemu-launch-freebsd.sh` attaches them through a per-launch vvfat USB mass-storage copy. The smoke test proves the root image remains pristine, the EFI loader preloads the modules, the kernel attaches `bifrost_conduit0`, `conduit-backend` ingests `DATA_SHM_READY`, `bifrost freebsd-proof --dof <fixture>` receives an explicit success response, the CLI renders the native record through schema metadata, and `bifrost data` sees the FreeBSD DTrace wrapper record with `probe_id=2`.

**What this does and does not prove**
- Proven: FreeBSD modules loaded before root userspace can bind the generic conduit, publish the data plane, drive a host-supplied native DTrace DOF through kernel load/start/drain/stop/destroy, and emit a Bifrost record into the same host-visible SHMEM ring used by Linux.
- Proven: the acceptance run does not use a guest daemon, guest helper process, guest `dtrace(1)`, SSH loop, package install, or root image modification.
- Not yet proven: broad FreeBSD provider coverage, argument decoding, predicates, aggregations, or libdtrace-compatible record formatting beyond supported scalar `trace(uint64_t)` descriptors.

**Implemented in this checkpoint**
- Add a FreeBSD QEMU harness separate from the Linux smolvm launcher:
  - Boot an official FreeBSD aarch64 QCOW2 with EDK2.
  - Attach `conduit-backend` through QEMU's `vhost-user-test-device`.
  - Default to the verified custom QEMU path and fail if `vhost-user-test-device` is missing.
- Add a FreeBSD guest kernel patch/module set:
  - A `bifrost_conduit` virtio driver binds to virtio id `45`, owns the same 3 queues, consumes host control payloads, emits `OP_CTRL_RESPONSE`, and publishes the 16 MB data ring through the existing PFN `OP_DATA_SHM_READY` fallback.
  - The module accepts a host control payload, calls the patched `dtrace.ko` wrapper, publishes supported Bifrost data-SHM records from the drained DTrace buffer, sends a doorbell so the host mirror catches up, and returns explicit success/failure.
  - The code stays in FreeBSD guest patches, not in `host/` or libkrun.
- Add the host proof path:
  - `bifrost freebsd-proof <pid>` builds a native-DTrace backend session from a host-selected D source or DOF input, sends it over the existing opaque control payload path, decodes the explicit `OP_CTRL_RESPONSE`, and renders observed records through the same schema renderer used by Linux direct data-SHM output.
  - `examples/freebsd-dtrace-smoke/run.sh` launches QEMU + `conduit-backend`, verifies FreeBSD boots to serial login with `vhost-user-test-device-pci`, and with `FREEBSD_PRELOAD_CONDUIT=1` verifies the kernel transport marker, host `DATA_SHM_READY` ingestion, the kernel `dtrace_bifrost` marker, the control-path success response, and `bifrost data` visibility.

**Remaining kernel proof work**
- Expand provider metadata and argument decoding beyond the initial scalar `trace(uint64_t)` record descriptors.
- Keep the same no-userspace acceptance rule: build/provisioning may use host or build-VM tools, but the trace run must not require a guest daemon, guest `dtrace(1)`, or root image mutation.

**Test Plan**
- Host checks:
  - `cargo test --manifest-path host/virtio-conduit/Cargo.toml`
  - `cargo test --manifest-path host/conduit-backend/Cargo.toml`
  - `cargo test --manifest-path host/bifrost/Cargo.toml backend::`
  - `guest/freebsd-bifrost/check-patches.sh`
- New FreeBSD proof:
  - `guest/freebsd-bifrost/build-module.sh`
  - `guest/freebsd-bifrost/stage-module-disk.sh`
  - `host/runtime/stage-conduit-backend.sh`
  - `QEMU=/private/tmp/qemu-11.0.0/build/qemu-system-aarch64 FREEBSD_PRELOAD_CONDUIT=1 examples/freebsd-dtrace-smoke/run.sh`
- Current pass criteria: FreeBSD boots, the EFI loader preloads `opensolaris.ko`, `dtrace.ko`, and `bifrost_conduit.ko` from the USB module disk, the kernel logs `bifrost_conduit0: transport ready`, `conduit-backend` logs `DATA_SHM_READY` for the 16 MB data SHM, `bifrost freebsd-proof --dof <fixture>` reports success and renders `value=0x4653424454524143`, the kernel logs `dtrace_bifrost host DOF records emitted`, `bifrost data` reports `probe_id=2`, and no guest runtime helper process is required.
- Evidence to preserve:
  - QEMU launch/serial log: `/tmp/bifrost-freebsd-launch.log`
  - conduit backend log: `/tmp/conduit-backend-fbsd.log`
  - data-SHM inspection log: `/tmp/bifrost-fbsd-data.log`

**Assumptions**
- The first portability proof targets FreeBSD, not illumos, because FreeBSD has official arm64 VM images and loadable kernel development is practical under QEMU/HVF.
- "No guest helper" means no runtime guest daemon or `dtrace(1)` process in the tracing path; one-time image provisioning/build steps may use userspace outside the acceptance path.
- Full FreeBSD D source compilation and libdtrace-compatible record formatting come after the kernel-only DOF consumer proof.
