# Troubleshooting rebuilds

Quick reference for the known failure modes encountered when rebuilding
the bifrost guest driver / smolvm host binary. The atomic pipeline at
`tools/rebuild-driver` handles most of these automatically; this doc
is for when you bypass the pipeline or hit something it doesn't catch.

The path-of-least-resistance for any rebuild is:

```sh
tools/rebuild-driver
```

If that succeeds, the failure modes below should not trigger. Read on
when something exotic happens.

---

## HV_DENIED (0xfae94007) on smolvm boot

**Symptom:** smolvm exits early; logs show `HV_DENIED` from
`hv_vm_create`.

**Cause:** the smolvm binary is missing the
`com.apple.security.hypervisor` entitlement. Apple's Hypervisor
framework refuses `hv_vm_create` without it. The error is opaque
because the failure is inside the framework, not user code.

**Fix:**

```sh
codesign -d --entitlements - third_party/smolvm/target/release/smolvm
# Inspect output. If hypervisor entitlement is absent:
codesign --force --sign - \
  --entitlements third_party/smolvm/smolvm.entitlements \
  third_party/smolvm/target/release/smolvm
```

**Why this keeps happening:** every plain `cargo build` produces a
binary with an adhoc *linker-signed* signature that has no
entitlements. Cargo strips them on every rebuild. The rebuild
pipeline's codesign hook re-applies them as part of the build, and
`tools/rebuild-driver` validates them before smoke testing. If you
bypass both (for example, `cargo build` from the wrong directory, or
copying the binary somewhere new), you'll lose the entitlement again.

---

## krun_start_enter -22

**Symptom:** smolvm fails with `krun_start_enter returned -22`
(`EINVAL`).

**Cause:** Almost always entitlement-related. libkrun's error chain
maps the underlying Hypervisor framework failure into a generic
`EINVAL`, which surfaces as `-22` to the caller. Check the
entitlement first (see HV_DENIED above).

If the entitlement is fine, the next likely cause is a kernel module
init failure inside the guest. Capture dmesg from the guest via
`bifrost-trace.sh` or by attaching with the macos-vm-lldb-debug
workflow.

---

## "another bifrost observer is already attached"

**Symptom:** `bifrost trace` refuses to start, claims the SPSC
observer slot is busy.

**Cause:** A previous trace run leaked the observer slot — the
host-side detach didn't run (kill -9, host crash, ungraceful exit).

**Fix:** restart smolvm or run `host/runtime/cleanup.sh` before
starting the next attach. The current observer lifecycle is designed
to detach cleanly, but ungraceful exits can still leave a busy slot in
a running VM.

---

## dmesg "MAX_KPROBES=N reached"

**Symptom:** Guest kernel log shows `MAX_KPROBES=N reached`; new
kprobe attaches start failing.

**Cause:** Static slot table exhaustion in the bifrost driver. The
limit is paired with the host-side `MAX_PROBE_SLOTS` constant.

**Fix:** reduce active probes or restart smolvm. The LOAD_PROG status
path reports per-program failures to the host; see
`host/bifrost-wire/src/lib.rs::MAX_PROBE_SLOTS` for the matching
constant on the host side.

---

## `bifrost.o` cache miss after a `.rs` edit

**Symptom:** You edited `bifrost.rs`, ran the kernel build, and the
new behavior still doesn't appear. kbuild says nothing to do.

**Cause:** kbuild's incremental dependency tracking didn't pick up
the change (most often: the canonical `bifrost.rs` lives in
`third_party/linux-bifrost/drivers/bifrost/`, but kbuild reads from
`third_party/smolvm/libkrunfw/linux-6.12.76/drivers/bifrost/`, so an
edit at the canonical path doesn't invalidate kbuild's mtime check).

**Fix:** Just run `tools/rebuild-driver` — stage 2 syncs the .rs and
nukes the kbuild cache automatically. If you must do it by hand:

```sh
cd third_party/smolvm/libkrunfw/linux-6.12.76
rm -f drivers/bifrost/*.o drivers/bifrost/.*.cmd drivers/bifrost/built-in.a
rm -f vmlinux ../kernel.c
```

---

## "Nothing to be done for 'all'" from libkrunfw build

**Symptom:** `make` in `third_party/smolvm/libkrunfw/` exits with
"Nothing to be done for 'all'" but you know things changed.

**Cause:** The libkrunfw kernel tree's `bifrost.rs` copy is stale —
it didn't receive your canonical edits, so kbuild correctly believes
it's already built.

**Fix:** `tools/rebuild-driver` syncs automatically. If you bypass
the script:

```sh
cp third_party/linux-bifrost/drivers/bifrost/bifrost.rs \
   third_party/smolvm/libkrunfw/linux-6.12.76/drivers/bifrost/bifrost.rs
# then nuke the kbuild cache (see "bifrost.o cache miss" above)
```

---

## See also

- `tools/rebuild-driver --help` — full stage list and stamp file
  semantics.
- `host/runtime/cleanup.sh` — process / mount / shmem cleanup if
  smolvm crashed mid-trace.
- `scripts/check-proto-drift.sh` — runs as stage 0 of the rebuild
  pipeline; flags wire-constant drift across host/libkrun/guest
  copies.
- macos-vm-lldb-debug skill — for opaque "child process died at
  startup" cases that aren't captured here.
