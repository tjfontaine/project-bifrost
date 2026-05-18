#!/usr/bin/env bifrost
/*
 * xstack.d — cross-domain stitched call chain
 *
 * `xstack()` is bifrost's headline trick: at every guest fire, it
 * captures the host-side ustack at the same instant and stitches
 * the two halves together. Implementation:
 *   1. The bifrost: clause captures gustack() inside the guest BPF
 *      program (frame pointer chase against guest userspace).
 *   2. The bifrost driver kicks the host via the doorbell.
 *   3. libkrun's SHMEM consumer thread forces a synchronous vCPU
 *      exit (or, in SAMPLE mode, profile-997hz pairs with a
 *      ±1 ms tolerance window).
 *   4. A host-side `pid$target::hv_vcpu_run:return` clause is
 *      auto-injected by the bifrost CLI; libdtrace captures
 *      `ustack()` at the exit instant.
 *   5. The renderer interleaves both halves into a single output.
 *
 * Use `xstack(SAMPLE, 32)` for the non-perturbing sampling mode
 * (no forced exits). Default is forced-exit which gives 100%
 * pairing but adds ~3-10 µs per guest fire (HVF MMIO trap floor).
 *
 * Run:
 *   sudo bifrost -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *       -s examples/primers/xstack.d
 *   sudo examples/primers/xstack.d -p $(pgrep -f '_boot-vm.*boot-config' | head -1)
 */

#pragma D option quiet

bifrost::do_sys_openat2:entry
{
    xstack();
}
