# Cross-domain interleaved stack — scoping note

Companion to `cross-domain-pair.md`. Today bifrost has four
independent stack walkers: `stack()` (macOS host kernel), `ustack()`
(macOS host user) via libdtrace, plus `gstack()` (guest kernel via
`arch_stack_walk` in the kprobe BPF kfunc) and `gustack()` (guest
user via `arch_stack_walk_user`) shipped over the SHMEM ringbuf.
The marquee feature is to splice all four into one logical stack
at a single fire site — *one trace, two kernels, four stacks*.

## Prior art landscape

Nobody ships this. The closest existing things are all *temporal*
joins, not unified-stack joins.

- **perf kvm** records on host and guest in parallel (`--host
  --guest --guestkallsyms --guestmodules`); each side keeps its
  own callchain, post-processed flame graphs put guest/host code
  side-by-side via the gray "syscall divider" colouring trick, but
  no single callchain ever spans the boundary.
- **Intel VTune KVM mode** runs two collectors and merges by
  timestamp; output is two interleaved tracks, not one stack.
- **Nemati / vPSD / HEC (Polytechnique Montréal)** post-hoc joins
  `kvm_entry`/`kvm_exit` against guest sched events at SQL level;
  the output is a Gantt of vCPU states, again no joined stack.
- **Magic-trace** (Intel PT) explicitly does not support VMs.
- **Tracy / Spall** are macro-based in-process profilers; no
  hypervisor awareness.
- **Brendan Gregg's Xen unikernel work** profiled domU from dom0
  via `perf record` of the vCPU thread plus a copy of the guest
  symbol map — single domain, sampled, no causal stitching.
- **ftrace `function_graph` + KVM events** stays inside one
  kernel; trace-cmd's "guest+host" mode synchronises clocks but
  emits two trace files, not a unified callchain.

Conclusion: no precedent for a *single primitive that returns one
interleaved callchain spanning hypervisor*. This would be novel.

## Mechanics on macOS HVF + Linux KVM-shaped guest

Three structural facts shape the design:

1. **Each vCPU is bound to one host pthread.** `hv_vcpu_run`
   blocks that thread until the guest exits. While the guest
   runs, the host kernel sees the vCPU thread parked inside the
   `hv_trap` syscall — its host kernel stack is `mach_msg_trap →
   hv_vm_run` and its host user stack is the libkrun vCPU loop.
   These are *static* during guest execution: the interesting
   host-side frames are the ones leading *into* `hv_vcpu_run`,
   captured before the vCPU enters guest mode.
2. **No host-side stack is reachable from inside the guest BPF
   program.** When our kprobe fires, we are running in the guest
   kernel, on the vCPU thread *from the guest's point of view*.
   The host kernel is not on the call chain — HVF entered the
   guest via an architectural EL1/EL2 transition; there is no host
   frame pointer to walk. We cannot do a synchronous host capture
   from the guest BPF program.
3. **The vCPU thread's host stack is reachable from a co-located
   host probe.** The harness already has bifrost CLI's PID; a
   `pid$harness::hv_vcpu_run:entry` (or simpler: a `profile-997hz`
   pinned to that thread) gives us the macOS user+kernel stack
   *adjacent in time* to the guest fire. Worst-case skew is bounded
   by HVF MMIO trap latency: median 3.3 µs, max 713 µs (README
   §HVF MMIO trap cost). For a stitched marquee output this is
   well under perceptual error.

Practical conclusion: the host-side legs ride a separate libdtrace
clause that fires on the same vCPU thread; the merge happens in
the bifrost CLI's record demuxer, keyed on `(vcpu_tid,
fire_window)`.

## Time-correlation approach

Pick **best-effort post-hoc stitch with deterministic anchoring**,
not single atomic capture.

- *Atomic* is mechanically impossible: the host frames are
  produced by libdtrace inside the macOS kernel; the guest frames
  are produced by `arch_stack_walk` inside the guest kernel. They
  live in two different ringbufs and two different clock domains.
- *Stitch* is cheap: bifrost already converts both clocks via
  `bifrost_skew.d`'s table, and 3.3 µs median MMIO trap is the
  natural causal window. The failure modes are: (a) host clause
  doesn't fire (vCPU was scheduled out before bifrost saw it) —
  emit guest-only stanza with a `[host: missing]` divider; (b) host
  clause fires twice in window — keep the closest by `|Δt|`. Both
  failures degrade gracefully to today's output.

## Syntax sketch

Reject a single magic `xstack()` builtin: it hides the four
clocks, the four resolvers, and the failure modes. Prefer an
explicit *stitch directive* on top of the four existing builtins.

```d
/* (a) per-side mix; render-time stitch via co-thread implicit key */
bifrost:guest_kernel:do_sys_openat2:entry {
    gustack();      /* guest user  */
    gstack();       /* guest kern  */
    xstitch();      /* sentinel: pair me with the next host clause
                       on this vcpu's tid, within 1ms */
}
pid$harness::hv_vcpu_run:return /xstitch_pending()/ {
    stack();        /* macOS kern  */
    ustack();       /* macOS user  */
}
```

```d
/* (b) flag form, single fire — host legs are best-effort lookups
   against the most recent vcpu sample */
bifrost:guest_kernel:tcp_v4_rcv:entry {
    xstack(XS_GUEST_USER | XS_GUEST_KERN | XS_HOST_KERN | XS_HOST_USER);
}
```

```d
/* (c) the marquee one-liner — sugar over (b) */
bifrost:guest_kernel:tcp_v4_rcv:entry { xstack(); }   /* all four */
```

Form (c) compiles to (b); form (b) compiles to (a) plus a
host-side `profile-997hz /tid==arg0/ { stack(); ustack(); }`
auto-injected by the lowerer, anchored on the vCPU tid carried in
the SHMEM record header.

## Renderer story

One record per fire, four stack slices, three divider lines:

```
[vdso]!__kernel_clock_gettime+0x164                    <-- gustack
redis-server!main+0x304
==== guest user / guest kernel ====
arm64_sys_clock_gettime+0x40                           <-- gstack
el0_svc_common+0x100
==== guest kernel / hypervisor ====
hv_vcpu_run+0x12                                       <-- stack
mach_msg_trap+0x80
==== hypervisor / macOS user ====
libkrun.dylib!krun_vcpu_loop+0x2e0                     <-- ustack
bifrost!main+0x1f0
```

Resolvers are already built: the guest ELF symtab parser for
gustack; the on-disk libdtrace USDT/pid resolver for ustack; the
shipped kallsyms slice for gstack; libdtrace's `stack()` resolver
for the macOS kernel. The renderer's only new code is the
**stitcher**: a `HashMap<(vcpu_tid, window_id),
StanzaBuilder>` in `host/bifrost/src/bin/bifrost.rs` that closes
a stanza when both sides arrive or `expire=1ms` elapses.

## Stitching approaches

Three approaches to joining host and guest stacks, in increasing
order of causal fidelity and invasiveness:

- **Side-by-side, no causality.** Two clauses fire from
  one D script; renderer emits adjacent stanzas under a single
  divider header `==== guest fire / nearest host sample ====`.
  No vCPU keying. Pure renderer glue. Produces useful output for
  any single-vCPU workload.
- **Explicit vcpu-tid pairing.** Lowerer auto-injects
  the `pid$harness:hv_vcpu_run` clause and stamps the vCPU tid
  into every guest record. Stitcher keys on tid + window.
  The hard part: getting libdtrace pid-provider probes to attach
  reliably to libkrun's dynamically-spawned vCPU threads (dtrace
  needs the PID; the threads exist before the bifrost CLI starts).
  Workaround: have libkrun publish `vcpu_tid[N]` via a USDT probe
  in `bifrost_event_send`, which we already control.
- **Synchronous host capture from guest kfunc.** Add a
  host-side stack-grabber daemon that owns a SHMEM control slot;
  the guest BPF kprobe writes the request, the host signals the
  vCPU thread out of guest mode (via `hv_vcpu_interrupt`), libdtrace
  trips on the resulting `hv_vcpu_run:return`, captures host
  stacks, returns to guest. Most invasive; perturbs guest
  scheduling. Open question: whether `hv_vcpu_interrupt`
  is callable from a non-vcpu host thread without races. Reserved
  for cases where the explicit-pairing stitch error is unacceptable.

## Starting point

The side-by-side approach on a single-vCPU clock_gettime workload
is the simplest fixture to drive. A guest-side loop firing
`gustack()` + `gstack()` on `clock_gettime`, plus a host-side
clause `pid$target::hv_vcpu_run:entry { stack(); ustack(); }`
attached to the bifrost CLI itself, with a divider per stanza,
renders one example. This needs only the stitching code in
`host/bifrost/src/bin/bifrost.rs`, no parser/lowerer changes.

From there, the choice between explicit vcpu-tid pairing (causal
correctness) and the "nearest sample" model depends on whether
real workloads (HTTP roundtrip, openat, fs activity) produce
visibly wrong stitches.

## Relevant files

- `host/bifrost/src/bin/bifrost.rs` (record demuxer and
  renderer; stitcher lands here)
- `host/bifrost/src/schema.rs` (`KernelStack`/`UserStack`
  field kinds; add `vcpu_tid` header field for explicit pairing)
- `third_party/smolvm/libkrun/src/devices/src/virtio/bifrost/`
  (libkrun-side vCPU thread spawn — would need a USDT probe for
  explicit vcpu-tid pairing; the directory contains 9 files: agg, control, mod,
  payload, probes, render, shmem, syms, vma)
- `third_party/linux-bifrost/drivers/bifrost/bifrost.rs`
  (`bifrost_get_stack` kfunc; reuse the same record-shape
  contract for the future synchronous host-capture path)

## Sources

- [Perf events on KVM (linux-kvm.org)](https://www.linux-kvm.org/page/Perf_events)
- [perf-kvm(1) man page](https://www.man7.org/linux/man-pages/man1/perf-kvm.1.html)
- [Profile KVM Kernel and User Space from the Host (Intel VTune)](https://www.intel.com/content/www/us/en/docs/vtune-profiler/user-guide/2024-2/profiling-kvm-kernel-and-user-space-from-the-host.html)
- [Brendan Gregg — Unikernel Profiling: Flame Graphs from dom0](https://www.brendangregg.com/blog/2016-01-27/unikernel-profiling-from-dom0.html)
- [Brendan Gregg — CPU Flame Graphs (kernel/user colouring)](https://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html)
- [Magic-trace (Jane Street) — Intel PT, no VM support](https://github.com/janestreet/magic-trace)
- [Tracy frame profiler](https://github.com/wolfpld/tracy)
- [VM Flow Analysis Using Host Kernel Tracing (Nemati, Polytechnique Montréal)](https://publications.polymtl.ca/3902/1/2019_HaniNemati.pdf)
- [Host-Based VM Workload Characterization (ACM TOMPECS)](https://dl.acm.org/doi/10.1145/3460197)
- [Apple Hypervisor framework — vCPU lifecycle](https://developer.apple.com/documentation/hypervisor)
- [libkrun virtual CPU implementation (DeepWiki)](https://deepwiki.com/containers/libkrun/3.2-virtual-cpu-implementation)
- [eBPF-based Extensible Paravirtualization (Springer)](https://link.springer.com/chapter/10.1007/978-3-031-23220-6_27)
- [DTrace ustack() reference (Oracle)](https://docs.oracle.com/cd/E19253-01/817-6223/chp-actsub-ustack/index.html)
