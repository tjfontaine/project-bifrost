# profile-stub — profile renderer demo

Exercise of the profile-N sample renderer while the VMM is being
reduced to an opaque conduit. Today's landing is a *scaffold*: the
CLI performs OBSERVER_HELLO, drains any transport samples that arrive,
and emits one local synthetic sample if none do. Real periodic guest
sampling plugs into the same wire format without requiring libkrun to
understand profile semantics.

## What this demonstrates

- The CLI's `bifrost profile -p $PID` subcommand attaches, performs
  HELLO with `FEATURE_PROFILE_N` requested, and drains
  `D4_KIND_PROFILE_SAMPLE` records from the rsp ring.
- If no profile record arrives, the CLI encodes a kernel-context
  sample with `bifrost_wire::codec::encode_profile_sample` and runs
  it through the same renderer.
- Cross-layer rendering: synthetic PCs in the
  `0xffff_ff80_0dea_dXXX` range are recognizably fake, so the
  operator can distinguish "scaffold sample" from "real workload".

## Running

    # 1. Start smolvm:
    smolvm --kernel /path/to/kernel ...

    # 2. In another shell, drive the CLI:
    bifrost profile -p $SMOLVM_PID

Expected output:

    bifrost profile -p 53413
      status  attaching control SHM
      status  OBSERVER_ATTACH acked
      caps    HELLO_ACK: driver=0x10003 negotiated=0x10003 observer_id=53413
      warn    driver does not advertise FEATURE_PROFILE_N; using CLI-owned
              synthetic profile sample if no transport sample arrives.
      status  draining profile samples (max=16)
      ─────────────────────────────────────────────────
      status  no transport profile samples received in 5s
      info    emitting CLI-owned synthetic sample
      #1     pid=<cli-pid> tid=0 cpu=0 flags=[kernel] frames=[0xffffff800dead000]

## What this does NOT yet exercise

- Periodic sampling: the demo emits exactly one local synthetic sample
  if no transport sample arrives; the timer-driven sampler is future
  work.
- Real PCs: the demo PCs are synthetic; vcpu pause + frame walk will
  extract real guest stacks.
- Symbolication: the CLI renders raw PCs as hex; the host-side
  symbolicator (kallsyms for kernel-context, per-task symtab
  side-channel for user-context) plugs in alongside M.2.

The demo is not part of the smoke harness because its exit-code shape
doesn't fit the harness's "drops=0 / agg-populated" contract. A
real-sampling demo should live alongside the others under examples/
once real samples are flowing.
