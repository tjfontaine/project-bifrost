// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// bifrost-dtrace-lower — the DOF-generic guest-side IR.
//
// ## Why this crate exists
//
// Bifrost is built around one rule: **DTrace DOF is the guest
// control-plane IR, and SHMEM is the generic data plane**. The host
// compiles D to DOF, packages it in a `DTRACE_SESSION_V1` envelope
// (see `bifrost-wire`), and ships the bytes opaquely through
// virtio-conduit. Each guest kernel module *decodes* the same envelope
// against this crate, then drives a local `KernelAdapter` to talk to
// its native tracing engine (eBPF on Linux, native DTrace state on
// FreeBSD/illumos).
//
// Before this rebuild the host CLI carried Linux-specific DIF→eBPF
// lowering and pre-built BFR7 wrappers; the kernel module just executed
// what arrived. That coupled the host to one guest OS and made
// FreeBSD/illumos guests "almost the same" rather than uniform. This
// crate is the inversion: **the lowering crate lives in the root repo,
// guests consume it, and the host never speaks an OS-specific dialect.**
//
// ## Module layout
//
//   - `dof`        — DOF object header + section-table parsing.
//                    Borrowed-slice views; no allocation.
//   - `dif`        — DIF instruction decoder + DIFO scratch model.
//                    Mirrors the libdtrace bytecode shape from
//                    `sys/dtrace.h`.
//   - `ecb`        — ECB descriptor + action-chain walker.
//   - `action`     — DTrace action kinds (`DTRACEACT_*`) and their
//                    semantic record shape.
//   - `agg`        — aggregation kinds (`DTRACEAGG_*`) and planner
//                    helpers (key/value classification, multi-agg
//                    chain decomposition).
//   - `adapter`    — `KernelAdapter` trait — the surface every guest
//                    kernel module implements.
//   - `session`    — `Session` driver that walks ECBs from a parsed
//                    DOF blob and dispatches into an adapter.
//
// ## Invariants this crate enforces
//
//   - **Bounds first.** Every offset/length pair in DOF is checked
//     against the input slice before deref. The fuzz fixtures in
//     `tests/malformed_dof.rs` exist to prove a bad DOF cannot panic.
//   - **No host-only deps.** `no_std`, no `std::io`, no `Vec` without
//     the `alloc` feature gate.
//   - **OS-agnostic.** Nothing in this crate names "Linux", "BPF",
//     "eBPF", "FreeBSD", "kprobe" outside of doc comments that
//     describe how a particular adapter lowers an action. The
//     adapter trait is the only customization surface.
//
// ## What this crate is *not*
//
//   - Not a full D parser. D source → DOF is libdtrace's job, on
//     the host. This crate consumes DOF, never `.d` text.
//   - Not a kernel runtime. It plans, it walks, it dispatches; the
//     adapter does the work.
//   - Not a wire-format library. Session/SHMEM envelopes live in
//     `bifrost-wire`. Consumers link both.

#![no_std]
#![deny(unreachable_pub)]
#![allow(clippy::needless_range_loop)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod action;
pub mod adapter;
pub mod agg;
pub mod dif;
pub mod dof;
pub mod ecb;
pub mod session;

/// Errors that any DOF-driven path can return. Kept as a flat enum so
/// `#[no_std]` callers can match without pulling `Box<dyn Error>` or a
/// trait-object error type. Conversion to an OS-specific errno (or to
/// a host-side `anyhow::Error`) is the caller's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// DOF magic (`\x7fDOF`) missing or wrong endian.
    BadMagic,
    /// DOF header smaller than the canonical 64 bytes.
    ShortHeader,
    /// A section's offset+size overflows the input slice.
    SectionOutOfBounds {
        section_index: u32,
        section_offset: u64,
        section_size: u64,
        blob_len: u64,
    },
    /// A section's `entsize` does not divide its `size` cleanly — the
    /// table would slice unevenly. libdtrace rejects this; so do we.
    SectionEntsizeMismatch {
        section_index: u32,
        entsize: u32,
        size: u64,
    },
    /// A DOF section index referenced from an ECB / action descriptor
    /// is out of range for this blob's section table.
    SectionIndexOutOfRange { referenced: u32, section_count: u32 },
    /// DIFO buffer terminated mid-instruction.
    TruncatedDif,
    /// A DIF instruction opcode is outside the documented range. We
    /// pass it through verbatim so the caller can report the byte.
    UnknownDifOp(u8),
    /// An action descriptor's kind is outside `[DTRACEACT_NONE,
    /// DTRACEACT_MAX]`.
    UnknownActionKind(u32),
    /// An aggregation descriptor's kind is outside the
    /// `DTRACEAGG_*` enumeration.
    UnknownAggKind(u32),
    /// The adapter refused to materialise this action (e.g. no local
    /// provider). The session walker carries this through to a
    /// per-ECB status the host can fanout.
    AdapterRejected(adapter::RejectReason),
    /// The DOF declared more ECBs / actions than the adapter is
    /// configured to handle. Soft cap; raise the cap to fix.
    CapacityExceeded { limit: u32 },
}

/// Canonical target-OS discriminator. Lives here (not just in
/// `bifrost-wire`) because the session walker needs to gate
/// adapter-call shapes on the same value.
///
/// Wire-encoded as a `u16` in `DTRACE_SESSION_V1::target_os`. New
/// values are additive: a guest receiving a session for an unknown
/// target_os must STATUS-reject the whole session rather than guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TargetOs {
    /// Any target. Used when the host fanouts to every connected
    /// guest and lets each one decide.
    Any = 0,
    Linux = 1,
    FreeBsd = 2,
    Illumos = 3,
    Macos = 4,
}

impl TargetOs {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0 => Self::Any,
            1 => Self::Linux,
            2 => Self::FreeBsd,
            3 => Self::Illumos,
            4 => Self::Macos,
            _ => return None,
        })
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}
