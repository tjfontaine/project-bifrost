// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// `KernelAdapter` — the single customization point for guest kernel
// modules. Every guest implements this trait against its local
// tracing engine; the session walker drives the trait, never the
// engine directly.
//
// Trait shape rationale:
//
//   - **Methods return Result, not panic.** A guest probe may be
//     missing on this kernel, an aggregation kind may be unsupported,
//     a destructive action may be policy-denied. The reason returns
//     to the host as a per-ECB `EcbStatus`; the session keeps
//     attaching the rest of the chain.
//
//   - **Slices, not Strings.** Probe-spec text comes from a DOF
//     strtab section — borrowed from the parsed blob, never copied
//     into kernel memory.
//
//   - **`provider_supports` is mandatory; the rest is optional but
//     the default impls return `RejectReason::NotImplemented`.** A
//     barely-wired adapter still surfaces useful status; full
//     adapters (Linux DIF→eBPF, FreeBSD native DTrace) override
//     everything.

use crate::LowerError;
use crate::action::ActionDescriptor;
use crate::agg::AggKind;

/// Reason an adapter refused to materialise an ECB or action. The
/// session walker carries this verbatim into the per-ECB status the
/// host fanout consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RejectReason {
    /// The local provider exists but the function/event named was
    /// not found in the running kernel.
    ZeroMatch = 1,
    /// The local kernel does not have this provider at all (e.g. a
    /// `usdt:` probe on a kernel without uprobes).
    NoProvider = 2,
    /// Provider exists and the symbol resolved, but the adapter
    /// hasn't been wired up to attach yet.
    NotImplemented = 3,
    /// Destructive action (`stop`, `raise`, `chill`, `panic`,
    /// `breakpoint`) and policy says no.
    DestructiveDisabled = 4,
    /// Aggregation kind not supported (e.g. `llquantize` on a guest
    /// that hasn't implemented log-linear buckets yet).
    AggKindUnsupported = 5,
    /// Adapter resource limit hit (slot table full, JIT failed, BPF
    /// verifier rejected the program).
    ResourceExhausted = 6,
    /// Probe attached but the per-ECB DIFO lowering failed. The
    /// adapter should carry a numeric detail code via its own
    /// channel; this enum stays small.
    LoweringFailed = 7,
}

/// Probe target. Matches the canonical DTrace `provider:module:
/// function:name` tuple. Each adapter is free to ignore fields that
/// don't apply (e.g. Linux fbt ignores `module`).
#[derive(Debug, Clone, Copy)]
pub struct ProbeTarget<'a> {
    pub provider: &'a str,
    pub module: &'a str,
    pub function: &'a str,
    pub name: &'a str,
}

/// Per-ECB attach status returned through the session walker.
#[derive(Debug, Clone, Copy)]
pub enum EcbStatus {
    Accepted { attached_id: u64 },
    Rejected(RejectReason),
    /// Provider matched but no live symbol matched on this kernel.
    /// Distinct from `Rejected(ZeroMatch)` so the host can render
    /// the ECB as "no targets" rather than "error".
    ZeroMatch,
}

/// The trait every guest kernel module implements. Method names match
/// the DTrace action semantics; bodies are OS-specific.
///
/// Default impls return `NotImplemented`; the bare minimum a brand-new
/// adapter must override is `provider_supports` and `attach_probe`.
pub trait KernelAdapter {
    /// Lifetime of borrowed bytes returned to the walker — usually
    /// tied to the DOF blob.
    type Blob<'b>: 'b
    where
        Self: 'b;

    /// True iff this adapter recognises the named provider on the
    /// running kernel. Should return cheaply — the walker calls it
    /// once per ECB before doing any DIFO work.
    fn provider_supports(&self, provider: &str) -> bool;

    /// Attach the named probe and return either an opaque adapter
    /// handle (id, slot pointer, BPF prog fd value — your choice) or
    /// a reject reason. The session walker hands the returned
    /// `attached_id` back through `record_action` so the adapter
    /// keeps no global state to look up.
    fn attach_probe(&mut self, target: ProbeTarget<'_>) -> Result<u64, RejectReason>;

    /// Bind a predicate DIFO to a previously-attached probe.
    /// Default: NotImplemented.
    fn bind_predicate(
        &mut self,
        _attached_id: u64,
        _difo_bytes: &[u8],
    ) -> Result<(), RejectReason> {
        Err(RejectReason::NotImplemented)
    }

    /// Record one action against an attached probe. The DIFO bytes
    /// implementing the action's value-expression are passed inline;
    /// the adapter compiles or interprets them. Default:
    /// NotImplemented.
    fn record_action(
        &mut self,
        _attached_id: u64,
        _action: &ActionDescriptor,
        _difo_bytes: &[u8],
    ) -> Result<(), RejectReason> {
        Err(RejectReason::NotImplemented)
    }

    /// Declare an aggregation slot. Default: NotImplemented.
    fn declare_aggregation(
        &mut self,
        _var_id: u32,
        _kind: AggKind,
        _bucket_count: u32,
    ) -> Result<(), RejectReason> {
        Err(RejectReason::AggKindUnsupported)
    }

    /// Detach a previously-attached probe. Idempotent; called once
    /// per attached_id at session teardown.
    fn detach_probe(&mut self, _attached_id: u64) {}

    /// Hook for adapter-defined session lifecycle events. The walker
    /// calls `on_session_event(SessionEvent::Begin)` before the first
    /// ECB and `SessionEvent::End` after the last. Default no-op.
    fn on_session_event(&mut self, _event: SessionEvent) -> Result<(), LowerError> {
        Ok(())
    }
}

/// Adapter-visible session lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Begin,
    End,
}

/// Test-only stub adapter that accepts every probe and records every
/// action without doing real work. Lives behind `cfg(test)` so the
/// kernel build doesn't pull it in.
#[cfg(test)]
pub(crate) struct StubAdapter {
    pub attached: u64,
    pub records: u32,
    pub aggs: u32,
}

#[cfg(test)]
impl StubAdapter {
    pub(crate) fn new() -> Self {
        Self { attached: 0, records: 0, aggs: 0 }
    }
}

#[cfg(test)]
impl KernelAdapter for StubAdapter {
    type Blob<'b> = &'b [u8];

    fn provider_supports(&self, _provider: &str) -> bool {
        true
    }

    fn attach_probe(&mut self, _target: ProbeTarget<'_>) -> Result<u64, RejectReason> {
        self.attached += 1;
        Ok(self.attached)
    }

    fn record_action(
        &mut self,
        _attached_id: u64,
        _action: &ActionDescriptor,
        _difo_bytes: &[u8],
    ) -> Result<(), RejectReason> {
        self.records += 1;
        Ok(())
    }

    fn declare_aggregation(
        &mut self,
        _var_id: u32,
        _kind: AggKind,
        _bucket_count: u32,
    ) -> Result<(), RejectReason> {
        self.aggs += 1;
        Ok(())
    }
}
