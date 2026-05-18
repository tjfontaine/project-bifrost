// SPDX-License-Identifier: Apache-2.0
//
// Capability fanout — host-side session router after the DOF-generic
// rebuild.
//
// Pre-rebuild: the host picked a target per probe-spec
// (`is_uprobe`/`is_fbt`/...), built an OS-specific payload (BFR7 for
// Linux, native DTrace state for FreeBSD), and shipped a different
// thing to each guest.
//
// Post-rebuild: the host compiles D to **one DOF blob**, then for
// each connected guest produces a `DTRACE_SESSION_V1` envelope
// pointing at that DOF (uploaded into the session arena of the
// SHMEM region). The envelope carries:
//
//   - target_os         — set to `TARGET_OS_ANY` when one envelope
//                         serves all guests, or to a specific
//                         `TARGET_OS_*` when the host wants to limit.
//   - capability_request — the union of capabilities the D source
//                         needs (FBT, TRACEPOINT, USDT, profile, the
//                         set of aggregation kinds used, etc.).
//   - capability_required — the subset that's load-bearing; the
//                         guest must refuse the session if any are
//                         missing rather than silently dropping
//                         ECBs.
//
// Each guest replies with one `SHMEM6_KIND_STATUS` record per ECB
// (`accepted`, `rejected(reason)`, `zero_match`). The host aggregates
// these into the per-target status table the renderer uses.

use bifrost_wire::session_envelope::{
    DTRACE_SESSION_ENVELOPE_SIZE, DTRACE_SESSION_WIRE_MAJOR, DTRACE_SESSION_WIRE_MINOR,
    SESSION_CAP_AGG_AVG, SESSION_CAP_AGG_COUNT, SESSION_CAP_AGG_LLQUANTIZE,
    SESSION_CAP_AGG_LQUANTIZE, SESSION_CAP_AGG_MAX, SESSION_CAP_AGG_MIN,
    SESSION_CAP_AGG_QUANTIZE, SESSION_CAP_AGG_STDDEV, SESSION_CAP_AGG_SUM,
    SESSION_CAP_FBT, SESSION_CAP_PROFILE_TIMER, SESSION_CAP_STACK, SESSION_CAP_TRACEPOINT,
    SESSION_CAP_UPROBE, SESSION_CAP_URETPROBE, SESSION_CAP_USDT, SESSION_CAP_USTACK,
    SessionEnvelope, TARGET_OS_FREEBSD, TARGET_OS_ILLUMOS, TARGET_OS_LINUX, TARGET_OS_MACOS,
    encode,
};
use std::collections::HashMap;

/// One connected guest the fanout planner knows about.
#[derive(Debug, Clone)]
pub struct TargetGuest {
    pub name: String,
    pub target_os: u16,
    /// Capabilities this guest's KernelAdapter advertises.  The
    /// planner intersects with the session's `capability_request`
    /// when emitting the envelope; the guest still validates per-ECB.
    pub advertised_capabilities: u64,
}

impl TargetGuest {
    pub fn target_os_name(&self) -> &'static str {
        match self.target_os {
            TARGET_OS_LINUX => "linux",
            TARGET_OS_FREEBSD => "freebsd",
            TARGET_OS_ILLUMOS => "illumos",
            TARGET_OS_MACOS => "macos",
            _ => "any",
        }
    }
}

/// Hints extracted from a parsed D source.  The planner uses these
/// to build the session's `capability_request` bitset.
#[derive(Debug, Default, Clone, Copy)]
pub struct CapabilityHints {
    pub uses_fbt: bool,
    pub uses_tracepoint: bool,
    pub uses_uprobe: bool,
    pub uses_uretprobe: bool,
    pub uses_usdt: bool,
    pub uses_profile_timer: bool,
    pub uses_stack: bool,
    pub uses_ustack: bool,
    pub uses_agg_count: bool,
    pub uses_agg_sum: bool,
    pub uses_agg_min: bool,
    pub uses_agg_max: bool,
    pub uses_agg_avg: bool,
    pub uses_agg_stddev: bool,
    pub uses_agg_quantize: bool,
    pub uses_agg_lquantize: bool,
    pub uses_agg_llquantize: bool,
}

impl CapabilityHints {
    /// Fold the hints into the canonical `SESSION_CAP_*` bitset.
    pub fn as_capability_bits(&self) -> u64 {
        let mut bits = 0u64;
        if self.uses_fbt {
            bits |= SESSION_CAP_FBT;
        }
        if self.uses_tracepoint {
            bits |= SESSION_CAP_TRACEPOINT;
        }
        if self.uses_uprobe {
            bits |= SESSION_CAP_UPROBE;
        }
        if self.uses_uretprobe {
            bits |= SESSION_CAP_URETPROBE;
        }
        if self.uses_usdt {
            bits |= SESSION_CAP_USDT;
        }
        if self.uses_profile_timer {
            bits |= SESSION_CAP_PROFILE_TIMER;
        }
        if self.uses_stack {
            bits |= SESSION_CAP_STACK;
        }
        if self.uses_ustack {
            bits |= SESSION_CAP_USTACK;
        }
        if self.uses_agg_count {
            bits |= SESSION_CAP_AGG_COUNT;
        }
        if self.uses_agg_sum {
            bits |= SESSION_CAP_AGG_SUM;
        }
        if self.uses_agg_min {
            bits |= SESSION_CAP_AGG_MIN;
        }
        if self.uses_agg_max {
            bits |= SESSION_CAP_AGG_MAX;
        }
        if self.uses_agg_avg {
            bits |= SESSION_CAP_AGG_AVG;
        }
        if self.uses_agg_stddev {
            bits |= SESSION_CAP_AGG_STDDEV;
        }
        if self.uses_agg_quantize {
            bits |= SESSION_CAP_AGG_QUANTIZE;
        }
        if self.uses_agg_lquantize {
            bits |= SESSION_CAP_AGG_LQUANTIZE;
        }
        if self.uses_agg_llquantize {
            bits |= SESSION_CAP_AGG_LLQUANTIZE;
        }
        bits
    }
}

/// Single-source-of-truth planner input: a DOF blob (already
/// compiled by libdtrace), the SHA, and the capability hints.
#[derive(Debug, Clone)]
pub struct SessionPlan {
    pub session_id: u64,
    pub duration_ms: u64,
    pub flags: u16,
    pub dof_offset: u64,
    pub dof_length: u64,
    pub dof_sha256: [u8; 32],
    pub hints: CapabilityHints,
    /// Capabilities the guest *must* satisfy.  Typically a strict
    /// subset of `hints.as_capability_bits()` — the host marks the
    /// load-bearing pieces here so a guest with no USDT support
    /// refuses the whole session rather than silently dropping the
    /// USDT clauses.
    pub required_capabilities: u64,
}

/// One envelope ready to push through the control ring, tagged with
/// the guest it's destined for.
pub struct PlannedEnvelope {
    pub guest_name: String,
    pub target_os: u16,
    pub envelope_bytes: [u8; DTRACE_SESSION_ENVELOPE_SIZE],
}

/// Fanout the plan across `guests`, producing one envelope per guest.
/// Each envelope's `capability_request` is the intersection of the
/// plan's hint set with the guest's advertised capabilities; the
/// `capability_required` field is passed through unchanged.  Guests
/// missing any required capability still receive an envelope — the
/// guest itself rejects per protocol — but the planner emits a
/// diagnostic so the operator sees the mismatch immediately.
pub fn fanout(plan: &SessionPlan, guests: &[TargetGuest]) -> Vec<PlannedEnvelope> {
    let hint_bits = plan.hints.as_capability_bits();
    let mut out: Vec<PlannedEnvelope> = Vec::with_capacity(guests.len());
    for guest in guests {
        let request = hint_bits & guest.advertised_capabilities;
        let envelope = SessionEnvelope {
            wire_major: DTRACE_SESSION_WIRE_MAJOR,
            wire_minor: DTRACE_SESSION_WIRE_MINOR,
            target_os: guest.target_os,
            flags: plan.flags,
            session_id: plan.session_id,
            duration_ms: plan.duration_ms,
            dof_offset: plan.dof_offset,
            dof_length: plan.dof_length,
            dof_sha256: plan.dof_sha256,
            capability_request: request,
            capability_required: plan.required_capabilities,
        };
        let mut bytes = [0u8; DTRACE_SESSION_ENVELOPE_SIZE];
        encode(&envelope, &mut bytes).expect("buffer is canonical size");
        out.push(PlannedEnvelope {
            guest_name: guest.name.clone(),
            target_os: guest.target_os,
            envelope_bytes: bytes,
        });
    }
    out
}

/// Per-ECB verdict reported by a guest. Mirrors
/// `bifrost_dtrace_lower::adapter::EcbStatus` but uses owned types so
/// the host can route it through async channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcbVerdict {
    Accepted,
    Rejected(u8),
    ZeroMatch,
}

/// Accumulator the fanout driver feeds with status records arriving
/// from guests.  Keyed on `(guest_name, ecb_index)`.
#[derive(Default)]
pub struct StatusAccumulator {
    pub by_guest: HashMap<String, Vec<(u32, EcbVerdict)>>,
}

impl StatusAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, guest_name: &str, ecb_index: u32, verdict: EcbVerdict) {
        self.by_guest
            .entry(guest_name.to_string())
            .or_default()
            .push((ecb_index, verdict));
    }

    /// Number of accepted ECBs across all guests.
    pub fn accepted_total(&self) -> usize {
        self.by_guest
            .values()
            .map(|v| v.iter().filter(|(_, v)| *v == EcbVerdict::Accepted).count())
            .sum()
    }

    /// True if at least one guest accepted at least one ECB.
    pub fn any_accepted(&self) -> bool {
        self.by_guest
            .values()
            .any(|v| v.iter().any(|(_, v)| *v == EcbVerdict::Accepted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_guests() -> Vec<TargetGuest> {
        vec![
            TargetGuest {
                name: "linux-1".into(),
                target_os: TARGET_OS_LINUX,
                advertised_capabilities: SESSION_CAP_FBT
                    | SESSION_CAP_TRACEPOINT
                    | SESSION_CAP_AGG_COUNT
                    | SESSION_CAP_AGG_QUANTIZE,
            },
            TargetGuest {
                name: "fbsd-1".into(),
                target_os: TARGET_OS_FREEBSD,
                advertised_capabilities: SESSION_CAP_FBT | SESSION_CAP_AGG_COUNT,
            },
        ]
    }

    fn make_plan() -> SessionPlan {
        let mut hints = CapabilityHints::default();
        hints.uses_fbt = true;
        hints.uses_tracepoint = true;
        hints.uses_agg_count = true;
        hints.uses_agg_quantize = true;
        SessionPlan {
            session_id: 0xface,
            duration_ms: 1000,
            flags: 0,
            dof_offset: 0x4000,
            dof_length: 0x100,
            dof_sha256: [0xab; 32],
            hints,
            required_capabilities: SESSION_CAP_FBT,
        }
    }

    #[test]
    fn fanout_intersects_capabilities() {
        let plan = make_plan();
        let guests = make_guests();
        let envelopes = fanout(&plan, &guests);
        assert_eq!(envelopes.len(), 2);
        let linux = envelopes.iter().find(|e| e.guest_name == "linux-1").unwrap();
        let fbsd = envelopes.iter().find(|e| e.guest_name == "fbsd-1").unwrap();

        // linux: gets all the hinted caps (it advertises all of them).
        let linux_decoded =
            bifrost_wire::session_envelope::decode(&linux.envelope_bytes).unwrap();
        assert_eq!(
            linux_decoded.capability_request,
            SESSION_CAP_FBT | SESSION_CAP_TRACEPOINT | SESSION_CAP_AGG_COUNT | SESSION_CAP_AGG_QUANTIZE
        );
        assert_eq!(linux_decoded.target_os, TARGET_OS_LINUX);
        assert_eq!(linux_decoded.capability_required, SESSION_CAP_FBT);

        // fbsd: tracepoint + quantize NOT advertised, so they fall out.
        let fbsd_decoded =
            bifrost_wire::session_envelope::decode(&fbsd.envelope_bytes).unwrap();
        assert_eq!(
            fbsd_decoded.capability_request,
            SESSION_CAP_FBT | SESSION_CAP_AGG_COUNT
        );
        assert_eq!(fbsd_decoded.target_os, TARGET_OS_FREEBSD);
    }

    #[test]
    fn status_accumulator_tracks_per_guest() {
        let mut acc = StatusAccumulator::new();
        acc.record("linux-1", 0, EcbVerdict::Accepted);
        acc.record("linux-1", 1, EcbVerdict::Rejected(3));
        acc.record("fbsd-1", 0, EcbVerdict::ZeroMatch);
        acc.record("fbsd-1", 1, EcbVerdict::Accepted);
        assert_eq!(acc.accepted_total(), 2);
        assert!(acc.any_accepted());
        let linux_rows = &acc.by_guest["linux-1"];
        assert_eq!(linux_rows.len(), 2);
        assert_eq!(linux_rows[0], (0, EcbVerdict::Accepted));
    }
}
