// DIFO result category — what shape of value does this DIF object
// leave in r0 at completion?
//
// A single category enum classifies each DIFO's result so the
// downstream lowering arms (in `lower/agg.rs` and a few sites in
// `lower/action.rs`) can dispatch with one match instead of a
// per-shape predicate scanned at every dispatch site.  Adding a new
// pointer-shape — e.g. `strjoin(execname, "_")` returning a pointer
// to a per-clause scratch buffer of joined bytes — becomes one new
// `DifoCategory` variant plus one new arm in the lowering match.
//
// The opcode-scanning machinery (LDGS=0x29 with imm16=0x0118 →
// execname; SETS=0x26 → string literal) provides the raw signal;
// this module turns it into a usable classification.

use crate::Dof;

/// Coarse classification of what a DIF object's result register
/// (r0 at end-of-program) actually points at.
///
/// The four variants cover everything the lowering currently
/// special-cases.  Adding a new pointer-shape is one new variant
/// here, one new arm in `lower/agg.rs::emit_agg_chain_at` (and any
/// other call site that needs to deref).  Predicate-dispatch chains
/// in callers stay flat instead of growing per shape.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DifoCategory {
    /// r0 holds a u64 scalar — the agg-key store can take it
    /// verbatim, no deref needed.  This is the default for any
    /// DIFO that doesn't trip one of the special cases below.
    Scalar,

    /// r0 points at the per-clause `comm@fp-136` buffer (16 bytes
    /// of NUL-padded process name on the BPF stack).  Produced by
    /// LDGS 0x0118.  Agg-key lowering must deref 8 bytes;
    /// otherwise every clause invocation hashes on a different
    /// stack address.
    PtrComm,

    /// r0 points at a STR_SCRATCH-resident string literal on the
    /// per-clause BPF stack (e.g. `"commit\0…"` from
    /// `@txn["commit"]`).  Produced by SETS=0x26.  Same deref
    /// requirement as `PtrComm`; without it the agg fans out into
    /// one entry per fire.  8-byte truncation matches the existing
    /// per-key wire format.
    PtrStrScratch,
}

/// Compute the category for a DIF object identified by section
/// index.  Returns `Scalar` for any DIFO that doesn't trip a
/// pointer-shape opcode — that's the safe default (taking r0
/// verbatim is correct for all integer-shaped results).
///
/// Note on conservative-true: if a DIFO contains *both* an LDGS
/// 0x0118 (e.g. as a sub-expression for a no-op concatenation) and
/// arithmetic that promotes the result back into a scalar, this
/// returns `PtrComm` because the LDGS appears.  False positives
/// here cost an extra 8-byte load before the agg-key store —
/// benign.  False negatives leave the pointer-key fanout bug
/// unfixed, which is the worse failure mode.
///
/// The same conservatism applies to SETS — any SETS in the DIFO
/// is enough to choose `PtrStrScratch`.  In practice DTrace
/// doesn't synthesize string literals into integer-typed results
/// without an intervening conversion, so the false-positive rate
/// is essentially zero.
pub fn category_for_difo(dof: &Dof, difo_secidx: u32) -> DifoCategory {
    let difo = match dof.difo(difo_secidx) {
        Some(d) => d,
        None => return DifoCategory::Scalar,
    };
    let dif_idx = match difo.dif_section() {
        Some(i) => i,
        None => return DifoCategory::Scalar,
    };
    let dif_sec = match dof.sections.get(dif_idx as usize) {
        Some(s) => s,
        None => return DifoCategory::Scalar,
    };
    // LDGS 0x29 with imm16=0x0118 wins over SETS — execname is the
    // older special case and the comm pointer is what the lowered
    // code actually references.  In a DIFO that contains both, the
    // result still points at comm.
    let mut has_ldgs_execname = false;
    let mut has_sets = false;
    for ins in dof.dif_instructions(dif_sec) {
        if ins.op == 0x29 && ins.imm16() == 0x0118 {
            has_ldgs_execname = true;
        }
        if ins.op == 0x26 {
            has_sets = true;
        }
    }
    if has_ldgs_execname {
        DifoCategory::PtrComm
    } else if has_sets {
        DifoCategory::PtrStrScratch
    } else {
        DifoCategory::Scalar
    }
}

impl DifoCategory {
    /// True if the agg-key (or printf %s arg) lowering must emit
    /// an 8-byte deref of r0 before storing.  Both pointer-shape
    /// variants need it; `Scalar` does not.
    pub fn needs_8byte_deref(self) -> bool {
        matches!(self, DifoCategory::PtrComm | DifoCategory::PtrStrScratch)
    }
}
