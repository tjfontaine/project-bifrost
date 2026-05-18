// SPDX-License-Identifier: Apache-2.0
use super::{AGG_MAP_FAKE_FD, PendingCmp, RetMode};
use crate::schema::RecordSchema;
use std::collections::HashMap;

/// Stack region used for clause-local (`this->`) variables.
/// Starts at -200 and grows downward by 8 per slot. -200 is below
/// every other scratch region currently in use (TLS spills at -64,
/// LDGS_SCRATCH at -120, READ_SCRATCH at -144, EXECNAME_SCRATCH at
/// -136, READ_SRC_SAVE at -152) — bumping past those boundaries
/// would corrupt them. Cap at 8 locals per clause for now; raise
/// LOCALS_SLOT_COUNT if real D code exceeds it.
pub const LOCALS_BASE: i16 = -200;
pub const LOCALS_SLOT_COUNT: usize = 8;

/// State carried across `lower_one_state` invocations during a single
/// pass over a DIF section.
pub struct LowerState<'a> {
    pub body: Vec<u8>,
    /// `insn_offsets[i]` = byte offset within `body` where DIF
    /// instruction `i`'s eBPF lowering begins. Length is dif_count + 1
    /// (last entry is "one past end"; DIF can branch here).
    pub insn_offsets: Vec<usize>,
    /// (body_byte_offset of the branch's eBPF slot, dif_target_idx)
    pub pending_branches: Vec<(usize, u32)>,
    /// Result of the last CMP/TST waiting for a Bxx to consume it.
    pub pending_cmp: Option<PendingCmp>,
    pub schema: Option<&'a RecordSchema>,
    /// Active IntTab for the DIF section currently being lowered.
    pub inttab: Option<Vec<u64>>,
    /// Active StrTab bytes for the DIF section currently being lowered.
    /// SETS uses imm16 as a byte offset into this; the string runs
    /// from there to the next NUL.
    pub strtab: Option<Vec<u8>>,
    pub value_off: Option<i16>,
    pub ret_mode: RetMode,
    /// Fake fd for this program's agg map.
    pub agg_map_fake_fd: i32,
    /// Per-program kfunc relocation accumulator. Each entry is
    /// `(insn_idx, name)` where insn_idx is the 8-byte slot in
    /// `body` whose `imm` field needs to be patched at LOAD_PROG
    /// time on the guest with the BTF id resolved against the
    /// running kernel's vmlinux BTF.
    ///
    /// Replaces the BFR6-era practice of baking btf_ids at CLI
    /// compile time — eliminates the BTF-mismatch bug class by
    /// construction.
    pub kfunc_relocs: Vec<(u32, &'static str)>,
    /// Set to true by the gustack action handler when it wants the
    /// program-level wrapper to prepend a VMA-table side-trip.
    /// Whether the gustack VMA-table side-trip kfuncs are available
    /// in the running kernel. We always know they exist by name,
    /// but legacy code paths gated on `*_kfunc_btf_id.is_some()`
    /// to decide whether the kfunc transport was wired up at all.
    /// Defaults to true (kfunc names always emitted; resolution
    /// failure on the guest surfaces as a verifier error).
    pub gustack_kfuncs_available: bool,
    pub needs_vma_table_emit: bool,
    /// Clause-local (`this->`) DIF var_id → stack offset map.
    /// Allocated lazily as LDLS/STLS instructions are encountered.
    /// Slots are zeroed by the program prologue so a `this->x` read
    /// before any write resolves to 0 (matches DTrace semantics).
    pub locals: HashMap<u16, i16>,
    /// Number of values currently pushed onto the tuple stack via
    /// PUSHTR/PUSHTV. Reset to 0 by CALL (which pops the args it
    /// consumes). DIF subroutines and aggregation tuple keys both
    /// flow through this stack. Capacity = TUPLE_STACK_SLOTS;
    /// overflow is a lowering error.
    pub tuple_depth: u32,
    /// Per-DIF-register provenance hint, indexed by DIF register
    /// number (0..=7). Stamped by LDGS-execname and SETS so that
    /// SCMP can gate its inline 16-byte compare on operand shapes
    /// it actually supports (goal item 2). Cleared per section.
    pub reg_kind: [RegKind; 8],
    /// Count of SETS instances lowered in the current program.
    /// Each SETS instance gets its own 16-byte stack slot at
    /// `SETS_SCRATCH_BASE - 16 * idx` so multiple SETS in one program
    /// don't alias (goal item 3). Reset by `new_with_strtab` per
    /// program; the count drives slot assignment and the cap check.
    pub sets_instance_count: usize,
}

/// Maximum SETS instances per program. Each instance reserves a
/// 16-byte stack slot starting at SETS_SCRATCH_BASE (=-344) and
/// growing toward TUPLE_STACK_BASE (=-416). Cap of 3 keeps us
/// strictly above TUPLE_STACK_BASE:
///   slot 0 @ [-344, -329]
///   slot 1 @ [-360, -345]
///   slot 2 @ [-376, -361]
///   (slot 3 would overlap TUPLE_STACK_BASE region — refused.)
/// Suffices for `execname == "a" || execname == "b" || execname == "c"`
/// shaped predicates; rejects beyond.
pub const SETS_INSTANCE_SLOTS: usize = 3;
pub const SETS_SCRATCH_BASE: i16 = -344;
pub const SETS_INSTANCE_SIZE: i16 = 16;

/// Provenance hint for a DIF register's current value.  Used by SCMP
/// to gate the inline 16-byte byte-compare on operand shapes it can
/// support without misreading off-end stack data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegKind {
    /// No specific provenance (raw scalar / kfunc return / probe arg).
    /// SCMP rejects these as operands.
    Unknown,
    /// Pointer to the 16-byte zero-padded comm scratch buffer from a
    /// LDGS(execname) lowering. Safe for inline 16-byte compare.
    ExecnameScratch,
    /// Pointer to a 64-byte zero-padded SETS string-literal scratch
    /// buffer. Safe for inline 16-byte compare against an execname.
    StrLiteralScratch,
}

/// Tuple-stack scratch region. Each slot is 8 bytes; CALL consumes
/// `arity` slots, then resets depth to 0. TUPLE_STACK_SLOTS caps
/// max push depth between two CALLs (and between predicate/action
/// boundaries — each ECB segment starts at depth 0).
pub const TUPLE_STACK_BASE: i16 = -416;
pub const TUPLE_STACK_SLOTS: u32 = 5;

impl<'a> LowerState<'a> {
    pub fn new(schema: Option<&'a RecordSchema>, inttab: Option<Vec<u64>>) -> Self {
        Self::new_with_strtab(schema, inttab, None)
    }

    pub fn new_with_strtab(
        schema: Option<&'a RecordSchema>,
        inttab: Option<Vec<u64>>,
        strtab: Option<Vec<u8>>,
    ) -> Self {
        let value_off = schema.and_then(|s| {
            s.fields.iter().enumerate().find_map(|(i, f)| {
                if f.name == "value" {
                    Some(s.field_offset(i) as i16)
                } else {
                    None
                }
            })
        });
        let ret_mode = if schema.is_some() {
            RetMode::SchemaAction
        } else {
            RetMode::Schemaless
        };
        LowerState {
            body: Vec::new(),
            insn_offsets: Vec::new(),
            pending_branches: Vec::new(),
            pending_cmp: None,
            schema,
            inttab,
            strtab,
            value_off,
            ret_mode,
            agg_map_fake_fd: AGG_MAP_FAKE_FD,
            kfunc_relocs: Vec::new(),
            gustack_kfuncs_available: true,
            needs_vma_table_emit: false,
            locals: HashMap::new(),
            tuple_depth: 0,
            reg_kind: [RegKind::Unknown; 8],
            sets_instance_count: 0,
        }
    }

    /// Reset per-section state for processing another DIFO into the
    /// same `body` buffer. Clause-local slot map is intentionally
    /// preserved across sections of the same clause (predicate +
    /// action share `this->` storage); cleared at clause boundaries
    /// by the caller.
    pub fn begin_section(&mut self) {
        self.insn_offsets.clear();
        self.pending_cmp = None;
        self.reg_kind = [RegKind::Unknown; 8];
    }

    /// Lazily allocate a stack slot for a `this->` var_id. Repeat
    /// calls with the same var_id return the same slot. Returns
    /// None if the LOCALS_SLOT_COUNT budget is exhausted.
    pub fn alloc_local(&mut self, var_id: u16) -> Option<i16> {
        if let Some(&off) = self.locals.get(&var_id) {
            return Some(off);
        }
        if self.locals.len() >= LOCALS_SLOT_COUNT {
            return None;
        }
        let off = LOCALS_BASE - (self.locals.len() as i16) * 8;
        self.locals.insert(var_id, off);
        Some(off)
    }
}
