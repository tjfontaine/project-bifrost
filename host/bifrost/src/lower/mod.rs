// SPDX-License-Identifier: Apache-2.0
//
// DIF → eBPF lowering pipeline.
//
// ## Conceptual model
//
// libdtrace hands bifrost a DOF object describing one or more probe
// clauses.  Each clause carries:
//
//   - an optional predicate (a single DIFO),
//   - an action chain (a sequence of `dof_actdesc_t`, each with its
//     own DIFO that computes the action's value expression and an
//     `action.kind` selecting what to do with it — `DTRACEACT_DIFEXPR`
//     trace, `DTRACEACT_PRINTF`, an aggregation, `DTRACEACT_LIBACT`,
//     etc.),
//   - integer and string constant pools (`SECT_IntTab`, `SECT_StrTab`)
//     shared across DIFOs.
//
// Lowering proceeds in four stages, each owned by a submodule:
//
//   1. *Pre-scan* (`dif::collect_locals_in_section`) — walks every
//      DIFO once to find `this->` accesses so the prologue can
//      pre-allocate and zero-init each clause-local stack slot.  This
//      runs before any DIF instruction lowering: clause-local
//      lifetime is exactly clause-invocation lifetime, so an
//      uninitialised slot would otherwise leak whatever stale frame
//      data the verifier let through.
//
//   2. *Per-clause lower* (`dif.rs`) — translates each DIF
//      instruction into eBPF using `LowerState` to track register
//      kinds (`reg_kind`), branch fixups, tuple-stack depth, and
//      pending compares.  Tuple stack slots index downward from
//      `TUPLE_STACK_BASE - depth*8` rather than post-incrementing so
//      the verifier sees fixed offsets; `depth` resets across CALLs
//      because the subroutine ABI does not preserve it.
//
//   3. *Action emit* (`emit.rs`, `agg.rs`, `action.rs`) — wraps the
//      per-action DIF output with the action-specific epilogue: a
//      record reserve/submit pair for `DTRACEACT_DIFEXPR`, a
//      per-CPU hash update for aggregations, a kfunc invocation for
//      string built-ins and clear/normalize/trunc.  Aggregation
//      chains are decomposed in `emit_agg_chain` /
//      `emit_agg_chain_at`: a clause body like
//      `{ @x[k] = count(); @y[k] = count(); }` lowers to *separate*
//      programs sharing the same prologue, one per agg sub-chain.
//
//   4. *Branch and reloc fixup* — `fixup_branches` resolves every
//      forward branch once the body is fully laid out; per-kfunc
//      relocations are accumulated as `(insn_idx, kfunc_name)` pairs
//      so the guest worker can patch the `imm` of each kfunc call
//      against the *running* kernel's BTF at LOAD_PROG time.
//
// ## Invariants the pipeline maintains
//
//   - Tuple-stack depth ≤ `TUPLE_STACK_CAP`; overflow returns
//     `TupleStackOverflow` rather than producing a program the
//     verifier will reject.
//   - At most one AGG action per emitted program.  Multi-agg
//     clauses fan out at the bifrost binary level into one
//     LOAD_PROG per sub-chain.
//   - String comparisons (`SCMP`) are accepted only in the
//     canonical `execname == "<literal>"` shape — see
//     `ScmpUnsupportedShape`.  Other shapes would silently misread
//     off-end stack data because the TASK_COMM_LEN ceiling that
//     guards the canonical path does not hold for arbitrary
//     operands.
//   - String-literal scratch slots (`SETS`) are bounded by
//     `SETS_INSTANCE_SLOTS`; running out returns
//     `SetsScratchExhausted` rather than aliasing the prior
//     literal.
//   - DIF built-in variable ids in `[DIF_VAR_BUILTIN_LO,
//     DIF_VAR_BUILTIN_HI]` (`timestamp`, `arg0`..`arg9`, `pid`,
//     `tid`, `execname`, ...) lower directly to BPF helpers /
//     kfuncs; var_ids outside that range are user globals and
//     fall through to the `GLOBAL_MAP_*` hash path keyed on
//     var_id.
//
// ## Constraints the implementation leans on
//
//   - The eBPF verifier's instruction-count budget — unrolled
//     string built-ins (`strlen`, `copyinstr`, `strstr`, …) carry a
//     fixed cap rather than a runtime length, and `progenyof`
//     walks `current->real_parent` for a bounded number of hops.
//   - The BPF subroutine ABI — `CALL` clobbers the tuple stack,
//     so callers must spill anything they need preserved.
//   - The `dof_actdesc_t` chain order — aggregation actions arrive
//     *after* their value-expression DIFEXPR action; the chain
//     decomposition relies on this to pair them up.
//   - The DTrace user-globals var_id space starts at `0x0200`; the
//     `0x0100..0x01ff` range is reserved for built-ins and is
//     handled in-line rather than through the GLOBAL_MAP path.
//
// ## Submodules
//
//   - `dif.rs`      — per-instruction DIF → eBPF translation,
//                     register-kind tracking, tuple-stack spill.
//   - `agg.rs`      — aggregation chain decomposition, `lquantize`
//                     / `llquantize` bucket lowering, agg-map
//                     update emission.
//   - `emit.rs`     — record reserve/submit, kfunc dispatch table,
//                     subroutine descriptors for string built-ins
//                     and time helpers.
//   - `action.rs`   — action-kind dispatch (DIFEXPR, PRINTF,
//                     STACK, USTACK, SPECULATE, LIBACT, TRACEMEM).
//   - `branch.rs`   — forward-branch fixups across the body.
//   - `category.rs` — register-kind classification (Scalar /
//                     ExecnameScratch / SetsScratch / Tls / ...)
//                     used by SCMP / printf to pick the right
//                     load shape.
//   - `state.rs`    — `LowerState` carrying body bytes, reloc
//                     list, locals map, pending compares, and the
//                     int/strtab borrows.

pub mod action;
pub mod agg;
pub mod branch;
pub mod category;
pub mod dif;
pub mod emit;
pub mod state;
#[cfg(test)]
mod tests;

use crate::schema::RecordSchema;
use crate::{Dof, DofSection, SectKind};
pub use action::*;
pub use agg::*;
pub use branch::*;
pub use dif::*;
pub use emit::*;
pub use state::LowerState;

#[derive(Debug)]
pub enum LoweringError {
    IntTabOob {
        idx: usize,
        len: usize,
    },
    NoIntTab,
    StrTabOob {
        off: usize,
        len: usize,
    },
    NoStrTab,
    UnsupportedOp {
        op: u8,
        mnemonic: &'static str,
    },
    UnsupportedVar {
        var_id: u16,
    },
    UnsupportedSubr {
        subr: u16,
    },
    TupleStackOverflow {
        depth: u32,
        cap: u32,
    },
    BadDifInstrCount,
    NoEcb,
    BadSectionLink,
    UnsupportedActionKind {
        kind: u32,
    },
    /// SCMP (string compare) only supports the canonical execname-shape
    /// pattern: one operand from LDGS(execname) and the other from
    /// SETS(literal).  Other shapes would silently misread off-end
    /// stack data (TASK_COMM_LEN ceiling no longer holds).
    ScmpUnsupportedShape {
        r1_kind: &'static str,
        r2_kind: &'static str,
    },
    /// SETS scratch budget exhausted in a single program. The current
    /// per-instance allocator can fit up to SETS_INSTANCE_SLOTS literals
    /// per program; beyond that lowering must reject rather than alias
    /// the prior literal.
    SetsScratchExhausted {
        count: usize,
        cap: usize,
    },
}

impl std::fmt::Display for LoweringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoweringError::IntTabOob { idx, len } => {
                write!(f, "inttab index {} out of bounds (len={})", idx, len)
            }
            LoweringError::NoIntTab => write!(
                f,
                "DIF program references inttab but no SECT_IntTab present"
            ),
            LoweringError::StrTabOob { off, len } => {
                write!(f, "strtab offset {} out of bounds (len={})", off, len)
            }
            LoweringError::NoStrTab => write!(
                f,
                "DIF program references strtab but no SECT_StrTab present"
            ),
            LoweringError::UnsupportedSubr { subr } => {
                write!(f, "DIF CALL subroutine id {} not yet lowered to eBPF", subr)
            }
            LoweringError::TupleStackOverflow { depth, cap } => {
                write!(
                    f,
                    "tuple stack overflow: depth {} exceeds capacity {}",
                    depth, cap
                )
            }
            LoweringError::UnsupportedOp { op, mnemonic } => {
                write!(
                    f,
                    "DIF op 0x{:02x} ({}) not yet lowered to eBPF",
                    op, mnemonic
                )
            }
            LoweringError::UnsupportedVar { var_id } => {
                write!(
                    f,
                    "DIF variable id 0x{:04x} not yet lowered to eBPF",
                    var_id
                )
            }
            LoweringError::BadDifInstrCount => write!(f, "DIF section has no instructions"),
            LoweringError::NoEcb => write!(f, "DOF has no ECBDESC"),
            LoweringError::BadSectionLink => {
                write!(f, "ECB/ACTDESC/DIFOHDR section link doesn't resolve")
            }
            LoweringError::UnsupportedActionKind { kind } => {
                write!(f, "DTRACEACT kind 0x{:x} not yet lowered to eBPF", kind)
            }
            LoweringError::ScmpUnsupportedShape { r1_kind, r2_kind } => {
                write!(
                    f,
                    "SCMP only supports `execname == \"<literal>\"` shape today \
                     (got r1={}, r2={}); for other string comparisons, file an issue \
                     with the source D fragment so the general path can be wired up",
                    r1_kind, r2_kind
                )
            }
            LoweringError::SetsScratchExhausted { count, cap } => {
                write!(
                    f,
                    "SETS string-literal scratch exhausted: {} literals in one program \
                     exceeds the {}-slot per-program cap. Move the comparison into a \
                     predicate that runs against a smaller set of literals, or split \
                     the clause.",
                    count, cap
                )
            }
        }
    }
}

impl std::error::Error for LoweringError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RetMode {
    SchemaAction,
    Predicate,
    Schemaless,
}

#[derive(Clone, Copy)]
pub enum PendingCmp {
    Reg(u8, u8),
    Tst(u8),
}

impl PendingCmp {
    pub fn reads_dif_r0(self) -> bool {
        match self {
            PendingCmp::Reg(a, b) => a == 0 || b == 0,
            PendingCmp::Tst(a) => a == 0,
        }
    }
}

pub const AGG_MAP_FAKE_FD: i32 = 200;
pub const TLS_MAP_FAKE_FD: i32 = 300;
pub const TLS_MAP_KEY_SIZE: u32 = 8;
pub const TLS_MAP_VALUE_SIZE: u32 = 8;
pub const TLS_MAP_MAX_ENTRIES: u32 = 1024;

/// User-defined global storage map (`n = n + 1`, `t0 = walltimestamp`).
/// HASH keyed on the 4-byte DIF var_id (DTrace assigns user globals
/// var_ids ≥ 0x0200 — the 0x0100-range is reserved for built-ins like
/// `timestamp`, `curtask`, `pid` which lower directly to BPF helpers).
/// Distinct from the TLS map: globals are shared across threads, so
/// the key is just var_id (no pid_tgid mixing).
pub const GLOBAL_MAP_FAKE_FD: i32 = 400;
pub const GLOBAL_MAP_KEY_SIZE: u32 = 4;
pub const GLOBAL_MAP_VALUE_SIZE: u32 = 8;
pub const GLOBAL_MAP_MAX_ENTRIES: u32 = 256;
/// var_ids 0x0100..0x01ff are built-in globals (timestamp, curtask,
/// arg0..arg9, pid, tid, execname). Anything outside that range is a
/// user-defined global and falls through to the GLOBAL_MAP path.
pub const DIF_VAR_BUILTIN_LO: u16 = 0x0100;
pub const DIF_VAR_BUILTIN_HI: u16 = 0x01ff;

pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;

pub const BPF_F_USER_STACK: i32 = 1 << 8;

pub const DTRACEACT_DIFEXPR: u32 = 1;
pub const DTRACEACT_EXIT: u32 = 2;
pub const DTRACEACT_PRINTF: u32 = 3;
/// `printa(@<name>)` action.  libdtrace emits this to format an
/// aggregation snapshot at consumer side; in Bifrost, the host
/// renderer reads AGG_SNAPSHOT records and prints them, so the
/// kernel-side bridge silently skips printa records during the
/// principal-buffer drain (only DIFEXPR is decoded).
pub const DTRACEACT_PRINTA: u32 = 4;
/// `tracemem(addr, len)` action kind. libdtrace emits this for
/// `tracemem(addr, len)` where `len` is a compile-time constant
/// baked into `action.arg`. The value DIFO computes `addr`; the
/// lowering reads `len` bytes from `addr` (treated as a kernel
/// pointer via `bpf_probe_read_kernel`) into a `Bytes` slot of
/// the per-fire record. Variable-length `tracemem` uses
/// `DTRACEACT_TRACEMEM_DYNSIZE = 7` and is folded into the same
/// lowering path with `arg` as the max cap.
pub const DTRACEACT_TRACEMEM: u32 = 6;
pub const DTRACEACT_TRACEMEM_DYNSIZE: u32 = 7;
pub const DTRACEACT_USTACK: u32 = 0x0100 + 1;
pub const DTRACEACT_STACK: u32 = 0x0400 + 1;
/// Speculative-tracing action descriptors — one per
/// `speculate()` / `commit()` / `discard()` call.  Apple
/// libdtrace emits these as dedicated DOF actions whose value
/// DIFO computes the lane id; the lowering invokes the matching
/// kfunc with the DIFO's r0 in r1.  Distinct from the DIF subr
/// path (10 / 41 / 46 / 47) which OpenDTrace uses for the
/// expression-context call — Bifrost supports both encodings.
pub const DTRACEACT_SPECULATIVE: u32 = 0x0600;
pub const DTRACEACT_SPECULATE: u32 = 0x0600 + 1;
pub const DTRACEACT_COMMIT: u32 = 0x0600 + 2;
pub const DTRACEACT_DISCARD: u32 = 0x0600 + 3;
/// `DTRACEACT_LIBACT` — libdtrace-controlled actions.  Sub-kind
/// lives in `action.arg`:
///   `DT_ACT_CLEAR       = 0x40` — zero the agg map
///   `DT_ACT_NORMALIZE   = 0x41` — render-time divide
///   `DT_ACT_DENORMALIZE = 0x42` — clear normalize hint
///   `DT_ACT_TRUNC       = 0x43` — render-time top-N truncation
/// `clear` lowers to `KFUNC_CLEAR_AGG` (walks per-CPU agg slots
/// and zeroes them); normalize/denormalize/trunc are recognized
/// at parse time and stashed as render-time hints on the
/// xagg-state side channel.
pub const DTRACEACT_LIBACT: u32 = 5;
pub const DT_ACT_CLEAR: u64 = 0x40;
pub const DT_ACT_NORMALIZE: u64 = 0x41;
pub const DT_ACT_DENORMALIZE: u64 = 0x42;
pub const DT_ACT_TRUNC: u64 = 0x43;

pub fn lower(dof: &Dof) -> Result<Vec<u8>, LoweringError> {
    lower_with(dof, None)
}

pub fn lower_with(dof: &Dof, schema: Option<&RecordSchema>) -> Result<Vec<u8>, LoweringError> {
    lower_with_opts(dof, schema, LoweringOpts::default()).map(|(b, _)| b)
}

pub fn lower_with_agg_base(
    dof: &Dof,
    schema: Option<&RecordSchema>,
    agg_base: u32,
) -> Result<Vec<u8>, LoweringError> {
    lower_with_opts(
        dof,
        schema,
        LoweringOpts {
            agg_base,
            ..LoweringOpts::default()
        },
    )
    .map(|(b, _)| b)
}

#[derive(Clone, Copy)]
pub struct LoweringOpts {
    pub agg_base: u32,
    pub probe_id: u32,
    pub agg_map_fake_fd: i32,
    /// Which action in the ECB chain to lower. 0 = first (default).
    /// Used to fan out a multi-action clause into N programs (one
    /// per action) without changing the per-program prologue/epilogue
    /// shape. agg + printf chains start at 0 and consume multiple
    /// actions, so action_idx > 0 only makes sense for plain DIFEXPR
    /// multi-action chains.
    pub action_idx: usize,
    /// For multi-agg clauses (`{ @x[k]=count(); @y[k]=count(); }`),
    /// the bin/bifrost.rs caller emits one program per agg sub-chain.
    /// `agg_chain_start = Some(N)` tells lower_with_opts to compile
    /// the agg chain whose value DIFEXPR is at actions[N] and whose
    /// AGG action is the first AGG-shaped action at index >= N.
    /// Default None = first agg (chain_start=0, behaviour unchanged).
    pub agg_chain_start: Option<usize>,
    /// When set, lower the action at `action_idx` as
    /// a STANDALONE per-fire program, even when it sits BEFORE the
    /// first agg in source order (the existing post_agg path only
    /// handles indices > agg_pos).  Without this, a peer
    /// ExtraProg::Action emitted for the leading `trace(timestamp)`
    /// of a `profile { trace(timestamp); @x[k]=count(); }` clause
    /// falls through to emit_agg_chain instead of lower_action_into
    /// and never produces per-fire records.
    pub force_standalone_action: bool,
}

impl Default for LoweringOpts {
    fn default() -> Self {
        Self {
            agg_base: 0,
            probe_id: 0,
            agg_map_fake_fd: AGG_MAP_FAKE_FD,
            action_idx: 0,
            agg_chain_start: None,
            force_standalone_action: false,
        }
    }
}

/// Returns `(ebpf_bytes, kfunc_relocs)`. The reloc list is `(insn_idx,
/// kfunc_name)` pairs the guest worker uses at LOAD_PROG time to patch
/// each kfunc-call's `imm` with the locally-resolved BTF id (BFR7
/// protocol — no compile-time btf_id baking, no fingerprint check).
pub fn lower_with_opts(
    dof: &Dof,
    schema: Option<&RecordSchema>,
    opts: LoweringOpts,
) -> Result<(Vec<u8>, Vec<(u32, &'static str)>), LoweringError> {
    let default_inttab_sec = dof.sections_of(SectKind::IntTab).next().map(|(_, s)| s);
    let default_inttab = read_inttab(dof, default_inttab_sec);
    let default_strtab_sec = dof.sections_of(SectKind::StrTab).next().map(|(_, s)| s);
    let default_strtab = read_strtab(dof, default_strtab_sec).map(|b| b.to_vec());

    let mut state = LowerState::new_with_strtab(schema, default_inttab, default_strtab);
    state.agg_map_fake_fd = opts.agg_map_fake_fd;

    if let Some(schema) = schema {
        fill_correlation_fields(&mut state.body, schema, opts.probe_id);
    } else {
        state.body.extend_from_slice(&bpf_mov64_reg(CTX_REG, 1));
    }

    for r in 1u8..=5 {
        state.body.extend_from_slice(&bpf_mov64_imm(r, 0));
    }

    // Pre-scan all DIF sections this clause will lower (predicate +
    // each action's DIFO) for `this->` (LDLS/STLS) usage. Allocate
    // a stack slot per unique var_id so the prologue can zero-init
    // them — DTrace semantics: an uninitialized `this->x` reads as
    // 0, and clause-local lifetime is exactly clause-invocation
    // lifetime so we can't rely on stale frame data being benign.
    if let Some(ecb) = dof.first_ecb() {
        if ecb.pred != crate::DOF_SECIDX_NONE
            && let Some(pred_difo) = dof.difo(ecb.pred)
            && let Some(idx) = pred_difo.dif_section()
            && let Some(sec) = dof.sections.get(idx as usize)
        {
            crate::lower::dif::collect_locals_in_section(&mut state, dof, sec);
        }
        for action in dof.actions_in_chain(ecb.actions) {
            if action.difo == crate::DOF_SECIDX_NONE {
                continue;
            }
            if let Some(difo) = dof.difo(action.difo)
                && let Some(idx) = difo.dif_section()
                && let Some(sec) = dof.sections.get(idx as usize)
            {
                crate::lower::dif::collect_locals_in_section(&mut state, dof, sec);
            }
        }
    }
    // Zero-init each allocated `this->` slot. r1 is 0 from the
    // initialization above; reuse it as the zero source. Sort by
    // offset for deterministic prologue bytes.
    if !state.locals.is_empty() {
        let mut offsets: Vec<i16> = state.locals.values().copied().collect();
        offsets.sort_unstable();
        for off in offsets {
            state.body.extend_from_slice(&bpf_stx_dw(10, 1, off));
        }
    }

    if let Some(ecb) = dof.first_ecb() {
        if ecb.pred != crate::DOF_SECIDX_NONE {
            let pred_difo = dof.difo(ecb.pred).ok_or(LoweringError::BadSectionLink)?;
            let pred_dif_idx = pred_difo
                .dif_section()
                .ok_or(LoweringError::BadSectionLink)?;
            let pred_dif_sec = dof
                .sections
                .get(pred_dif_idx as usize)
                .ok_or(LoweringError::BadSectionLink)?;
            let pred_inttab_sec = pred_difo
                .inttab_section_in(dof)
                .and_then(|i| dof.sections.get(i as usize));
            state.inttab = read_inttab(dof, pred_inttab_sec);
            let pred_strtab_sec = pred_difo
                .strtab_section_in(dof)
                .and_then(|i| dof.sections.get(i as usize));
            state.strtab = read_strtab(dof, pred_strtab_sec).map(|b| b.to_vec());
            state.ret_mode = RetMode::Predicate;
            lower_dif_section_into(&mut state, dof, pred_dif_sec)?;
            fixup_branches(&mut state)?;
            state.pending_branches.clear();

            let guard_pos = state.body.len();
            state.body.extend_from_slice(&bpf_jeq_imm(0, 0, 0));

            state.begin_section();
            let actions = dof.actions_in_chain(ecb.actions);
            let agg_idx = actions.iter().position(|a| is_agg_action(a.kind));
            let is_agg = agg_idx.map(|i| i >= 1).unwrap_or(false);
            // Multi-action fan-out: caller asked for an action past
            // the agg chain (e.g. gustack() after `@x[..] = count();`).
            // Lower it as a single action with its own schema —
            // emit_agg_chain has already been emitted by the prog at
            // action_idx == 0.
            let post_agg =
                is_agg && opts.agg_chain_start.is_none() && opts.action_idx > agg_idx.unwrap();
            if let Some(chain_start) = opts.agg_chain_start {
                // Multi-agg fan-out: lower the agg sub-chain whose
                // value DIFEXPR is at actions[chain_start].  Find the
                // first AGG at or after chain_start.
                let sub_agg_pos = actions
                    .iter()
                    .enumerate()
                    .skip(chain_start)
                    .find(|(_, a)| is_agg_action(a.kind))
                    .map(|(i, _)| i)
                    .ok_or(LoweringError::BadDifInstrCount)?;
                state.ret_mode = RetMode::Predicate;
                crate::lower::agg::emit_agg_chain_at(
                    &mut state,
                    dof,
                    &actions,
                    chain_start,
                    sub_agg_pos,
                )?;
            } else if post_agg || opts.force_standalone_action {
                state.ret_mode = RetMode::SchemaAction;
                if let Some(action) = actions.get(opts.action_idx) {
                    lower_action_into(&mut state, dof, action)?;
                }
            } else if is_agg {
                state.ret_mode = RetMode::Predicate;
                emit_agg_chain(&mut state, dof, &actions, agg_idx.unwrap())?;
            } else if actions
                .first()
                .map(|a| a.kind == DTRACEACT_PRINTF)
                .unwrap_or(false)
            {
                emit_printf_chain(&mut state, dof, &actions)?;
            } else {
                state.ret_mode = RetMode::SchemaAction;
                if let Some(action) = actions.get(opts.action_idx) {
                    lower_action_into(&mut state, dof, action)?;
                }
            }

            let after_action = state.body.len();
            let guard_skip_slots = ((after_action - guard_pos - 8) / 8) as i16;
            state.body[guard_pos + 2..guard_pos + 4]
                .copy_from_slice(&guard_skip_slots.to_le_bytes());

            // emit_agg_chain / emit_agg_chain_at end with their own
            // bpf_exit; the post-agg single-action path's
            // lower_action_into emits its own.  Only the predicate-
            // gated agg-only branches need the trailer here.
            if (is_agg && !post_agg) || opts.agg_chain_start.is_some() {
                state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
                state.body.extend_from_slice(&bpf_exit());
            }
        } else {
            let actions = dof.actions_in_chain(ecb.actions);
            let agg_idx = actions.iter().position(|a| is_agg_action(a.kind));
            let agg_pos_for_main = agg_idx.filter(|i| *i >= 1);
            let post_agg = agg_pos_for_main
                .filter(|_| opts.agg_chain_start.is_none())
                .map(|p| opts.action_idx > p)
                .unwrap_or(false);
            if let Some(chain_start) = opts.agg_chain_start {
                let sub_agg_pos = actions
                    .iter()
                    .enumerate()
                    .skip(chain_start)
                    .find(|(_, a)| is_agg_action(a.kind))
                    .map(|(i, _)| i)
                    .ok_or(LoweringError::BadDifInstrCount)?;
                state.ret_mode = RetMode::Predicate;
                crate::lower::agg::emit_agg_chain_at(
                    &mut state,
                    dof,
                    &actions,
                    chain_start,
                    sub_agg_pos,
                )?;
            } else if post_agg || opts.force_standalone_action {
                state.ret_mode = if schema.is_some() {
                    RetMode::SchemaAction
                } else {
                    RetMode::Schemaless
                };
                if let Some(action) = actions.get(opts.action_idx) {
                    lower_action_into(&mut state, dof, action)?;
                } else {
                    return Err(LoweringError::BadDifInstrCount);
                }
            } else if let Some(agg_pos) = agg_pos_for_main {
                state.ret_mode = RetMode::Predicate;
                emit_agg_chain(&mut state, dof, &actions, agg_pos)?;
            } else if actions
                .first()
                .map(|a| a.kind == DTRACEACT_PRINTF)
                .unwrap_or(false)
            {
                emit_printf_chain(&mut state, dof, &actions)?;
            } else {
                state.ret_mode = if schema.is_some() {
                    RetMode::SchemaAction
                } else {
                    RetMode::Schemaless
                };
                if let Some(action) = actions.get(opts.action_idx) {
                    lower_action_into(&mut state, dof, action)?;
                } else {
                    return Err(LoweringError::BadDifInstrCount);
                }
            }
        }
    } else {
        for (_, dif_sec) in dof.sections_of(SectKind::Dif) {
            lower_dif_section_into(&mut state, dof, dif_sec)?;
        }
        fixup_branches(&mut state)?;
        state.pending_branches.clear();
    }

    let body = state.body;
    // Body relocs are body-local (insn_idx relative to start of body).
    // We'll shift them into the merged output frame once we know
    // body_start_slots; meanwhile prologue relocs (collected below
    // into prologue_relocs) are out-local from the start.
    let body_relocs = state.kfunc_relocs;
    let Some(schema) = schema else {
        // Schemaless path emits body alone — body-local indices are
        // already correct.
        return Ok((body, body_relocs));
    };

    let mut out = Vec::<u8>::new();
    let mut prologue_relocs: Vec<(u32, &'static str)> = Vec::new();
    out.extend_from_slice(&bpf_mov64_reg(CTX_REG, 1));

    // gustack VMA-table side-trip — emitted only when the action
    // path flagged it via state.needs_vma_table_emit. Guest's reloc
    // resolver fails the load if the kfunc isn't in vmlinux BTF.
    if state.needs_vma_table_emit {
        // Buf must be ≥ 16 (hdr) + BIFROST_VMA_TABLE_MAX × 32 (entries),
        // with the remainder used for d_path() strings. Cap=96 →
        // entries_size = 3088, leaving ~5104 bytes of strings_avail in
        // an 8KB buf — comfortably covers redis-server's 70 file-backed
        // VMAs (used 2987 bytes of strings in the diagnostic dump).
        let vma_size = 8192 + 512;
        let _ = emit_record_reserve(&mut out, &mut prologue_relocs, vma_size, true);
        out.extend_from_slice(&bpf_mov64_reg(RB_PTR_REG, 0));
        let skip_vma = out.len();
        out.extend_from_slice(&bpf_jeq_imm(RB_PTR_REG, 0, 0));
        fill_correlation_fields(&mut out, schema, 0xFFFFFFFF);
        out.extend_from_slice(&bpf_mov64_reg(1, RB_PTR_REG));
        out.extend_from_slice(&bpf_alu64_imm(0x07, 1, 24));
        out.extend_from_slice(&bpf_mov64_imm(2, 8192));
        emit_kfunc_call(&mut out, &mut prologue_relocs, KFUNC_VMA_TABLE);
        emit_record_submit(&mut out, &mut prologue_relocs, RB_PTR_REG, true, true);
        let after_vma = out.len();
        let skip = ((after_vma - skip_vma - 8) / 8) as i16;
        out[skip_vma + 2..skip_vma + 4].copy_from_slice(&skip.to_le_bytes());
    }

    let _ = emit_record_reserve(
        &mut out,
        &mut prologue_relocs,
        schema.record_size() as i32,
        true,
    );
    out.extend_from_slice(&bpf_mov64_reg(RB_PTR_REG, 0));
    out.extend_from_slice(&bpf_jeq_imm(RB_PTR_REG, 0, (body.len() / 8) as i16));
    let body_start_slots = (out.len() / 8) as u32;
    out.extend_from_slice(&body);
    out.extend_from_slice(&bpf_mov64_imm(0, 0));
    out.extend_from_slice(&bpf_exit());

    // Merge: prologue relocs are already out-local. Body relocs need
    // to be shifted by body_start_slots.
    let mut merged: Vec<(u32, &'static str)> =
        Vec::with_capacity(prologue_relocs.len() + body_relocs.len());
    merged.extend(prologue_relocs);
    for (idx, name) in body_relocs {
        merged.push((idx + body_start_slots, name));
    }
    Ok((out, merged))
}

pub fn lower_difo_by_secidx(
    state: &mut LowerState,
    dof: &Dof,
    difo_secidx: u32,
) -> Result<(), LoweringError> {
    let difo = dof.difo(difo_secidx).ok_or(LoweringError::BadSectionLink)?;
    let dif_idx = difo.dif_section().ok_or(LoweringError::BadSectionLink)?;
    let dif_sec = dof
        .sections
        .get(dif_idx as usize)
        .ok_or(LoweringError::BadSectionLink)?;
    let inttab_sec = difo
        .inttab_section_in(dof)
        .and_then(|i| dof.sections.get(i as usize));
    state.inttab = read_inttab(dof, inttab_sec);
    let strtab_sec = difo
        .strtab_section_in(dof)
        .and_then(|i| dof.sections.get(i as usize));
    state.strtab = read_strtab(dof, strtab_sec).map(|b| b.to_vec());
    lower_dif_section_into(state, dof, dif_sec)?;
    fixup_branches(state)?;
    state.pending_branches.clear();
    Ok(())
}

pub fn lower_dif_section_into(
    state: &mut LowerState,
    dof: &Dof,
    dif_sec: &DofSection,
) -> Result<(), LoweringError> {
    let dif_insns = dof.dif_instructions(dif_sec);
    if dif_insns.is_empty() {
        return Err(LoweringError::BadDifInstrCount);
    }
    for (dif_idx, ins) in dif_insns.iter().enumerate() {
        state.insn_offsets.push(state.body.len());
        lower_one_state(state, *ins, dif_idx)?;
    }
    state.insn_offsets.push(state.body.len());
    Ok(())
}

pub fn read_inttab(dof: &Dof, sec: Option<&DofSection>) -> Option<Vec<u64>> {
    let sec = sec?;
    let bytes = dof.section_bytes(sec);
    Some(
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
            .collect(),
    )
}

/// Read a DIFO StrTab section as a borrowed byte slice. SETS imm16
/// indexes into this directly (offset of the start of the string;
/// runs to the next NUL).
pub fn read_strtab<'a>(dof: &'a Dof<'a>, sec: Option<&'a DofSection>) -> Option<&'a [u8]> {
    let sec = sec?;
    Some(dof.section_bytes(sec))
}

fn fill_correlation_fields(out: &mut Vec<u8>, schema: &RecordSchema, probe_id: u32) {
    use crate::schema::FieldKind;
    for (idx, field) in schema.fields.iter().enumerate() {
        let off = schema.field_offset(idx) as i16;
        match field.name.as_str() {
            "vmid" => {
                if matches!(field.kind, FieldKind::U32) {
                    out.extend_from_slice(&bpf_call(8)); // HELPER_GET_SMP_PROCESSOR_ID
                    out.extend_from_slice(&bpf_stx_w(RB_PTR_REG, 0, off));
                }
            }
            "probe_id" => {
                if matches!(field.kind, FieldKind::U32) {
                    out.extend_from_slice(&bpf_mov64_imm(1, probe_id as i32));
                    out.extend_from_slice(&bpf_stx_w(RB_PTR_REG, 1, off));
                }
            }
            "gns" => {
                if matches!(field.kind, FieldKind::U64) {
                    out.extend_from_slice(&bpf_call(5)); // HELPER_KTIME_GET_NS
                    out.extend_from_slice(&bpf_stx_dw(RB_PTR_REG, 0, off));
                }
            }
            "gpid" => {
                if matches!(field.kind, FieldKind::U64) {
                    out.extend_from_slice(&bpf_call(14)); // HELPER_GET_CURRENT_PID_TGID
                    out.extend_from_slice(&bpf_stx_dw(RB_PTR_REG, 0, off));
                }
            }
            _ => {}
        }
    }
}

pub fn disasm_ebpf(bytes: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    let mut idx = 0;
    while i + 8 <= bytes.len() {
        let code = bytes[i];
        let dst = bytes[i + 1] & 0x0f;
        let src = (bytes[i + 1] >> 4) & 0x0f;
        let off = i16::from_le_bytes([bytes[i + 2], bytes[i + 3]]);
        let imm = i32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        let mnem = match code {
            BPF_LD_IMM_DW_LO => "ld_imm64_lo",
            BPF_LD_IMM_DW_HI => "ld_imm64_hi",
            BPF_MOV64_IMM => "mov64_imm",
            BPF_MOV64_REG => "mov64_reg",
            BPF_EXIT => "exit",
            _ => "?",
        };
        use std::fmt::Write;
        writeln!(
            s,
            "  [{:3}] code=0x{:02x}  {:<12} dst=r{:<2} src=r{:<2} off={:<5} imm=0x{:08x}",
            idx, code, mnem, dst, src, off, imm as u32
        )
        .unwrap();
        i += 8;
        idx += 1;
    }
    s
}
