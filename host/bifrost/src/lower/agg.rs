// SPDX-License-Identifier: Apache-2.0
use super::LoweringError;
use super::emit::*;
use super::state::LowerState;
use crate::Dof;

pub const DTRACEAGG_COUNT: u32 = 0x0701;
pub const DTRACEAGG_MIN: u32 = 0x0702;
pub const DTRACEAGG_MAX: u32 = 0x0703;
pub const DTRACEAGG_AVG: u32 = 0x0704;
pub const DTRACEAGG_SUM: u32 = 0x0705;
pub const DTRACEAGG_STDDEV: u32 = 0x0706;
pub const DTRACEAGG_QUANTIZE: u32 = 0x0707;
/// `lquantize(value, base, upper, step)`.  Linear-bucket
/// histogram.  Apple libdtrace packs the three parameters into
/// `action.arg`:
///
///   bits 63-48 = step    (u16)
///   bits 47-32 = levels  (u16, = (upper - base) / step)
///   bits 31-0  = base    (i32; signed)
///
/// Total bucket count is `levels + 2` (one underflow, one
/// overflow, `levels` in-range).  The kernel-side map is a
/// PERCPU_HASH keyed on `bucket_id: u32` with `value_size = 8`
/// — same shape as `quantize`.  The BPF lowering computes
/// `bucket_id` from the value via the
/// `(value - base) / step` formula with clamp at both ends.
pub const DTRACEAGG_LQUANTIZE: u32 = 0x0708;
/// `llquantize(value, factor, low_mag, high_mag, steps_per_mag)`.
/// Log-linear-bucket histogram.  Apple libdtrace packs the
/// parameters into `action.arg` as a 6-tuple where each field
/// occupies a sub-range; the precise layout is decoded by the
/// host-side parameter scanner.  The kernel-side map shape
/// matches `quantize` / `lquantize` (PERCPU_HASH keyed on
/// `bucket_id`).
pub const DTRACEAGG_LLQUANTIZE: u32 = 0x0709;

pub fn is_agg_action(kind: u32) -> bool {
    (kind & 0xff00) == 0x0700
}

pub fn emit_agg_chain(
    state: &mut LowerState,
    dof: &Dof,
    actions: &[crate::Action],
    agg_pos: usize,
) -> Result<(), LoweringError> {
    emit_agg_chain_at(state, dof, actions, 0, agg_pos)
}

/// Variant that supports multiple agg chains in the same actions
/// vec.  `chain_start` is the index of the leading value DIFEXPR;
/// `agg_pos` is the AGG's index.  Keys live at
/// `actions[chain_start+1 .. agg_pos]`.
///
/// ## Why one program per agg chain
///
/// A clause body like `{ @x[k] = count(); @y[k1, k2] = count(); }`
/// produces a single DOF action chain containing both aggs, but
/// every emitted eBPF program owns *exactly one* aggregation: the
/// per-action prologue reserves a record-shaped slot, the per-action
/// epilogue updates a single agg map, and the verifier-visible
/// program shape (registers, map relocations, return value) is
/// fixed at LOAD_PROG time.  Trying to fit a second agg into the
/// same program would force the prologue and epilogue to branch on
/// runtime state the verifier cannot track.
///
/// `chain_start` lets the caller fan out — the bin/bifrost.rs
/// dispatcher calls `lower_with_opts` once per agg sub-chain, each
/// time with a different `chain_start` and the same DOF.  Each call
/// produces an independent program; libdtrace stitches them onto
/// the same probe-id so the firing order is preserved.
pub fn emit_agg_chain_at(
    state: &mut LowerState,
    dof: &Dof,
    actions: &[crate::Action],
    chain_start: usize,
    agg_pos: usize,
) -> Result<(), LoweringError> {
    let agg = &actions[agg_pos];
    // libdtrace's chain shape for `@[k0..kN-1] = AGG(value)` is
    //   [value_DIFEXPR, k0_DIFEXPR, .., k{N-1}_DIFEXPR, AGG]
    // (value first, keys next, AGG last). The value DIFO is also
    // attached to the AGG action's `difo` field for AGG kinds that
    // need it (SUM/MIN/MAX/AVG/QUANTIZE) — we read it from there.
    // For COUNT the chain still has a leading DIFEXPR (libdtrace
    // emits a dummy zero) but our lowering ignores it.
    //
    // Net: n_keys = agg_pos - chain_start - 1, keys at
    // actions[chain_start+1..agg_pos].
    let n_keys = agg_pos.saturating_sub(chain_start + 1);
    // Hard cap matches AGG_MAX_KEYS in agg_map_decl_for_chain; raise
    // both together if real D needs >4 keys per agg.
    const MAX_KEYS: usize = 4;
    if n_keys > MAX_KEYS {
        return Err(LoweringError::UnsupportedActionKind { kind: agg.kind });
    }
    if agg.kind == DTRACEAGG_QUANTIZE {
        return emit_quantize_chain(state, dof, actions);
    }
    if agg.kind == DTRACEAGG_LQUANTIZE {
        return emit_lquantize_chain(state, dof, actions);
    }
    if agg.kind == DTRACEAGG_LLQUANTIZE {
        return emit_llquantize_chain(state, dof, actions);
    }
    if !matches!(
        agg.kind,
        DTRACEAGG_COUNT
            | DTRACEAGG_SUM
            | DTRACEAGG_MIN
            | DTRACEAGG_MAX
            | DTRACEAGG_AVG
            | DTRACEAGG_STDDEV
    ) {
        return Err(LoweringError::UnsupportedActionKind { kind: agg.kind });
    }
    // COUNT increments by 1; SUM/MIN/MAX/AVG/STDDEV need the value DIFO.
    let needs_value = !matches!(agg.kind, DTRACEAGG_COUNT);
    let kind = agg.kind;

    if needs_value {
        super::lower_difo_by_secidx(state, dof, agg.difo)?;
        state.body.extend_from_slice(&bpf_mov64_reg(6, 0));
    }

    // Composite key layout. For n_keys=N, key_i lands at stack
    // offset KEY_BASE + i*8, with KEY_BASE chosen so the highest
    // key (index N-1) sits at -16. That makes n_keys==1 keep the
    // historical -16 layout (no behavior change for single-key
    // aggs) and n_keys>1 grow downward into r10-24, r10-32, ...
    //
    //   N=1: key0 @ -16          ; ptr = r10-16, size = 8
    //   N=2: key0 @ -24, key1 @ -16 ; ptr = r10-24, size = 16
    //   N=3: key0 @ -32, key1 @ -24, key2 @ -16 ; ptr = r10-32, size = 24
    //   N=4: key0 @ -40, ..., key3 @ -16 ; ptr = r10-40, size = 32
    //
    // For n_keys==0 (unkeyed `@ = ...`), key buffer is just a u32
    // zero at -16 (matches BPF_MAP_TYPE_PERCPU_ARRAY's index=0 key).
    let key_size = if n_keys == 0 { 4 } else { 8 * n_keys as i32 };
    let key_base_off: i16 = if n_keys == 0 {
        -16
    } else {
        -16 - 8 * (n_keys as i16 - 1)
    };

    if n_keys == 0 {
        state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
        state.body.extend_from_slice(&bpf_stx_dw(10, 0, -16));
    } else {
        // Lower each key action's DIFO; store r0 to its assigned
        // stack slot. Keys are at actions[1..agg_pos] (skipping
        // the leading value DIFEXPR). Each DIFO trashes r0; the
        // prior store is already committed before the next runs.
        //
        // Special case for execname (var_id 0x0118): the LDGS
        // lowering returns a *pointer* to the 16-byte comm buffer
        // on the BPF stack, not the bytes themselves. If we stored
        // that pointer as the key, every distinct stack frame of
        // every clause invocation would hash to a different key —
        // breaking aggregation. Detect single-LDGS-execname keys
        // and dereference: load the first 8 bytes of comm from the
        // pointer and use those as the key. 8 bytes is enough to
        // distinguish common program names ("cc1\0", "gcc\0",
        // "as\0", "ld\0", "redis-se", "compile-") and matches the
        // existing 8-byte-per-key wire format.
        for (i, key_action) in actions[chain_start + 1..=chain_start + n_keys]
            .iter()
            .enumerate()
        {
            super::action::lower_action_into(state, dof, key_action)?;
            // Dispatch on DIFO category instead of
            // chained per-shape predicates.  PtrComm and
            // PtrStrScratch both need an 8-byte deref before the
            // agg-key store; Scalar takes r0 verbatim.  Adding a
            // new pointer-shape (e.g. strjoin scratch) is one new
            // category variant + one new arm here, not a new
            // is_*_difo predicate scanned at every call site.
            if super::category::category_for_difo(dof, key_action.difo).needs_8byte_deref() {
                state.body.extend_from_slice(&bpf_ldx_dw(0, 0, 0));
            }
            let off = -16 - 8 * (n_keys as i16 - 1 - i as i16);
            state.body.extend_from_slice(&bpf_stx_dw(10, 0, off));
        }
    }

    state
        .body
        .extend_from_slice(&bpf_ld_map_fd(1, state.agg_map_fake_fd));
    state.body.extend_from_slice(&bpf_mov64_reg(2, 10));
    state
        .body
        .extend_from_slice(&bpf_alu64_imm(0x07, 2, key_base_off as i32));
    state.body.extend_from_slice(&bpf_call(1)); // HELPER_MAP_LOOKUP_ELEM

    if n_keys >= 1 {
        // Upsert path: if lookup returned NULL, insert a zero value
        // for this key, then re-lookup. Same code shape as before
        // but parameterized on key_base_off.
        let upsert_jne = state.body.len();
        state.body.extend_from_slice(&bpf_jcc_imm(0x55, 0, 0, 0)); // BPF_JNE_IMM
        state.body.extend_from_slice(&bpf_mov64_imm(7, 0));
        state.body.extend_from_slice(&bpf_stx_dw(10, 7, -8));
        state
            .body
            .extend_from_slice(&bpf_ld_map_fd(1, state.agg_map_fake_fd));
        state.body.extend_from_slice(&bpf_mov64_reg(2, 10));
        state
            .body
            .extend_from_slice(&bpf_alu64_imm(0x07, 2, key_base_off as i32));
        state.body.extend_from_slice(&bpf_mov64_reg(3, 10));
        state.body.extend_from_slice(&bpf_alu64_imm(0x07, 3, -8));
        state.body.extend_from_slice(&bpf_mov64_imm(4, 0));
        state.body.extend_from_slice(&bpf_call(2)); // HELPER_MAP_UPDATE_ELEM
        state
            .body
            .extend_from_slice(&bpf_ld_map_fd(1, state.agg_map_fake_fd));
        state.body.extend_from_slice(&bpf_mov64_reg(2, 10));
        state
            .body
            .extend_from_slice(&bpf_alu64_imm(0x07, 2, key_base_off as i32));
        state.body.extend_from_slice(&bpf_call(1));
        let after_upsert = state.body.len();
        let skip = ((after_upsert - upsert_jne - 8) / 8) as i16;
        state.body[upsert_jne + 2..upsert_jne + 4].copy_from_slice(&skip.to_le_bytes());
    }
    let _ = key_size; // size lives in agg_map_decl_for_chain

    let bail_pos = state.body.len();
    state.body.extend_from_slice(&bpf_jeq_imm(0, 0, 0));
    // Kind-specific update on the per-cpu slot at *r0.
    //
    // PERCPU maps mean each CPU writes its OWN slot — no atomicity
    // required. We still use bpf_atomic_add for SUM/COUNT (it's
    // single-instruction, slightly cheaper than load/add/store).
    // MIN/MAX/AVG can't use atomic_add so we emit explicit ldx/stx.
    match kind {
        DTRACEAGG_COUNT => {
            state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
        }
        DTRACEAGG_SUM => {
            state.body.extend_from_slice(&bpf_mov64_reg(1, 6));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
        }
        DTRACEAGG_MIN => {
            // if (current == 0 || new < current) *r0 = new
            // r1 ← current;  r2 ← new
            state.body.extend_from_slice(&bpf_ldx_dw(1, 0, 0));
            state.body.extend_from_slice(&bpf_mov64_reg(2, 6));
            // jeq r1, 0, +1   ; current == 0 → jump past the JGE skip
            // jge r2, r1, +1  ; new >= current → skip store
            // stx_dw [r0], r2
            state.body.extend_from_slice(&bpf_jeq_imm(1, 0, 1));
            state.body.extend_from_slice(&bpf_insn(0x3d, 2, 1, 1, 0)); // BPF_JGE_REG
            state.body.extend_from_slice(&bpf_insn(0x7b, 0, 2, 0, 0)); // BPF_STX_DW
        }
        DTRACEAGG_MAX => {
            state.body.extend_from_slice(&bpf_ldx_dw(1, 0, 0));
            state.body.extend_from_slice(&bpf_mov64_reg(2, 6));
            // if (new > current) { *r0 = new }
            // jle r2, r1, +1  ; new <= current, skip store
            // stx_dw [r0], r2
            state.body.extend_from_slice(&bpf_insn(0xbd, 2, 1, 1, 0)); // jle r2, r1, +1
            state.body.extend_from_slice(&bpf_insn(0x7b, 0, 2, 0, 0)); // stx_dw [r0], r2
        }
        DTRACEAGG_AVG => {
            // value_size = 16: [sum, count]
            // *r0 += new;   *(r0+8) += 1
            state.body.extend_from_slice(&bpf_mov64_reg(1, 6));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
            state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 8));
        }
        DTRACEAGG_STDDEV => {
            // value_size = 24: [n, sum, sum_of_squares].
            //   *(r0+0)  += 1            (n)
            //   *(r0+8)  += value        (sum, in r6)
            //   *(r0+16) += value*value  (sum_sq)
            //
            // BPF_MUL64_REG is opcode 0x2f. Compute r1 = r6 * r6
            // before the atomic_add into sum_sq.
            state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
            state.body.extend_from_slice(&bpf_mov64_reg(1, 6));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 8));
            // r1 = r6; r1 *= r6; atomic_add into sum_sq.
            state.body.extend_from_slice(&bpf_mov64_reg(1, 6));
            state.body.extend_from_slice(&super::emit::bpf_insn(
                super::emit::BPF_MUL64_REG,
                1,
                6,
                0,
                0,
            ));
            state.body.extend_from_slice(&bpf_atomic_add(0, 1, 16));
        }
        _ => {}
    }
    let after_inc = state.body.len();
    let bail = ((after_inc - bail_pos - 8) / 8) as i16;
    state.body[bail_pos + 2..bail_pos + 4].copy_from_slice(&bail.to_le_bytes());
    state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
    state.body.extend_from_slice(&bpf_exit());
    Ok(())
}

pub fn emit_quantize_chain(
    state: &mut LowerState,
    dof: &Dof,
    actions: &[crate::Action],
) -> Result<(), LoweringError> {
    let agg = actions
        .iter()
        .find(|a| a.kind == DTRACEAGG_QUANTIZE)
        .ok_or(LoweringError::UnsupportedActionKind { kind: 0 })?;
    // Lower the value DIFO; result lands in r0.
    super::lower_difo_by_secidx(state, dof, agg.difo)?;
    state.body.extend_from_slice(&bpf_mov64_reg(6, 0));
    // r7 = computed bucket-id (0..NBUCKETS-1) from the DTrace
    // power-of-two layout.  Same bucket-id derivation as before;
    // we just don't use it as the BPF map key anymore.
    state.body.extend_from_slice(&bpf_mov64_imm(7, 0));

    state.body.extend_from_slice(&bpf_mov64_reg(5, 6));
    state.body.extend_from_slice(&bpf_alu64_imm(0x77, 5, 32)); // BPF_RSH64_IMM
    state.body.extend_from_slice(&bpf_jcc_imm(0x15, 5, 0, 2)); // BPF_JEQ_IMM
    state.body.extend_from_slice(&bpf_alu64_imm(0x07, 7, 32));
    state.body.extend_from_slice(&bpf_alu64_imm(0x77, 6, 32));

    for step in [(16u8, 16i32), (8, 8), (4, 4), (2, 2), (1, 1)] {
        let (shift_bits, add) = step;
        let threshold = 1i32 << shift_bits;
        state
            .body
            .extend_from_slice(&bpf_jcc_imm(0xa5, 6, threshold, 2)); // BPF_JLT_IMM
        state.body.extend_from_slice(&bpf_alu64_imm(0x07, 7, add));
        state
            .body
            .extend_from_slice(&bpf_alu64_imm(0x77, 6, shift_bits as i32));
    }
    state.body.extend_from_slice(&bpf_jcc_imm(0xa5, 6, 1, 1));
    state.body.extend_from_slice(&bpf_alu64_imm(0x07, 7, 1));

    // One PERCPU_ARRAY slot per (user-key); within
    // that slot a 127-u64 bucket array.  For `@latency = quantize(
    // value)` (n_keys=0) the user-key is constant 0.  We:
    //   1. write 0 at [r10-16] (the BPF map key buffer).
    //   2. call bpf_map_lookup_elem → r0 = &bucket_array (1016 B).
    //   3. compute offset_bytes = bucket_id * 8 into r8.
    //   4. r0 += r8; atomic_add 1 at [r0+0].
    //
    // Net per-fire: 1 map lookup + 1 shift + 1 add + 1 atomic_add.
    // Cross-kernel reducer sees ONE row per `@latency` (matching
    // FreeBSD's libdtrace-emitted shape) so both targets fold
    // into one histogram cell.
    //
    // Multi-key shape (`@latency[pid] = quantize(...)`) is the
    // next-next iteration: needs a key-store loop before the
    // lookup and PERCPU_HASH with `map_lookup_or_init`.
    // Shift to DTrace's standard zero-bucket index.  sys/dtrace.h:
    // DTRACE_QUANTIZE_ZEROBUCKET = sizeof(uint64_t) * NBBY - 1 = 63
    // on a 64-bit kernel.  For value=0 our r7=0; +63 → 63 (the
    // zero bucket).  For value=2^k (k=0..62), r7=k+1; +63 →
    // 64+k (matches DTrace's bucket for 2^k).  The host's
    // `decode_quantize_buckets` reverses this exact convention.
    // Negative input values aren't yet handled (the signed
    // mirror buckets below 63 stay zero); a future iteration can
    // add sign-folding before this point.
    state.body.extend_from_slice(&bpf_alu64_imm(0x07, 7, 63)); // r7 += 63 (ADD64_IMM)
    state.body.extend_from_slice(&bpf_mov64_reg(8, 7)); // r8 = bucket_id (save)
    state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
    state.body.extend_from_slice(&bpf_stx_w(10, 0, -16));
    state
        .body
        .extend_from_slice(&bpf_ld_map_fd(1, state.agg_map_fake_fd));
    state.body.extend_from_slice(&bpf_mov64_reg(2, 10));
    state.body.extend_from_slice(&bpf_alu64_imm(0x07, 2, -16));
    state.body.extend_from_slice(&bpf_call(1));
    let bail_pos = state.body.len();
    state.body.extend_from_slice(&bpf_jeq_imm(0, 0, 0));
    // Bound-check bucket_id < NBUCKETS to keep the verifier happy
    // (otherwise it can't prove the offset stays inside the
    // 1016-byte slot).  Clamp instead of bail so a degenerate
    // value still accounts somewhere (last bucket).
    let nbuckets = bifrost_wire::DTRACE_QUANTIZE_NBUCKETS as i32;
    state
        .body
        .extend_from_slice(&bpf_jcc_imm(0xa5, 8, nbuckets, 1)); // JLT r8, NBUCKETS, +1 (skip clamp)
    state
        .body
        .extend_from_slice(&bpf_mov64_imm(8, nbuckets - 1));
    // r8 <<= 3 (multiply by 8 to get byte offset).
    state.body.extend_from_slice(&bpf_alu64_imm(0x67, 8, 3));
    // r0 += r8 (BPF_ADD64_REG opcode 0x0f).
    state
        .body
        .extend_from_slice(&super::emit::bpf_insn(0x0f, 0, 8, 0, 0));
    state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
    state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
    let after_inc = state.body.len();
    let bail = ((after_inc - bail_pos - 8) / 8) as i16;
    state.body[bail_pos + 2..bail_pos + 4].copy_from_slice(&bail.to_le_bytes());
    state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
    state.body.extend_from_slice(&bpf_exit());
    Ok(())
}

/// Decode Apple libdtrace's packed `lquantize` parameters from
/// `action.arg`.  Layout:
///   bits 63-48 = step  (u16)
///   bits 47-32 = levels (u16)
///   bits 31-0  = base  (i32, sign-extended)
pub fn decode_lquantize_arg(arg: u64) -> (i32, u32, u32) {
    let base = (arg & 0xffff_ffff) as i32;
    let levels = ((arg >> 32) & 0xffff) as u32;
    let step = ((arg >> 48) & 0xffff) as u32;
    (base, levels, step)
}

/// Lower `lquantize(value, base, upper, step)`.  Same
/// shape as `emit_quantize_chain` (PERCPU_HASH keyed on a u32
/// bucket id, value = per-CPU count) but the bucket id comes
/// from a linear computation: `bucket = clamp((value - base) /
/// step, 0, levels) + 1`, with `bucket = 0` reserved for
/// underflow and `bucket = levels + 1` for overflow.  The
/// linear range covers buckets `1..=levels` representing
/// `[base + (i-1)*step, base + i*step)`.
///
/// Currently the value DIFO is treated as u64 (we drop the
/// signedness DTrace would otherwise apply).  Negative deltas
/// (value < base) route through the underflow guard via
/// unsigned-less-than against the literal `base`.
pub fn emit_lquantize_chain(
    state: &mut LowerState,
    dof: &Dof,
    actions: &[crate::Action],
) -> Result<(), LoweringError> {
    let agg = actions
        .iter()
        .find(|a| a.kind == DTRACEAGG_LQUANTIZE)
        .ok_or(LoweringError::UnsupportedActionKind { kind: 0 })?;
    let (base, levels, step) = decode_lquantize_arg(agg.arg);
    if step == 0 || levels == 0 {
        return Err(LoweringError::UnsupportedActionKind { kind: agg.kind });
    }

    super::lower_difo_by_secidx(state, dof, agg.difo)?;
    // r6 = value
    state.body.extend_from_slice(&bpf_mov64_reg(6, 0));
    // r7 = bucket id (initialized to underflow=0; overwritten below
    // when value lands in-range or in overflow).
    state.body.extend_from_slice(&bpf_mov64_imm(7, 0));

    // Underflow: if r6 (unsigned) < base ⇒ keep r7=0, store.
    // BPF_JLT_IMM = 0xa5 unsigned-less-than.  Skip past the
    // in-range / overflow blocks if underflow.
    //
    // We compute the in-range and overflow blocks first to know
    // their total size in slots so we can emit the JLT skip with
    // the right offset.
    //
    // Strategy:
    //   1.  Compute the body for the in-range/overflow logic in a
    //       separate buffer.
    //   2.  Emit `JLT r6, base, body_slots` first.
    //   3.  Append the body — which leaves r7 = bucket id in all
    //       paths.
    //
    // Body:
    //   r6 -= base
    //   if (r6 >= levels * step) → r7 = levels + 1; goto store
    //   r6 /= step
    //   r6 += 1
    //   r7 = r6
    //   store
    let upper_minus_base = (levels as i32).saturating_mul(step as i32);
    if base != 0 {
        // We need to skip the body when underflow.  Build it now.
    }

    let mut body = Vec::<u8>::new();
    // r6 -= base   (BPF_SUB64_IMM = 0x17)
    if base != 0 {
        body.extend_from_slice(&bpf_alu64_imm(0x17, 6, base));
    }
    // If r6 >= levels*step → overflow.
    // We need to emit `r7 = levels+1` and skip the in-range
    // computation.  Use a placeholder JGE offset patched after
    // emission.
    let jge_pos = body.len();
    body.extend_from_slice(&bpf_jcc_imm(0x35, 6, upper_minus_base, 0)); // BPF_JGE_IMM
    // In-range path: r6 /= step; r6 += 1; r7 = r6
    body.extend_from_slice(&bpf_alu64_imm(0x37, 6, step as i32)); // BPF_DIV64_IMM
    body.extend_from_slice(&bpf_alu64_imm(0x07, 6, 1)); // BPF_ADD64_IMM
    body.extend_from_slice(&bpf_mov64_reg(7, 6));
    // Jump past the overflow branch.
    let ja_pos = body.len();
    body.extend_from_slice(&bpf_ja(0));
    // Overflow path target:
    let overflow_target = body.len();
    body.extend_from_slice(&bpf_mov64_imm(7, (levels + 1) as i32));
    let after_body = body.len();

    // Patch JGE offset (from end of jge insn) to overflow_target.
    let jge_skip = ((overflow_target - (jge_pos + 8)) / 8) as i16;
    body[jge_pos + 2..jge_pos + 4].copy_from_slice(&jge_skip.to_le_bytes());
    // Patch JA offset (from end of ja insn) to after_body.
    let ja_skip = ((after_body - (ja_pos + 8)) / 8) as i16;
    body[ja_pos + 2..ja_pos + 4].copy_from_slice(&ja_skip.to_le_bytes());

    // Emit the JLT underflow-skip first, sized to skip the body.
    let body_slots = (body.len() / 8) as i16;
    if base != 0 {
        // JLT r6, base, body_slots  → underflow keeps r7=0 and
        // jumps over body.
        state
            .body
            .extend_from_slice(&bpf_jcc_imm(0xa5, 6, base, body_slots)); // BPF_JLT_IMM
    }
    state.body.extend_from_slice(&body);

    // Store bucket id (r7) to stack key slot at -16 (u32).
    state.body.extend_from_slice(&bpf_stx_w(10, 7, -16));
    // Standard map upsert + atomic_add +1 (identical to quantize).
    state
        .body
        .extend_from_slice(&bpf_ld_map_fd(1, state.agg_map_fake_fd));
    state.body.extend_from_slice(&bpf_mov64_reg(2, 10));
    state.body.extend_from_slice(&bpf_alu64_imm(0x07, 2, -16));
    state.body.extend_from_slice(&bpf_call(1)); // HELPER_MAP_LOOKUP_ELEM
    let bail_pos = state.body.len();
    state.body.extend_from_slice(&bpf_jeq_imm(0, 0, 0));
    state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
    state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
    let after_inc = state.body.len();
    let bail = ((after_inc - bail_pos - 8) / 8) as i16;
    state.body[bail_pos + 2..bail_pos + 4].copy_from_slice(&bail.to_le_bytes());
    state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
    state.body.extend_from_slice(&bpf_exit());
    Ok(())
}

/// Decode Apple libdtrace's packed `llquantize` parameters.
/// The parameters are `factor`, `low_mag`, `high_mag`,
/// `steps_per_mag`.  Apple packs them into `action.arg` as:
///   bits 63-48 = factor          (u16)
///   bits 47-40 = low_mag         (u8)
///   bits 39-32 = high_mag        (u8)
///   bits 31-16 = steps_per_mag   (u16)
///   bits 15-0  = reserved
pub fn decode_llquantize_arg(arg: u64) -> (u16, u8, u8, u16) {
    let steps_per_mag = ((arg >> 16) & 0xffff) as u16;
    let high_mag = ((arg >> 32) & 0xff) as u8;
    let low_mag = ((arg >> 40) & 0xff) as u8;
    let factor = ((arg >> 48) & 0xffff) as u16;
    (factor, low_mag, high_mag, steps_per_mag)
}

/// Lower `llquantize(value, factor, low_mag, high_mag,
/// steps_per_mag, value)`.  Log-linear-bucket histogram: each
/// magnitude band `factor^low_mag .. factor^high_mag` is
/// subdivided into `steps_per_mag` linear buckets.  The kernel
/// map shape matches quantize/lquantize (PERCPU_HASH keyed on
/// `bucket_id: u32`).
///
/// The BPF lowering computes the magnitude `m` by an unrolled
/// loop comparing value against `factor^m` for
/// `m = low_mag..=high_mag`, then picks the linear sub-bucket
/// via `((value - factor^(m-1)) * steps_per_mag) /
/// (factor^m - factor^(m-1))`.  Bucket id is
/// `(m - low_mag) * steps_per_mag + sub + 1`, with 0 reserved
/// for underflow and `(high_mag - low_mag + 1) * steps_per_mag
/// + 1` for overflow.
///
/// To keep the BPF program bounded for the verifier we cap
/// `(high_mag - low_mag)` at 8 (covers `1e0..1e8` typical
/// latency-range histograms) and unroll the magnitude detection
/// inline.
pub fn emit_llquantize_chain(
    state: &mut LowerState,
    dof: &Dof,
    actions: &[crate::Action],
) -> Result<(), LoweringError> {
    let agg = actions
        .iter()
        .find(|a| a.kind == DTRACEAGG_LLQUANTIZE)
        .ok_or(LoweringError::UnsupportedActionKind { kind: 0 })?;
    let (factor, low_mag, high_mag, steps_per_mag) = decode_llquantize_arg(agg.arg);
    if factor < 2 || steps_per_mag == 0 || low_mag > high_mag {
        return Err(LoweringError::UnsupportedActionKind { kind: agg.kind });
    }
    let n_mags = (high_mag as u32) - (low_mag as u32) + 1;
    const MAX_MAGS: u32 = 8;
    if n_mags > MAX_MAGS {
        return Err(LoweringError::UnsupportedActionKind { kind: agg.kind });
    }

    super::lower_difo_by_secidx(state, dof, agg.difo)?;
    // r6 = value
    state.body.extend_from_slice(&bpf_mov64_reg(6, 0));
    // r7 = bucket id, initialized to 0 (underflow).
    state.body.extend_from_slice(&bpf_mov64_imm(7, 0));

    // Pre-compute magnitude thresholds: T[i] = factor^(low_mag+i).
    // Use u64 in host code; emit as i32 immediates (truncated).
    // For magnitudes that overflow u64 the BPF JLT_IMM
    // signed-extended immediate will not work; in practice
    // factor*high_mag of 10^16 is just inside u63 so safe.
    let mut thresholds: Vec<u64> = Vec::with_capacity(n_mags as usize + 1);
    let mut t: u128 = 1;
    for _ in 0..low_mag as u32 {
        t = t.saturating_mul(factor as u128);
    }
    thresholds.push(t as u64);
    for _ in 0..n_mags {
        t = t.saturating_mul(factor as u128);
        thresholds.push(t as u64);
    }
    // thresholds[i] = factor^(low_mag+i); buckets sit in
    // [thresholds[i], thresholds[i+1]).

    // Underflow guard: if r6 < thresholds[0] ⇒ bucket=0; skip.
    let underflow_t = thresholds[0] as i32;
    // Build the in-range / overflow body in a side buffer so we
    // know how far to skip on underflow.
    let mut body = Vec::<u8>::new();
    // Walk magnitudes high-to-low so the first match wins.  For
    // each magnitude i (low_mag..high_mag): if r6 < thresholds[i+1]
    // ⇒ bucket = (i)*steps_per_mag + (r6 - thresholds[i]) /
    // ((thresholds[i+1]-thresholds[i])/steps_per_mag) + 1.
    //
    // Use a "skip the next K instructions if r6 >= threshold"
    // pattern.  After all magnitudes are checked, fall through to
    // overflow: bucket = n_mags*steps_per_mag + 1.
    for i in 0..n_mags as usize {
        let lo = thresholds[i];
        let hi = thresholds[i + 1];
        let band = hi.saturating_sub(lo);
        let sub_step = band / steps_per_mag as u64;
        // Per-magnitude block in another side buffer.
        let mut blk = Vec::<u8>::new();
        // r6 -= lo
        if lo != 0 {
            // BPF immediates are 32-bit signed; clamp.
            let lo_imm = if lo > i32::MAX as u64 {
                i32::MAX
            } else {
                lo as i32
            };
            blk.extend_from_slice(&bpf_alu64_imm(0x17, 6, lo_imm)); // SUB
        }
        if sub_step != 0 {
            let ss_imm = if sub_step > i32::MAX as u64 {
                i32::MAX
            } else {
                sub_step as i32
            };
            blk.extend_from_slice(&bpf_alu64_imm(0x37, 6, ss_imm)); // DIV
        }
        // r6 += (i)*steps_per_mag + 1
        let bias = (i as u32) * (steps_per_mag as u32) + 1;
        blk.extend_from_slice(&bpf_alu64_imm(0x07, 6, bias as i32)); // ADD
        // r7 = r6
        blk.extend_from_slice(&bpf_mov64_reg(7, 6));
        // JA past the rest of the magnitudes.
        let ja_pos = blk.len();
        blk.extend_from_slice(&bpf_ja(0)); // patched later

        let blk_slots = (blk.len() / 8) as i16;
        // Guard: if r6 >= hi ⇒ skip this block.
        let hi_imm = if hi > i32::MAX as u64 {
            i32::MAX
        } else {
            hi as i32
        };
        body.extend_from_slice(&bpf_jcc_imm(0x35, 6, hi_imm, blk_slots)); // JGE
        // Track ja_pos absolute index in body for later patch.
        let blk_start = body.len();
        body.extend_from_slice(&blk);
        // Compute absolute ja position in body for later patch.
        let ja_abs = blk_start + ja_pos;
        // Stash for post-loop patch — we don't know `body` final
        // length yet.  Record (ja_abs) in a vec.
        // Actually we'll patch all JAs to point at body.len() after
        // we've appended all magnitudes + overflow tail.  Mark via
        // a sentinel value of 0 (already) and walk back later.
        let _ = ja_abs;
    }
    // Overflow tail: r7 = n_mags*steps_per_mag + 1
    let overflow_id = (n_mags * steps_per_mag as u32 + 1) as i32;
    body.extend_from_slice(&bpf_mov64_imm(7, overflow_id));

    // Patch every JA insn in `body` whose off field is 0 to jump
    // to body.len().  Walk slot-by-slot.
    let body_end = body.len();
    let mut i = 0;
    while i + 8 <= body.len() {
        if body[i] == super::emit::BPF_JA {
            // Skip if non-zero (placeholder convention: 0 ⇒
            // unpatched).
            let off = i16::from_le_bytes([body[i + 2], body[i + 3]]);
            if off == 0 {
                let skip = ((body_end - (i + 8)) / 8) as i16;
                body[i + 2..i + 4].copy_from_slice(&skip.to_le_bytes());
            }
        }
        i += 8;
    }

    // Underflow skip in main body.
    let body_slots = (body.len() / 8) as i16;
    if underflow_t > 0 {
        state
            .body
            .extend_from_slice(&bpf_jcc_imm(0xa5, 6, underflow_t, body_slots)); // JLT
    }
    state.body.extend_from_slice(&body);

    // Store r7 as the u32 bucket id, then the standard upsert +
    // atomic_add +1 pattern.
    state.body.extend_from_slice(&bpf_stx_w(10, 7, -16));
    state
        .body
        .extend_from_slice(&bpf_ld_map_fd(1, state.agg_map_fake_fd));
    state.body.extend_from_slice(&bpf_mov64_reg(2, 10));
    state.body.extend_from_slice(&bpf_alu64_imm(0x07, 2, -16));
    state.body.extend_from_slice(&bpf_call(1));
    let bail_pos = state.body.len();
    state.body.extend_from_slice(&bpf_jeq_imm(0, 0, 0));
    state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
    state.body.extend_from_slice(&bpf_atomic_add(0, 1, 0));
    let after_inc = state.body.len();
    let bail = ((after_inc - bail_pos - 8) / 8) as i16;
    state.body[bail_pos + 2..bail_pos + 4].copy_from_slice(&bail.to_le_bytes());
    state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
    state.body.extend_from_slice(&bpf_exit());
    Ok(())
}

pub fn agg_map_decl_for_chain(
    actions: &[crate::Action],
    agg_pos: usize,
) -> Option<(u32, u32, u32, u32)> {
    agg_map_decl_for_chain_at(actions, 0, agg_pos)
}

/// Like [`agg_map_decl_for_chain`] but honors a non-zero
/// `chain_start`.  The convention matches [`emit_agg_chain_at`]:
/// the leading value DIFEXPR sits at `actions[chain_start]` and
/// keys at `actions[chain_start+1..agg_pos]`.  Callers must pass a
/// chain_start past any leading non-agg DIFEXPRs (e.g. a clause's
/// initial `trace(timestamp)`) so the BPF map's `key_size` matches
/// the agg's actual key arity instead of swallowing the standalone
/// actions as phantom keys.
pub fn agg_map_decl_for_chain_at(
    actions: &[crate::Action],
    chain_start: usize,
    agg_pos: usize,
) -> Option<(u32, u32, u32, u32)> {
    let agg = &actions[agg_pos];
    let n_keys = agg_pos.saturating_sub(chain_start + 1);
    // AVG stores [sum:u64][count:u64] per slot — 16 bytes.
    // STDDEV stores [n:u64][sum:u64][sum_of_squares:u64] — 24 bytes.
    // QUANTIZE/COUNT/SUM/MIN/MAX use 8 bytes.
    let value_size: u32 = match agg.kind {
        DTRACEAGG_AVG => 16,
        DTRACEAGG_STDDEV => 24,
        _ => 8,
    };
    if agg.kind == DTRACEAGG_QUANTIZE {
        // One row per (name, user-key) with the
        // full 127-bucket array as the value.  For
        // `@latency = quantize(...)` (n_keys=0), key=u32 0,
        // value=`QUANTIZE_VALUE_SIZE = 127 * 8 = 1016` bytes;
        // the BPF lowering looks up map[0] once per fire then
        // indexes by computed bucket-id into the value array.
        // n_keys>=1 (`@latency[k] = quantize(...)`) lands as
        // PERCPU_HASH with key=8*n_keys; same 1016-byte value
        // payload.  Matches FreeBSD's libdtrace-emitted
        // AGG_SNAPSHOT row shape so the cross-target reducer
        // folds both kernels' contributions into one histogram
        // cell.
        let quant_val_size: u32 = bifrost_wire::QUANTIZE_VALUE_SIZE;
        if n_keys == 0 {
            return Some((6, 4, quant_val_size, 1)); // PERCPU_ARRAY[1]
        }
        const MAX_KEYS: usize = 4;
        if n_keys > MAX_KEYS {
            return None;
        }
        return Some((5, (8 * n_keys) as u32, quant_val_size, 64)); // PERCPU_HASH
    }
    if agg.kind == DTRACEAGG_LQUANTIZE || agg.kind == DTRACEAGG_LLQUANTIZE {
        // PERCPU_ARRAY of 64 buckets (covers linear/log-linear
        // shapes that fit ≤ 64 buckets).
        return Some((6, 4, value_size, 64)); // BPF_MAP_TYPE_PERCPU_ARRAY
    }
    // n_keys=0  → PERCPU_ARRAY (key=u32 index, max=1).
    // n_keys≥1  → PERCPU_HASH with key_size = 8 * n_keys.
    //             max_entries=64 (matches single-key default; tunable
    //             later if multi-key cardinality grows).
    if n_keys == 0 {
        return Some((6, 4, value_size, 1));
    }
    const MAX_KEYS: usize = 4;
    if n_keys > MAX_KEYS {
        return None;
    }
    Some((5, (8 * n_keys) as u32, value_size, 64))
}

pub fn agg_kind_str(kind: u32) -> Option<&'static str> {
    match kind {
        DTRACEAGG_COUNT => Some("count"),
        DTRACEAGG_SUM => Some("sum"),
        DTRACEAGG_STDDEV => Some("stddev"),
        DTRACEAGG_MIN => Some("min"),
        DTRACEAGG_MAX => Some("max"),
        DTRACEAGG_AVG => Some("avg"),
        DTRACEAGG_QUANTIZE => Some("quantize"),
        DTRACEAGG_LQUANTIZE => Some("lquantize"),
        DTRACEAGG_LLQUANTIZE => Some("llquantize"),
        _ => None,
    }
}

/// Returns true if `difo_secidx` decodes to a body that loads the
/// `execname` builtin (DIF var_id 0x0118) — the canonical single-
/// LDGS pattern produced for both `@agg[execname] = ...` (agg-key
/// path) and `printf("%s", execname)` (per-fire printf path). Both
/// callers special-case the result by inserting an extra
/// `ldx_dw R0, [R0 + 0]` after the lowering so R0 holds the first
/// 8 bytes of comm rather than a pointer to the scratch buffer.
///
/// Conservatively true: any LDGS 0x0118 in the DIFO triggers the
/// special case. False positives are rare in practice — DTrace
/// doesn't compose execname into longer expressions because it has
/// no useful arithmetic identity, and `strjoin(execname, ...)` etc.
/// already lower differently.
pub fn is_execname_difo(dof: &crate::Dof, difo_secidx: u32) -> bool {
    let difo = match dof.difo(difo_secidx) {
        Some(d) => d,
        None => return false,
    };
    let dif_idx = match difo.dif_section() {
        Some(i) => i,
        None => return false,
    };
    let dif_sec = match dof.sections.get(dif_idx as usize) {
        Some(s) => s,
        None => return false,
    };
    for ins in dof.dif_instructions(dif_sec) {
        // LDGS opcode is 0x29; var_id is encoded in imm16 as
        // (r1 << 8) | r2. Execname is var_id 0x0118.
        if ins.op == 0x29 && ins.imm16() == 0x0118 {
            return true;
        }
    }
    false
}

/// True if `difo_secidx` points at a DIF object whose result is a
/// pointer to a string literal — i.e. its DIF program ends with a
/// SETS (opcode 0x26).  The string materialization in
/// `dif::lower_one` copies bytes into the per-program STR_SCRATCH
/// buffer on the BPF stack, then returns a pointer to that buffer.
/// Like the execname special case (LDGS), the agg-key lowering must
/// **dereference** that pointer so the first 8 bytes of the string
/// itself end up in the map key — without this, every clause
/// invocation hashes to a different stack address and the map fans
/// out into one entry per fire.  8 bytes covers the common short
/// SDT-style discriminators ("commit", "abort", "open", "read", …);
/// longer strings get truncated at the 8-byte boundary, same
/// contract as the existing 8-byte-per-key wire format.
pub fn is_string_literal_difo(dof: &crate::Dof, difo_secidx: u32) -> bool {
    let difo = match dof.difo(difo_secidx) {
        Some(d) => d,
        None => return false,
    };
    let dif_idx = match difo.dif_section() {
        Some(i) => i,
        None => return false,
    };
    let dif_sec = match dof.sections.get(dif_idx as usize) {
        Some(s) => s,
        None => return false,
    };
    // SETS (0x26) anywhere in the DIFO is enough — DIF for a string
    // literal compiles to `SETS rd, <imm16>` followed by a RET (or
    // similar terminator); the SETS is what produced the pointer
    // result that flows into the agg-key store.  Conservative:
    // returns true if the DIFO touches the string-scratch path at
    // all, even when there's also other arithmetic.  False positives
    // here mean an extra 8-byte load instruction before the store —
    // benign; false negatives leave the pointer-key bug unfixed.
    for ins in dof.dif_instructions(dif_sec) {
        if ins.op == 0x26 {
            return true;
        }
    }
    false
}
