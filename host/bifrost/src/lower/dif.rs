// SPDX-License-Identifier: Apache-2.0
use super::emit::*;
use super::state::LowerState;
use super::{LoweringError, PendingCmp, RetMode};

/// Scan a DIF section for LDLS/STLS references and pre-allocate
/// stack slots for each unique var_id. Called from the program-level
/// prologue so we can zero-init the slots once, before any clause
/// code runs (matches DTrace's "uninitialized this-> reads as 0"
/// semantic). Idempotent — repeat calls return the same slot map.
pub fn collect_locals_in_section(
    state: &mut crate::lower::LowerState,
    dof: &crate::Dof,
    dif_sec: &crate::DofSection,
) {
    for ins in dof.dif_instructions(dif_sec) {
        if ins.op == 0x38 || ins.op == 0x39 {
            let _ = state.alloc_local(ins.imm16());
        }
    }
}

/// Lower a single DIF instruction into the body.
pub fn lower_one_state(
    state: &mut LowerState,
    ins: crate::DifInstr,
    _dif_idx: usize,
) -> Result<(), LoweringError> {
    // Clause-local (`this->`) opcodes need state-mutating slot
    // allocation, which can't coexist with the &mut state.body borrow
    // taken just below. Handle them up-front and return early.
    match ins.op {
        0x38 => {
            // LDLS — load this->x
            let var_id = ins.imm16();
            let off = state
                .alloc_local(var_id)
                .ok_or(LoweringError::UnsupportedVar { var_id })?;
            state.body.extend_from_slice(&bpf_ldx_dw(ins.rd, 10, off));
            return Ok(());
        }
        0x39 => {
            // STLS — store this->x
            let var_id = ins.imm16();
            let off = state
                .alloc_local(var_id)
                .ok_or(LoweringError::UnsupportedVar { var_id })?;
            state.body.extend_from_slice(&bpf_stx_dw(10, ins.rd, off));
            return Ok(());
        }
        0x31 | 0x32 => {
            // PUSHTR (0x31) / PUSHTV (0x32) — push a value onto the
            // tuple stack.  Both opcodes share the same wire shape:
            // PUSHTR pushes a typed reference (pointer), PUSHTV pushes
            // a typed value (scalar).  For this backend they are
            // identical because the BPF verifier sees only 8-byte
            // stack slots; the type distinction is recovered later by
            // the consuming `CALL`.
            //
            // ## Slot addressing
            //
            // Slots index *downward* from `TUPLE_STACK_BASE` as
            // `TUPLE_STACK_BASE - depth*8`.  The verifier requires
            // every stack access to use a constant offset from r10,
            // and reasons about stack-slot kinds by absolute offset;
            // post-incrementing a runtime pointer would defeat both.
            // The downward direction matches the layout the consuming
            // `CALL` arm reads back (LDX from the same offset
            // formula).
            //
            // ## CALL boundary
            //
            // `depth` resets to 0 inside the `CALL` arm: the DIF
            // subroutine ABI consumes every pushed argument, and the
            // BPF subroutine ABI does not preserve the tuple stack
            // across the call boundary.  Callers that need a value
            // preserved across a CALL must spill it explicitly into a
            // `this->`-allocated local slot instead.
            //
            // Aggregation tuple keys also flow through here; the
            // emit-side reads them back via the same `TUPLE_STACK_BASE
            // - depth*8` formula when building the agg map key.
            use super::state::{TUPLE_STACK_BASE, TUPLE_STACK_SLOTS};
            if state.tuple_depth >= TUPLE_STACK_SLOTS {
                return Err(LoweringError::TupleStackOverflow {
                    depth: state.tuple_depth,
                    cap: TUPLE_STACK_SLOTS,
                });
            }
            let slot = TUPLE_STACK_BASE - (state.tuple_depth as i16) * 8;
            state.body.extend_from_slice(&bpf_stx_dw(10, ins.rd, slot));
            state.tuple_depth += 1;
            return Ok(());
        }
        0x2f => {
            // CALL — DIF subroutine. imm16 = DIF_SUBR_*. Args were
            // pushed via preceding PUSHTV/PUSHTR; pop them, apply
            // the op, store result in rd. Reset tuple depth to 0
            // (subroutine ABI is "consumes all").
            //
            // Covered today:
            //   - 11  DIF_SUBR_PROGENYOF  → bifrost_kfunc_progenyof(pid)
            //   - 12  DIF_SUBR_STRLEN     → bifrost_kfunc_strlen(s)
            //   -  9  DIF_SUBR_COPYINSTR  → bifrost_kfunc_copyinstr(uaddr)
            //   - 35..40 ntohs/ntohl/ntohll + htons/htonl/htonll
            //     (all map to bpf_to_be on little-endian targets).
            use super::state::TUPLE_STACK_BASE;
            let subr = ins.imm16();
            match subr {
                // progenyof — walk current->real_parent up to
                // init; returns 1 if `pid` is current or an
                // ancestor, 0 otherwise. Single-arg (target pid).
                11 => {
                    emit_single_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_PROGENYOF,
                    );
                }
                // strlen — single-arg (string pointer); the
                // kfunc bounds the read at a fixed cap via
                // `bpf_probe_read_user_str` to keep the verifier
                // happy on userspace strings.
                12 => {
                    emit_single_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_STRLEN,
                    );
                }
                // copyinstr — bounded NUL-terminated user-string
                // copy into a per-CPU scratch buffer; returns a
                // pointer that BPF treats as `string`.
                9 => {
                    emit_single_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_COPYINSTR,
                    );
                }
                // strchr(s, c) — first occurrence of char c in s
                // (or NULL). Two-arg subr; arg0=haystack, arg1=char.
                28 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_STRCHR,
                    );
                }
                // strrchr(s, c) — last occurrence of char c.
                29 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_STRRCHR,
                    );
                }
                // copyin(uaddr, len) — bounded user-memory byte
                // copy; returns a pointer to per-CPU scratch.
                8 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_COPYIN,
                    );
                }
                // tracemem(addr, len).  The canonical form is
                // a `DTRACEACT_TRACEMEM` action (handled in
                // `host/bifrost/src/lower/action.rs`); the DIF
                // subr 50 path remains as an expression-context
                // fallback that returns a per-CPU scratch pointer
                // via `KFUNC_COPYIN` so user scripts that pass
                // `tracemem(arg0, N)` into a longer expression
                // (e.g. `trace(tracemem(arg0, 16))`) still
                // compile.  Action-form usage produces a hex/
                // ASCII record dump via the host renderer.
                50 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_COPYIN,
                    );
                }
                // strstr(s, sub) — substring search, returns
                // pointer or NULL.
                30 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_STRSTR,
                    );
                }
                // index(s, sub) — substring search, returns
                // offset (-1 if not found).
                33 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_INDEX,
                    );
                }
                // strjoin(a, b) — concatenate two user strings
                // into scratch, returns pointer.
                23 => {
                    super::emit::emit_two_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_STRJOIN,
                    );
                }
                // substr(s, idx, len) — three-arg slice.
                32 => {
                    super::emit::emit_three_arg_kfunc_subr(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        ins.rd,
                        super::emit::KFUNC_SUBSTR,
                    );
                }
                // speculation() — zero-arg subr returns an integer
                // lane id (protocol-level placeholder). Today returns
                // 1 so dependent calls (`speculate`, `commit`,
                // `discard`) have a valid id to thread. No real
                // side-buffer routing.
                10 => {
                    // Zero-arg: spill r1..r5, call, restore. Mirror
                    // the value-DIFO helper-call sequence but with
                    // a kfunc reloc.
                    for r in 1u8..=5u8 {
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        state.body.extend_from_slice(&bpf_stx_dw(10, r, slot));
                    }
                    emit_kfunc_call(
                        &mut state.body,
                        &mut state.kfunc_relocs,
                        super::emit::KFUNC_SPECULATION,
                    );
                    for r in 1u8..=5u8 {
                        if r == ins.rd {
                            continue;
                        }
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        state.body.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
                    }
                    if ins.rd != 0 {
                        state.body.extend_from_slice(&bpf_mov64_reg(ins.rd, 0));
                    }
                }
                // speculate/commit/discard — single-arg subrs, all
                // no-op kfuncs today (protocol-level placeholders).
                41 => super::emit::emit_single_arg_kfunc_subr(
                    &mut state.body,
                    &mut state.kfunc_relocs,
                    ins.rd,
                    super::emit::KFUNC_SPECULATE,
                ),
                46 => super::emit::emit_single_arg_kfunc_subr(
                    &mut state.body,
                    &mut state.kfunc_relocs,
                    ins.rd,
                    super::emit::KFUNC_COMMIT,
                ),
                47 => super::emit::emit_single_arg_kfunc_subr(
                    &mut state.body,
                    &mut state.kfunc_relocs,
                    ins.rd,
                    super::emit::KFUNC_DISCARD,
                ),
                35 | 38 | 36 | 39 | 37 | 40 => {
                    let width = match subr {
                        35 | 38 => 16,
                        36 | 39 => 32,
                        37 | 40 => 64,
                        _ => unreachable!(),
                    };
                    state
                        .body
                        .extend_from_slice(&bpf_ldx_dw(ins.rd, 10, TUPLE_STACK_BASE));
                    state.body.extend_from_slice(&bpf_to_be(ins.rd, width));
                }
                _ => return Err(LoweringError::UnsupportedSubr { subr }),
            }
            state.tuple_depth = 0;
            return Ok(());
        }
        _ => {}
    }

    // Clear reg_kind[rd] for opcodes that overwrite rd BEFORE the
    // per-opcode arm runs. Specific arms (SETS, LDGS execname)
    // re-stamp a known kind after emitting. Other writes (ALU, LDX,
    // helper-call results) leave rd as Unknown — SCMP rejects those
    // as operands, which is the correctness invariant this stamping
    // protects.
    if writes_rd(ins.op) && (ins.rd as usize) < state.reg_kind.len() {
        state.reg_kind[ins.rd as usize] = super::state::RegKind::Unknown;
    }

    // Snapshot read-only state we'll need after the split-borrow.
    // `inttab` is borrowed via clone of the option to avoid aliasing
    // with the mutable body borrow below.
    let inttab_snapshot = state.inttab.clone();
    let inttab = inttab_snapshot.as_deref();
    let strtab_snapshot = state.strtab.clone();
    let strtab = strtab_snapshot.as_deref();
    let value_off = state.value_off;
    let ret_mode = state.ret_mode;
    // Split borrow: body + kfunc_relocs are independent fields, so
    // both can be mutably borrowed at once via destructuring.
    let LowerState {
        body: out,
        kfunc_relocs: relocs,
        ..
    } = state;

    match ins.op {
        // ----- 3-operand ALU64: rd = r1 OP r2 -----
        0x01 => lower_binary(out, BPF_OR64_REG, ins.r1, ins.r2, ins.rd), // OR
        0x02 => lower_binary(out, BPF_XOR64_REG, ins.r1, ins.r2, ins.rd), // XOR
        0x03 => lower_binary(out, BPF_AND64_REG, ins.r1, ins.r2, ins.rd), // AND
        0x04 => lower_binary(out, BPF_LSH64_REG, ins.r1, ins.r2, ins.rd), // SLL
        0x05 => lower_binary(out, BPF_RSH64_REG, ins.r1, ins.r2, ins.rd), // SRL
        0x06 => lower_binary(out, BPF_SUB64_REG, ins.r1, ins.r2, ins.rd), // SUB
        0x07 => lower_binary(out, BPF_ADD64_REG, ins.r1, ins.r2, ins.rd), // ADD
        0x08 => lower_binary(out, BPF_MUL64_REG, ins.r1, ins.r2, ins.rd), // MUL
        0x0a => lower_binary(out, BPF_DIV64_REG, ins.r1, ins.r2, ins.rd), // UDIV
        0x0c => lower_binary(out, BPF_MOD64_REG, ins.r1, ins.r2, ins.rd), // UREM
        0x2e => lower_binary(out, BPF_ARSH64_REG, ins.r1, ins.r2, ins.rd), // SRA

        0x0d => {
            if ins.r1 == 0 {
                out.extend_from_slice(&bpf_mov64_imm(ins.rd, 0));
            } else if ins.rd != ins.r1 {
                out.extend_from_slice(&bpf_mov64_reg(ins.rd, ins.r1));
            }
            out.extend_from_slice(&bpf_insn(0xa7, ins.rd, 0, 0, -1));
        }

        0x0e => {
            if ins.r1 == 0 {
                out.extend_from_slice(&bpf_mov64_imm(ins.rd, 0));
            } else if ins.rd != ins.r1 {
                out.extend_from_slice(&bpf_mov64_reg(ins.rd, ins.r1));
            }
        }

        0x25 => {
            let idx = ins.imm16() as usize;
            let table = inttab.ok_or(LoweringError::NoIntTab)?;
            let val = *table.get(idx).ok_or(LoweringError::IntTabOob {
                idx,
                len: table.len(),
            })?;
            out.extend_from_slice(&bpf_ld_imm64(ins.rd, val));
        }

        // SETS — load string literal pointer. imm16 indexes into the
        // DIFO's strtab; the string runs from there to the next NUL.
        // We emit a sequence of stack stores that materialize the
        // string into a per-instance 16-byte scratch slot, then return
        // the pointer to that slot in `rd`.
        //
        // Per-instance slot layout (goal item 3): instance N occupies
        // `[SETS_SCRATCH_BASE - 16*N, SETS_SCRATCH_BASE - 16*N + 15]`.
        // SETS_INSTANCE_SLOTS=3 cap keeps every slot above TUPLE_STACK
        // (=-416). Capped slot count rejects beyond the budget instead
        // of silently aliasing prior literals (which would miscompile
        // a clause like `/execname == "redis" || execname == "psql"/`).
        //
        // 16 bytes is TASK_COMM_LEN-sized: matches what SCMP needs for
        // execname-shape comparisons. Longer literals truncate at 15
        // chars + NUL — exactly the comparison budget SCMP's inline
        // 16-byte byte-compare uses, so a long literal can never
        // match an execname regardless.
        0x26 => {
            use super::state::{SETS_INSTANCE_SIZE, SETS_INSTANCE_SLOTS, SETS_SCRATCH_BASE};
            let instance_idx = state.sets_instance_count;
            if instance_idx >= SETS_INSTANCE_SLOTS {
                return Err(LoweringError::SetsScratchExhausted {
                    count: instance_idx + 1,
                    cap: SETS_INSTANCE_SLOTS,
                });
            }
            let scratch_base: i16 = SETS_SCRATCH_BASE - SETS_INSTANCE_SIZE * (instance_idx as i16);
            const SCRATCH_SIZE: usize = 16;
            let off = ins.imm16() as usize;
            let strtab_bytes = strtab.ok_or(LoweringError::NoStrTab)?;
            if off >= strtab_bytes.len() {
                return Err(LoweringError::StrTabOob {
                    off,
                    len: strtab_bytes.len(),
                });
            }
            let end = strtab_bytes[off..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| off + i)
                .unwrap_or(strtab_bytes.len());
            let raw = &strtab_bytes[off..end];
            let copy_len = raw.len().min(SCRATCH_SIZE - 1);
            // Zero the 16-byte slot first for guaranteed NUL-term.
            out.extend_from_slice(&bpf_mov64_imm(0, 0));
            out.extend_from_slice(&bpf_stx_dw(10, 0, scratch_base));
            out.extend_from_slice(&bpf_stx_dw(10, 0, scratch_base + 8));
            // Materialize string bytes into scratch, 8-byte chunks.
            let s = &raw[..copy_len];
            for (chunk_idx, chunk) in s.chunks(8).enumerate() {
                let mut buf = [0u8; 8];
                buf[..chunk.len()].copy_from_slice(chunk);
                let val = u64::from_le_bytes(buf);
                out.extend_from_slice(&bpf_ld_imm64(0, val));
                out.extend_from_slice(&bpf_stx_dw(10, 0, scratch_base + (chunk_idx as i16) * 8));
            }
            // rd ← r10 + scratch_base
            if ins.rd != 10 {
                out.extend_from_slice(&bpf_mov64_reg(ins.rd, 10));
            }
            out.extend_from_slice(&bpf_alu64_imm(0x07, ins.rd, scratch_base as i32));
            state.sets_instance_count = instance_idx + 1;
            if (ins.rd as usize) < state.reg_kind.len() {
                state.reg_kind[ins.rd as usize] = super::state::RegKind::StrLiteralScratch;
            }
        }

        // SCMP — compare strings at r1 (against the immediately-
        // preceding SETX-loaded string in r2). Lowered to a
        // bpf_strncmp helper call: r0 ← strncmp(r1, len, r2),
        // and we set pending_cmp to Tst(0) so the subsequent
        // BCEQ/BCNE branches against r0 (== 0 means equal). Same
        // contract as the integer CMP / BC* pair: the comparison
        // result is consumed by the next branch, not stored.
        //
        // The helper signature is
        //   int bpf_strncmp(const char *s1, u32 s1_sz, const char *s2)
        // which returns 0 iff s1[..s1_sz] (truncated at first NUL)
        // matches s2 byte-for-byte. We pass the SETX-loaded scratch
        // string as s1 because it has a known fixed buffer length;
        // s2 is the kernel-helper-derived pointer (e.g. execname).
        0x27 => {
            // Inline 16-byte byte-for-byte compare. We avoid
            // bpf_strncmp because its arg3 is ARG_PTR_TO_CONST_STR,
            // which the verifier strictly requires to be PTR_TO_
            // MAP_VALUE (rdonly map); a stack-resident SETS scratch
            // pointer is not accepted, even though it is a valid
            // NUL-terminated buffer at runtime.
            //
            // Gate the inline path on operand shapes it actually
            // supports. The 16-byte XOR is correct iff
            // BOTH inputs are 16-byte zero-padded stack regions:
            //   - ExecnameScratch (LDGS execname → fp-136 + comm)
            //   - StrLiteralScratch (SETS → fp-344-... + 16 bytes)
            // Any other operand could be any pointer kind (e.g. a
            // probe-arg deref); the 16-byte XOR would silently
            // misread off-end stack data and produce a meaningless
            // "equality" result. Refuse at lowering with an
            // actionable diagnostic instead.
            use super::state::RegKind;
            let r1_kind = state
                .reg_kind
                .get(ins.r1 as usize)
                .copied()
                .unwrap_or(RegKind::Unknown);
            let r2_kind = state
                .reg_kind
                .get(ins.r2 as usize)
                .copied()
                .unwrap_or(RegKind::Unknown);
            let kind_label = |k: RegKind| -> &'static str {
                match k {
                    RegKind::Unknown => "<unknown>",
                    RegKind::ExecnameScratch => "execname",
                    RegKind::StrLiteralScratch => "string-literal",
                }
            };
            let supported = matches!(
                (r1_kind, r2_kind),
                (RegKind::ExecnameScratch, RegKind::StrLiteralScratch)
                    | (RegKind::StrLiteralScratch, RegKind::ExecnameScratch)
                    | (RegKind::ExecnameScratch, RegKind::ExecnameScratch)
                    | (RegKind::StrLiteralScratch, RegKind::StrLiteralScratch)
            );
            if !supported {
                return Err(LoweringError::ScmpUnsupportedShape {
                    r1_kind: kind_label(r1_kind),
                    r2_kind: kind_label(r2_kind),
                });
            }
            // Stack slots:
            //   [r10-16] : s1 spill (so we can restore r{ins.r1})
            //   [r10-24] : s2 spill (so we can restore r{ins.r2})
            // Both stay clear of the SETS scratch region.
            const SCMP_R1_SLOT: i16 = -16;
            const SCMP_R2_SLOT: i16 = -24;
            out.extend_from_slice(&bpf_stx_dw(10, ins.r1, SCMP_R1_SLOT));
            out.extend_from_slice(&bpf_stx_dw(10, ins.r2, SCMP_R2_SLOT));
            // Load both pointers via spill/reload — preserves
            // PTR_TO_STACK across any aliasing.
            out.extend_from_slice(&bpf_ldx_dw(1, 10, SCMP_R1_SLOT)); // r1 = s1 ptr
            out.extend_from_slice(&bpf_ldx_dw(3, 10, SCMP_R2_SLOT)); // r3 = s2 ptr
            // r0 = chunk0(s1) ^ chunk0(s2)
            out.extend_from_slice(&bpf_ldx_dw(0, 1, 0));
            out.extend_from_slice(&bpf_ldx_dw(2, 3, 0));
            out.extend_from_slice(&bpf_insn(BPF_XOR64_REG, 0, 2, 0, 0));
            // r2 = chunk1(s1) ^ chunk1(s2)
            out.extend_from_slice(&bpf_ldx_dw(4, 1, 8));
            out.extend_from_slice(&bpf_ldx_dw(2, 3, 8));
            out.extend_from_slice(&bpf_insn(BPF_XOR64_REG, 2, 4, 0, 0));
            // r0 |= r2  → r0 == 0 iff all 16 bytes matched.
            out.extend_from_slice(&bpf_insn(BPF_OR64_REG, 0, 2, 0, 0));
            // Restore — paranoia for downstream code that might
            // expect ins.r1/ins.r2 to still hold their inputs.
            out.extend_from_slice(&bpf_ldx_dw(ins.r1, 10, SCMP_R1_SLOT));
            out.extend_from_slice(&bpf_ldx_dw(ins.r2, 10, SCMP_R2_SLOT));
            // pending_cmp consumed by next BCEQ (jeq r0, 0 → equal)
            // or BCNE (jne r0, 0 → different).
            state.pending_cmp = Some(PendingCmp::Tst(0));
        }

        0x23 => match ret_mode {
            RetMode::SchemaAction => {
                if let Some(off) = value_off {
                    if ins.rd == 0 {
                        out.extend_from_slice(&bpf_mov64_imm(0, 0));
                    }
                    out.extend_from_slice(&bpf_stx_dw(RB_PTR_REG, ins.rd, off));
                }
                emit_record_submit(out, relocs, RB_PTR_REG, true, true);
                out.extend_from_slice(&bpf_mov64_imm(0, 0));
                out.extend_from_slice(&bpf_exit());
            }
            RetMode::Predicate => {
                if ins.rd == 0 {
                    out.extend_from_slice(&bpf_mov64_imm(0, 0));
                } else {
                    out.extend_from_slice(&bpf_mov64_reg(0, ins.rd));
                }
            }
            RetMode::Schemaless => {
                if ins.rd == 0 {
                    out.extend_from_slice(&bpf_mov64_imm(0, 0));
                } else {
                    out.extend_from_slice(&bpf_mov64_reg(0, ins.rd));
                }
                out.extend_from_slice(&bpf_exit());
            }
        },

        0x24 => {}

        0x0f => {
            state.pending_cmp = Some(PendingCmp::Reg(ins.r1, ins.r2));
        }
        0x10 => {
            state.pending_cmp = Some(PendingCmp::Tst(ins.r1));
        }

        0x11 => {
            let target = ins.branch_target();
            let insn = bpf_ja(0);
            super::branch::emit_branch_placeholder(state, insn, target);
        }

        op @ 0x12..=0x1b => {
            let cmp = state
                .pending_cmp
                .take()
                .ok_or(LoweringError::UnsupportedOp {
                    op,
                    mnemonic: ins.mnemonic(),
                })?;
            if cmp.reads_dif_r0() {
                out.extend_from_slice(&bpf_mov64_imm(0, 0));
            }
            let target = ins.branch_target();
            let insn = match (op, cmp) {
                (0x12, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JEQ_REG, a, b, 0),
                (0x12, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JEQ_IMM, a, 0, 0),
                (0x13, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JNE_REG, a, b, 0),
                (0x13, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JNE_IMM, a, 0, 0),
                (0x14, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JSGT_REG, a, b, 0),
                (0x14, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JSGT_IMM, a, 0, 0),
                (0x15, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JGT_REG, a, b, 0),
                (0x15, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JGT_IMM, a, 0, 0),
                (0x16, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JSGE_REG, a, b, 0),
                (0x16, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JSGE_IMM, a, 0, 0),
                (0x17, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JGE_REG, a, b, 0),
                (0x17, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JGE_IMM, a, 0, 0),
                (0x18, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JSLT_REG, a, b, 0),
                (0x18, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JSLT_IMM, a, 0, 0),
                (0x19, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JLT_REG, a, b, 0),
                (0x19, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JLT_IMM, a, 0, 0),
                (0x1a, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JSLE_REG, a, b, 0),
                (0x1a, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JSLE_IMM, a, 0, 0),
                (0x1b, PendingCmp::Reg(a, b)) => bpf_jcc_reg(BPF_JLE_REG, a, b, 0),
                (0x1b, PendingCmp::Tst(a)) => bpf_jcc_imm(BPF_JLE_IMM, a, 0, 0),
                _ => unreachable!(),
            };
            super::branch::emit_branch_placeholder(state, insn, target);
        }

        0x29 => {
            let var_id = ins.imm16();
            match var_id {
                0x0100 => emit_helper_call_difo(out, HELPER_GET_CURRENT_TASK, ins.rd),
                // 0x0101 = DIF_VAR_TIMESTAMP — monotonic ns since boot,
                // straight `bpf_ktime_get_ns()`.
                0x0101 => emit_helper_call_difo(out, HELPER_KTIME_GET_NS, ins.rd),
                // 0x0102 = DIF_VAR_VTIMESTAMP — "ns spent in probe
                // context for the current thread". Route through a
                // dedicated kfunc so the upgrade to per-task delta
                // tracking is purely internal (no DIF / wire format
                // change). Today the kfunc aliases ktime_get_ns().
                0x0102 => {
                    for r in 1u8..=5u8 {
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
                    }
                    emit_kfunc_call(out, relocs, KFUNC_VTIMESTAMP_NS);
                    for r in 1u8..=5u8 {
                        if r == ins.rd {
                            continue;
                        }
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
                    }
                    if ins.rd != 0 {
                        out.extend_from_slice(&bpf_mov64_reg(ins.rd, 0));
                    }
                }
                0x0106..=0x010f => {
                    let reg_idx = (var_id - 0x0106) as i16;
                    out.extend_from_slice(&bpf_ldx_dw(ins.rd, CTX_REG, reg_idx * 8));
                }
                0x0116 => {
                    emit_helper_call_difo(out, HELPER_GET_CURRENT_PID_TGID, ins.rd);
                    out.extend_from_slice(&bpf_alu64_imm(BPF_RSH64_IMM, ins.rd, 32));
                }
                0x0117 => {
                    emit_helper_call_difo(out, HELPER_GET_CURRENT_PID_TGID, ins.rd);
                    out.extend_from_slice(&bpf_alu64_imm(BPF_LSH64_IMM, ins.rd, 32));
                    out.extend_from_slice(&bpf_alu64_imm(BPF_RSH64_IMM, ins.rd, 32));
                }
                0x0118 => {
                    for r in 1u8..=5 {
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
                    }
                    out.extend_from_slice(&bpf_mov64_reg(1, 10));
                    out.extend_from_slice(&bpf_alu64_imm(0x07, 1, -136)); // EXECNAME_SCRATCH_BASE
                    out.extend_from_slice(&bpf_mov64_imm(2, 16));
                    out.extend_from_slice(&bpf_call(HELPER_GET_CURRENT_COMM));
                    for r in 1u8..=5 {
                        if r == ins.rd {
                            continue;
                        }
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
                    }
                    if ins.rd != 10 {
                        out.extend_from_slice(&bpf_mov64_reg(ins.rd, 10));
                    }
                    out.extend_from_slice(&bpf_alu64_imm(0x07, ins.rd, -136));
                    // Stamp the destination as ExecnameScratch so SCMP
                    // can recognize this operand shape and emit the
                    // 16-byte byte-compare safely.
                    if (ins.rd as usize) < state.reg_kind.len() {
                        state.reg_kind[ins.rd as usize] = super::state::RegKind::ExecnameScratch;
                    }
                }
                // walltimestamp — real wall-clock ns since the Unix
                // epoch. Lowers via a kfunc call so the guest module
                // can wire it to `ktime_get_real_ns()`; using the
                // monotonic `bpf_ktime_get_boot_ns` helper here would
                // misalign scripts that compare against
                // `date +%s%N`.
                0x011a => {
                    // Spill r1..r5 first because the BPF call ABI
                    // clobbers them; the kfunc takes no args and
                    // returns u64 in r0, but the call still
                    // clobbers caller-saved regs.
                    for r in 1u8..=5u8 {
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
                    }
                    emit_kfunc_call(out, relocs, KFUNC_WALLTIME_NS);
                    for r in 1u8..=5u8 {
                        if r == ins.rd {
                            continue;
                        }
                        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
                    }
                    if ins.rd != 0 {
                        out.extend_from_slice(&bpf_mov64_reg(ins.rd, 0));
                    }
                }
                0x0203 => {
                    emit_helper_call_difo(out, HELPER_GET_SMP_PROCESSOR_ID, ins.rd);
                    out.extend_from_slice(&bpf_alu64_imm(BPF_LSH64_IMM, ins.rd, 32));
                    out.extend_from_slice(&bpf_alu64_imm(BPF_RSH64_IMM, ins.rd, 32));
                }
                // User-defined globals (DTrace assigns var_ids ≥ 0x0200
                // for these; the 0x0100 range is the built-in vars
                // matched above). Lower to a hash-map lookup keyed on
                // var_id (4 bytes); missing key reads as zero, matching
                // DTrace's "uninitialized global == 0" semantics.
                _ if var_id >= 0x0200 => {
                    let rd = ins.rd;
                    for r in 1u8..=5u8 {
                        let slot = -32i16 - ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
                    }
                    // key (u32 var_id) at stack -8.
                    out.extend_from_slice(&bpf_mov64_imm(0, var_id as i32));
                    out.extend_from_slice(&bpf_stx_w(10, 0, -8));
                    out.extend_from_slice(&bpf_ld_map_fd(1, super::GLOBAL_MAP_FAKE_FD));
                    out.extend_from_slice(&bpf_mov64_reg(2, 10));
                    out.extend_from_slice(&bpf_alu64_imm(0x07, 2, -8));
                    out.extend_from_slice(&bpf_call(HELPER_MAP_LOOKUP_ELEM));
                    out.extend_from_slice(&bpf_mov64_reg(6, 0)); // stash result ptr
                    for r in 1u8..=5u8 {
                        let slot = -32i16 - ((r as i16 - 1) * 8);
                        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
                    }
                    out.extend_from_slice(&bpf_mov64_imm(rd, 0)); // default 0
                    out.extend_from_slice(&bpf_jeq_imm(6, 0, 1)); // skip load if null
                    out.extend_from_slice(&bpf_ldx_dw(rd, 6, 0)); // *ptr → rd
                }
                _ => return Err(LoweringError::UnsupportedVar { var_id }),
            }
        }

        op @ 0x1c..=0x22 => {
            let (size, signed) = match op {
                0x1c => (1, true),
                0x1d => (2, true),
                0x1e => (4, true),
                0x1f => (1, false),
                0x20 => (2, false),
                0x21 => (4, false),
                0x22 => (8, false),
                _ => unreachable!(),
            };
            out.extend_from_slice(&bpf_stx_dw(10, ins.r1, -152)); // READ_SRC_SAVE_OFF
            for r in 1u8..=5 {
                let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_stx_dw(10, r, slot));
            }
            out.extend_from_slice(&bpf_mov64_reg(1, 10));
            out.extend_from_slice(&bpf_alu64_imm(0x07, 1, -144)); // READ_SCRATCH_BASE
            out.extend_from_slice(&bpf_mov64_imm(2, size));
            out.extend_from_slice(&bpf_ldx_dw(3, 10, -152));
            out.extend_from_slice(&bpf_call(HELPER_PROBE_READ_KERNEL));
            for r in 1u8..=5 {
                if r == ins.rd {
                    continue;
                }
                let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
            }
            let ldx_op: u8 = match size {
                1 => 0x71,
                2 => 0x69,
                4 => 0x61,
                8 => 0x79,
                _ => unreachable!(),
            };
            out.extend_from_slice(&bpf_insn(ldx_op, ins.rd, 10, -144, 0));
            if signed {
                let shift = 64 - (size * 8);
                out.extend_from_slice(&bpf_alu64_imm(BPF_LSH64_IMM, ins.rd, shift));
                out.extend_from_slice(&bpf_alu64_imm(0xc7, ins.rd, shift));
            }
        }

        // STGS — store user-defined global. var_id-keyed hash map,
        // value is the u64 in `rd`. Mirrors STTS (0x2d) but without
        // the pid_tgid mixing — globals are shared across threads.
        0x2a => {
            let var_id = ins.imm16() as i32;
            let rs = ins.rd;
            for r in 1u8..=5u8 {
                let slot = -32i16 - ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_stx_dw(10, r, slot));
            }
            // value at stack -16 (must spill BEFORE we clobber rs).
            out.extend_from_slice(&bpf_stx_dw(10, rs, -16));
            // key (u32 var_id) at stack -8.
            out.extend_from_slice(&bpf_mov64_imm(0, var_id));
            out.extend_from_slice(&bpf_stx_w(10, 0, -8));
            out.extend_from_slice(&bpf_ld_map_fd(1, super::GLOBAL_MAP_FAKE_FD));
            out.extend_from_slice(&bpf_mov64_reg(2, 10));
            out.extend_from_slice(&bpf_alu64_imm(0x07, 2, -8));
            out.extend_from_slice(&bpf_mov64_reg(3, 10));
            out.extend_from_slice(&bpf_alu64_imm(0x07, 3, -16));
            out.extend_from_slice(&bpf_mov64_imm(4, 0)); // BPF_ANY
            out.extend_from_slice(&bpf_call(HELPER_MAP_UPDATE_ELEM));
            for r in 1u8..=5u8 {
                let slot = -32i16 - ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
            }
        }

        0x2d => {
            let var_id = ins.imm16() as i32;
            let rs = ins.rd;
            for r in 1u8..=5u8 {
                let slot = -32i16 - ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_stx_dw(10, r, slot));
            }
            out.extend_from_slice(&bpf_stx_dw(10, rs, -16));
            out.extend_from_slice(&bpf_call(HELPER_GET_CURRENT_PID_TGID));
            out.extend_from_slice(&bpf_alu64_imm(BPF_LSH64_IMM, 0, 32));
            out.extend_from_slice(&bpf_alu64_imm(0x47, 0, var_id));
            out.extend_from_slice(&bpf_stx_dw(10, 0, -24));
            out.extend_from_slice(&bpf_ld_map_fd(1, 300)); // TLS_MAP_FAKE_FD
            out.extend_from_slice(&bpf_mov64_reg(2, 10));
            out.extend_from_slice(&bpf_alu64_imm(0x07, 2, -24));
            out.extend_from_slice(&bpf_mov64_reg(3, 10));
            out.extend_from_slice(&bpf_alu64_imm(0x07, 3, -16));
            out.extend_from_slice(&bpf_mov64_imm(4, 0));
            out.extend_from_slice(&bpf_call(HELPER_MAP_UPDATE_ELEM));
            for r in 1u8..=5u8 {
                let slot = -32i16 - ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
            }
        }

        0x2c => {
            let var_id = ins.imm16() as i32;
            let rd = ins.rd;
            for r in 1u8..=5u8 {
                let slot = -32i16 - ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_stx_dw(10, r, slot));
            }
            out.extend_from_slice(&bpf_call(HELPER_GET_CURRENT_PID_TGID));
            out.extend_from_slice(&bpf_alu64_imm(BPF_LSH64_IMM, 0, 32));
            out.extend_from_slice(&bpf_alu64_imm(0x47, 0, var_id));
            out.extend_from_slice(&bpf_stx_dw(10, 0, -24));
            out.extend_from_slice(&bpf_ld_map_fd(1, 300));
            out.extend_from_slice(&bpf_mov64_reg(2, 10));
            out.extend_from_slice(&bpf_alu64_imm(0x07, 2, -24));
            out.extend_from_slice(&bpf_call(HELPER_MAP_LOOKUP_ELEM));
            out.extend_from_slice(&bpf_mov64_reg(6, 0));
            for r in 1u8..=5u8 {
                let slot = -32i16 - ((r as i16 - 1) * 8);
                out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
            }
            out.extend_from_slice(&bpf_mov64_imm(rd, 0));
            out.extend_from_slice(&bpf_jeq_imm(6, 0, 1));
            out.extend_from_slice(&bpf_ldx_dw(rd, 6, 0));
        }

        // FLUSHTS — flush thread-local storage at end of clause.
        // Our `this->` locals live in eBPF stack scratch (frame
        // automatically reclaimed on probe exit) and STGS globals
        // live in a hash map (no TLS state), so we have nothing
        // meaningful to flush. Emit no instructions.
        0x33 => {}

        _ => {
            return Err(LoweringError::UnsupportedOp {
                op: ins.op,
                mnemonic: ins.mnemonic(),
            });
        }
    }
    Ok(())
}

fn lower_binary(out: &mut Vec<u8>, ebpf_op: u8, r1: u8, r2: u8, rd: u8) {
    if r1 == 0 {
        out.extend_from_slice(&bpf_mov64_imm(rd, 0));
    } else if rd != r1 {
        out.extend_from_slice(&bpf_mov64_reg(rd, r1));
    }
    if r2 == 0 {
        out.extend_from_slice(&bpf_mov64_imm(0, 0));
    }
    out.extend_from_slice(&bpf_insn(ebpf_op, rd, r2, 0, 0));
}

/// True if DIF opcode `op` writes to `ins.rd` (vs reading it or
/// leaving it untouched). Used by `lower_one_state` to clear
/// `state.reg_kind[rd]` before dispatch so SCMP's operand-shape
/// gate doesn't see stale provenance from a prior instruction.
fn writes_rd(op: u8) -> bool {
    matches!(
        op,
        // ALU64 binary (rd = r1 OP r2)
        0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 |
        0x0a | 0x0c | 0x2e |
        // NEG / MOV reg
        0x0d | 0x0e |
        // SETX (load int constant)
        0x25 |
        // SETS (load string literal pointer) — stamps StrLiteralScratch
        0x26 |
        // LDGS (load builtin/global) — may stamp ExecnameScratch
        0x29 |
        // LDTS (load TLS), LDLS (load this->)
        0x2c | 0x38 |
        // LDx loads (signed/unsigned byte/half/word, plus 8-byte)
        0x1c | 0x1d | 0x1e | 0x1f | 0x20 | 0x21 | 0x22
    )
}
