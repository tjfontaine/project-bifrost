// SPDX-License-Identifier: Apache-2.0
#[cfg(test)]
mod tests {
    use crate::lower::category::{DifoCategory, category_for_difo};
    use crate::lower::*;
    use crate::schema::{Field, FieldKind, RecordSchema};

    #[test]
    fn category_needs_8byte_deref_table() {
        // Truth table — keep these literal so a regression to
        // "scalar must deref" or "ptr_comm must not" surfaces here
        // before it ever lowers.
        assert!(!DifoCategory::Scalar.needs_8byte_deref());
        assert!(DifoCategory::PtrComm.needs_8byte_deref());
        assert!(DifoCategory::PtrStrScratch.needs_8byte_deref());
    }

    #[test]
    fn category_variants_distinct() {
        // Variants must not collapse — equality is load-bearing
        // for action.rs's `cat == PtrComm` dispatch site.
        assert_ne!(DifoCategory::Scalar, DifoCategory::PtrComm);
        assert_ne!(DifoCategory::Scalar, DifoCategory::PtrStrScratch);
        assert_ne!(DifoCategory::PtrComm, DifoCategory::PtrStrScratch);
    }

    // Note: opcode-scanning behavior of `category_for_difo` is
    // exercised end-to-end via the wrapper_golden + postgres-USDT
    // demo paths; constructing a synthetic Dof here would require
    // hand-rolling the DOF-section format, which is its own
    // adventure.  The legacy predicates `is_execname_difo` and
    // `is_string_literal_difo` already had no unit tests for the
    // same reason; the category function inherits that posture.
    #[test]
    fn category_for_difo_is_pub() {
        // Compile-time check that the function is callable from
        // tests; the actual behavior is exercised end-to-end.
        let _ = category_for_difo;
    }

    /// Confirm the time / string DIF dispatch paths register the
    /// expected kfunc names so the BFR7 reloc pass at LOAD_PROG
    /// time resolves them against the running kernel's vmlinux
    /// BTF.  Each test lowers a single instruction and asserts
    /// the kfunc_relocs vec collects the right name.
    fn lower_one(op: u8, rd: u8, r1: u8, r2: u8) -> LowerState<'static> {
        let raw = ((op as u32) << 24) | ((r1 as u32) << 16) | ((r2 as u32) << 8) | (rd as u32);
        let ins = crate::DifInstr::decode(raw);
        let mut state = LowerState::new(None, None);
        crate::lower::dif::lower_one_state(&mut state, ins, 0)
            .expect("lower_one_state should accept the new opcodes");
        state
    }

    #[test]
    fn dif_vtimestamp_routes_to_kfunc() {
        // op=0x29 (LDGS) with imm16=0x0102 = DIF_VAR_VTIMESTAMP.
        let state = lower_one(0x29, /*rd=*/ 3, /*r1=*/ 0x01, /*r2=*/ 0x02);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_VTIMESTAMP_NS),
            "expected KFUNC_VTIMESTAMP_NS in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_walltimestamp_routes_to_kfunc() {
        // op=0x29 (LDGS) with imm16=0x011a is DIF_VAR_WALLTIMESTAMP.
        // imm16 lives in (r1,r2) — set r1=0x01, r2=0x1a.
        let state = lower_one(0x29, /*rd=*/ 3, /*r1=*/ 0x01, /*r2=*/ 0x1a);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_WALLTIME_NS),
            "expected KFUNC_WALLTIME_NS in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_progenyof_routes_to_kfunc() {
        // op=0x2f (CALL) with subr=11 (DIF_SUBR_PROGENYOF).
        let state = lower_one(0x2f, /*rd=*/ 3, /*r1=*/ 0x00, /*r2=*/ 11);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_PROGENYOF),
            "expected KFUNC_PROGENYOF in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_strlen_routes_to_kfunc() {
        // op=0x2f (CALL) with subr=12 (DIF_SUBR_STRLEN).
        let state = lower_one(0x2f, /*rd=*/ 3, /*r1=*/ 0x00, /*r2=*/ 12);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_STRLEN),
            "expected KFUNC_STRLEN in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_strchr_routes_to_kfunc() {
        // op=0x2f (CALL) with subr=28 (DIF_SUBR_STRCHR).
        let state = lower_one(0x2f, /*rd=*/ 3, /*r1=*/ 0x00, /*r2=*/ 28);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_STRCHR),
            "expected KFUNC_STRCHR in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_strstr_routes_to_kfunc() {
        let state = lower_one(0x2f, 3, 0x00, 30);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&super::super::emit::KFUNC_STRSTR));
    }

    #[test]
    fn dif_index_routes_to_kfunc() {
        let state = lower_one(0x2f, 3, 0x00, 33);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&super::super::emit::KFUNC_INDEX));
    }

    #[test]
    fn dif_strjoin_routes_to_kfunc() {
        let state = lower_one(0x2f, 3, 0x00, 23);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&super::super::emit::KFUNC_STRJOIN));
    }

    #[test]
    fn dif_substr_routes_to_kfunc() {
        let state = lower_one(0x2f, 3, 0x00, 32);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&super::super::emit::KFUNC_SUBSTR));
    }

    #[test]
    fn dif_copyin_routes_to_kfunc() {
        // op=0x2f (CALL) with subr=8 (DIF_SUBR_COPYIN).
        let state = lower_one(0x2f, /*rd=*/ 3, /*r1=*/ 0x00, /*r2=*/ 8);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_COPYIN),
            "expected KFUNC_COPYIN in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_strrchr_routes_to_kfunc() {
        // op=0x2f (CALL) with subr=29 (DIF_SUBR_STRRCHR).
        let state = lower_one(0x2f, /*rd=*/ 3, /*r1=*/ 0x00, /*r2=*/ 29);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_STRRCHR),
            "expected KFUNC_STRRCHR in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn dif_copyinstr_routes_to_kfunc() {
        // op=0x2f (CALL) with subr=9 (DIF_SUBR_COPYINSTR).
        let state = lower_one(0x2f, /*rd=*/ 3, /*r1=*/ 0x00, /*r2=*/ 9);
        let names: Vec<&str> = state.kfunc_relocs.iter().map(|(_, n)| *n).collect();
        assert!(
            names.contains(&super::super::emit::KFUNC_COPYINSTR),
            "expected KFUNC_COPYINSTR in relocs, got {:?}",
            names
        );
    }

    #[test]
    fn test_bpf_insn_layout() {
        // mov64 r1, 42 -> 0xb7 0x01 0x00 0x00 0x2a 0x00 0x00 0x00
        let insn = bpf_insn(0xb7, 1, 0, 0, 42);
        assert_eq!(insn, [0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_branch_fixup() {
        let mut state = LowerState::new(None, None);
        // 0: mov r1, 1
        state.body.extend_from_slice(&bpf_mov64_imm(1, 1));
        state.insn_offsets.push(0);
        // 1: ja +0 (placeholder) -> should point to index 4
        let ja = bpf_ja(0);
        state.insn_offsets.push(8);
        emit_branch_placeholder(&mut state, ja, 4);
        // 2: mov r1, 2
        state.insn_offsets.push(16);
        state.body.extend_from_slice(&bpf_mov64_imm(1, 2));
        // 3: mov r1, 3
        state.insn_offsets.push(24);
        state.body.extend_from_slice(&bpf_mov64_imm(1, 3));
        // 4: exit
        state.insn_offsets.push(32);
        state.body.extend_from_slice(&bpf_exit());
        // final offset
        state.insn_offsets.push(40);

        fixup_branches(&mut state).unwrap();

        // The branch at byte 8 (index 1) should jump to byte 32 (index 4).
        // slot_off = (32 - 8 - 8) / 8 = 16 / 8 = 2.
        assert_eq!(state.body[10..12], 2i16.to_le_bytes());
    }

    /// Pack a DIF instruction `(op, r1, r2, rd)` into a `DifInstr`.
    /// Mirrors the wire layout: `[op << 24 | r1 << 16 | r2 << 8 | rd]`.
    fn dif(op: u8, r1: u8, r2: u8, rd: u8) -> crate::DifInstr {
        let raw = ((op as u32) << 24) | ((r1 as u32) << 16) | ((r2 as u32) << 8) | rd as u32;
        crate::DifInstr::decode(raw)
    }

    /// Pack a DIF instruction that uses imm16 in (r1, r2): high byte
    /// in r1, low byte in r2.
    fn dif_imm16(op: u8, imm16: u16, rd: u8) -> crate::DifInstr {
        let r1 = (imm16 >> 8) as u8;
        let r2 = (imm16 & 0xff) as u8;
        dif(op, r1, r2, rd)
    }

    /// Two SETS in one program must use distinct scratch slots,
    /// not alias into a single fixed region.
    #[test]
    fn sets_two_instances_use_distinct_scratch() {
        use crate::lower::dif::lower_one_state;
        // strtab: "redis\0postgres\0"
        let strtab = b"redis\0postgres\0".to_vec();
        let mut state = LowerState::new_with_strtab(None, None, Some(strtab));

        // SETS instance 0: rd=1, imm16=0 ("redis").
        lower_one_state(&mut state, dif_imm16(0x26, 0, 1), 0).expect("first SETS lowers");
        // SETS instance 1: rd=2, imm16=6 ("postgres").
        lower_one_state(&mut state, dif_imm16(0x26, 6, 2), 1).expect("second SETS lowers");

        assert_eq!(state.sets_instance_count, 2);
        // The two SETS pointer-loads should target distinct slots:
        // body must contain `r10 + (-344)` AND `r10 + (-360)` — i.e.
        // the ALU64 imm fields of the final ALU instruction in each
        // emission. We look for the LE-encoded imm values.
        let body = &state.body;
        let mut found_344 = false;
        let mut found_360 = false;
        for window in body.chunks_exact(8) {
            let imm = i32::from_le_bytes([window[4], window[5], window[6], window[7]]);
            if imm == -344 {
                found_344 = true;
            }
            if imm == -360 {
                found_360 = true;
            }
        }
        assert!(found_344, "first SETS should target slot 0 at -344");
        assert!(found_360, "second SETS should target slot 1 at -360");
    }

    /// More than SETS_INSTANCE_SLOTS literals must refuse rather
    /// than alias into a previously-used slot.
    #[test]
    fn sets_overflow_rejects_with_typed_error() {
        use crate::lower::dif::lower_one_state;
        use crate::lower::state::SETS_INSTANCE_SLOTS;
        let strtab = b"a\0b\0c\0d\0e\0".to_vec();
        let mut state = LowerState::new_with_strtab(None, None, Some(strtab));
        // Push exactly SETS_INSTANCE_SLOTS successful SETS, then expect
        // the next to fail.
        for n in 0..SETS_INSTANCE_SLOTS {
            let imm = (n * 2) as u16;
            lower_one_state(&mut state, dif_imm16(0x26, imm, 1), n).expect("under-cap SETS lowers");
        }
        let imm = (SETS_INSTANCE_SLOTS * 2) as u16;
        match lower_one_state(&mut state, dif_imm16(0x26, imm, 1), SETS_INSTANCE_SLOTS) {
            Err(LoweringError::SetsScratchExhausted { count, cap }) => {
                assert_eq!(cap, SETS_INSTANCE_SLOTS);
                assert_eq!(count, SETS_INSTANCE_SLOTS + 1);
            }
            other => panic!("expected SetsScratchExhausted, got {:?}", other),
        }
    }

    /// SCMP requires execname-shape operands. Without a prior
    /// LDGS(execname) / SETS to stamp reg_kind, SCMP must reject.
    #[test]
    fn scmp_without_stamped_operands_rejects() {
        use crate::lower::dif::lower_one_state;
        let mut state = LowerState::new(None, None);
        // SCMP r1, r2 -- both registers Unknown.
        match lower_one_state(&mut state, dif(0x27, 1, 2, 0), 0) {
            Err(LoweringError::ScmpUnsupportedShape { r1_kind, r2_kind }) => {
                assert_eq!(r1_kind, "<unknown>");
                assert_eq!(r2_kind, "<unknown>");
            }
            other => panic!("expected ScmpUnsupportedShape, got {:?}", other),
        }
    }

    /// SCMP accepts when one operand is execname and the other is
    /// a SETS string literal — the canonical predicate shape.
    #[test]
    fn scmp_execname_vs_setstring_accepts() {
        use crate::lower::dif::lower_one_state;
        let strtab = b"redis\0".to_vec();
        let mut state = LowerState::new_with_strtab(None, None, Some(strtab));
        // LDGS execname -> r1 (var_id 0x0118).
        lower_one_state(&mut state, dif_imm16(0x29, 0x0118, 1), 0).expect("LDGS execname lowers");
        // SETS "redis" -> r2.
        lower_one_state(&mut state, dif_imm16(0x26, 0, 2), 1).expect("SETS lowers");
        // SCMP r1, r2 — should accept.
        lower_one_state(&mut state, dif(0x27, 1, 2, 0), 2).expect("execname-shape SCMP accepts");
        // pending_cmp must be set so a downstream BCEQ consumes it.
        assert!(state.pending_cmp.is_some());
    }

    #[test]
    fn test_correlation_fields() {
        let schema = RecordSchema {
            fields: vec![
                Field {
                    name: "vmid".into(),
                    kind: FieldKind::U32,
                },
                Field {
                    name: "gns".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "other".into(),
                    kind: FieldKind::U64,
                },
            ],
            printf_format: None,
        };
        let mut out = Vec::new();
        fill_correlation_fields(&mut out, &schema, 123);
        // vmid: call 8, stx_w [rb+0]
        // gns: call 5, stx_dw [rb+4]
        // 4 instructions total
        assert_eq!(out.len(), 4 * 8);
    }
}
