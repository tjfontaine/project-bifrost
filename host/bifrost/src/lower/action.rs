// SPDX-License-Identifier: Apache-2.0
use super::LoweringError;
use super::emit::*;
use super::state::LowerState;
use crate::{Action, Dof};

pub fn emit_printf_chain(
    state: &mut LowerState,
    dof: &Dof,
    actions: &[Action],
) -> Result<(), LoweringError> {
    let printf = actions
        .first()
        .ok_or(LoweringError::UnsupportedActionKind { kind: 0 })?;
    let n_args = actions.len();
    let schema = state
        .schema
        .ok_or(LoweringError::UnsupportedActionKind { kind: printf.kind })?;
    if schema.printf_format.is_none() {
        return Err(LoweringError::UnsupportedActionKind { kind: printf.kind });
    }
    let prior_mode = state.ret_mode;
    state.ret_mode = super::RetMode::Predicate;
    for i in 0..n_args {
        let arg_action = if i == 0 { printf } else { &actions[i] };
        let arg_difo = arg_action.difo;
        let field_name = format!("arg{}", i);
        let (offset, _size, is_string_slot) = schema
            .fields
            .iter()
            .enumerate()
            .find_map(|(j, f)| {
                if f.name == field_name {
                    let is_str = matches!(f.kind, crate::schema::FieldKind::String { .. });
                    Some((
                        schema.field_offset(j) as i32,
                        f.kind.record_size() as i32,
                        is_str,
                    ))
                } else {
                    None
                }
            })
            .ok_or(LoweringError::UnsupportedActionKind { kind: printf.kind })?;
        super::lower_difo_by_secidx(state, dof, arg_difo)?;
        // Classify once, then dispatch on category.  PtrComm with a
        // String-typed printf slot takes the 16-byte execname-
        // specific path (re-uses the EXECNAME_SCRATCH_BASE comm
        // buffer at fp-136); every other pointer shape
        // (PtrStrScratch, PtrComm in a u64 slot) drops into the
        // legacy 8-byte deref path.
        let arg_cat = super::category::category_for_difo(dof, arg_difo);
        if is_string_slot && arg_cat == super::category::DifoCategory::PtrComm {
            // ## Why we re-use EXECNAME_SCRATCH_BASE
            //
            // The LDGS-execname lowering above already wrote 16
            // bytes of `task->comm` to fp-136 via
            // `bpf_get_current_comm` and left r0 = fp-136 as a
            // pointer.  Allocating a *fresh* stack slot for the
            // printf-slot copy would force a second
            // `bpf_get_current_comm` and a second 16-byte stack
            // region, and would land us on a verifier path the rest
            // of the bifrost lowering does not exercise.  Re-using
            // the existing fp-136 buffer keeps the program on the
            // same verifier path as the LDGS-pointer form (which
            // the verifier already accepts), so adding String-slot
            // printf args does not enlarge the set of programs the
            // verifier has to certify.
            //
            // Copy 16 bytes via 2× ldx/stx from r0 (fp-136) into
            // the record slot.  r0 holds the source pointer; r1 is
            // a free scratch from this point onward.
            state.body.extend_from_slice(&bpf_ldx_dw(1, 0, 0));
            state
                .body
                .extend_from_slice(&bpf_stx_dw(RB_PTR_REG, 1, offset as i16));
            state.body.extend_from_slice(&bpf_ldx_dw(1, 0, 8));
            state
                .body
                .extend_from_slice(&bpf_stx_dw(RB_PTR_REG, 1, (offset + 8) as i16));
        } else {
            // Legacy 8-byte u64 slot path. Deref 8 bytes when r0
            // is a pointer (PtrComm or PtrStrScratch) so the host
            // renderer's ASCII heuristic can render the bytes.
            // Truncates strings > 8 chars; the String-slot path
            // above avoids that for execname.
            if arg_cat.needs_8byte_deref() {
                state.body.extend_from_slice(&bpf_ldx_dw(0, 0, 0));
            }
            state
                .body
                .extend_from_slice(&bpf_stx_dw(RB_PTR_REG, 0, offset as i16));
        }
    }
    state.ret_mode = prior_mode;
    emit_record_submit(
        &mut state.body,
        &mut state.kfunc_relocs,
        RB_PTR_REG,
        true,
        true,
    );
    state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
    state.body.extend_from_slice(&bpf_exit());
    Ok(())
}

pub fn lower_action_into(
    state: &mut LowerState,
    dof: &Dof,
    action: &Action,
) -> Result<(), LoweringError> {
    match action.kind {
        super::DTRACEACT_DIFEXPR => super::lower_difo_by_secidx(state, dof, action.difo),
        super::DTRACEACT_EXIT => {
            // exit(N) terminates the per-fire BPF program early.
            //
            // The full DTrace semantics ("end the trace, dump aggs,
            // detach, propagate exit code") need consumer-side
            // wiring: a control message to the host CLI's drain loop
            // signaling clean shutdown.  That follow-up lives in
            // the SHM control plane (KIND_EXIT_REQUEST is the
            // natural home — same shape as KIND_AGG_PUSH).  Until
            // it lands, exit(N) here drops the rest of the clause's
            // actions and returns from the BPF prog cleanly.
            //
            // The N argument (action.difo) is intentionally not
            // evaluated yet — once consumer-side support lands, we
            // will lower it into a register and forward through the
            // exit-request marker.  For now, predicate-gated
            // exit() in a clause body still serves the demo's
            // intent: a clause body that wants to "stop processing
            // further actions for this fire" finishes cleanly.
            state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
            state.body.extend_from_slice(&bpf_exit());
            Ok(())
        }
        k if k == super::DTRACEACT_SPECULATE
            || k == super::DTRACEACT_COMMIT
            || k == super::DTRACEACT_DISCARD =>
        {
            // Speculative-tracing actions.  Apple libdtrace
            // emits `speculate(id)` / `commit(id)` / `discard(id)`
            // as dedicated DOF actions; the value DIFO computes
            // the lane id and leaves it in r0.  We move r0 → r1
            // and call the matching kfunc.  Each kfunc is a
            // statement (no record submit) so we end with the
            // standard `r0 = 0; exit` epilogue.
            let kfunc_name = match action.kind {
                k if k == super::DTRACEACT_SPECULATE => super::emit::KFUNC_SPECULATE,
                k if k == super::DTRACEACT_COMMIT => super::emit::KFUNC_COMMIT,
                k if k == super::DTRACEACT_DISCARD => super::emit::KFUNC_DISCARD,
                _ => unreachable!(),
            };
            let prior_mode = state.ret_mode;
            state.ret_mode = super::RetMode::Predicate;
            super::lower_difo_by_secidx(state, dof, action.difo)?;
            state.ret_mode = prior_mode;
            // r1 = lane id
            state.body.extend_from_slice(&bpf_mov64_reg(1, 0));
            super::emit::emit_kfunc_call(&mut state.body, &mut state.kfunc_relocs, kfunc_name);
            state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
            state.body.extend_from_slice(&bpf_exit());
            Ok(())
        }
        k if k == super::DTRACEACT_TRACEMEM || k == super::DTRACEACT_TRACEMEM_DYNSIZE => {
            // `tracemem(addr, len)` — copy `len`
            // bytes from `addr` into the record body. `addr` comes
            // from the value DIFO (puts it in r0); `len` lives in
            // `action.arg` (clamped against the schema's Bytes
            // max_len). The DYNSIZE variant compiles its length
            // arg into the DIFO instead of `arg`; for the host-
            // visible byte count we still cap at the schema-side
            // max, treating action.arg as the upper bound.
            //
            // We use `bpf_probe_read_kernel` (helper 113) rather
            // than `copyin` because DTrace's `tracemem` reads
            // kernel pointers by default. For user pointers the
            // user wires `copyin(addr, len)` first and passes the
            // returned per-CPU scratch pointer as `addr`.
            let schema = state
                .schema
                .ok_or(LoweringError::UnsupportedActionKind { kind: action.kind })?;
            let (offset, max_len) = schema
                .fields
                .iter()
                .enumerate()
                .find_map(|(i, f)| {
                    if f.name == "tracemem" {
                        if let crate::schema::FieldKind::Bytes { max_len } = f.kind {
                            Some((schema.field_offset(i) as i32, max_len))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .ok_or(LoweringError::UnsupportedActionKind { kind: action.kind })?;
            // Apple libdtrace stashes the length in the value
            // DIFO's `rtype_size`; OpenDTrace stashes it in
            // `action.arg`.  Read both, prefer rtype_size, fall
            // back to arg, clamp against the schema's Bytes
            // max_len so the helper-call's size argument fits.
            let mut len_u32 = dof.difo(action.difo).map(|d| d.rtype_size).unwrap_or(0);
            if len_u32 == 0 {
                len_u32 = action.arg as u32;
            }
            let len = len_u32.clamp(1, max_len) as i32;

            // Lower the addr DIFO; r0 = address. PtrComm /
            // PtrStrScratch DIFOs would still leave the pointer
            // in r0 (just to a scratch buffer rather than a raw
            // VA) — bpf_probe_read_kernel handles both fine.
            let prior_mode = state.ret_mode;
            state.ret_mode = super::RetMode::Predicate;
            super::lower_difo_by_secidx(state, dof, action.difo)?;
            state.ret_mode = prior_mode;

            // r3 = addr   (preserve through helper-call clobber)
            state.body.extend_from_slice(&bpf_mov64_reg(3, 0));
            // r1 = record + offset
            state.body.extend_from_slice(&bpf_mov64_reg(1, RB_PTR_REG));
            state
                .body
                .extend_from_slice(&bpf_alu64_imm(0x07, 1, offset));
            // r2 = len
            state.body.extend_from_slice(&bpf_mov64_imm(2, len));
            // bpf_probe_read_kernel(dest, size, src)
            state
                .body
                .extend_from_slice(&bpf_call(super::HELPER_PROBE_READ_KERNEL));

            emit_record_submit(
                &mut state.body,
                &mut state.kfunc_relocs,
                RB_PTR_REG,
                true,
                true,
            );
            state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
            state.body.extend_from_slice(&bpf_exit());
            Ok(())
        }
        super::DTRACEACT_STACK | super::DTRACEACT_USTACK => {
            let (field_name, flags) = if action.kind == super::DTRACEACT_STACK {
                ("kstack", 0)
            } else {
                ("ustack", super::BPF_F_USER_STACK)
            };
            let schema = state
                .schema
                .ok_or(LoweringError::UnsupportedActionKind { kind: action.kind })?;
            let (offset, size) = schema
                .fields
                .iter()
                .enumerate()
                .find_map(|(i, f)| {
                    if f.name == field_name {
                        Some((schema.field_offset(i) as i32, f.kind.record_size() as i32))
                    } else {
                        None
                    }
                })
                .ok_or(LoweringError::UnsupportedActionKind { kind: action.kind })?;

            state.body.extend_from_slice(&bpf_mov64_reg(1, CTX_REG));
            state.body.extend_from_slice(&bpf_mov64_reg(2, RB_PTR_REG));
            state
                .body
                .extend_from_slice(&bpf_alu64_imm(0x07, 2, offset));
            state.body.extend_from_slice(&bpf_mov64_imm(3, size));
            state.body.extend_from_slice(&bpf_mov64_imm(4, flags));
            state.body.extend_from_slice(&bpf_call(HELPER_GET_STACK));

            if action.kind == super::DTRACEACT_USTACK && state.gustack_kfuncs_available {
                state.needs_vma_table_emit = true;
            }
            if action.kind == super::DTRACEACT_USTACK
                && state.gustack_kfuncs_available
                && let Some((exe_offset, exe_len)) =
                    schema.fields.iter().enumerate().find_map(|(i, f)| {
                        if f.name == "exe_path" {
                            Some((schema.field_offset(i) as i32, f.kind.record_size() as i32))
                        } else {
                            None
                        }
                    })
            {
                state.body.extend_from_slice(&bpf_mov64_reg(1, RB_PTR_REG));
                state
                    .body
                    .extend_from_slice(&bpf_alu64_imm(0x07, 1, exe_offset));
                state.body.extend_from_slice(&bpf_mov64_imm(2, exe_len));
                emit_kfunc_call(&mut state.body, &mut state.kfunc_relocs, KFUNC_EXE_PATH);
            }

            emit_record_submit(
                &mut state.body,
                &mut state.kfunc_relocs,
                RB_PTR_REG,
                true,
                true,
            );
            state.body.extend_from_slice(&bpf_mov64_imm(0, 0));
            state.body.extend_from_slice(&bpf_exit());
            Ok(())
        }
        _ => Err(LoweringError::UnsupportedActionKind { kind: action.kind }),
    }
}
