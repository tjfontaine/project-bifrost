// DOF-introspection helpers used by the bifrost CLI to decide which
// RecordSchema (printf, ustack, kernel-stack, default-trace) a given
// program should emit, and whether it requires the shared TLS or
// global-storage maps.
//
// All functions inspect a parsed DOF and return scalar/structured
// answers — no side effects, no I/O.  Tests for this module live
// alongside; they're macOS-gated because the parent crate gates DOF
// machinery (which depends on libdtrace headers) the same way.

#![cfg(target_os = "macos")]

use crate::Dof;
use crate::lower::{DTRACEACT_STACK, DTRACEACT_USTACK, is_agg_action};
use crate::schema::RecordSchema;

/// True when this clause's action chain is an aggregation. libdtrace
/// shapes:
///   unkeyed `@ = ...;`   → [DIFEXPR(value), AGG]            (agg @ idx 1)
///   1-key `@[k] = ...;`  → [DIFEXPR(value), DIFEXPR(key), AGG] (agg @ idx 2)
/// Search for the AGG action anywhere in the chain after position 0.
pub fn is_aggregation_program(dof: &Dof) -> bool {
    if let Some(ecb) = dof.first_ecb() {
        let actions = dof.actions_in_chain(ecb.actions);
        if actions
            .iter()
            .enumerate()
            .any(|(i, a)| i >= 1 && is_agg_action(a.kind))
        {
            return true;
        }
    }
    false
}

/// Walk every DIF section and check for LDTS (0x2c) or STTS (0x2d)
/// — the thread-local load/store opcodes. Used by the runner to
/// decide whether to declare the shared TLS HASH map for this
/// clause's wrapper. The guest dedupes by fake_fd so only one map
/// is allocated for the whole run regardless of how many clauses
/// declare it.
pub fn program_uses_tls(dof: &Dof) -> bool {
    use crate::SectKind;
    for (_, dif_sec) in dof.sections_of(SectKind::Dif) {
        for ins in dof.dif_instructions(dif_sec) {
            if ins.op == 0x2c || ins.op == 0x2d {
                return true;
            }
        }
    }
    false
}

/// Detect user-defined global storage references in any DIF section.
/// Triggers on:
///   - 0x2a (STGS): any user-global write — built-in globals are
///     read-only so STGS always implies a user-defined slot.
///   - 0x29 (LDGS) with var_id ≥ 0x0200: built-in vars (timestamp,
///     curtask, arg0..arg9, pid, tid, execname) live in 0x0100-range
///     and are lowered directly to BPF helpers; var_ids ≥ 0x0200 are
///     user-defined and need the GLOBAL_MAP for backing storage.
pub fn program_uses_globals(dof: &Dof) -> bool {
    use crate::SectKind;
    for (_, dif_sec) in dof.sections_of(SectKind::Dif) {
        for ins in dof.dif_instructions(dif_sec) {
            if ins.op == 0x2a {
                return true;
            }
            if ins.op == 0x29 && ins.imm16() >= 0x0200 {
                return true;
            }
        }
    }
    false
}

pub fn pick_schema(dof: &Dof) -> RecordSchema {
    pick_schema_for_action(dof, 0)
}

/// Schema for the program emitted to handle action[`action_idx`] of
/// the first ECB. The multi-action fan-out (one program per
/// non-aggregating action) needs each program to carry a schema
/// tuned to its action — a USTACK action after a DIFEXPR can't
/// reuse the DIFEXPR's `default_trace` schema because it has no
/// `ustack` field for the lowering to write into.
pub fn pick_schema_for_action(dof: &Dof, action_idx: usize) -> RecordSchema {
    use crate::lower::{DTRACEACT_PRINTF, DTRACEACT_TRACEMEM, DTRACEACT_TRACEMEM_DYNSIZE};
    if let Some(ecb) = dof.first_ecb() {
        let actions = dof.actions_in_chain(ecb.actions);
        if let Some(action) = actions.get(action_idx) {
            return match action.kind {
                k if k == DTRACEACT_STACK => RecordSchema::for_kernel_stack(32),
                k if k == DTRACEACT_USTACK => RecordSchema::for_user_stack(32),
                k if k == DTRACEACT_TRACEMEM || k == DTRACEACT_TRACEMEM_DYNSIZE => {
                    // Apple's libdtrace stashes the tracemem length
                    // in the value DIFO's return-type size
                    // (`dtdt_size`), not in `action.arg`.  Clamp to
                    // a sane record-size ceiling — TRACEMEM_MAX
                    // matches OpenDTrace's stable 4 KiB limit (one
                    // record shouldn't exceed the SHMEM ringbuf's
                    // per-record cap).
                    const TRACEMEM_MAX: u32 = 4096;
                    let mut len = dof.difo(action.difo).map(|d| d.rtype_size).unwrap_or(0);
                    // Fallback to `action.arg` for the OpenDTrace
                    // encoding so the same lowering works on a
                    // future host shipping the OpenDTrace
                    // userland.
                    if len == 0 {
                        len = action.arg as u32;
                    }
                    let max_len = len.clamp(1, TRACEMEM_MAX);
                    RecordSchema::for_tracemem(max_len)
                }
                k if k == DTRACEACT_PRINTF => {
                    // For printf, the format string lives in the
                    // strtab section indexed by action.strtab; arg
                    // count is the number of actions in the chain
                    // (DTrace emits PRINTF + N-1 DIFEXPR continuations
                    // for a printf with N args; ntuple in the action
                    // descriptor is the agg-tuple count, not the
                    // printf arg count).
                    let fmt = read_strtab_string(dof, action.strtab, action.arg as usize)
                        .unwrap_or_else(|| String::from("(printf format unavailable)"));
                    let n_args = actions.len();
                    // Widen execname args from u64 → 16-byte String
                    // slot so the full TASK_COMM_LEN comm bytes
                    // round-trip. Without this, names >8 chars
                    // (redis-server, kube-apiserver, dockerd-init,
                    // etc.) truncate at the first 8 bytes.
                    let string_arg_indices: Vec<usize> = actions
                        .iter()
                        .enumerate()
                        .filter_map(|(i, a)| {
                            if crate::lower::agg::is_execname_difo(dof, a.difo) {
                                Some(i)
                            } else {
                                None
                            }
                        })
                        .collect();
                    RecordSchema::for_printf_with_string_args(&fmt, n_args, &string_arg_indices)
                }
                _ => RecordSchema::default_trace(),
            };
        }
    }
    RecordSchema::default_trace()
}

pub fn read_strtab_string(dof: &Dof, sec_idx: u32, offset: usize) -> Option<String> {
    use crate::SectKind;
    let sec = dof.sections.get(sec_idx as usize)?;
    if sec.kind != SectKind::StrTab {
        return None;
    }
    let bytes = dof.section_bytes(sec);
    if offset >= bytes.len() {
        return None;
    }
    let nul = bytes[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(bytes.len() - offset);
    std::str::from_utf8(&bytes[offset..offset + nul])
        .ok()
        .map(|s| s.to_string())
}
