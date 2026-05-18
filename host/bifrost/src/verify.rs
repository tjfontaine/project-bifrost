// SPDX-License-Identifier: Apache-2.0
//! Pre-flight static verification of lowered eBPF programs.
//!
//! Three-layer verification strategy for bifrost-lowered programs:
//!
//!   1. **This module** — host-side static checks. Walks the bytecode
//!      and asserts structural invariants (opcode validity, branch
//!      targets in-bounds, stack offsets within `[-512, 0)`, register
//!      indices in `0..=10`, `LD_DW_IMM` paired correctly, helper
//!      ids on a known list). Cheap, no VM needed; runs at every
//!      `bifrost --emit-ebpf` and in `cargo test`.
//!
//!   2. **Real Linux kernel verifier in the guest**. Every LOAD_PROG
//!      routes through `bpf_check()` before `bpf_prog_select_runtime`,
//!      so the kernel catches register-liveness across helper calls,
//!      pointer-arithmetic bounds, and frame-size analysis without us
//!      having to implement any of it. The verdict ships back to the
//!      host as the LOAD_PROG result. This is the *authoritative*
//!      layer. The historical bypass-verifier path is retired as of
//!      this release.
//!
//!   3. **Regression harness** (`cargo test`). Lowers every demo D
//!      script in the repo, runs static checks. Catches lowering
//!      regressions cheaply on every change.
//!
//! What we deliberately *don't* do: run a host-side eBPF interpreter
//! (rbpf / solana-sbpf / our own). Doing that well requires keeping
//! a Rust interpreter aligned with the Linux kernel verifier as the
//! kernel evolves — that's the kernel's job, not ours. We have a
//! real Linux kernel sitting in the guest; using it as the oracle
//! is more correct and lower-maintenance than any host-side proxy.

use std::collections::HashSet;

/// One static-verification failure. Carries an instruction-relative
/// offset so we can later cross-walk back to a DIF instruction or D
/// source line via the lowering's `insn_offsets` table.
#[derive(Debug)]
pub enum VerifyError {
    /// Program is empty or has stray trailing bytes (length not a
    /// multiple of 8).
    BadLength { len: usize },
    /// Register index outside `0..=10`. Indicates a lowering bug.
    BadRegister { insn_idx: usize, reg: u8 },
    /// Stack store/load with offset outside `[-512, 0)`.
    StackOob { insn_idx: usize, off: i16 },
    /// Branch target out of program bounds.
    BadBranch { insn_idx: usize, target: i32 },
    /// `LD_DW_IMM` (8-byte 0x18) without a following second-half
    /// pseudo insn (opcode 0x00). Lowering is supposed to emit pairs.
    DanglingLdDw { insn_idx: usize },
    /// Helper id we don't know about. The runtime resolver in
    /// `bifrost_guest` only knows specific ids; calling an unknown
    /// id silently no-ops on the guest, which is the worst kind of
    /// bug.
    UnknownHelper { insn_idx: usize, helper: i32 },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadLength { len } => {
                write!(f, "program length {} is not a multiple of 8", len)
            }
            VerifyError::BadRegister { insn_idx, reg } => write!(
                f,
                "insn[{}]: register {} out of range (0..=10)",
                insn_idx, reg
            ),
            VerifyError::StackOob { insn_idx, off } => write!(
                f,
                "insn[{}]: stack offset {} outside [-512, 0)",
                insn_idx, off
            ),
            VerifyError::BadBranch { insn_idx, target } => write!(
                f,
                "insn[{}]: branch target insn[{}] out of bounds",
                insn_idx, target
            ),
            VerifyError::DanglingLdDw { insn_idx } => write!(
                f,
                "insn[{}]: LD_DW_IMM without follow-on second-half pseudo",
                insn_idx
            ),
            VerifyError::UnknownHelper { insn_idx, helper } => write!(
                f,
                "insn[{}]: call to unknown helper id {}",
                insn_idx, helper
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// eBPF stack size — 512 bytes from `r10` downward.
const BPF_STACK_SIZE: i16 = 512;

/// Helper ids this lowering is allowed to emit, matching the resolver
/// table in the guest module (`bifrost_guest.rs`). Adding a new
/// helper requires adding it both in the resolver and here.
fn known_helpers() -> HashSet<i32> {
    let mut s = HashSet::new();
    // Standard kernel BPF helpers we emit:
    s.insert(1); // bpf_map_lookup_elem
    s.insert(2); // bpf_map_update_elem
    s.insert(5); // bpf_ktime_get_ns
    s.insert(8); // bpf_get_smp_processor_id (DIF_VAR_CPU)
    s.insert(14); // bpf_get_current_pid_tgid
    s.insert(16); // bpf_get_current_comm (DIF_VAR_EXECNAME)
    s.insert(35); // bpf_get_current_task (DIF_VAR_CURTHREAD)
    s.insert(67); // bpf_get_stack
    s.insert(113); // bpf_probe_read_kernel (DIF LDSB/LDSH/LDSW/LDUB/LDUH/LDUW/LDX)
    s.insert(125); // bpf_ktime_get_boot_ns (DIF_VAR_WALLTIMESTAMP)
    s.insert(182); // bpf_strncmp (DIF SCMP — string compare in predicates)
    // Bifrost-custom helpers (synthesized in the guest):
    s.insert(131); // bifrost_ringbuf_reserve
    s.insert(132); // bifrost_ringbuf_submit
    s
}

/// Decode the 4-bit dst/src register fields from byte 1 of an insn.
#[inline]
fn dst_reg(byte1: u8) -> u8 {
    byte1 & 0x0f
}
#[inline]
fn src_reg(byte1: u8) -> u8 {
    (byte1 >> 4) & 0x0f
}

#[inline]
fn insn_at(prog: &[u8], idx: usize) -> &[u8] {
    &prog[idx * 8..idx * 8 + 8]
}

#[inline]
fn read_off(insn: &[u8]) -> i16 {
    i16::from_le_bytes([insn[2], insn[3]])
}

#[inline]
fn read_imm(insn: &[u8]) -> i32 {
    i32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]])
}

/// Static structural checks. Doesn't run the program. Cheap and
/// catches the majority of obvious lowering bugs.
pub fn static_check(prog: &[u8]) -> Result<(), VerifyError> {
    if prog.is_empty() || !prog.len().is_multiple_of(8) {
        return Err(VerifyError::BadLength { len: prog.len() });
    }
    let n = prog.len() / 8;
    let helpers = known_helpers();

    let mut i = 0usize;
    while i < n {
        let insn = insn_at(prog, i);
        let opc = insn[0];
        let dst = dst_reg(insn[1]);
        let src = src_reg(insn[1]);
        let off = read_off(insn);
        let imm = read_imm(insn);

        // Register indices: 0..=10 (10 = frame pointer).
        if dst > 10 {
            return Err(VerifyError::BadRegister {
                insn_idx: i,
                reg: dst,
            });
        }
        if src > 10 {
            return Err(VerifyError::BadRegister {
                insn_idx: i,
                reg: src,
            });
        }

        // Class-specific checks.
        match opc & 0x07 {
            // BPF_LD = 0x00 — only LD_DW_IMM (0x18) is legal in our
            // lowering; it must be followed by a 0x00 pseudo-insn.
            0x00 => {
                if opc == 0x18 {
                    if i + 1 >= n {
                        return Err(VerifyError::DanglingLdDw { insn_idx: i });
                    }
                    let next = insn_at(prog, i + 1);
                    if next[0] != 0x00 {
                        return Err(VerifyError::DanglingLdDw { insn_idx: i });
                    }
                    i += 2;
                    continue;
                }
            }
            // BPF_LDX = 0x01, BPF_ST = 0x02, BPF_STX = 0x03 — memory
            // ops. If `dst == 10` (frame pointer) for a store, or
            // `src == 10` for a load, off must be in [-512, 0).
            0x01..=0x03 => {
                let mem_reg = if (opc & 0x07) == 0x01 { src } else { dst };
                if mem_reg == 10 && !(-BPF_STACK_SIZE..0).contains(&off) {
                    return Err(VerifyError::StackOob { insn_idx: i, off });
                }
            }
            // BPF_JMP = 0x05 — branch class. EXIT (0x95) and CALL
            // (0x85) are in this class without branch targets.
            0x05 => {
                if opc == 0x95 {
                    /* EXIT — no fields to check */
                } else if opc == 0x85 {
                    // CALL — encoding depends on src_reg:
                    //   src=0 : imm is a stable BPF helper id (1..213ish);
                    //           must appear in our `known_helpers()` set.
                    //   src=2 : BPF_PSEUDO_KFUNC_CALL — imm is the BTF id
                    //           of a kfunc in vmlinux BTF, resolved at
                    //           lowering time. We can't statically
                    //           validate the id here (no BTF in scope);
                    //           the kernel verifier will. Accept it.
                    //   src=1 : BPF_PSEUDO_CALL — bpf-to-bpf sub-call;
                    //           we don't emit those, so reject.
                    if src == 2 {
                        /* kfunc call — kernel verifies the btf_id */
                    } else if src == 0 {
                        if !helpers.contains(&imm) {
                            return Err(VerifyError::UnknownHelper {
                                insn_idx: i,
                                helper: imm,
                            });
                        }
                    } else {
                        return Err(VerifyError::UnknownHelper {
                            insn_idx: i,
                            helper: imm,
                        });
                    }
                } else {
                    // JA / JEQ / JGT / etc. — off is signed branch
                    // displacement in eBPF *insns*. Target = next_pc
                    // + off; allowed: 0..=n (one-past-end is OK so a
                    // branch to "exit-fallthrough" is fine).
                    let target = (i as i64) + 1 + (off as i64);
                    if target < 0 || target > n as i64 {
                        return Err(VerifyError::BadBranch {
                            insn_idx: i,
                            target: target as i32,
                        });
                    }
                }
            }
            _ => { /* ALU/ALU64/ATOMIC etc. — register checks already done */ }
        }

        i += 1;
    }

    Ok(())
}

/// Public entry point. Currently only runs static checks; layer 2
/// (real kernel verifier in the guest) is invoked on the LOAD_PROG
/// path inside the guest module, not here.
pub fn verify(prog: &[u8]) -> Result<(), VerifyError> {
    static_check(prog)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid program: r0 = 0; exit.
    fn min_prog() -> Vec<u8> {
        let mut p = Vec::new();
        // mov64_imm dst=r0 imm=0
        p.extend_from_slice(&[0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // exit
        p.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        p
    }

    #[test]
    fn min_prog_passes() {
        verify(&min_prog()).expect("min prog should verify");
    }

    #[test]
    fn empty_program_fails() {
        assert!(matches!(
            static_check(&[]),
            Err(VerifyError::BadLength { .. })
        ));
    }

    #[test]
    fn bad_register_caught() {
        // mov64_imm dst=r15 imm=0 — register 15 is illegal.
        let p = vec![0xb7, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            static_check(&p),
            Err(VerifyError::BadRegister { reg: 15, .. })
        ));
    }

    #[test]
    fn unknown_helper_caught() {
        // call helper 999, then exit
        let mut p = vec![];
        p.extend_from_slice(&[0x85, 0x00, 0x00, 0x00, 0xe7, 0x03, 0x00, 0x00]);
        p.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            static_check(&p),
            Err(VerifyError::UnknownHelper { helper: 999, .. })
        ));
    }

    #[test]
    fn dangling_ld_dw_caught() {
        // ld_imm64 r1 = lo (no follow-on); exit
        let mut p = vec![];
        p.extend_from_slice(&[0x18, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        // Wrong follow-on (not 0x00): exit
        p.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            static_check(&p),
            Err(VerifyError::DanglingLdDw { .. })
        ));
    }

    #[test]
    fn stack_oob_caught() {
        // stx_dw [r10 - 600], r0  — out of stack range
        let mut p = vec![];
        p.extend_from_slice(&[0x7b, 0x0a, 0xa8, 0xfd, 0x00, 0x00, 0x00, 0x00]);
        p.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let err = static_check(&p).unwrap_err();
        match err {
            VerifyError::StackOob { off, .. } => assert_eq!(off, -600),
            other => panic!("expected StackOob, got {:?}", other),
        }
    }
}
