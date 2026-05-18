// SPDX-License-Identifier: Apache-2.0

// eBPF opcodes (linux/bpf.h subset)
pub const BPF_LD_IMM_DW_LO: u8 = 0x18; // BPF_LD | BPF_DW | BPF_IMM
pub const BPF_LD_IMM_DW_HI: u8 = 0x00;
pub const BPF_MOV64_IMM: u8 = 0xb7; // BPF_ALU64 | BPF_K  | BPF_MOV
pub const BPF_MOV64_REG: u8 = 0xbf; // BPF_ALU64 | BPF_X  | BPF_MOV
pub const BPF_CALL: u8 = 0x85;
pub const BPF_JEQ_IMM: u8 = 0x15;
pub const BPF_STX_W: u8 = 0x63;
pub const BPF_STX_DW: u8 = 0x7b;
pub const BPF_EXIT: u8 = 0x95;

// 64-bit ALU register-source ops (BPF_ALU64 | BPF_X | BPF_OP):
pub const BPF_ADD64_REG: u8 = 0x0f;
pub const BPF_SUB64_REG: u8 = 0x1f;
pub const BPF_MUL64_REG: u8 = 0x2f;
pub const BPF_DIV64_REG: u8 = 0x3f; // unsigned
pub const BPF_OR64_REG: u8 = 0x4f;
pub const BPF_AND64_REG: u8 = 0x5f;
pub const BPF_LSH64_REG: u8 = 0x6f;
pub const BPF_RSH64_REG: u8 = 0x7f; // logical
pub const BPF_MOD64_REG: u8 = 0x9f;
pub const BPF_XOR64_REG: u8 = 0xaf;
pub const BPF_ARSH64_REG: u8 = 0xcf; // arithmetic right shift

// 64-bit ALU immediate ops (BPF_ALU64 | BPF_K | BPF_OP):
pub const BPF_LSH64_IMM: u8 = 0x67;
pub const BPF_RSH64_IMM: u8 = 0x77;

// Loads: BPF_LDX | BPF_DW | BPF_MEM = 0x79  (rd = *(u64*)(src + off))
pub const BPF_LDX_DW: u8 = 0x79;

// Conditional jumps, register-source form (BPF_JMP | BPF_X | BPF_OP):
pub const BPF_JEQ_REG: u8 = 0x1d;
pub const BPF_JNE_REG: u8 = 0x5d;
pub const BPF_JGT_REG: u8 = 0x2d; // unsigned >
pub const BPF_JGE_REG: u8 = 0x3d; // unsigned >=
pub const BPF_JLT_REG: u8 = 0xad; // unsigned <
pub const BPF_JLE_REG: u8 = 0xbd; // unsigned <=
pub const BPF_JSGT_REG: u8 = 0x6d; // signed >
pub const BPF_JSGE_REG: u8 = 0x7d; // signed >=
pub const BPF_JSLT_REG: u8 = 0xcd; // signed <
pub const BPF_JSLE_REG: u8 = 0xdd; // signed <=
// Conditional jumps, immediate form (BPF_JMP | BPF_K | BPF_OP):
pub const BPF_JNE_IMM: u8 = 0x55;
pub const BPF_JGT_IMM: u8 = 0x25;
pub const BPF_JGE_IMM: u8 = 0x35;
pub const BPF_JLT_IMM: u8 = 0xa5;
pub const BPF_JLE_IMM: u8 = 0xb5;
pub const BPF_JSGT_IMM: u8 = 0x65;
pub const BPF_JSGE_IMM: u8 = 0x75;
pub const BPF_JSLT_IMM: u8 = 0xc5;
pub const BPF_JSLE_IMM: u8 = 0xd5;
// Unconditional jump:
pub const BPF_JA: u8 = 0x05;

pub const BPF_PSEUDO_MAP_FD: u8 = 1; // src_reg sentinel for map-fd LD_IMM64
pub const BPF_PSEUDO_KFUNC_CALL: u8 = 2;

pub const HELPER_KTIME_GET_NS: i32 = 5;
pub const HELPER_GET_SMP_PROCESSOR_ID: i32 = 8;
pub const HELPER_GET_CURRENT_PID_TGID: i32 = 14;
pub const HELPER_GET_CURRENT_COMM: i32 = 16;
pub const HELPER_GET_CURRENT_TASK: i32 = 35;
pub const HELPER_KTIME_GET_BOOT_NS: i32 = 125;
pub const HELPER_PROBE_READ_KERNEL: i32 = 113;
pub const HELPER_MAP_LOOKUP_ELEM: i32 = 1;
pub const HELPER_MAP_UPDATE_ELEM: i32 = 2;

pub const RINGBUF_FAKE_FD: i32 = 100;
pub const HELPER_RINGBUF_RESERVE: i32 = 131;
pub const HELPER_RINGBUF_SUBMIT: i32 = 132;
pub const HELPER_GET_STACK: i32 = 67;
/// `bpf_strncmp(const char *s1, u32 s1_sz, const char *s2)` —
/// returns 0 iff s1[..s1_sz] equals s2 up to the first NUL.
/// Used by the DIF SCMP (string-compare) opcode lowering.
/// Available since Linux 5.17 (BPF_FUNC_strncmp = 182).
pub const HELPER_STRNCMP: i32 = 182;

pub const RB_PTR_REG: u8 = 9;
pub const CTX_REG: u8 = 8;

pub const LDGS_SCRATCH_BASE: i16 = -120;

/// Pack a single 8-byte eBPF instruction. Layout (little-endian):
///   [0]   code
///   [1]   src_reg<<4 | dst_reg   (each register is 4 bits)
///   [2-3] s16 off (LE)
///   [4-7] s32 imm (LE)
pub fn bpf_insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = code;
    out[1] = ((src & 0x0f) << 4) | (dst & 0x0f);
    out[2..4].copy_from_slice(&off.to_le_bytes());
    out[4..8].copy_from_slice(&imm.to_le_bytes());
    out
}

/// `r{dst} = imm64`, encoded as the eBPF wide-immediate two-slot form.
pub fn bpf_ld_imm64(dst: u8, imm: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    let lo = bpf_insn(BPF_LD_IMM_DW_LO, dst, 0, 0, imm as u32 as i32);
    let hi = bpf_insn(BPF_LD_IMM_DW_HI, 0, 0, 0, (imm >> 32) as u32 as i32);
    out[..8].copy_from_slice(&lo);
    out[8..].copy_from_slice(&hi);
    out
}

pub fn bpf_mov64_reg(dst: u8, src: u8) -> [u8; 8] {
    bpf_insn(BPF_MOV64_REG, dst, src, 0, 0)
}

pub fn bpf_mov64_imm(dst: u8, imm: i32) -> [u8; 8] {
    bpf_insn(BPF_MOV64_IMM, dst, 0, 0, imm)
}

pub fn bpf_call(helper_id: i32) -> [u8; 8] {
    bpf_insn(BPF_CALL, 0, 0, 0, helper_id)
}

/// Canonical kfunc names. The guest worker resolves these to btf_ids
/// against the running kernel's vmlinux BTF at LOAD_PROG time
/// (BFR7 protocol) — replaces the BFR6-era practice of baking btf_ids
/// at CLI compile time, which kept getting out of sync when the kernel
/// was rebuilt.
pub const KFUNC_SHMEM_RESERVE: &str = "bifrost_kfunc_shmem_reserve";
pub const KFUNC_SHMEM_SUBMIT: &str = "bifrost_kfunc_shmem_submit";
pub const KFUNC_SHMEM_KICK: &str = "bifrost_kfunc_shmem_kick";
pub const KFUNC_EXE_PATH: &str = "bifrost_kfunc_current_exe_path";
pub const KFUNC_VMA_TABLE: &str = "bifrost_kfunc_emit_vma_table";
pub const KFUNC_VMA_PUBLISH: &str = "bifrost_kfunc_publish_vma_table";
/// Real wall-clock time. Calls `ktime_get_real_ns()` (CLOCK_REALTIME
/// since the epoch), distinct from `bpf_ktime_get_boot_ns` (which is
/// monotonic since boot).
pub const KFUNC_WALLTIME_NS: &str = "bifrost_kfunc_walltime_ns";
/// Probe-context virtual time. The kfunc currently aliases
/// `ktime_get_ns()` so scripts using `vtimestamp` parse, lower,
/// and execute without breakage; proper per-thread delta tracking
/// (a per-CPU `pid_tgid`-keyed map that captures entry time on
/// probe entry and reports the running sum) is open work in
/// `docs/dtrace-roadmap.md`. The dedicated kfunc keeps the upgrade
/// path purely internal: no wire format or host renderer change.
pub const KFUNC_VTIMESTAMP_NS: &str = "bifrost_kfunc_vtimestamp_ns";
/// `progenyof(pid)`. Walks `current->real_parent` up the ancestor
/// chain to init; returns 1 if `pid` is current or any ancestor of
/// current, 0 otherwise.
pub const KFUNC_PROGENYOF: &str = "bifrost_kfunc_progenyof";
/// `strlen(s)`. Reads up to a fixed cap from `s` via
/// `bpf_probe_read_user_str`; returns the strlen, not including NUL.
pub const KFUNC_STRLEN: &str = "bifrost_kfunc_strlen";
/// `copyinstr(uaddr)`. Bounded copy of a NUL-terminated user string
/// into a per-CPU scratch buffer; returns the pointer to the scratch
/// (caller treats as `string`). The pointer is reused across calls
/// in the same probe.
pub const KFUNC_COPYINSTR: &str = "bifrost_kfunc_copyinstr";
/// `strchr(s, c)`. Returns a pointer to the first occurrence of `c`
/// in user-string `s`, or NULL if not found. The result points into
/// the same per-CPU scratch buffer `copyinstr` uses.
pub const KFUNC_STRCHR: &str = "bifrost_kfunc_strchr";
/// `strrchr(s, c)`. Same as `strchr` but returns the last
/// occurrence rather than the first.
pub const KFUNC_STRRCHR: &str = "bifrost_kfunc_strrchr";
/// `copyin(uaddr, len)`. Bounded byte copy from user memory into a
/// per-CPU scratch buffer; returns a pointer to the scratch BPF
/// programs use as a generic byte blob (e.g. for `tracemem`).
/// Distinct from `copyinstr` in that it does not stop at NUL and
/// the length is explicit.
pub const KFUNC_COPYIN: &str = "bifrost_kfunc_copyin";
/// `strstr(haystack, needle)`. Both args are user pointers to
/// NUL-terminated strings. Returns a kernel pointer to the first
/// occurrence of `needle` in `haystack` (in the haystack's per-CPU
/// scratch copy), or NULL.
pub const KFUNC_STRSTR: &str = "bifrost_kfunc_strstr";
/// `index(haystack, needle)`. Like `strstr` but returns the
/// zero-based byte offset (or -1 if not found).
pub const KFUNC_INDEX: &str = "bifrost_kfunc_index";
/// `strjoin(a, b)`. Concatenates two user strings into a per-CPU
/// scratch buffer; returns the pointer. Total length bounded by
/// `BIFROST_STR_MAX`.
pub const KFUNC_STRJOIN: &str = "bifrost_kfunc_strjoin";
/// `substr(s, idx, len)`. Returns a per-CPU scratch pointer holding
/// `len` bytes of `s` starting at `idx`. Out-of-range indices clamp;
/// `len < 0` is treated as 0 length.
pub const KFUNC_SUBSTR: &str = "bifrost_kfunc_substr";
/// `speculation()` returns a speculation id (protocol-level
/// placeholder). Today returns 1 (single conceptual lane) so
/// scripts that call `speculate(speculation())` parse + lower +
/// load.  True per-lane side-buffer routing (records go into a
/// discardable lane until `commit()` promotes them) is open work.
pub const KFUNC_SPECULATION: &str = "bifrost_kfunc_speculation";
/// `speculate(id)` flags subsequent record reservations to route
/// into lane `id`'s side buffer (protocol-level placeholder). Today
/// a no-op — records still emit to the principal sub-ring.
pub const KFUNC_SPECULATE: &str = "bifrost_kfunc_speculate";
/// `commit(id)` promotes a speculation lane's records into the
/// principal stream (protocol-level placeholder). Today a no-op.
pub const KFUNC_COMMIT: &str = "bifrost_kfunc_commit";
/// `discard(id)` drops a speculation lane's records (protocol-level
/// placeholder). Today a no-op.
pub const KFUNC_DISCARD: &str = "bifrost_kfunc_discard";
/// `clear(@agg)` zeroes every entry of the named aggregation map.
/// The kfunc takes a `struct bpf_map *` (the BPF verifier resolves
/// the agg's fake-fd to a real map at LOAD_PROG time).
pub const KFUNC_CLEAR_AGG: &str = "bifrost_kfunc_clear_agg";

/// Emit a kfunc call with `imm = 0` placeholder + record a
/// `(insn_idx, name)` reloc entry so the guest can patch the imm
/// field with the locally-resolved btf_id before the verifier
/// pass.  Insn idx is the 8-byte slot count at emit time.
pub fn emit_kfunc_call(
    out: &mut Vec<u8>,
    relocs: &mut Vec<(u32, &'static str)>,
    name: &'static str,
) {
    let insn_idx = (out.len() / 8) as u32;
    relocs.push((insn_idx, name));
    out.extend_from_slice(&bpf_insn(BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, 0));
}

/// Emit a record reservation. Returns the number of eBPF
/// instruction *slots* (8-byte units) emitted.
///
/// `use_shmem`: true → SHMEM kfunc path (BFR7 reloc'd), false →
/// legacy BPF_MAP_TYPE_RINGBUF helper path.
pub fn emit_record_reserve(
    out: &mut Vec<u8>,
    relocs: &mut Vec<(u32, &'static str)>,
    size: i32,
    use_shmem: bool,
) -> usize {
    if use_shmem {
        out.extend_from_slice(&bpf_mov64_imm(1, size));
        emit_kfunc_call(out, relocs, KFUNC_SHMEM_RESERVE);
        2
    } else {
        out.extend_from_slice(&bpf_ld_map_fd(1, RINGBUF_FAKE_FD));
        out.extend_from_slice(&bpf_mov64_imm(2, size));
        out.extend_from_slice(&bpf_mov64_imm(3, 0));
        out.extend_from_slice(&bpf_call(HELPER_RINGBUF_RESERVE));
        5
    }
}

/// Emit a record submission. `ptr_reg` holds the pointer the
/// reserve returned (typically `RB_PTR_REG`).
///
/// `use_shmem`: as in `emit_record_reserve`.
/// `kick`: true → also emit a `bifrost_kfunc_shmem_kick` call after
/// the submit so the host's doorbell wakes early.
pub fn emit_record_submit(
    out: &mut Vec<u8>,
    relocs: &mut Vec<(u32, &'static str)>,
    ptr_reg: u8,
    use_shmem: bool,
    kick: bool,
) {
    out.extend_from_slice(&bpf_mov64_reg(1, ptr_reg));
    if use_shmem {
        emit_kfunc_call(out, relocs, KFUNC_SHMEM_SUBMIT);
    } else {
        out.extend_from_slice(&bpf_mov64_imm(2, 0));
        out.extend_from_slice(&bpf_call(HELPER_RINGBUF_SUBMIT));
    }
    if kick {
        emit_kfunc_call(out, relocs, KFUNC_SHMEM_KICK);
    }
}

pub fn bpf_exit() -> [u8; 8] {
    bpf_insn(BPF_EXIT, 0, 0, 0, 0)
}

/// `*(u32 *)(dst + off) = src`
pub fn bpf_stx_w(dst: u8, src: u8, off: i16) -> [u8; 8] {
    bpf_insn(BPF_STX_W, dst, src, off, 0)
}

/// `*(u64 *)(dst + off) = src`
pub fn bpf_stx_dw(dst: u8, src: u8, off: i16) -> [u8; 8] {
    bpf_insn(BPF_STX_DW, dst, src, off, 0)
}

/// `if rd == imm { pc += off }`. Off is in instruction slots, not bytes.
pub fn bpf_jeq_imm(dst: u8, imm: i32, off: i16) -> [u8; 8] {
    bpf_insn(BPF_JEQ_IMM, dst, 0, off, imm)
}

/// `r{dst} = *(u64 *)(r{src} + off)`
pub fn bpf_ldx_dw(dst: u8, src: u8, off: i16) -> [u8; 8] {
    bpf_insn(BPF_LDX_DW, dst, src, off, 0)
}

/// Emit a single-arg DIF_SUBR_* lowering via a kfunc call.
/// Used for one-arg subroutines (`strlen`, `copyinstr`,
/// `progenyof`) where the routine takes one tuple-stack argument
/// and returns a u64 scalar (or string pointer treated as u64 by
/// BPF).
///
/// Sequence:
///   r1 = *(u64 *)(r10 + TUPLE_STACK_BASE)   ; load arg0
///   spill r2..r5                            ; BPF call ABI
///   call <kfunc>                            ; emits reloc
///   restore r2..r5                          ; skip dst
///   rd = r0                                 ; if dst != 0
///
/// Caller is responsible for resetting `tuple_depth = 0` after the
/// call (subroutine ABI consumes all pushed args).
pub fn emit_single_arg_kfunc_subr(
    out: &mut Vec<u8>,
    relocs: &mut Vec<(u32, &'static str)>,
    dst: u8,
    name: &'static str,
) {
    use super::state::TUPLE_STACK_BASE;
    // Spill r2..r5 — we'll overwrite r1 with arg0 directly so no
    // spill needed for it.
    for r in 2u8..=5u8 {
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
    }
    // Spill r1 too (in case dst != 1 and a later load needs the
    // old value — keep symmetry with `emit_helper_call_difo`).
    let slot1 = LDGS_SCRATCH_BASE;
    out.extend_from_slice(&bpf_stx_dw(10, 1, slot1));
    // r1 = arg0
    out.extend_from_slice(&bpf_ldx_dw(1, 10, TUPLE_STACK_BASE));
    emit_kfunc_call(out, relocs, name);
    // Restore r2..r5, skipping dst since it's about to receive r0.
    for r in 2u8..=5u8 {
        if r == dst {
            continue;
        }
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
    }
    if dst != 1 {
        out.extend_from_slice(&bpf_ldx_dw(1, 10, slot1));
    }
    if dst != 0 {
        out.extend_from_slice(&bpf_mov64_reg(dst, 0));
    }
}

/// Emit a two-arg DIF_SUBR_* lowering via a kfunc call. Used for
/// string built-ins like `strchr(s, c)` / `strrchr(s, c)` — arg0
/// (haystack) is at the deepest tuple-stack slot, arg1 (needle /
/// char) is one slot above. Pushes are in source-order so PUSHTV
/// at depth=0 → TUPLE_STACK_BASE (arg0), depth=1 →
/// TUPLE_STACK_BASE-8 (arg1).
pub fn emit_two_arg_kfunc_subr(
    out: &mut Vec<u8>,
    relocs: &mut Vec<(u32, &'static str)>,
    dst: u8,
    name: &'static str,
) {
    use super::state::TUPLE_STACK_BASE;
    for r in 3u8..=5u8 {
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
    }
    // r1 = arg0 (haystack), r2 = arg1 (needle / char).
    out.extend_from_slice(&bpf_ldx_dw(1, 10, TUPLE_STACK_BASE));
    out.extend_from_slice(&bpf_ldx_dw(2, 10, TUPLE_STACK_BASE - 8));
    emit_kfunc_call(out, relocs, name);
    for r in 3u8..=5u8 {
        if r == dst {
            continue;
        }
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
    }
    if dst != 0 {
        out.extend_from_slice(&bpf_mov64_reg(dst, 0));
    }
}

/// Emit a three-arg DIF_SUBR_* lowering. arg0/1/2 are at
/// tuple-stack offsets 0, -8, -16 from TUPLE_STACK_BASE.
pub fn emit_three_arg_kfunc_subr(
    out: &mut Vec<u8>,
    relocs: &mut Vec<(u32, &'static str)>,
    dst: u8,
    name: &'static str,
) {
    use super::state::TUPLE_STACK_BASE;
    for r in 4u8..=5u8 {
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
    }
    out.extend_from_slice(&bpf_ldx_dw(1, 10, TUPLE_STACK_BASE));
    out.extend_from_slice(&bpf_ldx_dw(2, 10, TUPLE_STACK_BASE - 8));
    out.extend_from_slice(&bpf_ldx_dw(3, 10, TUPLE_STACK_BASE - 16));
    emit_kfunc_call(out, relocs, name);
    for r in 4u8..=5u8 {
        if r == dst {
            continue;
        }
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
    }
    if dst != 0 {
        out.extend_from_slice(&bpf_mov64_reg(dst, 0));
    }
}

/// Emit a spilled helper-call sequence inside a value-DIFO.
pub fn emit_helper_call_difo(out: &mut Vec<u8>, helper_id: i32, dst: u8) {
    for r in 1u8..=5 {
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_stx_dw(10, r, slot));
    }
    out.extend_from_slice(&bpf_call(helper_id));
    for r in 1u8..=5 {
        if r == dst {
            // About to be overwritten with r0; no need to restore.
            continue;
        }
        let slot = LDGS_SCRATCH_BASE + ((r as i16 - 1) * 8);
        out.extend_from_slice(&bpf_ldx_dw(r, 10, slot));
    }
    if dst != 0 {
        out.extend_from_slice(&bpf_mov64_reg(dst, 0));
    }
}

/// `r{dst} OP= imm` for ALU64 immediate ops (LSH/RSH/etc.).
pub fn bpf_alu64_imm(opcode: u8, dst: u8, imm: i32) -> [u8; 8] {
    bpf_insn(opcode, dst, 0, 0, imm)
}

/// Conditional jump-register: `if r{dst} OP r{src} { pc += off }`.
pub fn bpf_jcc_reg(opcode: u8, dst: u8, src: u8, off: i16) -> [u8; 8] {
    bpf_insn(opcode, dst, src, off, 0)
}

/// Conditional jump-immediate: `if r{dst} OP imm { pc += off }`.
pub fn bpf_jcc_imm(opcode: u8, dst: u8, imm: i32, off: i16) -> [u8; 8] {
    bpf_insn(opcode, dst, 0, off, imm)
}

/// Unconditional jump: `pc += off`.
pub fn bpf_ja(off: i16) -> [u8; 8] {
    bpf_insn(BPF_JA, 0, 0, off, 0)
}

/// `*(u64*)(r{dst} + off) += r{src}` — eBPF atomic add.
pub fn bpf_atomic_add(dst: u8, src: u8, off: i16) -> [u8; 8] {
    bpf_insn(0xdb, dst, src, off, 0)
}

/// Byte-swap r{dst} as if its low `width` bits were a network-byte-
/// order integer.  `width` must be 16, 32, or 64.  On little-endian
/// targets (arm64, x86_64) this is the standard ntohs/ntohl/ntohll
/// implementation: `BPF_ALU | BPF_END | BPF_TO_BE` with the width
/// in `imm`.  Upper bits above `width` are zeroed.
pub fn bpf_to_be(dst: u8, width: i32) -> [u8; 8] {
    bpf_insn(0xdc, dst, 0, 0, width)
}

/// `r{dst} = map_fd` for the ringbuf.
pub fn bpf_ld_map_fd(dst: u8, fake_fd: i32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let lo = bpf_insn(BPF_LD_IMM_DW_LO, dst, BPF_PSEUDO_MAP_FD, 0, fake_fd);
    let hi = bpf_insn(BPF_LD_IMM_DW_HI, 0, 0, 0, 0);
    out[..8].copy_from_slice(&lo);
    out[8..].copy_from_slice(&hi);
    out
}
