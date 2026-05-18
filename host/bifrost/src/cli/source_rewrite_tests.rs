// Unit tests for source rewriting. Kept out of source_rewrite.rs so
// the production rewrite passes stay navigable.

use super::*;

#[test]
fn rewrite_g_actions_replaces_helpers() {
    assert_eq!(rewrite_g_actions("gstack();"), "stack();");
    assert_eq!(rewrite_g_actions("gustack(8)"), "ustack(8)");
}

#[test]
fn rewrite_g_actions_word_boundary_safe() {
    // Identifiers containing "gstack" as a substring must NOT be
    // rewritten — only standalone tokens.
    assert_eq!(rewrite_g_actions("my_gstack_var"), "my_gstack_var");
    assert_eq!(rewrite_g_actions("agstack"), "agstack");
}

#[test]
fn replace_word_token_word_boundary_safe() {
    assert_eq!(
        replace_word_token("retval + 1", "retval", "arg3"),
        "arg3 + 1"
    );
    assert_eq!(replace_word_token("xretval", "retval", "arg3"), "xretval");
    assert_eq!(replace_word_token("retval2", "retval", "arg3"), "retval2");
}

#[test]
fn contains_word_word_boundary_safe() {
    assert!(contains_word("foo retval bar", "retval"));
    assert!(!contains_word("foo retval2 bar", "retval"));
    assert!(!contains_word("xretval", "retval"));
}

#[test]
fn stable_providers_proc_exec() {
    let src = "proc:::exec { trace(execname); }";
    let out = rewrite_stable_providers(src);
    assert_eq!(
        out,
        "tracepoint:guest:sched:sched_process_exec { trace(execname); }",
    );
}

#[test]
fn stable_providers_sched_switch() {
    let src = "sched:::switch / pid != 0 / { @runs[execname] = count(); }";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:sched:sched_switch"));
    assert!(!out.contains("sched:::switch"));
}

#[test]
fn stable_providers_io_pair() {
    let src = "io:::start { ts[args[0]] = timestamp; } io:::done { /* ... */ }";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:block:block_rq_issue"));
    assert!(out.contains("tracepoint:guest:block:block_rq_complete"));
    assert!(!out.contains("io:::start"));
    assert!(!out.contains("io:::done"));
}

#[test]
fn stable_providers_syscall_generic() {
    let src = "syscall:::entry { @[probefunc] = count(); }";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:raw_syscalls:sys_enter"));
    assert!(!out.contains("syscall:::entry"));
}

#[test]
fn stable_providers_no_match_passes_through() {
    // No stable-provider tokens; output equals input.
    let src = "fbt:guest:vfs_read:entry { trace(arg0); }";
    assert_eq!(rewrite_stable_providers(src), src);
}

#[test]
fn stable_providers_word_boundary_safe() {
    // A token that *contains* a stable-provider name as a
    // substring must not be rewritten.  `proc:::exec_extra`
    // ends with `_extra`, so the word boundary at the trailing
    // `c` is broken (`_` is an ident char) — keep the source
    // verbatim.
    let src = "proc:::exec_extra { /* ... */ }";
    assert_eq!(rewrite_stable_providers(src), src);
}

#[test]
fn stable_providers_multiple_clauses_all_rewritten() {
    // A realistic D source with multiple stable-provider
    // clauses; all three get rewritten in one pass.
    let src = "proc:::exec { /* a */ }\n\
               sched:::wakeup { /* b */ }\n\
               io:::start { /* c */ }\n";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:sched:sched_process_exec"));
    assert!(out.contains("tracepoint:guest:sched:sched_wakeup"));
    assert!(out.contains("tracepoint:guest:block:block_rq_issue"));
}

#[test]
fn stable_providers_per_syscall_entry() {
    let src = "syscall::execve:entry { trace(arg0); }";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:syscalls:sys_enter_execve"));
    assert!(!out.contains("syscall::execve:entry"));
}

#[test]
fn stable_providers_per_syscall_return() {
    let src = "syscall::openat:return / errno != 0 / { @[execname] = count(); }";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:syscalls:sys_exit_openat"));
    assert!(!out.contains("syscall::openat:return"));
}

#[test]
fn stable_providers_per_syscall_word_boundary_safe() {
    // The static table's `syscall:::entry` rewrite should fire
    // first (giving raw_syscalls:sys_enter), and the per-syscall
    // pass should NOT then re-rewrite it.  Idempotent across both
    // passes.
    let src = "syscall:::entry { /* all syscalls */ }";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("tracepoint:guest:raw_syscalls:sys_enter"));
    // Must not contain the malformed double-rewrite.
    assert!(!out.contains("sys_enter_"));
}

#[test]
fn stable_providers_per_syscall_unrelated_token_unchanged() {
    // A bare `syscall_handler` identifier must NOT match the
    // syscall:: prefix.
    let src = "fn syscall_handler() { /* ... */ }";
    assert_eq!(rewrite_stable_providers(src), src);
}

#[test]
fn stable_providers_per_syscall_multiple_in_one_source() {
    let src = "syscall::execve:entry { /* a */ }\n\
               syscall::execve:return { /* b */ }\n\
               syscall::openat:entry { /* c */ }\n";
    let out = rewrite_stable_providers(src);
    assert!(out.contains("sys_enter_execve"));
    assert!(out.contains("sys_exit_execve"));
    assert!(out.contains("sys_enter_openat"));
}

#[test]
fn stable_providers_on_off_cpu_both_map_to_sched_switch() {
    let src = "sched:::on-cpu { @on[execname] = count(); }\n\
               sched:::off-cpu { @off[execname] = count(); }\n";
    let out = rewrite_stable_providers(src);
    // Both stable names ⇒ same underlying tracepoint.
    let count = out.matches("tracepoint:guest:sched:sched_switch").count();
    assert_eq!(count, 2);
    assert!(!out.contains("sched:::on-cpu"));
    assert!(!out.contains("sched:::off-cpu"));
}

#[test]
fn stable_providers_idempotent() {
    // Running the rewrite twice should be a no-op the second
    // time (the canonical shapes don't match any stable-provider
    // needle).
    let src = "proc:::exec { /* ... */ }";
    let once = rewrite_stable_providers(src);
    let twice = rewrite_stable_providers(&once);
    assert_eq!(once, twice);
}

/// Build a synthetic 16-byte `bpf_ld_imm64 r1, imm64` instruction.
/// Mirrors the layout in `host/bifrost/src/lower/emit.rs::bpf_ld_imm64`
/// so the materialize-pass scanner sees what the real lowering
/// would emit.
fn synth_ld_imm64(dst: u8, imm: u64) -> [u8; 16] {
    let lo = imm as u32;
    let hi = (imm >> 32) as u32;
    let mut out = [0u8; 16];
    out[0] = 0x18;
    out[1] = dst & 0x0f;
    out[4..8].copy_from_slice(&lo.to_le_bytes());
    out[8] = 0x00;
    out[9] = 0x00;
    out[12..16].copy_from_slice(&hi.to_le_bytes());
    out
}

#[test]
fn materialize_field_relocs_patches_imm_and_emits_record() {
    // One CORE_OFFSETOF(task_struct, comm) site → one sentinel
    // landed in inttab → SETX lowered to `bpf_ld_imm64 r1, sentinel`.
    // Materialize must:
    //   1. Patch slot 0's imm to the fallback (3168)
    //   2. Zero slot 1's imm (struct offsets fit in u32)
    //   3. Emit a MaterializedFieldReloc pointing at byte 4 of slot 0
    let sentinel = core_offsetof_sentinel(0);
    let markers = vec![CoreOffsetofMarker {
        sentinel,
        struct_name: "task_struct".into(),
        field_name: "comm".into(),
        fallback_offset: 3168,
    }];
    let mut ebpf = synth_ld_imm64(1, sentinel).to_vec();
    let relocs = materialize_field_relocs(&mut ebpf, &markers);
    assert_eq!(relocs.len(), 1, "exactly one reloc emitted");
    let r = &relocs[0];
    assert_eq!(r.insn_idx, 0);
    assert_eq!(r.byte_off_in_insn, 4);
    assert_eq!(r.access_kind, bifrost_wire::FIELD_RELOC_OFFSET);
    assert_eq!(r.struct_name, "task_struct");
    assert_eq!(r.field_name, "comm");
    // imm slot 0 patched to fallback offset; imm slot 1 zeroed.
    let lo_imm = u32::from_le_bytes(ebpf[4..8].try_into().unwrap());
    let hi_imm = u32::from_le_bytes(ebpf[12..16].try_into().unwrap());
    assert_eq!(lo_imm, 3168);
    assert_eq!(hi_imm, 0);
}

#[test]
fn materialize_field_relocs_skips_non_sentinel_imm64() {
    // A regular imm64 (e.g. a literal `42`) must not match.
    let markers = vec![CoreOffsetofMarker {
        sentinel: core_offsetof_sentinel(0),
        struct_name: "task_struct".into(),
        field_name: "comm".into(),
        fallback_offset: 3168,
    }];
    let mut ebpf = synth_ld_imm64(1, 42).to_vec();
    let relocs = materialize_field_relocs(&mut ebpf, &markers);
    assert!(relocs.is_empty(), "non-sentinel imm64 must not match");
    // imm slot 0 unchanged.
    assert_eq!(u32::from_le_bytes(ebpf[4..8].try_into().unwrap()), 42);
}

#[test]
fn materialize_field_relocs_handles_multiple_sites_with_distinct_sentinels() {
    // Two CORE_OFFSETOF sites resolve to two distinct sentinels →
    // two distinct LD_IMM64 instructions → two distinct relocs.
    // Critically, they retain their (struct, field) identity even
    // when the fallback offsets happen to differ.
    let s0 = core_offsetof_sentinel(0);
    let s1 = core_offsetof_sentinel(1);
    let markers = vec![
        CoreOffsetofMarker {
            sentinel: s0,
            struct_name: "task_struct".into(),
            field_name: "comm".into(),
            fallback_offset: 3168,
        },
        CoreOffsetofMarker {
            sentinel: s1,
            struct_name: "mm_struct".into(),
            field_name: "start_brk".into(),
            fallback_offset: 360,
        },
    ];
    let mut ebpf = Vec::new();
    ebpf.extend_from_slice(&synth_ld_imm64(1, s0));
    // One unrelated 8-byte mov in between to confirm slot scan
    // doesn't drift.
    ebpf.extend_from_slice(&[0xb7, 0x02, 0, 0, 7, 0, 0, 0]);
    ebpf.extend_from_slice(&synth_ld_imm64(3, s1));
    let relocs = materialize_field_relocs(&mut ebpf, &markers);
    assert_eq!(relocs.len(), 2);
    assert_eq!(relocs[0].insn_idx, 0);
    assert_eq!(relocs[0].struct_name, "task_struct");
    assert_eq!(relocs[1].insn_idx, 24); // 16 (ld_imm64) + 8 (mov)
    assert_eq!(relocs[1].struct_name, "mm_struct");
}

#[test]
fn materialize_field_relocs_ignores_map_fd_loads() {
    // bpf_ld_map_fd has the same `0x18` opcode as bpf_ld_imm64
    // but uses src=BPF_PSEUDO_MAP_FD=1 in the high nibble of
    // byte 1.  Even if the map_fd value happened to land on a
    // sentinel (it can't realistically, but defensively), the
    // src!=0 check must keep it from matching.
    let sentinel = core_offsetof_sentinel(0);
    let markers = vec![CoreOffsetofMarker {
        sentinel,
        struct_name: "task_struct".into(),
        field_name: "comm".into(),
        fallback_offset: 3168,
    }];
    let mut ebpf = synth_ld_imm64(1, sentinel).to_vec();
    // Forge it into a map_fd by setting src=1 in the high nibble.
    ebpf[1] |= 1 << 4;
    let relocs = materialize_field_relocs(&mut ebpf, &markers);
    assert!(
        relocs.is_empty(),
        "map_fd loads must not be treated as CORE sentinel hits"
    );
}

#[test]
fn is_core_offsetof_sentinel_recognizes_only_pinned_hi() {
    let s = core_offsetof_sentinel(42);
    assert!(is_core_offsetof_sentinel(s));
    // High 32 bits must match exactly; off-by-one or zero rejected.
    assert!(!is_core_offsetof_sentinel(0));
    assert!(!is_core_offsetof_sentinel(0xC0FECAFD_00000000));
    assert!(!is_core_offsetof_sentinel(0xFFFF_FFFF_FFFF_FFFF));
}

#[test]
fn rewrite_core_offsetof_without_btf_is_pass_through() {
    // No BTF loaded ⇒ source unchanged + empty marker list.
    // Matches the rewrite_offsetof posture so the missing-BTF
    // diagnostic surfaces from the libdtrace compile path
    // exactly the same way.
    let src = "{ trace(*(int*)(curtask + CORE_OFFSETOF(task_struct, tgid))); }";
    let (out, markers) = rewrite_core_offsetof(src, None);
    assert_eq!(out, src);
    assert!(markers.is_empty());
}
