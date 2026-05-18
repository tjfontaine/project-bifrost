//! Golden-byte regression tests for the BFR7 wrapper format.
//!
//! Pinned via expectorate against fixtures in `tests/fixtures/`.
//! Any byte-level change to the wire format surfaces as a test
//! failure with a diff.  Regenerate fixtures with:
//!
//!     EXPECTORATE=overwrite cargo test --test wrapper_golden
//!
//! Why these matter: three independent layers (host CLI emit,
//! libkrun parse, guest LOAD_PROG decode) all read this byte
//! stream.  An edit that bumps the layout silently risks misparse
//! at the libkrun or guest end.  expectorate locks the byte
//! representation in a checked-in file so reviewers see the
//! impact in the PR diff before the change ever ships.

use bifrost::cli::wrapper::{MapDecl, OwnedFieldReloc, build_wrapper_bytes};
use bifrost::elf_syms::UprobeTarget;
use bifrost::schema::RecordSchema;
use expectorate::assert_contents;

/// Render bytes as a copy-paste-friendly hex dump for the golden
/// fixture.  16 bytes per line, two-digit hex lowercase, prefixed
/// with the byte offset.  Not the most compact format but
/// optimises for readability when reviewing a wire-format change.
fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:04x}: ", i * 16));
        for (j, b) in chunk.iter().enumerate() {
            if j > 0 && j % 8 == 0 {
                out.push(' ');
            }
            out.push_str(&format!("{:02x} ", b));
        }
        // pad short final line so columns line up across diffs
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push_str(" |");
        for b in chunk {
            out.push(if (0x20..=0x7e).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

#[test]
fn kprobe_minimal_wrapper() {
    // Canonical kprobe wrapper for do_sys_openat2 with no maps,
    // no insns, no kfunc relocs.  Smallest non-trivial BFR7
    // payload — exercises magic + num_progs + program header
    // + (empty) schema + (empty) maps + (empty) insns + (empty)
    // kfunc reloc table.
    let progs = vec![(
        "do_sys_openat2".to_string(),
        RecordSchema::default(),
        Vec::<MapDecl>::new(),
        Vec::<u8>::new(),
        0u8, // probe_type=0 → kprobe entry (retired but still
        // accepted by the encoder for compat)
        None::<UprobeTarget>,
        Vec::<(u32, String)>::new(),
        Vec::<OwnedFieldReloc>::new(),
        None,
    )];
    let bytes = build_wrapper_bytes(&progs).expect("encode");
    assert_contents(
        "tests/fixtures/wrapper_kprobe_minimal.hex",
        &hex_dump(&bytes),
    );
}

#[test]
fn fbt_with_one_map() {
    // FENTRY (probe_type=6) wrapper with a single PERCPU_ARRAY agg
    // map.  Exercises the per-map serialization path.
    let progs = vec![(
        "tcp_v4_do_rcv".to_string(),
        RecordSchema::default(),
        vec![MapDecl {
            map_type: 6, // BPF_MAP_TYPE_PERCPU_ARRAY
            key_size: 4,
            value_size: 8,
            max_entries: 1024,
            fake_fd: 100,
            name: "by_pid".to_string(),
        }],
        Vec::<u8>::new(),
        6u8,
        None::<UprobeTarget>,
        Vec::<(u32, String)>::new(),
        Vec::<OwnedFieldReloc>::new(),
        None,
    )];
    let bytes = build_wrapper_bytes(&progs).expect("encode");
    assert_contents("tests/fixtures/wrapper_fbt_one_map.hex", &hex_dump(&bytes));
}

#[test]
fn uprobe_kernel_resolved_trailer() {
    // Uprobe-by-symbol (probe_type=4) — exercises the kernel-
    // resolved trailer (basename + symbol_name) which is its own
    // shape distinct from the kprobe / host-resolved-uprobe paths.
    let progs = vec![(
        "redis-cmd-uprobe".to_string(),
        RecordSchema::default(),
        Vec::<MapDecl>::new(),
        Vec::<u8>::new(),
        4u8,
        Some(UprobeTarget {
            guest_path: "/usr/local/bin/redis-server".to_string(),
            file_offset: 0,
            sym_size: 0,
            basename: "redis-server".to_string(),
            symbol: "processCommand".to_string(),
            sdt_provider: String::new(),
        }),
        Vec::<(u32, String)>::new(),
        Vec::<OwnedFieldReloc>::new(),
        None,
    )];
    let bytes = build_wrapper_bytes(&progs).expect("encode");
    assert_contents(
        "tests/fixtures/wrapper_uprobe_kernel_resolved.hex",
        &hex_dump(&bytes),
    );
}

#[test]
fn kfunc_reloc_table() {
    // BFR7's kfunc reloc table: per-program list of (insn_idx,
    // name) pairs that the guest uses to patch insn[idx].imm at
    // LOAD_PROG time.  Worth golden-pinning so a change to the
    // length-prefix discipline (u32 insn_idx + u8 name_len +
    // bytes) surfaces in a diff.
    let progs = vec![(
        "do_sys_openat2".to_string(),
        RecordSchema::default(),
        Vec::<MapDecl>::new(),
        // Tiny dummy ebpf — empty is fine, the test is about
        // the reloc table tail.
        Vec::<u8>::new(),
        0u8,
        None::<UprobeTarget>,
        vec![
            (3, "bifrost_kfunc_emit_record".to_string()),
            (8, "bifrost_kfunc_emit_vma_table".to_string()),
            (12, "bpf_get_smp_processor_id".to_string()),
        ],
        Vec::<OwnedFieldReloc>::new(),
        None,
    )];
    let bytes = build_wrapper_bytes(&progs).expect("encode");
    assert_contents(
        "tests/fixtures/wrapper_kfunc_reloc_table.hex",
        &hex_dump(&bytes),
    );
}
