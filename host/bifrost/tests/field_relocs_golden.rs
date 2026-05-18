//! Byte-level goldens for the BTF field-reloc payload format.
//!
//! Driver↔VMM kernel-version durability: pinning these
//! bytes here means a layout change surfaces in a PR diff before it
//! ships across the lowering / libkrun-patcher seam.  These payloads
//! are wired into the BFR7 wrapper body via
//! PROGRAM_FLAG_FIELD_RELOCS_PRESENT; the standalone fixture is the
//! pin for the per-record encoding regardless of where the section
//! lands.
//!
//! Regenerate with `EXPECTORATE=overwrite cargo test --test
//! field_relocs_golden` after an *intentional* wire change.

use bifrost_wire::codec::{FieldRelocInput, encode_field_relocs};
use bifrost_wire::*;
use expectorate::assert_contents;

fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}: ", i * 16));
        for b in chunk {
            out.push_str(&format!("{:02x} ", b));
        }
        out.push('\n');
    }
    out
}

#[test]
fn field_relocs_empty() {
    // Smallest legal payload: just `[u32 0]`.  Pins the count
    // header layout.
    let mut payload = Vec::new();
    encode_field_relocs(&mut payload, &[]).unwrap();
    assert_contents("tests/fixtures/field_relocs_empty.hex", &hex_dump(&payload));
}

#[test]
fn field_relocs_single_offset_reloc() {
    // The canonical "one OFFSET reloc against task_struct.comm" shape.
    // Pins the per-record header (insn_idx, kind, byte_off, two
    // length prefixes) and the name encoding.
    let mut payload = Vec::new();
    encode_field_relocs(
        &mut payload,
        &[FieldRelocInput {
            insn_idx: 8,
            access_kind: FIELD_RELOC_OFFSET,
            byte_off_in_insn: 4,
            struct_name: "task_struct",
            field_name: "comm",
        }],
    )
    .unwrap();
    assert_contents(
        "tests/fixtures/field_relocs_offset.hex",
        &hex_dump(&payload),
    );
}

#[test]
fn field_relocs_three_records_mixed() {
    // The diagnostic-friendly shape: one of each access_kind, with
    // realistic struct/field names.  Pins the discriminants
    // (FIELD_RELOC_OFFSET=0, _SIZE=1, _EXISTS=2) and the iteration
    // order across the byte stream.
    let mut payload = Vec::new();
    encode_field_relocs(
        &mut payload,
        &[
            FieldRelocInput {
                insn_idx: 8,
                access_kind: FIELD_RELOC_OFFSET,
                byte_off_in_insn: 4,
                struct_name: "task_struct",
                field_name: "comm",
            },
            FieldRelocInput {
                insn_idx: 24,
                access_kind: FIELD_RELOC_SIZE,
                byte_off_in_insn: 4,
                struct_name: "mm_struct",
                field_name: "start_brk",
            },
            FieldRelocInput {
                insn_idx: 56,
                access_kind: FIELD_RELOC_EXISTS,
                byte_off_in_insn: 4,
                struct_name: "task_struct",
                field_name: "android_kabi_reserved1",
            },
        ],
    )
    .unwrap();
    assert_contents("tests/fixtures/field_relocs_mixed.hex", &hex_dump(&payload));
}
