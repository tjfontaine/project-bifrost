//! Golden-byte regression tests for the SHMEM record-header
//! layout.
//!
//! The libkrun `shmem_consumer_thread` and the guest's
//! `bifrost_kfunc_emit_record` agree on an 8-byte record header
//! `{u32 size, u32 flags}` followed by `size` bytes of payload,
//! padded up to a 4-byte boundary.  Two flag bits matter:
//!
//!   READY   (bit 0) — record is fully written, consumer may read
//!   PADDING (bit 1) — skip-to-end-of-buffer marker (size covers
//!                     the bytes the consumer should advance past)
//!
//! These bytes flow across two independent layers: the guest
//! kernel module writes them, the libkrun device consumer reads
//! them.  An inadvertent edit to flag values, header size, or
//! field order at one layer silently misparses at the other.
//! Pin the layout via expectorate so any byte-level change shows
//! up in the PR diff.
//!
//! Pinned via `assert_contents` against fixtures in
//! `tests/fixtures/`.  Regenerate with:
//!
//!     EXPECTORATE=overwrite cargo test --test shmem_record_golden

use bifrost_wire::typed::{IntoWireBytes, ShmemRecordHeader};
use bifrost_wire::{SHMEM_RECORD_FLAG_PADDING, SHMEM_RECORD_FLAG_READY};
use expectorate::assert_contents;

/// Same hex-dump format as `wrapper_golden.rs` for cross-test
/// readability.  16 bytes per line, two-digit lowercase hex,
/// printable-ASCII gutter on the right.
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

/// Encode a sequence of (payload, flags) records using the typed
/// header.  Mirrors what the guest's emit path writes into the
/// SHMEM ringbuf: header, payload, 4-byte padding to align the
/// next header.
fn build_record_stream(records: &[(&[u8], u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (payload, flags) in records {
        let hdr = ShmemRecordHeader {
            size: payload.len() as u32,
            flags: *flags,
        };
        out.extend_from_slice(hdr.as_bytes());
        out.extend_from_slice(payload);
        // Pad payload up to a 4-byte boundary.
        let padding = (4 - (payload.len() % 4)) % 4;
        out.extend(std::iter::repeat(0u8).take(padding));
    }
    out
}

#[test]
fn shmem_record_header_alone() {
    // Bare header: a 16-byte READY record claiming a 16-byte
    // payload.  Pins the {u32 size, u32 flags} order.
    let hdr = ShmemRecordHeader {
        size: 16,
        flags: SHMEM_RECORD_FLAG_READY,
    };
    assert_contents(
        "tests/fixtures/shmem_record_header_alone.hex",
        &hex_dump(hdr.as_bytes()),
    );
}

#[test]
fn shmem_record_padding_marker() {
    // PADDING record: the consumer sees this and skips `size`
    // bytes (typically to wrap to the start of the buffer).  No
    // payload follows a PADDING marker — the size field tells
    // the consumer how many bytes to skip past.
    let hdr = ShmemRecordHeader {
        size: 1024,
        flags: SHMEM_RECORD_FLAG_PADDING,
    };
    assert_contents(
        "tests/fixtures/shmem_record_padding.hex",
        &hex_dump(hdr.as_bytes()),
    );
}

#[test]
fn shmem_record_stream_two_ready_then_padding() {
    // Realistic stream: two READY records back-to-back followed
    // by a PADDING marker that skips to the end of the buffer.
    // Validates the per-record 4-byte alignment + flag values.
    let stream = build_record_stream(&[
        // 6-byte payload (will pad 2 bytes)
        (b"hello!", SHMEM_RECORD_FLAG_READY),
        // 12-byte payload (already 4-byte-aligned)
        (b"world----xxx", SHMEM_RECORD_FLAG_READY),
        // PADDING: 256 bytes to skip
        (&[][..], SHMEM_RECORD_FLAG_PADDING),
    ]);
    // PADDING entry above had size=0; in practice the guest
    // writes the skip count.  Patch it for the golden:
    let mut bytes = stream;
    let pad_off = bytes.len() - 8;
    bytes[pad_off..pad_off + 4].copy_from_slice(&256u32.to_le_bytes());
    assert_contents("tests/fixtures/shmem_record_stream.hex", &hex_dump(&bytes));
}
