//! Byte-level goldens for the self-trace event body format.
//!
//! Structured self-trace events flow from each layer through the
//! same SHMEM ringbuf as user records, tagged with reserved probe
//! IDs.  Pinning the body bytes here means a layout change
//! surfaces in a PR diff before it ever ships across the host CLI
//! / libkrun / guest seam.
//!
//! Regenerate with `EXPECTORATE=overwrite cargo test --test
//! self_trace_golden` after an *intentional* wire change.  Forbid
//! the overwrite during routine work — every byte change is a
//! cross-layer wire-contract regression.

use bifrost_wire::codec::{SelfFieldOwned, encode_event};
use bifrost_wire::*;
use expectorate::assert_contents;

/// Render bytes as a copy-paste-friendly hex dump matching the
/// `wrapper_golden.rs` style.
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
fn empty_event_body() {
    // Smallest legal event: zero-length msg, zero fields.  Pins
    // the 6-byte header layout (level + subsys + num_fields + msg_len).
    let mut payload = Vec::new();
    encode_event(
        &mut payload,
        SELF_LEVEL_INFO,
        SELF_SUBSYS_LOADPROG,
        b"",
        &[],
    )
    .unwrap();
    assert_contents("tests/fixtures/self_trace_empty.hex", &hex_dump(&payload));
}

#[test]
fn slot_exhausted_event() {
    // Slot-exhaustion reproducer — what the driver emits when it
    // runs out of probe slots.  Captures the canonical "msg + a
    // handful of structured fields" shape so the byte layout of
    // the most common event is locked.
    let mut payload = Vec::new();
    encode_event(
        &mut payload,
        SELF_LEVEL_ERROR,
        SELF_SUBSYS_LOADPROG,
        b"slot exhausted",
        &[
            (b"slot", SelfFieldOwned::U64(8)),
            (b"max_slots", SelfFieldOwned::U64(8)),
            (b"target", SelfFieldOwned::Bytes(b"transaction__commit")),
        ],
    )
    .unwrap();
    assert_contents(
        "tests/fixtures/self_trace_slot_exhausted.hex",
        &hex_dump(&payload),
    );
}

#[test]
fn observer_attach_event() {
    // Observer-attach diagnostics — ties host fd liveness to slot
    // leases.  Today the lease ID is a placeholder; future plumbing
    // will fill it from the real attach record.
    let mut payload = Vec::new();
    encode_event(
        &mut payload,
        SELF_LEVEL_INFO,
        SELF_SUBSYS_OBSERVER,
        b"attached",
        &[
            (b"lease", SelfFieldOwned::U64(0xDEAD_BEEF_CAFE_F00D)),
            (b"persistent", SelfFieldOwned::Bool(false)),
        ],
    )
    .unwrap();
    assert_contents(
        "tests/fixtures/self_trace_observer_attach.hex",
        &hex_dump(&payload),
    );
}
