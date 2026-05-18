//! Byte-level goldens for the profile-N sample body format.
//!
//! Pinning these bytes here means a layout change surfaces
//! in a PR diff before it ships across the libkrun emit / CLI consume
//! seam.  Profile samples are a hot path (>=997 Hz × N vcpus); the
//! fixed-layout encoding (no varint-keyed extension fields) keeps
//! per-sample overhead minimal.
//!
//! Regenerate with `EXPECTORATE=overwrite cargo test --test
//! profile_sample_golden` after an *intentional* wire change.

use bifrost_wire::codec::encode_profile_sample;
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
fn profile_sample_empty_stack() {
    // Smallest legal sample: zero-frame stack, idle vcpu (pid=0,
    // tid=0, cpu=0, flags=0).  Pins the 20-byte header layout.
    let mut payload = Vec::new();
    encode_profile_sample(&mut payload, 0, 0, 0, 0, &[]).unwrap();
    assert_contents(
        "tests/fixtures/profile_sample_empty.hex",
        &hex_dump(&payload),
    );
}

#[test]
fn profile_sample_kernel_context() {
    // A 4-frame kernel-context stack — the canonical "vcpu was in
    // kernel mode at sample time" shape.  Pins the (pid, tid, cpu,
    // flags) ordering and the LE frame_pc encoding.
    let mut payload = Vec::new();
    encode_profile_sample(
        &mut payload,
        53413,
        53420,
        2,
        PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT,
        &[
            0xffff_ff80_0010_0000,
            0xffff_ff80_0010_0080,
            0xffff_ff80_0011_0000,
            0xffff_ff80_0012_0000,
        ],
    )
    .unwrap();
    assert_contents(
        "tests/fixtures/profile_sample_kernel.hex",
        &hex_dump(&payload),
    );
}

#[test]
fn profile_sample_truncated_stack() {
    // An incomplete + truncated stack — the worst-case shape the
    // walker emits when MAX_PROFILE_FRAMES caps before the end of
    // the chain AND a frame-pointer dereference faults on the way.
    // Both flag bits land together in one fixture.
    let mut payload = Vec::new();
    let frames: Vec<u64> = (0..3).map(|i| 0x4000_0000 + i * 0x40).collect();
    encode_profile_sample(
        &mut payload,
        100,
        100,
        0,
        PROFILE_SAMPLE_FLAG_STACK_TRUNCATED | PROFILE_SAMPLE_FLAG_STACK_INCOMPLETE,
        &frames,
    )
    .unwrap();
    assert_contents(
        "tests/fixtures/profile_sample_truncated.hex",
        &hex_dump(&payload),
    );
}
