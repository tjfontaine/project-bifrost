// SPDX-License-Identifier: Apache-2.0
//
// Post-DOF-generic-rebuild host emitter.
//
// **Before the rebuild**, this module built a BFR7 wrapper from the
// host-side eBPF lowering pipeline, then re-decoded the wrapper into
// per-program `LOAD_PROG` payloads and shipped them under
// `KIND_LOAD_PROG`.
//
// **After the rebuild**, the host does not lower D
// to eBPF. It compiles the parsed D source to DOF via libdtrace and
// ships exactly one `DTRACE_SESSION_V1` envelope (followed by the
// DOF bytes) under `KIND_DTRACE_SESSION`. The Linux guest decodes
// the DOF against `crates/bifrost-dtrace-lower` and drives its own
// adapter; the host stays OS-agnostic.
//
// This file keeps the historical entry-point name
// (`build_direct_load_progs`) so the call sites in `cli/runtime.rs`
// and `cli/orchestrate.rs` keep working through the rename. The
// `LinuxEbpfBackend` type and `LinuxEbpfSessionRequest` have been
// retired; their roles are absorbed into the new session emitter.

use crate::cli::capability_fanout::CapabilityHints;
use crate::cli::wrapper::MapDecl;
use crate::schema::RecordSchema;
use anyhow::{Result, anyhow};
use bifrost_wire::session_envelope::{
    DTRACE_SESSION_ENVELOPE_SIZE, DTRACE_SESSION_WIRE_MAJOR, DTRACE_SESSION_WIRE_MINOR,
    SessionEnvelope, TARGET_OS_LINUX, encode,
};

/// Historical record shape preserved so the runtime keeps building a
/// `Vec<DirectLoadProgram>` from the parsed source. The fields are
/// no longer used to build BFR7 wrappers — the post-rebuild path
/// only needs the probe type counts to derive capability hints.
pub type DirectLoadProgram = (
    String,
    RecordSchema,
    Vec<MapDecl>,
    Vec<u8>,
    u8,
    Option<crate::elf_syms::UprobeTarget>,
    Vec<(u32, String)>,
    Vec<crate::cli::wrapper::OwnedFieldReloc>,
    Option<u64>,
);

/// Result of session-envelope construction. The payload list is now
/// always exactly one item — the envelope followed by the DOF bytes
/// — because the post-rebuild host emits a single session per
/// target, not N independent LOAD_PROG payloads. `statuses` is
/// preserved at length 1 with `RSP_LOADPROG_STATUS_OK` on success
/// so the existing per-payload status loop in runtime.rs surfaces a
/// single OK rather than misreporting partial progress.
#[derive(Debug)]
pub struct DirectLoadProgs {
    pub payloads: Vec<Vec<u8>>,
    pub statuses: Vec<u8>,
}

/// `BifrostCmd.op` value that the guest worker uses to dispatch a
/// DOF-generic session command. Lives in the first 4 bytes of the
/// payload (the BifrostCmd header), inside the conduit's opaque
/// `KIND_CTRL_PAYLOAD_REQ` envelope. Distinct from the transport
/// `KIND_DTRACE_SESSION` constant (which is the host-CLI alias for
/// the conduit's PAYLOAD_REQ kind — value 2 by coincidence).
pub const BIFROST_CMD_OP_DTRACE_SESSION: u32 = 3;

/// Build the wire payload for a `KIND_CTRL_PAYLOAD_REQ` command
/// carrying a DTRACE_SESSION_V1 envelope. Layout:
///
///   [u32 BifrostCmd.op = 3]    ← guest worker dispatches on this
///   [u32 BifrostCmd.len]       ← length of the payload AFTER the
///                                 8-byte BifrostCmd header (i.e.
///                                 envelope + dof bytes)
///   [96 bytes DTRACE_SESSION_V1 envelope]
///   [dof bytes ...]
///
/// `dof_offset` inside the envelope is set to the position of the
/// DOF bytes RELATIVE TO THE START OF THE BIFROSTCMD HEADER (so the
/// guest can slice the DOF without re-doing the framing math).
pub fn build_session_payload(
    session_id: u64,
    duration_ms: u64,
    hints: &CapabilityHints,
    dof_bytes: &[u8],
) -> Vec<u8> {
    const BIFROST_CMD_HDR_SIZE: usize = 8;
    let dof_sha = sha256_no_alloc(dof_bytes);
    let envelope_off = BIFROST_CMD_HDR_SIZE;
    let dof_off = envelope_off + DTRACE_SESSION_ENVELOPE_SIZE;
    let envelope = SessionEnvelope {
        wire_major: DTRACE_SESSION_WIRE_MAJOR,
        wire_minor: DTRACE_SESSION_WIRE_MINOR,
        target_os: TARGET_OS_LINUX,
        flags: 0,
        session_id,
        duration_ms,
        dof_offset: dof_off as u64,
        dof_length: dof_bytes.len() as u64,
        dof_sha256: dof_sha,
        capability_request: hints.as_capability_bits(),
        capability_required: 0,
    };
    let body_len = (DTRACE_SESSION_ENVELOPE_SIZE + dof_bytes.len()) as u32;
    let total_len = BIFROST_CMD_HDR_SIZE + DTRACE_SESSION_ENVELOPE_SIZE + dof_bytes.len();
    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(&BIFROST_CMD_OP_DTRACE_SESSION.to_le_bytes());
    payload.extend_from_slice(&body_len.to_le_bytes());
    payload.resize(BIFROST_CMD_HDR_SIZE + DTRACE_SESSION_ENVELOPE_SIZE, 0);
    encode(&envelope, &mut payload[envelope_off..]).expect("envelope buffer is canonical size");
    payload.extend_from_slice(dof_bytes);
    payload
}

/// Derive a CapabilityHints from the probe-type discriminant the
/// host CLI assigns to each program. The mapping mirrors
/// `bifrost_wire::PROBE_TYPE_*`.
pub fn hints_from_probe_types(programs: &[DirectLoadProgram]) -> CapabilityHints {
    let mut h = CapabilityHints::default();
    for prog in programs {
        match prog.4 {
            bifrost_wire::PROBE_TYPE_UPROBE | bifrost_wire::PROBE_TYPE_UPROBE_BY_SYM => {
                h.uses_uprobe = true;
            }
            bifrost_wire::PROBE_TYPE_URETPROBE | bifrost_wire::PROBE_TYPE_URETPROBE_BY_SYM => {
                h.uses_uretprobe = true;
            }
            bifrost_wire::PROBE_TYPE_FENTRY | bifrost_wire::PROBE_TYPE_FEXIT => {
                h.uses_fbt = true;
            }
            bifrost_wire::PROBE_TYPE_TRACEPOINT => h.uses_tracepoint = true,
            bifrost_wire::PROBE_TYPE_USDT => h.uses_usdt = true,
            bifrost_wire::PROBE_TYPE_PROFILE_TIMER => h.uses_profile_timer = true,
            _ => {}
        }
    }
    h
}

/// Build the host's post-rebuild control payload from a parsed D
/// source. **No BFR7, no host-side eBPF lowering, no LOAD_PROG.**
///
/// `dof_bytes` is the libdtrace-emitted DOF blob for the routed D
/// source (callers obtain it via `DtraceHandle::compile_to_dof`).
/// `programs` is preserved as a hint source for the capability
/// bitset; the per-program eBPF bytes inside it are intentionally
/// not packaged anywhere — they were the artefact of the retired
/// host-side lowering pipeline and have no place in a DOF-generic
/// envelope.
///
/// Returns a single-element payload list under the expected
/// `DirectLoadProgs` shape so the caller's existing
/// `for payload in payloads { push_cmd(...) }` loop continues to
/// work; the caller MUST switch from `KIND_LOAD_PROG` to
/// `KIND_DTRACE_SESSION` to actually have the guest accept the
/// envelope.
pub fn build_direct_load_progs(
    programs: &[DirectLoadProgram],
    dof_bytes: &[u8],
) -> Result<DirectLoadProgs> {
    if dof_bytes.is_empty() {
        return Err(anyhow!(
            "DOF blob is empty — refusing to emit a DTRACE_SESSION_V1 envelope \
             with no program"
        ));
    }
    let hints = hints_from_probe_types(programs);
    // Session id: derive a stable u64 from the SHA so repeat sessions
    // with the same DOF deduplicate cleanly in the guest's audit log.
    // duration_ms = 0 means "run until the host stops the session"
    // (canonical for attach-mode traces).
    let sha = sha256_no_alloc(dof_bytes);
    let session_id = u64::from_le_bytes([
        sha[0], sha[1], sha[2], sha[3], sha[4], sha[5], sha[6], sha[7],
    ]);
    let payload = build_session_payload(session_id, 0, &hints, dof_bytes);
    Ok(DirectLoadProgs {
        payloads: vec![payload],
        statuses: vec![bifrost_wire::RSP_LOADPROG_STATUS_OK],
    })
}

/// Compute SHA-256 of a byte slice without pulling a new crate
/// dependency. Implementation matches RFC 6234; the host CLI has no
/// other SHA-256 consumer, so vendoring 60 lines is cheaper than
/// adding `sha2` as a transitive dep. The output is bit-exact with
/// `sha2::Sha256::digest`.
fn sha256_no_alloc(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Build padded message: input || 0x80 || zeros || u64 BE bit length
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded: Vec<u8> = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_wire::session_envelope::{
        DTRACE_SESSION_ENVELOPE_SIZE, DTRACE_SESSION_MAGIC, decode,
    };

    #[test]
    fn payload_carries_bifrost_cmd_then_envelope_then_dof() {
        let dof = b"\x7fDOF dummy contents".to_vec();
        let hints = CapabilityHints::default();
        let payload = build_session_payload(0xcafe, 1000, &hints, &dof);
        // BifrostCmd { op = 3, len = envelope + dof } at offset 0.
        let op = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
        assert_eq!(op, BIFROST_CMD_OP_DTRACE_SESSION);
        assert_eq!(len, DTRACE_SESSION_ENVELOPE_SIZE + dof.len());
        // Envelope at offset 8.
        assert_eq!(&payload[8..12], &DTRACE_SESSION_MAGIC[..]);
        let env = decode(&payload[8..8 + DTRACE_SESSION_ENVELOPE_SIZE]).unwrap();
        assert_eq!(env.session_id, 0xcafe);
        assert_eq!(env.duration_ms, 1000);
        // dof_offset is relative to the BifrostCmd header start.
        assert_eq!(env.dof_offset, (8 + DTRACE_SESSION_ENVELOPE_SIZE) as u64);
        assert_eq!(env.dof_length, dof.len() as u64);
        // DOF bytes follow at dof_offset.
        let dof_start = env.dof_offset as usize;
        assert_eq!(&payload[dof_start..], dof.as_slice());
    }

    #[test]
    fn empty_dof_rejected() {
        let err = build_direct_load_progs(&[], &[]).unwrap_err();
        assert!(err.to_string().contains("DOF blob is empty"));
    }

    #[test]
    fn one_payload_one_status() {
        let dof = b"\x7fDOF some bytes".to_vec();
        let progs = build_direct_load_progs(&[], &dof).unwrap();
        assert_eq!(progs.payloads.len(), 1);
        assert_eq!(progs.statuses.len(), 1);
        assert_eq!(progs.statuses[0], bifrost_wire::RSP_LOADPROG_STATUS_OK);
    }

    #[test]
    fn sha256_matches_canonical_for_empty_input() {
        // SHA-256 of "" is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = sha256_no_alloc(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn sha256_matches_canonical_for_abc() {
        // SHA-256 of "abc" is ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256_no_alloc(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn hints_pick_up_probe_types() {
        let prog = (
            "redis_cmd".to_string(),
            RecordSchema::default(),
            Vec::<MapDecl>::new(),
            Vec::<u8>::new(),
            bifrost_wire::PROBE_TYPE_UPROBE,
            None,
            Vec::<(u32, String)>::new(),
            Vec::new(),
            None,
        );
        let hints = hints_from_probe_types(std::slice::from_ref(&prog));
        assert!(hints.uses_uprobe);
        assert!(!hints.uses_fbt);
        assert!(!hints.uses_tracepoint);
    }
}
