// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// `DTRACE_SESSION_V1` — the canonical guest control payload for the
// DOF-generic control plane.
//
// ## Why this exists
//
// Before the rebuild, the host CLI emitted OS-specific control
// payloads: BFR7 wrappers carrying pre-lowered eBPF for Linux, native
// DTrace state for FreeBSD. That made libkrun and the host CLI
// implicitly tied to one guest dialect.
//
// `DTRACE_SESSION_V1` is the inversion: the host emits **one envelope
// per session**, carrying:
//
//   - the **DOF blob** (parsed by the guest via `bifrost-dtrace-lower`),
//   - a **target_os** discriminator so a multi-target session can
//     fanout to one envelope per guest with per-guest gating,
//   - a **capability bitset** so the host can request features
//     (destructive actions, ustack symbolication, USDT, etc.) and
//     each guest reports back which it satisfied.
//
// virtio-conduit ferries the envelope opaquely; libkrun does not need
// to peek inside. The DOF bytes typically live in the session arena
// region of SHMEM (offset + length), so the envelope itself stays
// tiny — only the descriptor goes through the control ring.
//
// ## Envelope layout (little-endian, packed)
//
//   bytes  0..4   magic (`DTS1`)
//   bytes  4..6   wire_major (`DTRACE_SESSION_WIRE_MAJOR`)
//   bytes  6..8   wire_minor (`DTRACE_SESSION_WIRE_MINOR`)
//   bytes  8..10  target_os (TargetOs)
//   bytes 10..12  flags     (SESSION_FLAG_*)
//   bytes 12..16  reserved (must be zero)
//   bytes 16..24  session_id (host-assigned, unique per session)
//   bytes 24..32  duration_ms (0 = run until host stops)
//   bytes 32..40  dof_offset (in the session arena)
//   bytes 40..48  dof_length (bytes)
//   bytes 48..80  dof_sha256 (canonical hash of the DOF bytes)
//   bytes 80..88  capability_request (SESSION_CAP_*)
//   bytes 88..96  capability_required (subset; refuse if not satisfied)
//
// Total: 96 bytes. Stays the same shape for the life of `wire_major`;
// new fields go through bumping `wire_minor` plus appending bytes.

#![allow(clippy::needless_range_loop)]

pub const DTRACE_SESSION_MAGIC: [u8; 4] = *b"DTS1";
pub const DTRACE_SESSION_MAGIC_LE: u32 = u32::from_le_bytes(*b"DTS1");

/// Wire-format compatibility version. `wire_major` mismatch refuses
/// the session at the guest's protocol parser; `wire_minor` is
/// informational (newer minor = newer optional fields).
pub const DTRACE_SESSION_WIRE_MAJOR: u16 = 1;
pub const DTRACE_SESSION_WIRE_MINOR: u16 = 0;

pub const DTRACE_SESSION_ENVELOPE_SIZE: usize = 96;

// =====================================================================
// SESSION_FLAG_* — session-wide behavior bits.  Bitfield in
// envelope[10..12].
// =====================================================================

/// Allow destructive actions (`stop`, `raise`, `chill`, `panic`,
/// `breakpoint`). Guests with no destructive support reject with
/// `EcbStatus::Rejected(DestructiveDisabled)` per ECB.
pub const SESSION_FLAG_ALLOW_DESTRUCTIVE: u16 = 1 << 0;
/// Buffering policy: switch (`bufpolicy=switch`). Default is fill.
pub const SESSION_FLAG_BUFPOLICY_SWITCH: u16 = 1 << 1;
/// Quiet mode — suppress `BEGIN` formatting.
pub const SESSION_FLAG_QUIET: u16 = 1 << 2;
/// Request per-ECB STATUS for every ECB, not just rejects.
pub const SESSION_FLAG_VERBOSE_STATUS: u16 = 1 << 3;

// =====================================================================
// SESSION_CAP_* — capability vocabulary.  Two 64-bit bitsets:
// `capability_request` is "host would like these"; `capability_required`
// is "refuse the session if not satisfied".  Per-ECB STATUS reports
// back the per-ECB capability that was actually used.
//
// Allocate by appending; never reuse a bit position.
// =====================================================================

pub const SESSION_CAP_FBT: u64 = 1 << 0;
pub const SESSION_CAP_TRACEPOINT: u64 = 1 << 1;
pub const SESSION_CAP_UPROBE: u64 = 1 << 2;
pub const SESSION_CAP_URETPROBE: u64 = 1 << 3;
pub const SESSION_CAP_USDT: u64 = 1 << 4;
pub const SESSION_CAP_PROFILE_TIMER: u64 = 1 << 5;
pub const SESSION_CAP_STACK: u64 = 1 << 6;
pub const SESSION_CAP_USTACK: u64 = 1 << 7;
pub const SESSION_CAP_USYM: u64 = 1 << 8;
pub const SESSION_CAP_USDT_SEMAPHORE: u64 = 1 << 9;
/// Aggregation kinds the guest must support; subset enforced by
/// `capability_required`.
pub const SESSION_CAP_AGG_COUNT: u64 = 1 << 16;
pub const SESSION_CAP_AGG_SUM: u64 = 1 << 17;
pub const SESSION_CAP_AGG_MIN: u64 = 1 << 18;
pub const SESSION_CAP_AGG_MAX: u64 = 1 << 19;
pub const SESSION_CAP_AGG_AVG: u64 = 1 << 20;
pub const SESSION_CAP_AGG_STDDEV: u64 = 1 << 21;
pub const SESSION_CAP_AGG_QUANTIZE: u64 = 1 << 22;
pub const SESSION_CAP_AGG_LQUANTIZE: u64 = 1 << 23;
pub const SESSION_CAP_AGG_LLQUANTIZE: u64 = 1 << 24;
/// Per-target backend metadata the host would like back as SHMEM v6
/// `OS_METADATA` / `SYMBOL_TABLE` records. Backend-typed: Linux ships
/// BTF/kallsyms/VMA; FreeBSD ships module/provider/symbol metadata;
/// illumos ships CTF.
pub const SESSION_CAP_META_BTF: u64 = 1 << 32;
pub const SESSION_CAP_META_KALLSYMS: u64 = 1 << 33;
pub const SESSION_CAP_META_VMA: u64 = 1 << 34;
pub const SESSION_CAP_META_CTF: u64 = 1 << 35;
pub const SESSION_CAP_META_FBSD_MODULES: u64 = 1 << 36;

// =====================================================================
// TargetOs — canonical u16 discriminator.  Matches
// `bifrost_dtrace_lower::TargetOs::as_u16`.
// =====================================================================

pub const TARGET_OS_ANY: u16 = 0;
pub const TARGET_OS_LINUX: u16 = 1;
pub const TARGET_OS_FREEBSD: u16 = 2;
pub const TARGET_OS_ILLUMOS: u16 = 3;
pub const TARGET_OS_MACOS: u16 = 4;

/// Decoded view of an envelope. All numeric fields little-endian.
/// `dof_sha256` is a raw 32-byte hash; the encoder copies it verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEnvelope {
    pub wire_major: u16,
    pub wire_minor: u16,
    pub target_os: u16,
    pub flags: u16,
    pub session_id: u64,
    pub duration_ms: u64,
    pub dof_offset: u64,
    pub dof_length: u64,
    pub dof_sha256: [u8; 32],
    pub capability_request: u64,
    pub capability_required: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Short,
    BadMagic,
    BadWireMajor,
    ReservedNonZero,
}

/// Encode an envelope into a fixed-size buffer. Returns the number of
/// bytes written (always `DTRACE_SESSION_ENVELOPE_SIZE` on success).
pub fn encode(env: &SessionEnvelope, out: &mut [u8]) -> Option<usize> {
    if out.len() < DTRACE_SESSION_ENVELOPE_SIZE {
        return None;
    }
    out[..DTRACE_SESSION_ENVELOPE_SIZE].fill(0);
    out[0..4].copy_from_slice(&DTRACE_SESSION_MAGIC);
    out[4..6].copy_from_slice(&env.wire_major.to_le_bytes());
    out[6..8].copy_from_slice(&env.wire_minor.to_le_bytes());
    out[8..10].copy_from_slice(&env.target_os.to_le_bytes());
    out[10..12].copy_from_slice(&env.flags.to_le_bytes());
    // reserved bytes 12..16 already zeroed.
    out[16..24].copy_from_slice(&env.session_id.to_le_bytes());
    out[24..32].copy_from_slice(&env.duration_ms.to_le_bytes());
    out[32..40].copy_from_slice(&env.dof_offset.to_le_bytes());
    out[40..48].copy_from_slice(&env.dof_length.to_le_bytes());
    out[48..80].copy_from_slice(&env.dof_sha256);
    out[80..88].copy_from_slice(&env.capability_request.to_le_bytes());
    out[88..96].copy_from_slice(&env.capability_required.to_le_bytes());
    Some(DTRACE_SESSION_ENVELOPE_SIZE)
}

/// Decode an envelope. Borrows nothing; copies the 32-byte SHA into
/// the returned struct so the caller does not need to keep the input
/// buffer alive.
pub fn decode(buf: &[u8]) -> Result<SessionEnvelope, DecodeError> {
    if buf.len() < DTRACE_SESSION_ENVELOPE_SIZE {
        return Err(DecodeError::Short);
    }
    if &buf[0..4] != &DTRACE_SESSION_MAGIC[..] {
        return Err(DecodeError::BadMagic);
    }
    let wire_major = u16::from_le_bytes([buf[4], buf[5]]);
    if wire_major != DTRACE_SESSION_WIRE_MAJOR {
        return Err(DecodeError::BadWireMajor);
    }
    for &b in &buf[12..16] {
        if b != 0 {
            return Err(DecodeError::ReservedNonZero);
        }
    }
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&buf[48..80]);
    Ok(SessionEnvelope {
        wire_major,
        wire_minor: u16::from_le_bytes([buf[6], buf[7]]),
        target_os: u16::from_le_bytes([buf[8], buf[9]]),
        flags: u16::from_le_bytes([buf[10], buf[11]]),
        session_id: u64_le(&buf[16..24]),
        duration_ms: u64_le(&buf[24..32]),
        dof_offset: u64_le(&buf[32..40]),
        dof_length: u64_le(&buf[40..48]),
        dof_sha256: sha,
        capability_request: u64_le(&buf[80..88]),
        capability_required: u64_le(&buf[88..96]),
    })
}

fn u64_le(s: &[u8]) -> u64 {
    u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SessionEnvelope {
        SessionEnvelope {
            wire_major: DTRACE_SESSION_WIRE_MAJOR,
            wire_minor: DTRACE_SESSION_WIRE_MINOR,
            target_os: TARGET_OS_LINUX,
            flags: SESSION_FLAG_VERBOSE_STATUS,
            session_id: 0xdead_beef_cafe_babe,
            duration_ms: 5_000,
            dof_offset: 0x1000,
            dof_length: 0x4000,
            dof_sha256: [0x42; 32],
            capability_request: SESSION_CAP_FBT
                | SESSION_CAP_TRACEPOINT
                | SESSION_CAP_AGG_QUANTIZE
                | SESSION_CAP_META_BTF,
            capability_required: SESSION_CAP_FBT,
        }
    }

    #[test]
    fn envelope_round_trip() {
        let env = sample();
        let mut buf = [0u8; DTRACE_SESSION_ENVELOPE_SIZE];
        assert_eq!(encode(&env, &mut buf), Some(DTRACE_SESSION_ENVELOPE_SIZE));
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = [0u8; DTRACE_SESSION_ENVELOPE_SIZE];
        encode(&sample(), &mut buf).unwrap();
        buf[0] = 0;
        assert_eq!(decode(&buf), Err(DecodeError::BadMagic));
    }

    #[test]
    fn rejects_bad_wire_major() {
        let mut buf = [0u8; DTRACE_SESSION_ENVELOPE_SIZE];
        encode(&sample(), &mut buf).unwrap();
        buf[4] = 9; // wire_major=9, should refuse
        assert_eq!(decode(&buf), Err(DecodeError::BadWireMajor));
    }

    #[test]
    fn rejects_reserved_nonzero() {
        let mut buf = [0u8; DTRACE_SESSION_ENVELOPE_SIZE];
        encode(&sample(), &mut buf).unwrap();
        buf[14] = 1; // poison reserved region
        assert_eq!(decode(&buf), Err(DecodeError::ReservedNonZero));
    }

    #[test]
    fn short_buf_rejected() {
        let buf = [0u8; 10];
        assert_eq!(decode(&buf), Err(DecodeError::Short));
    }

    #[test]
    fn envelope_size_is_canonical() {
        assert_eq!(DTRACE_SESSION_ENVELOPE_SIZE, 96);
    }
}
