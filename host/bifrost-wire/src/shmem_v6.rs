// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// SHMEM v6 — semantic envelopes that replace BFR7-shaped records.
//
// ## Why v6
//
// SHMEM v5 was Linux-eBPF-shaped: every record assumed a BFR7 wrapper
// produced by the host's eBPF lowering. With the DOF-generic data plane,
// records originate from per-OS adapters
// (eBPF/DTrace/native) and the host CLI no longer dictates the layout.
// The v6 envelope strips OS-shape from the record header so any
// adapter can publish without forging a BFR7 wrapper, and groups the
// supplementary metadata channels (symbols, stacks, OS-typed
// backend data) under stable kind tags.
//
// The transport mechanism is **unchanged** — same 16 MB virtio
// shared-memory region, same per-CPU SPSC rings, same doorbell
// semantics. Only the record vocabulary at offset 4 of each record
// header is generalized.
//
// ## Kind discriminant
//
// Every v6 record header is:
//
//   bytes 0..4  : u32 record_size (entire record including header)
//   bytes 4..8  : u32 kind        (`SHMEM6_KIND_*`)
//   bytes 8..16 : u64 session_id  (envelope's `session_id`)
//   bytes 16..24: u64 monotonic_ns (guest CLOCK_MONOTONIC at emit)
//
// Per-kind body follows. The host's renderer dispatches on
// `record_size` + `kind` only; the body layout is owned by the
// per-kind decoder.
//
// ## Reserved probe-id range
//
// v5 used probe-id magics in the top of the u32 namespace
// (`0xFFFFFFFB..FF` etc.) so user records could not collide. v6
// supersedes those with explicit kind tags here; the legacy
// probe-id magics remain valid for one transition cycle and the
// host renderer accepts both.

pub const SHMEM6_HEADER_SIZE: usize = 24;

// =====================================================================
// SHMEM6_KIND_* — every v6 record carries one of these in its
// 4-byte kind field.  Allocate by appending; never reuse a value.
// =====================================================================

/// Plain trace-action record: serialized DTrace records as produced
/// by `trace()`, `printf()`, `tracemem()`. Body layout:
///
///   u32 ecb_index                (the ECB this record came from)
///   u32 action_count             (number of action payloads)
///   action_count × {
///       u8  action_kind          (matches `bifrost_dtrace_lower::action::ActionKind`)
///       u8  reserved[3]
///       u32 payload_len
///       u8  payload[payload_len]
///   }
pub const SHMEM6_KIND_TRACE_RECORD: u32 = 1;

/// Aggregation snapshot — one row per (var_id, key) tuple. Body
/// layout supersedes v5's `AGG_SNAPSHOT` per-row schema; same
/// `AGG_SNAPSHOT_ROW_KIND_*` discriminant in the row header.
///
///   u32 var_id
///   u32 row_count
///   row_count × {
///       u8  row_kind             (`AGG_SNAPSHOT_ROW_KIND_*`)
///       u8  reserved[3]
///       u32 key_len
///       u8  key[key_len]
///       u32 value_len
///       u8  value[value_len]
///   }
pub const SHMEM6_KIND_AGG_SNAPSHOT: u32 = 2;

/// Per-ECB attach status report.  Streamed once per ECB at session
/// start (and any time an ECB transitions, e.g. on uprobe re-resolve).
/// Body layout matches `bifrost_dtrace_lower::adapter::EcbStatus`:
///
///   u32 ecb_index
///   u8  status                   (0 = accepted, 1 = rejected, 2 = zero-match)
///   u8  reject_reason            (`RejectReason::*` if status == 1)
///   u8  reserved[2]
///   u64 attached_id              (if status == 0)
pub const SHMEM6_KIND_STATUS: u32 = 3;

/// Per-class drop counter snapshot — replaces the v5 per-ring drop
/// arrays. One record per ring per session-end. Body:
///
///   u32 ring_id                  (per-CPU index)
///   u32 class_count
///   class_count × { u8 class; u8 reserved[3]; u64 drops }
pub const SHMEM6_KIND_DROP_SUMMARY: u32 = 4;

/// Symbol table for ustack/usym resolution. Replaces v5's
/// `SYM_TABLE_PROBE_ID`. Body shape is per-backend; the
/// `backend_tag` byte tells the host renderer how to parse the rest:
///
///   u8  backend_tag              (`SYM_BACKEND_*`)
///   u8  reserved[3]
///   u32 body_len
///   u8  body[body_len]
pub const SHMEM6_KIND_SYMBOL_TABLE: u32 = 5;

/// Stack trace table.  Body:
///
///   u32 stack_id
///   u32 frame_count
///   frame_count × u64 frame_pc
pub const SHMEM6_KIND_STACK_TABLE: u32 = 6;

/// Per-OS backend metadata (kallsyms, BTF, VMA, kmod list, CTF).
/// One record per chunk; the `metadata_kind` byte selects the body
/// decoder.
///
///   u8  metadata_kind            (`OS_META_*`)
///   u8  reserved[3]
///   u32 body_len
///   u8  body[body_len]
pub const SHMEM6_KIND_OS_METADATA: u32 = 7;

// =====================================================================
// Per-backend / per-metadata sub-discriminants.  These keep the
// kind field a flat number while letting the body be backend-typed.
// =====================================================================

pub const SYM_BACKEND_LINUX_VMA: u8 = 1;
pub const SYM_BACKEND_LINUX_KALLSYMS: u8 = 2;
pub const SYM_BACKEND_LINUX_BTF: u8 = 3;
pub const SYM_BACKEND_FBSD_KMODSYMS: u8 = 4;
pub const SYM_BACKEND_ILLUMOS_CTF: u8 = 5;

pub const OS_META_LINUX_KALLSYMS: u8 = 1;
pub const OS_META_LINUX_BTF: u8 = 2;
pub const OS_META_LINUX_VMA: u8 = 3;
pub const OS_META_FBSD_MODULE: u8 = 4;
pub const OS_META_FBSD_PROVIDER: u8 = 5;
pub const OS_META_ILLUMOS_CTF: u8 = 6;
pub const OS_META_ILLUMOS_PROVIDER: u8 = 7;

// =====================================================================
// STATUS body bytes — kept as small constants so adapters can fill
// the byte directly without a serialization helper.
// =====================================================================

pub const SHMEM6_STATUS_ACCEPTED: u8 = 0;
pub const SHMEM6_STATUS_REJECTED: u8 = 1;
pub const SHMEM6_STATUS_ZERO_MATCH: u8 = 2;

/// Decoded view of a SHMEM v6 record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shmem6Header {
    pub record_size: u32,
    pub kind: u32,
    pub session_id: u64,
    pub monotonic_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    Short,
    SizeUnderflow,
    SizeOverflow,
}

/// Decode the 24-byte v6 record header and bounds-check `record_size`
/// against the input slice.
pub fn decode_header(buf: &[u8]) -> Result<Shmem6Header, HeaderError> {
    if buf.len() < SHMEM6_HEADER_SIZE {
        return Err(HeaderError::Short);
    }
    let record_size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if (record_size as usize) < SHMEM6_HEADER_SIZE {
        return Err(HeaderError::SizeUnderflow);
    }
    if (record_size as usize) > buf.len() {
        return Err(HeaderError::SizeOverflow);
    }
    let kind = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let session_id = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let monotonic_ns = u64::from_le_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    Ok(Shmem6Header {
        record_size,
        kind,
        session_id,
        monotonic_ns,
    })
}

/// Encode a v6 record header at the start of `out`. Returns the
/// header size on success; the caller writes the per-kind body
/// starting at `out[SHMEM6_HEADER_SIZE..]`.
pub fn encode_header(hdr: &Shmem6Header, out: &mut [u8]) -> Option<usize> {
    if out.len() < SHMEM6_HEADER_SIZE {
        return None;
    }
    out[0..4].copy_from_slice(&hdr.record_size.to_le_bytes());
    out[4..8].copy_from_slice(&hdr.kind.to_le_bytes());
    out[8..16].copy_from_slice(&hdr.session_id.to_le_bytes());
    out[16..24].copy_from_slice(&hdr.monotonic_ns.to_le_bytes());
    Some(SHMEM6_HEADER_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let hdr = Shmem6Header {
            record_size: 64,
            kind: SHMEM6_KIND_TRACE_RECORD,
            session_id: 0x1234_5678_9abc_def0,
            monotonic_ns: 1_000_000_000,
        };
        let mut buf = [0u8; 64];
        assert_eq!(encode_header(&hdr, &mut buf), Some(SHMEM6_HEADER_SIZE));
        let decoded = decode_header(&buf).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn rejects_size_underflow() {
        let mut buf = [0u8; 64];
        // record_size = 8, smaller than header
        buf[0..4].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(decode_header(&buf), Err(HeaderError::SizeUnderflow));
    }

    #[test]
    fn rejects_size_overflow() {
        let mut buf = [0u8; 32];
        // record_size = 1_000_000, well beyond the 32-byte input
        buf[0..4].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert_eq!(decode_header(&buf), Err(HeaderError::SizeOverflow));
    }

    #[test]
    fn rejects_short_input() {
        let buf = [0u8; 8];
        assert_eq!(decode_header(&buf), Err(HeaderError::Short));
    }
}
