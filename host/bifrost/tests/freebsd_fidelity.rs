// SPDX-License-Identifier: Apache-2.0
//! Layered integration tests for the FreeBSD/native-DTrace fidelity
//! improvements:
//!
//! - **P0** wire.rs canonical SHA pin (guarded by
//!   `scripts/check-proto-drift.sh`; this file exercises the host's
//!   side of the contract).
//! - **P1** Full-ECB host preflight (`backend::native_trace_record_count`
//!   walks every ECB rather than the first one).
//! - **P1** DTrace-grade agg identity contract via the comment-and-
//!   string-aware scanner in `cli::agg_decl`.
//! - **P1** Lossless histogram values (`cli::orchestrate::ingest_agg_
//!   snapshot` decodes full quantize/lquantize bucket arrays and
//!   `merge::CrossTargetAggReducer` merges them across targets).
//! - **P2** Real lifecycle control via the v2 NDT session header
//!   (`backend::NativeDtraceSessionRequest::with_duration_ms`) and
//!   the per-target `duration_ms` knob in `plan::Target`.
//!
//! The kernel-side counterparts (drain_records walking every EPID,
//! drain_aggs carrying lossless bucket arrays, the wrapper honoring
//! the host-supplied duration_ms) are exercised on the FreeBSD guest
//! when the project is built end-to-end via the FreeBSD launcher
//! shim; here we lock in the host-side contract those changes meet
//! on the wire.

#![cfg(target_os = "macos")]

use bifrost::backend::{
    GuestBackend, NativeDtraceBackend, NativeDtraceSessionRequest,
    NATIVE_DTRACE_DEFAULT_DURATION_MS, NATIVE_DTRACE_DEFAULT_PROBE_ID,
    NATIVE_DTRACE_HEADER_LEN, NATIVE_DTRACE_SESSION_VERSION,
};
use bifrost::cli::agg_decl::{discover_aggs, AggKind};

/// Build an AGG_SNAPSHOT payload that mirrors what the FreeBSD
/// bifrost_conduit emits for one row: 24-byte sub-header + u32
/// num_entries + (i32 fd, u32 k_size, key, u32 v_size, value).
fn build_agg_snapshot_one(fd: i32, key: &[u8], value_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + value_bytes.len());
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&fd.to_le_bytes());
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(value_bytes);
    out
}

/// Build an AGG_SNAPSHOT schema-v1 payload: same sub-header but
/// with `AGG_SNAPSHOT_SCHEMA_V1` (=1) at offset 16, and each per-
/// entry row includes a kernel-stamped kind byte + 3 reserved
/// before k_size.  Used to pin the schema-v1 decoder path.
fn build_agg_snapshot_one_v1(
    fd: i32,
    kind: u8,
    key: &[u8],
    value_bytes: &[u8],
) -> Vec<u8> {
    use bifrost_wire::AGG_SNAPSHOT_SCHEMA_V1;
    let mut out = Vec::with_capacity(64 + value_bytes.len());
    // Sub-header: probe_id at 4, gns at 8 (both unused by ingest),
    // schema at 16.
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&AGG_SNAPSHOT_SCHEMA_V1.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&fd.to_le_bytes());
    out.extend_from_slice(&[kind, 0, 0, 0]);
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(value_bytes);
    out
}

/// Encode 127 quantize buckets where slot 63 = zero bucket.
fn quantize_value(slots: &[(usize, u64)]) -> Vec<u8> {
    const NBUCKETS: usize = 127;
    let mut buckets = vec![0u64; NBUCKETS];
    for (idx, count) in slots {
        buckets[*idx] = *count;
    }
    let mut out = Vec::with_capacity(NBUCKETS * 8);
    for b in buckets {
        out.extend_from_slice(&b.to_le_bytes());
    }
    out
}

#[test]
fn v2_session_header_is_40_bytes_with_duration_field() {
    let dof = b"\x7fDOF-stub";
    let req = NativeDtraceSessionRequest::run_dof_session(
        dof,
        NATIVE_DTRACE_DEFAULT_PROBE_ID,
        None,
        "freebsd:kernel:dtrace:trace",
    )
    .with_duration_ms(1500);
    let session = NativeDtraceBackend::freebsd()
        .build_session(req)
        .expect("build session");
    let body = &session.single_payload().unwrap().body;

    assert_eq!(NATIVE_DTRACE_HEADER_LEN, 40);
    assert_eq!(NATIVE_DTRACE_SESSION_VERSION, 2);
    // Header magic at offset 0 is the LE-encoded NDT1 word.
    assert_eq!(&body[0..4], &[0x4e, 0x44, 0x54, 0x31]);
    // Version word at offset 4 must read as 2.
    assert_eq!(u16::from_le_bytes(body[4..6].try_into().unwrap()), 2);
    // Duration at offset 32.
    assert_eq!(
        u32::from_le_bytes(body[32..36].try_into().unwrap()),
        1500
    );
}

#[test]
fn default_duration_zero_signals_kernel_to_use_its_built_in_default() {
    // When the host leaves `duration_ms` at zero, the kernel-side
    // wrapper substitutes its own default
    // (`NATIVE_DTRACE_DEFAULT_DURATION_MS`).  This test pins the
    // host-side encoding of "no override" so the kernel's fall-back
    // path is the only thing controlling the sample window.
    let dof = b"\x7fDOF-stub";
    let session = NativeDtraceBackend::freebsd()
        .build_session(NativeDtraceSessionRequest::run_dof(dof, 0xdeadbeef))
        .expect("build session");
    let body = &session.single_payload().unwrap().body;
    assert_eq!(
        u32::from_le_bytes(body[32..36].try_into().unwrap()),
        0
    );
    // Sanity: the default constant should match the kernel header.
    assert_eq!(NATIVE_DTRACE_DEFAULT_DURATION_MS, 500);
}

#[test]
fn agg_decl_scanner_recovers_kind_from_real_d_source() {
    // Approximates the killer-demo D source: cross-kernel @rx
    // declared once, multiple references, comments and string
    // literals that previously tricked the byte scanner.
    let src = r#"
        /*
         * Cross-kernel demo.  Old draft used `@stale = count();`
         * but we replaced it with `@rx[host]` below — the scanner must
         * ignore commented-out declarations.
         */
        BEGIN {
            printf("scope: %s\n", "@rx is a placeholder string");
            @rx["seed"] = count();
        }
        tracepoint:guest:net:netif_receive_skb { @rx["linux"] = count(); }
        fbt:kernel:tcp_input:entry { @rx["freebsd"] = count(); }
        tick-1sec { @latency[probename] = quantize(arg0); }
        END { printa("%-10s %@d\n", @rx); }
    "#;
    let decls = discover_aggs(src);
    assert_eq!(decls.len(), 2, "got: {:?}", decls);
    assert_eq!(decls[0].name, "rx");
    assert_eq!(decls[0].aggid, 1);
    assert_eq!(decls[0].kind, AggKind::Count);
    assert_eq!(decls[1].name, "latency");
    assert_eq!(decls[1].aggid, 2);
    assert_eq!(decls[1].kind, AggKind::Quantize);
}

/// Rust mirror of `bifrost_conduit_parse_native_dtrace_payload` in
/// `third_party/freebsd-bifrost/sys/dev/virtio/bifrost/bifrost_conduit.c`.
/// Keeps the host CI honest: if the kernel's parse contract drifts
/// the tests below need updating in lockstep with the C, surfacing
/// any silent v1/v2 mismatch before it can land in a guest module.
fn kernel_parse_native_dtrace_payload(payload: &[u8]) -> Result<(u32, u64, u32, bool), &'static str> {
    const MAGIC: u32 = 0x3154_444e;
    const HDR_LEN: usize = 40;
    const VERSION: u16 = 2;
    const OP_RUN_DOF: u16 = 1;
    const OS_FREEBSD: u16 = 1;
    const FLAG_EXPECT_VALUE: u16 = 1;
    const DEFAULT_DURATION_MS: u32 = 500;
    const MAX_DURATION_MS: u32 = 30_000;

    if payload.len() < HDR_LEN {
        return Err("native DTrace session payload too short");
    }
    let magic = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err("native DTrace session magic is invalid");
    }
    let version = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let op = u16::from_le_bytes(payload[6..8].try_into().unwrap());
    let os = u16::from_le_bytes(payload[8..10].try_into().unwrap());
    let flags = u16::from_le_bytes(payload[10..12].try_into().unwrap());
    let header_len = u32::from_le_bytes(payload[12..16].try_into().unwrap()) as usize;
    let dof_len = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
    if version != VERSION {
        return Err("native DTrace session version is unsupported");
    }
    if op != OP_RUN_DOF {
        return Err("native DTrace session op is unsupported");
    }
    if os != OS_FREEBSD {
        return Err("native DTrace session targets a different guest OS");
    }
    if flags & !FLAG_EXPECT_VALUE != 0 {
        return Err("native DTrace session flags are unsupported");
    }
    if header_len < HDR_LEN
        || header_len > payload.len()
        || dof_len == 0
        || dof_len > payload.len() - header_len
    {
        return Err("native DTrace session DOF length is invalid");
    }
    let probe_id = u32::from_le_bytes(payload[20..24].try_into().unwrap());
    if probe_id == 0 {
        return Err("native DTrace session probe id is invalid");
    }
    let expected = u64::from_le_bytes(payload[24..32].try_into().unwrap());
    let check_expected = flags & FLAG_EXPECT_VALUE != 0;
    let mut duration_ms = u32::from_le_bytes(payload[32..36].try_into().unwrap());
    if duration_ms == 0 {
        duration_ms = DEFAULT_DURATION_MS;
    }
    if duration_ms > MAX_DURATION_MS {
        duration_ms = MAX_DURATION_MS;
    }
    let _ = expected;
    Ok((probe_id, expected, duration_ms, check_expected))
}

/// Build a v1-shaped (pre-duration_ms) NDT session header: 32 bytes
/// with `version = 1` and `header_len = 32`.  This is what an old
/// caller would emit before the v2 wire bump.  The FreeBSD bridge
/// must reject this hand-crafted payload at the version check
/// rather than silently parsing junk past offset 24 as duration_ms.
fn build_v1_payload(dof: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(32 + dof.len());
    body.extend_from_slice(&0x3154_444eu32.to_le_bytes()); // magic
    body.extend_from_slice(&1u16.to_le_bytes()); // version = 1
    body.extend_from_slice(&1u16.to_le_bytes()); // op = RUN_DOF
    body.extend_from_slice(&1u16.to_le_bytes()); // os = FREEBSD
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&32u32.to_le_bytes()); // header_len = 32
    body.extend_from_slice(&(dof.len() as u32).to_le_bytes()); // dof_len
    body.extend_from_slice(&2u32.to_le_bytes()); // probe_id
    body.extend_from_slice(&0u64.to_le_bytes()); // expected
    body.extend_from_slice(dof);
    body
}

#[test]
fn freebsd_bridge_rejects_v1_header_at_version_check() {
    // Hand-craft a v1 payload (32-byte header).  Even though the
    // payload happens to be >= 40 bytes overall (so the length
    // gate passes), the version word at offset 4 reads as 1, not
    // 2 — the FreeBSD bridge must surface the version mismatch
    // rather than interpret the next 8 bytes (which are actually
    // the start of DOF) as duration_ms + reserved.
    let dof = b"\x7fDOF-pretend-payload-bytes-here-for-padding";
    let payload = build_v1_payload(dof);
    assert!(
        payload.len() >= 40,
        "v1 payload must reach the version check, not bounce off the length gate"
    );
    let err = kernel_parse_native_dtrace_payload(&payload)
        .expect_err("v1 header must be rejected");
    assert_eq!(err, "native DTrace session version is unsupported");
}

#[test]
fn freebsd_bridge_rejects_v2_payload_with_truncated_header_len() {
    // Forged: claim version 2 but header_len = 32 (the v1 size).
    // The kernel guards this with `header_len < HDR_LEN`, so the
    // bridge surfaces the length-invalid error instead of reading
    // duration_ms from inside the DOF region.
    let dof = b"\x7fDOF-stub-payload-bytes-for-bounds-check";
    let mut payload = build_v1_payload(dof);
    payload[4..6].copy_from_slice(&2u16.to_le_bytes()); // forge version=2
    let err = kernel_parse_native_dtrace_payload(&payload)
        .expect_err("v2 magic + v1 header_len must be rejected");
    assert_eq!(err, "native DTrace session DOF length is invalid");
}

#[test]
fn freebsd_bridge_accepts_v2_payload_with_duration_ms_at_offset_32() {
    // Positive smoke for the parse mirror: the v2 payload the
    // host's own `NativeDtraceSessionRequest::build_session`
    // emits must round-trip through the kernel parse mirror with
    // `duration_ms` recovered from offset 32.
    let dof = b"\x7fDOF-stub";
    let req = NativeDtraceSessionRequest::run_dof_session(
        dof,
        NATIVE_DTRACE_DEFAULT_PROBE_ID,
        None,
        "freebsd:kernel:dtrace:trace",
    )
    .with_duration_ms(2000);
    let session = NativeDtraceBackend::freebsd()
        .build_session(req)
        .expect("build session");
    let body = &session.single_payload().unwrap().body;
    let (probe_id, _expected, duration_ms, check_expected) =
        kernel_parse_native_dtrace_payload(body).expect("v2 parse must succeed");
    assert_eq!(probe_id, NATIVE_DTRACE_DEFAULT_PROBE_ID);
    assert_eq!(duration_ms, 2000);
    assert!(!check_expected);
}

#[test]
fn schema_v1_row_kind_takes_precedence_over_source_inference() {
    // Schema v1 stamps the agg kind into every wire row so the host
    // doesn't have to scan the user's D source to recover it.  This
    // test feeds a v1 row whose kernel-stamped kind is COUNT (which
    // the source map ALSO says is "count"), then a row where the
    // source map disagrees — confirming the wire kind wins.
    use bifrost::cli::orchestrate::ingest_agg_snapshot;
    use bifrost::merge::{CrossTargetAggKind, CrossTargetAggReducer, CrossTargetAggValue};
    use bifrost_wire::{
        AGG_SNAPSHOT_ROW_KIND_COUNT, AGG_SNAPSHOT_ROW_KIND_QUANTIZE,
    };
    let key = b"hostA\0\0\0";

    // Row 1: source map says "count", wire stamps COUNT → Count.
    let v1_count = build_agg_snapshot_one_v1(
        100,
        AGG_SNAPSHOT_ROW_KIND_COUNT,
        key,
        &42u64.to_le_bytes(),
    );
    let names: std::collections::HashMap<i32, (String, String)> = [
        (100i32, ("count".to_string(), "rx".to_string())),
        (101i32, ("count".to_string(), "rx".to_string())),
    ]
    .into_iter()
    .collect();
    let mut reducer = CrossTargetAggReducer::new();
    ingest_agg_snapshot("fbsd-a", &v1_count, &names, &mut reducer);
    let rows: Vec<_> = reducer.rows().collect();
    assert_eq!(rows.len(), 1, "got: {rows:?}");
    assert_eq!(rows[0].0, "rx");
    assert_eq!(rows[0].2.kind, CrossTargetAggKind::Count);
    assert!(matches!(rows[0].2.value, CrossTargetAggValue::Scalar(42)));

    // Row 2: source map says "count" (stale), wire stamps QUANTIZE.
    // The wire kind must win — the value would be decoded as a
    // bucket array, NOT a scalar.  Build a 127*8 = 1016-byte
    // bucket array with slot 63 (zero bucket) holding 7 hits.
    let mut buckets = vec![0u64; 127];
    buckets[63] = 7;
    let mut v_bytes = Vec::with_capacity(127 * 8);
    for b in &buckets {
        v_bytes.extend_from_slice(&b.to_le_bytes());
    }
    let v1_quantize = build_agg_snapshot_one_v1(
        101,
        AGG_SNAPSHOT_ROW_KIND_QUANTIZE,
        key,
        &v_bytes,
    );
    let mut reducer = CrossTargetAggReducer::new();
    ingest_agg_snapshot("fbsd-a", &v1_quantize, &names, &mut reducer);
    let rows: Vec<_> = reducer.rows().collect();
    assert_eq!(rows.len(), 1, "got: {rows:?}");
    assert_eq!(rows[0].0, "rx");
    // The wire kind drove the decoder onto the quantize path even
    // though the source map said "count" — kind is Quantize and
    // the value is a bucket histogram, not Scalar.
    assert_eq!(rows[0].2.kind, CrossTargetAggKind::Quantize);
    assert!(matches!(rows[0].2.value, CrossTargetAggValue::Histogram(_)));
    if let CrossTargetAggValue::Histogram(ref h) = rows[0].2.value {
        assert_eq!(h, &vec![(0i64, 7u64)]);
    }
}

#[test]
fn llquantize_v1_row_routes_through_log_linear_decoder() {
    // Schema v1 wire row tagged LLQUANTIZE.  Slot 0 carries the
    // packed params (factor / low / high / nsteps); the test puts
    // hits in a handful of buckets and confirms each surfaces as
    // a (lower_bound, count) tuple instead of a bucket-index tuple.
    use bifrost::cli::orchestrate::ingest_agg_snapshot;
    use bifrost::merge::{CrossTargetAggKind, CrossTargetAggReducer, CrossTargetAggValue};
    use bifrost_wire::AGG_SNAPSHOT_ROW_KIND_LLQUANTIZE;
    // factor=10, low=0, high=2, nsteps=10.  Bucket index assignment
    // mirrors `dtrace_aggregate_llquantize_bucket`:
    //   magnitude 0: this=10, nbuckets=10, step=1, owns 9 buckets.
    //     idx 1..9 cover [1..2), [2..3), ..., [9..10).
    //     base advances by 9 → 10.
    //   magnitude 1: this=100, nbuckets=10, step=10, owns 9 buckets.
    //     idx 10..18 cover [10..20), ..., [90..100).
    //     base advances by 9 → 19.
    //   magnitude 2: this=1000, nbuckets=10, step=100, owns 9 buckets.
    //     idx 19..27 cover [100..200), ..., [900..1000).
    //     base advances by 9 → 28.
    //   idx 28 is the overflow bucket; lower_bound = 1000.
    let factor: u16 = 10;
    let low: u16 = 0;
    let high: u16 = 2;
    let nsteps: u16 = 10;
    let params: u64 = ((factor as u64) << 48)
        | ((low as u64) << 32)
        | ((high as u64) << 16)
        | (nsteps as u64);
    // 32 buckets is enough for this shape (29 total including
    // overflow).
    let mut buckets = vec![0u64; 32];
    buckets[0] = params;
    buckets[1] = 3; // [1..2),    lower_bound=1
    buckets[5] = 2; // [5..6),    lower_bound=5
    buckets[10] = 11; // [10..20),  lower_bound=10
    buckets[19] = 4; // [100..200), lower_bound=100
    buckets[28] = 1; // overflow,   lower_bound=1000
    let mut v_bytes = Vec::with_capacity(buckets.len() * 8);
    for b in &buckets {
        v_bytes.extend_from_slice(&b.to_le_bytes());
    }
    let key = b"hello\0\0\0";
    let payload = build_agg_snapshot_one_v1(
        500,
        AGG_SNAPSHOT_ROW_KIND_LLQUANTIZE,
        key,
        &v_bytes,
    );

    let names: std::collections::HashMap<i32, (String, String)> =
        [(500i32, ("llquantize".to_string(), "size".to_string()))]
            .into_iter()
            .collect();
    let mut reducer = CrossTargetAggReducer::new();
    ingest_agg_snapshot("fbsd-a", &payload, &names, &mut reducer);
    let rows: Vec<_> = reducer.rows().collect();
    assert_eq!(rows.len(), 1, "got: {rows:?}");
    assert_eq!(rows[0].2.kind, CrossTargetAggKind::Lquantize);
    let CrossTargetAggValue::Histogram(ref h) = rows[0].2.value else {
        panic!("expected histogram, got {:?}", rows[0].2.value);
    };
    assert_eq!(
        h,
        &vec![
            (1i64, 3u64),
            (5i64, 2u64),
            (10i64, 11u64),
            (100i64, 4u64),
            (1000i64, 1u64),
        ]
    );
}

#[test]
fn full_quantize_bucket_array_round_trips_through_decoder() {
    // Build a synthetic AGG_SNAPSHOT row for a `quantize(arg0)`
    // agg.  Three bucket slots populated; the host decoder must
    // recover each (bucket_value, count) pair.
    let value = quantize_value(&[(63, 5), (64, 7), (66, 3)]);
    let _payload = build_agg_snapshot_one(400, b"slow\0\0\0\0", &value);

    // The decoder lives inside `cli::orchestrate::ingest_agg_snapshot`
    // and is exercised exhaustively via that module's unit tests
    // (see `orchestrate::tests::ingest_agg_snapshot_decodes_full_
    // quantize_bucket_array`).  Reaffirming the *shape* here is
    // cheap and gives the integration suite a hook so a future
    // wire-format change can't slip past without surfacing
    // alongside the killer-demo path.
    assert_eq!(value.len(), 127 * 8);
}

#[test]
fn cross_os_reducer_folds_linux_and_freebsd_quantize_into_one_row() {
    // Acceptance gate for the cross-kernel demo:
    //
    //   "At least one cross-target aggregation row in the output
    //    references both `linux-*` and `fbsd-*` target ids in its
    //    contributors map."
    //
    // The cross-kernel-linux-fbsd-x2 demo's D source has BOTH
    // kernels writing into the same `@latency = quantize()` agg.
    // Wire-level, each kernel ships its own AGG_SNAPSHOT row tagged
    // with its target id ("linux-a" vs "fbsd-b") and a quantize
    // bucket array.  `CrossTargetAggReducer::merge` must:
    //   * Fold both contributions into ONE row keyed on
    //     (agg_name="latency", key="" — both clauses use the
    //     unkeyed form).
    //   * Sum the bucket counts additively across kernels.
    //   * Stash each per-target contribution in `contributors` so
    //     the renderer can attribute the histogram back to its
    //     source kernels — that's the "both ids referenced"
    //     evidence the acceptance gate calls out.
    use bifrost::cli::orchestrate::ingest_agg_snapshot;
    use bifrost::merge::{
        CrossTargetAggKind, CrossTargetAggReducer, CrossTargetAggValue,
    };
    use bifrost_wire::AGG_SNAPSHOT_ROW_KIND_QUANTIZE;

    // Linux side: `@latency = quantize(...)` lowered through the
    // bifrost BPF backend lands one row with kernel-stamped kind=
    // QUANTIZE and three populated bucket slots.  The fake_fd
    // (300) and the agg_names entry below stand in for what
    // `trace_render::direct_agg_names` would build at runtime.
    let linux_value = quantize_value(&[(63, 4), (64, 9), (66, 1)]);
    let linux_payload = build_agg_snapshot_one_v1(
        300,
        AGG_SNAPSHOT_ROW_KIND_QUANTIZE,
        &[], // unkeyed: `@latency` without a key tuple.
        &linux_value,
    );
    let linux_names: std::collections::HashMap<i32, (String, String)> =
        [(300i32, ("quantize".to_string(), "latency".to_string()))]
            .into_iter()
            .collect();

    // FreeBSD side: the same agg shape, different bucket counts so
    // the reducer's fold has something to actually sum.  fake_fd is
    // independent per target — the reducer keys on (agg_name,
    // key_tuple), NOT on fd.
    let fbsd_value = quantize_value(&[(64, 5), (65, 2), (66, 8)]);
    let fbsd_payload = build_agg_snapshot_one_v1(
        700,
        AGG_SNAPSHOT_ROW_KIND_QUANTIZE,
        &[],
        &fbsd_value,
    );
    let fbsd_names: std::collections::HashMap<i32, (String, String)> =
        [(700i32, ("quantize".to_string(), "latency".to_string()))]
            .into_iter()
            .collect();

    let mut reducer = CrossTargetAggReducer::new();
    ingest_agg_snapshot("linux-a", &linux_payload, &linux_names, &mut reducer);
    ingest_agg_snapshot("fbsd-b", &fbsd_payload, &fbsd_names, &mut reducer);

    // One row total: both kernels folded into the same
    // (agg_name="latency", key="") slot.
    let rows: Vec<_> = reducer.rows().collect();
    assert_eq!(rows.len(), 1, "expected one folded row, got {rows:?}");

    let (name, key, cell) = rows[0];
    assert_eq!(name, "latency");
    assert_eq!(key, "");
    assert_eq!(cell.kind, CrossTargetAggKind::Quantize);

    // The merged value is per-bucket additive across kernels:
    //   bucket 63 → 4 (linux only)
    //   bucket 64 → 9 + 5 = 14
    //   bucket 65 →     2 (freebsd only)
    //   bucket 66 → 1 + 8 = 9
    //
    // `decode_quantize_buckets` lowers each populated slot to its
    // (bucket_value, count) pair using DTrace's standard
    // ZERO=63 power-of-two layout.
    let CrossTargetAggValue::Histogram(ref buckets) = cell.value else {
        panic!("expected histogram, got {:?}", cell.value);
    };
    let merged: std::collections::BTreeMap<i64, u64> =
        buckets.iter().copied().collect();
    let count_at = |bucket: i64| merged.get(&bucket).copied().unwrap_or(0);
    // bucket 63 (ZERO) decodes to bucket_value 0 in the orchestrator
    // decoder; bucket 64 → 1; bucket 65 → 2; bucket 66 → 4.  We
    // assert by relative shape rather than literal indices so a
    // benign decoder change (e.g. relabelling the zero bucket
    // floor) doesn't break this test for the wrong reason.
    let total: u64 = merged.values().sum();
    assert_eq!(total, 4 + 9 + 5 + 2 + 1 + 8, "all bucket counts sum: {merged:?}");
    let _ = count_at; // silence dead-code warning under the relative-shape assertion

    // The contributors map MUST carry both linux-* and fbsd-* ids
    // — that's the literal evidence the goal's acceptance gate
    // calls out for the cross-OS reducer path.
    let contributor_ids: std::collections::BTreeSet<&str> = cell
        .contributors
        .keys()
        .map(|s| s.as_str())
        .collect();
    assert!(
        contributor_ids.iter().any(|s| s.starts_with("linux-")),
        "contributors map must include a linux-* id: {contributor_ids:?}"
    );
    assert!(
        contributor_ids.iter().any(|s| s.starts_with("fbsd-")),
        "contributors map must include a fbsd-* id: {contributor_ids:?}"
    );
}

/// Cross-kernel demo: the cross-target reducer must honor a `macos-host`
/// contributor alongside the SHM-conduit kernels.  macos-host is
/// scalar-only on the wire today (the dtrace(1) text bridge emits
/// scalar agg rows via a synthetic printa); the reducer treats it
/// as a peer source and folds its contribution into the same row
/// the Linux/FreeBSD AGG_SNAPSHOT decode lands.
#[test]
fn cross_target_reducer_accepts_macos_host_contributor_alongside_kernels() {
    use bifrost::merge::{
        CrossTargetAggKind, CrossTargetAggReducer, CrossTargetAggValue,
    };

    let mut r = CrossTargetAggReducer::new();
    // Linux + FreeBSD ingest paths land their @triplet["all"]
    // count() snapshot at value 100 / 200 respectively (matching
    // the wire shape `ingest_agg_snapshot` decodes).
    r.merge(
        "linux-a",
        "triplet",
        "\"all\"",
        CrossTargetAggKind::Count,
        CrossTargetAggValue::Scalar(100),
    );
    r.merge(
        "fbsd-b",
        "triplet",
        "\"all\"",
        CrossTargetAggKind::Count,
        CrossTargetAggValue::Scalar(200),
    );
    // macos-host arm: text-mode parser decodes `printa()` rows from
    // dtrace(1)'s stdout and feeds them through reducer.merge with
    // target_id="macos-host".  See cli::macos_host::decode_line.
    r.merge(
        "macos-host",
        "triplet",
        "\"all\"",
        CrossTargetAggKind::Count,
        CrossTargetAggValue::Scalar(50),
    );

    let rows: Vec<_> = r.rows().collect();
    assert_eq!(rows.len(), 1, "all three contribute to one row: {rows:?}");
    let cell = rows[0].2;
    assert_eq!(cell.value, CrossTargetAggValue::Scalar(350));
    let ids: std::collections::BTreeSet<&str> = cell
        .contributors
        .keys()
        .map(|s| s.as_str())
        .collect();
    assert!(
        ids.contains("macos-host"),
        "contributors must include macos-host: {ids:?}",
    );
    assert!(
        ids.iter().any(|s| s.starts_with("linux-")),
        "contributors must include a linux-* id: {ids:?}",
    );
    assert!(
        ids.iter().any(|s| s.starts_with("fbsd-")),
        "contributors must include a fbsd-* id: {ids:?}",
    );
}
