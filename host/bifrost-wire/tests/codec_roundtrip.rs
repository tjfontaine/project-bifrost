// Round-trip tests for the BFR7 codec.
#![cfg(all(feature = "codec", feature = "alloc"))]
//
// Encode a wrapper, decode it, assert every field survived.
// Runs against both `Vec<u8>` (alloc) and `SliceSink` (no_std) sinks
// so the encoder's sink-genericity is exercised at test time.
//
// These tests do not pin specific bytes — that is the
// `host/bifrost/tests/wrapper_golden.rs` job.  The codec layer's
// contract is "encode and decode are inverses"; byte stability is
// pinned at the consumer layer where the schema bytes also matter.

use bifrost_wire::codec::*;

fn empty_schema_bytes() -> Vec<u8> {
    Vec::new()
}

#[test]
fn empty_wrapper_roundtrip() {
    let mut sink = Vec::<u8>::new();
    let _b = WrapperBuilder::new(&mut sink, 0).unwrap();
    drop(_b);

    assert_eq!(&sink[..4], b"BFR7");
    assert_eq!(u32::from_le_bytes(sink[4..8].try_into().unwrap()), 0);

    let mut iter = decode_bfr7(&sink).unwrap();
    assert!(iter.next().is_none());
}

#[test]
fn fbt_wrapper_roundtrip() {
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        field_relocs: &[],
        target_name: "do_sys_openat2",
        probe_type: 6, // PROBE_TYPE_FENTRY
        trailer: TrailerSpec::None,
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[],
    })
    .unwrap();

    let mut iter = decode_bfr7(&sink).unwrap();
    let p = iter.next().unwrap().unwrap();
    let nul = p.target_name.iter().position(|&b| b == 0).unwrap_or(32);
    assert_eq!(&p.target_name[..nul], b"do_sys_openat2");
    assert_eq!(p.probe_type, 6);
    assert!(matches!(p.trailer, TrailerView::None));
    assert_eq!(p.num_maps, 0);
    assert_eq!(p.num_insns, 0);
    assert!(iter.next().is_none());
}

#[test]
fn host_resolved_uprobe_roundtrip() {
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        field_relocs: &[],
        target_name: "redis-cli-PING",
        probe_type: 2,
        trailer: TrailerSpec::Path {
            path: "/usr/bin/redis-server",
            file_offset: 0xdeadbeef,
        },
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[],
    })
    .unwrap();

    let p = decode_bfr7(&sink).unwrap().next().unwrap().unwrap();
    match p.trailer {
        TrailerView::Path { path, file_offset } => {
            assert_eq!(path, b"/usr/bin/redis-server");
            assert_eq!(file_offset, 0xdeadbeef);
        }
        other => panic!("wrong trailer: {:?}", other),
    }
}

#[test]
fn kernel_resolved_uprobe_by_sym_roundtrip() {
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        field_relocs: &[],
        target_name: "rdb_save",
        probe_type: 4,
        trailer: TrailerSpec::Symbol {
            basename: "redis-server",
            symbol: "rdbSaveBackground",
        },
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[],
    })
    .unwrap();

    let p = decode_bfr7(&sink).unwrap().next().unwrap().unwrap();
    match p.trailer {
        TrailerView::Symbol { basename, symbol } => {
            assert_eq!(basename, b"redis-server");
            assert_eq!(symbol, b"rdbSaveBackground");
        }
        other => panic!("wrong trailer: {:?}", other),
    }
}

#[test]
fn usdt_roundtrip() {
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        field_relocs: &[],
        target_name: "transaction__commit",
        probe_type: 9,
        trailer: TrailerSpec::Usdt {
            basename: "postgres",
            provider: "postgresql",
            probe: "transaction__commit",
        },
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[],
    })
    .unwrap();

    let p = decode_bfr7(&sink).unwrap().next().unwrap().unwrap();
    match p.trailer {
        TrailerView::Usdt {
            basename,
            provider,
            probe,
        } => {
            assert_eq!(basename, b"postgres");
            assert_eq!(provider, b"postgresql");
            assert_eq!(probe, b"transaction__commit");
        }
        other => panic!("wrong trailer: {:?}", other),
    }
}

#[test]
fn maps_and_insns_roundtrip() {
    let schema = empty_schema_bytes();
    let insns: Vec<u8> = (0..16).map(|i: u8| i).collect(); // 2 fake instructions
    let maps = [
        MapSpec {
            map_type: 1,
            key_size: 4,
            value_size: 8,
            max_entries: 1024,
            fake_fd: -3,
            name: "by_pid",
        },
        MapSpec {
            map_type: 2,
            key_size: 8,
            value_size: 16,
            max_entries: 256,
            fake_fd: -4,
            name: "min\0qlat",
        },
    ];
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        field_relocs: &[],
        target_name: "t",
        probe_type: 6,
        trailer: TrailerSpec::None,
        schema_bytes: &schema,
        maps: &maps,
        insns: &insns,
        kfunc_relocs: &[],
    })
    .unwrap();

    let p = decode_bfr7(&sink).unwrap().next().unwrap().unwrap();
    assert_eq!(p.num_maps, 2);
    assert_eq!(p.maps_bytes.len(), 2 * 52);
    assert_eq!(p.num_insns, 2);
    assert_eq!(p.insns, insns.as_slice());
    // Per-map decode: first 20 bytes are the MapDef, then 32-byte name.
    assert_eq!(
        u32::from_le_bytes(p.maps_bytes[0..4].try_into().unwrap()),
        1
    );
    assert_eq!(
        i32::from_le_bytes(p.maps_bytes[16..20].try_into().unwrap()),
        -3
    );
    assert_eq!(&p.maps_bytes[20..26], b"by_pid");
    // Second map name has an embedded NUL.
    assert_eq!(&p.maps_bytes[52 + 20..52 + 20 + 8], b"min\0qlat");
}

#[test]
fn kfunc_relocs_roundtrip() {
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        field_relocs: &[],
        target_name: "t",
        probe_type: 6,
        trailer: TrailerSpec::None,
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[(7, "bpf_get_current_pid_tgid"), (12, "bpf_ringbuf_reserve")],
    })
    .unwrap();

    let p = decode_bfr7(&sink).unwrap().next().unwrap().unwrap();
    let r = p.kfunc_relocs_bytes;
    // [u32 num=2][u32 7][u8 24][24 bytes][u32 12][u8 19][19 bytes]
    assert_eq!(u32::from_le_bytes(r[0..4].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(r[4..8].try_into().unwrap()), 7);
    assert_eq!(r[8], 24);
    assert_eq!(&r[9..9 + 24], b"bpf_get_current_pid_tgid");
    let after = 9 + 24;
    assert_eq!(
        u32::from_le_bytes(r[after..after + 4].try_into().unwrap()),
        12
    );
    assert_eq!(r[after + 4], 19);
    assert_eq!(&r[after + 5..after + 5 + 19], b"bpf_ringbuf_reserve");
}

#[test]
fn rejects_non_bfr7_magic() {
    let mut bad = b"BFR6".to_vec();
    bad.extend_from_slice(&[0u8; 4]);
    let err = decode_bfr7(&bad).unwrap_err();
    assert!(matches!(err, WireError::UnsupportedMagic(b) if b == *b"BFR6"));
}

#[test]
fn rejects_short_wrapper() {
    let bad = b"BFR".to_vec();
    let err = decode_bfr7(&bad).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "wrapper-header",
            ..
        }
    ));
}

#[test]
fn rejects_oversize_kfunc_name() {
    let schema = empty_schema_bytes();
    let big = "x".repeat(300);
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    let err = b
        .push_program(&ProgramSpec {
            field_relocs: &[],
            target_name: "t",
            probe_type: 6,
            trailer: TrailerSpec::None,
            schema_bytes: &schema,
            maps: &[],
            insns: &[],
            kfunc_relocs: &[(0, &big)],
        })
        .unwrap_err();
    assert!(matches!(err, WireError::KfuncNameOutOfRange { len: 300 }));
}

#[test]
fn rejects_unknown_probe_type_on_decode() {
    let mut bytes = b"BFR7".to_vec();
    bytes.extend_from_slice(&1u32.to_le_bytes()); // num_progs
    bytes.extend_from_slice(&[0u8; 32]); // target_name
    bytes.extend_from_slice(&100u32.to_le_bytes()); // bogus probe type 100
    let err = decode_bfr7(&bytes).unwrap().next().unwrap().unwrap_err();
    assert!(matches!(err, WireError::BadProbeType { ty: 100 }));
}

#[test]
fn slice_sink_roundtrip() {
    let mut buf = [0u8; 256];
    let written = {
        let mut sink = SliceSink::new(&mut buf);
        let _ = WrapperBuilder::new(&mut sink, 0).unwrap();
        sink.written()
    };
    assert_eq!(written, 8);
    assert_eq!(&buf[..4], b"BFR7");

    // Decode from the slice we just wrote into.
    let mut iter = decode_bfr7(&buf[..written]).unwrap();
    assert!(iter.next().is_none());
}

#[test]
fn slice_sink_truncates_when_too_small() {
    let mut buf = [0u8; 4]; // only space for magic, not num_progs
    let mut sink = SliceSink::new(&mut buf);
    let err = WrapperBuilder::new(&mut sink, 0).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "slice-sink",
            ..
        }
    ));
}

#[test]
fn loadprog_status_roundtrip_empty() {
    let mut sink = Vec::<u8>::new();
    encode_loadprog_status(&mut sink, &[]).unwrap();
    // [u32 LE 0]
    assert_eq!(sink.len(), 4);
    assert_eq!(u32::from_le_bytes(sink[..4].try_into().unwrap()), 0);
    let view = decode_loadprog_status(&sink).unwrap();
    assert_eq!(view.entries.len(), 0);
}

#[test]
fn loadprog_status_roundtrip_mixed() {
    use bifrost_wire::{
        RSP_LOADPROG_STATUS_BTF_RESOLVE_FAIL, RSP_LOADPROG_STATUS_JIT_FAIL,
        RSP_LOADPROG_STATUS_OK, RSP_LOADPROG_STATUS_SLOT_EXHAUSTED,
    };
    let entries: &[(u8, &[u8])] = &[
        (RSP_LOADPROG_STATUS_OK, b""),
        (RSP_LOADPROG_STATUS_OK, b""),
        (RSP_LOADPROG_STATUS_SLOT_EXHAUSTED, b""),
        (RSP_LOADPROG_STATUS_JIT_FAIL, b"verifier rejected r1 at insn 42"),
        (
            RSP_LOADPROG_STATUS_BTF_RESOLVE_FAIL,
            b"bpf_probe_read_user_kfunc",
        ),
    ];
    let mut sink = Vec::<u8>::new();
    encode_loadprog_status(&mut sink, entries).unwrap();
    // 4 + per-entry (1 status + 2 len + detail_len)
    // 4 + (3) + (3) + (3) + (3+31) + (3+25) = 4 + 9 + 34 + 28 = 75
    assert_eq!(sink.len(), 4 + 9 + 34 + 28);
    let view = decode_loadprog_status(&sink).unwrap();
    assert_eq!(view.entries.len(), 5);
    assert_eq!(view.entries[3].status, RSP_LOADPROG_STATUS_JIT_FAIL);
    assert_eq!(view.entries[3].detail, b"verifier rejected r1 at insn 42");
    assert_eq!(view.entries[4].detail, b"bpf_probe_read_user_kfunc");
}

#[test]
fn loadprog_status_truncated_count() {
    let bad = [0u8, 0u8]; // only 2 bytes — count needs 4
    let err = decode_loadprog_status(&bad).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "loadprog-status-count",
            ..
        }
    ));
}

#[test]
fn loadprog_status_truncated_entry_header() {
    // count claims 5 but body has only 2 bytes (need 3 for first entry hdr)
    let mut bad = Vec::new();
    bad.extend_from_slice(&5u32.to_le_bytes());
    bad.push(0);
    bad.push(1);
    let err = decode_loadprog_status(&bad).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "loadprog-status-entry-header",
            ..
        }
    ));
}

#[test]
fn loadprog_status_truncated_entry_detail() {
    // count=1, status=0, detail_len=10, but only 3 detail bytes present
    let mut bad = Vec::new();
    bad.extend_from_slice(&1u32.to_le_bytes());
    bad.push(0);
    bad.extend_from_slice(&10u16.to_le_bytes());
    bad.extend_from_slice(b"abc");
    let err = decode_loadprog_status(&bad).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "loadprog-status-entry-detail",
            ..
        }
    ));
}

#[test]
fn loadprog_status_label_known_and_unknown() {
    use bifrost_wire::{
        RSP_LOADPROG_STATUS_OK, RSP_LOADPROG_STATUS_OTHER, RSP_LOADPROG_STATUS_SLOT_EXHAUSTED,
    };
    assert_eq!(loadprog_status_label(RSP_LOADPROG_STATUS_OK), "ok");
    assert_eq!(
        loadprog_status_label(RSP_LOADPROG_STATUS_SLOT_EXHAUSTED),
        "slot_exhausted"
    );
    assert_eq!(loadprog_status_label(RSP_LOADPROG_STATUS_OTHER), "other");
    assert_eq!(loadprog_status_label(200), "other"); // unknown → other
}

#[test]
fn self_trace_event_roundtrip_no_fields() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_event(
        &mut sink,
        SELF_LEVEL_INFO,
        SELF_SUBSYS_LOADPROG,
        b"slot exhausted",
        &[],
    )
    .unwrap();

    let view = decode_event(&sink).unwrap();
    assert_eq!(view.level, SELF_LEVEL_INFO);
    assert_eq!(view.subsystem, SELF_SUBSYS_LOADPROG);
    assert_eq!(view.msg, b"slot exhausted");
    assert!(view.fields().next().is_none());
}

#[test]
fn self_trace_event_roundtrip_mixed_fields() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_event(
        &mut sink,
        SELF_LEVEL_ERROR,
        SELF_SUBSYS_UPROBE,
        b"uprobe attach failed",
        &[
            (b"slot", SelfFieldOwned::U64(7)),
            (b"target", SelfFieldOwned::Bytes(b"redis-server")),
            (b"errno", SelfFieldOwned::I64(-22)),
            (b"retried", SelfFieldOwned::Bool(true)),
        ],
    )
    .unwrap();

    let view = decode_event(&sink).unwrap();
    assert_eq!(view.level, SELF_LEVEL_ERROR);
    assert_eq!(view.subsystem, SELF_SUBSYS_UPROBE);
    assert_eq!(view.msg, b"uprobe attach failed");

    let mut fields: Vec<_> = view.fields().map(|r| r.unwrap()).collect();
    assert_eq!(fields.len(), 4);

    let f0 = fields.remove(0);
    assert_eq!(f0.key, b"slot");
    match f0.value {
        SelfFieldValue::U64(7) => {}
        other => panic!("wrong slot value: {:?}", other),
    }
    let f1 = fields.remove(0);
    assert_eq!(f1.key, b"target");
    match f1.value {
        SelfFieldValue::Bytes(b) => assert_eq!(b, b"redis-server"),
        other => panic!("wrong target value: {:?}", other),
    }
    let f2 = fields.remove(0);
    assert_eq!(f2.key, b"errno");
    match f2.value {
        SelfFieldValue::I64(-22) => {}
        other => panic!("wrong errno value: {:?}", other),
    }
    let f3 = fields.remove(0);
    assert_eq!(f3.key, b"retried");
    match f3.value {
        SelfFieldValue::Bool(true) => {}
        other => panic!("wrong retried value: {:?}", other),
    }
}

#[test]
fn self_trace_event_into_slice_sink() {
    use bifrost_wire::*;
    let mut buf = [0u8; SELF_TRACE_MAX_BODY];
    let written = {
        let mut sink = SliceSink::new(&mut buf);
        encode_event(
            &mut sink,
            SELF_LEVEL_DEBUG,
            SELF_SUBSYS_AGG,
            b"agg snapshot",
            &[(b"rows", SelfFieldOwned::U64(42))],
        )
        .unwrap();
        sink.written()
    };
    let view = decode_event(&buf[..written]).unwrap();
    assert_eq!(view.level, SELF_LEVEL_DEBUG);
    assert_eq!(view.subsystem, SELF_SUBSYS_AGG);
    assert_eq!(view.msg, b"agg snapshot");
    let f0 = view.fields().next().unwrap().unwrap();
    assert_eq!(f0.key, b"rows");
    match f0.value {
        SelfFieldValue::U64(42) => {}
        other => panic!("{:?}", other),
    }
}

#[test]
fn self_trace_truncated_header() {
    let bad = [0u8; 4]; // need 6 for the header
    let err = decode_event(&bad).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "self-event-header",
            ..
        }
    ));
}

#[test]
fn self_trace_truncated_msg() {
    use bifrost_wire::*;
    // header claims msg_len = 100, but we only supply 6 + 2 = 8 bytes
    let mut bad = Vec::new();
    bad.push(SELF_LEVEL_INFO);
    bad.push(SELF_SUBSYS_LOADPROG);
    bad.extend_from_slice(&0u16.to_le_bytes()); // num_fields
    bad.extend_from_slice(&100u16.to_le_bytes()); // msg_len
    bad.extend_from_slice(b"AB"); // only 2 bytes of msg
    let err = decode_event(&bad).unwrap_err();
    assert!(matches!(
        err,
        WireError::Truncated {
            at: "self-event-msg",
            ..
        }
    ));
}

#[test]
fn self_trace_unknown_field_type_is_bytes() {
    use bifrost_wire::*;
    // Hand-crafted: one field with key "x", value_type=200 (unknown).
    // Forward-compat path renders this as Bytes — rolling upgrades
    // see future field types as opaque bytes rather than hard fail.
    let mut bad = Vec::new();
    bad.push(SELF_LEVEL_INFO);
    bad.push(SELF_SUBSYS_LOADPROG);
    bad.extend_from_slice(&1u16.to_le_bytes()); // num_fields
    bad.extend_from_slice(&3u16.to_le_bytes()); // msg_len
    bad.extend_from_slice(b"hi!");
    bad.extend_from_slice(&1u16.to_le_bytes()); // key_len
    bad.push(b'x');
    bad.push(200); // unknown value_type
    bad.extend_from_slice(&2u16.to_le_bytes()); // value_len
    bad.push(0xAB);
    bad.push(0xCD);
    let view = decode_event(&bad).unwrap();
    let f0 = view.fields().next().unwrap().unwrap();
    assert_eq!(f0.key, b"x");
    match f0.value {
        SelfFieldValue::Bytes(b) => assert_eq!(b, &[0xAB, 0xCD]),
        other => panic!("expected Bytes for unknown type, got {:?}", other),
    }
}

#[test]
fn self_level_and_subsystem_labels() {
    use bifrost_wire::*;
    assert_eq!(self_level_label(SELF_LEVEL_INFO), "info");
    assert_eq!(self_level_label(SELF_LEVEL_ERROR), "error");
    assert_eq!(self_level_label(99), "???");
    assert_eq!(self_subsystem_label(SELF_SUBSYS_USDT), "usdt");
    assert_eq!(self_subsystem_label(SELF_SUBSYS_OBSERVER), "observer");
    assert_eq!(self_subsystem_label(99), "???");
}

#[test]
fn shmem_record_hdr_roundtrip() {
    let mut buf = [0u8; bifrost_wire::SHMEM_RECORD_HDR_SIZE];
    shmem_record_hdr_encode(&mut buf, 0xDEADBEEF, bifrost_wire::SHMEM_RECORD_FLAG_READY);
    let h = shmem_record_hdr_decode(&buf).unwrap();
    // Pull packed-struct fields into locals before asserting —
    // packed structs forbid taking references to fields.
    let size = h.size;
    let flags = h.flags;
    assert_eq!(size, 0xDEADBEEF);
    assert_eq!(flags, bifrost_wire::SHMEM_RECORD_FLAG_READY);
}

#[test]
fn hello_roundtrip_no_fields() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_hello(
        &mut sink,
        BIFROST_WIRE_MAJOR,
        BIFROST_WIRE_MINOR,
        FEATURE_BASELINE,
        &[],
    )
    .unwrap();

    let view = decode_hello(&sink).unwrap();
    assert_eq!(view.wire_major, BIFROST_WIRE_MAJOR);
    assert_eq!(view.wire_minor, BIFROST_WIRE_MINOR);
    assert_eq!(view.feature_bits, FEATURE_BASELINE);
    assert!(view.fields().next().is_none());
}

#[test]
fn hello_roundtrip_with_extension_fields() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_hello(
        &mut sink,
        BIFROST_WIRE_MAJOR,
        BIFROST_WIRE_MINOR,
        FEATURE_BASELINE,
        &[
            (b"host_pid", SelfFieldOwned::U64(53413)),
            (b"host_uid", SelfFieldOwned::U64(501)),
            (
                b"required_features",
                SelfFieldOwned::U64(FEATURE_LOADPROG_STATUS | FEATURE_USDT),
            ),
        ],
    )
    .unwrap();

    let view = decode_hello(&sink).unwrap();
    let fields: Vec<_> = view.fields().map(|r| r.unwrap()).collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].key, b"host_pid");
    match fields[0].value {
        SelfFieldValue::U64(53413) => {}
        other => panic!("wrong host_pid: {:?}", other),
    }
    assert_eq!(fields[2].key, b"required_features");
    match fields[2].value {
        SelfFieldValue::U64(v) => assert_eq!(v, FEATURE_LOADPROG_STATUS | FEATURE_USDT),
        other => panic!("wrong required_features: {:?}", other),
    }
}

#[test]
fn hello_truncated_header() {
    // Only 17 bytes — needs at least 18 for major + minor + feature_bits + num_fields.
    let buf = [0u8; 17];
    match decode_hello(&buf) {
        Err(WireError::Truncated {
            at: "hello-header", ..
        }) => {}
        other => panic!("expected hello-header truncated error, got {:?}", other),
    }
}

#[test]
fn hello_ack_roundtrip_accepted() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_hello_ack(
        &mut sink,
        true,
        0,
        BIFROST_WIRE_MAJOR,
        BIFROST_WIRE_MINOR,
        FEATURE_BASELINE,
        &[],
    )
    .unwrap();

    let view = decode_hello_ack(&sink).unwrap();
    assert!(view.accepted);
    assert_eq!(view.reject_reason, 0);
    assert_eq!(view.wire_major, BIFROST_WIRE_MAJOR);
    assert_eq!(view.wire_minor, BIFROST_WIRE_MINOR);
    assert_eq!(view.feature_bits, FEATURE_BASELINE);
    assert!(view.fields().next().is_none());
}

#[test]
fn hello_ack_roundtrip_rejected_with_reason() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_hello_ack(
        &mut sink,
        false,
        HELLO_REJECT_WIRE_MAJOR_MISMATCH,
        BIFROST_WIRE_MAJOR,
        BIFROST_WIRE_MINOR,
        // Driver advertises only handshake itself + extensible-records;
        // CLI required something more, gets refused.
        FEATURE_HANDSHAKE_V1 | FEATURE_EXTENSIBLE_RECORDS,
        &[(
            b"reason",
            SelfFieldOwned::Bytes(b"driver wire_major=2, observer wire_major=1"),
        )],
    )
    .unwrap();

    let view = decode_hello_ack(&sink).unwrap();
    assert!(!view.accepted);
    assert_eq!(view.reject_reason, HELLO_REJECT_WIRE_MAJOR_MISMATCH);
    let fields: Vec<_> = view.fields().map(|r| r.unwrap()).collect();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].key, b"reason");
    match fields[0].value {
        SelfFieldValue::Bytes(b) => assert_eq!(b, b"driver wire_major=2, observer wire_major=1"),
        other => panic!("wrong reason: {:?}", other),
    }
}

#[test]
fn hello_ack_truncated_header() {
    // 19 bytes — needs at least 20 for accepted + reject_reason +
    // major + minor + feature_bits + num_fields.
    let buf = [0u8; 19];
    match decode_hello_ack(&buf) {
        Err(WireError::Truncated {
            at: "hello-ack-header",
            ..
        }) => {}
        other => panic!("expected hello-ack-header truncated error, got {:?}", other),
    }
}

#[test]
fn hello_reject_labels() {
    use bifrost_wire::*;
    assert_eq!(hello_reject_label(0), "ok");
    assert_eq!(
        hello_reject_label(HELLO_REJECT_WIRE_MAJOR_MISMATCH),
        "wire_major_mismatch"
    );
    assert_eq!(
        hello_reject_label(HELLO_REJECT_MISSING_REQUIRED_FEATURE),
        "missing_required_feature"
    );
    assert_eq!(
        hello_reject_label(HELLO_REJECT_OBSERVER_BUSY),
        "observer_busy"
    );
    assert_eq!(hello_reject_label(HELLO_REJECT_OTHER), "other");
    assert_eq!(hello_reject_label(50), "unknown");
}

#[test]
fn hello_into_slice_sink() {
    use bifrost_wire::*;
    // HELLO body fits comfortably in 256 bytes for a typical
    // 3-extension-field shape; this exercises the no-alloc path
    // a kernel-side encoder will use.
    let mut buf = [0u8; 256];
    let written = {
        let mut sink = SliceSink::new(&mut buf);
        encode_hello(
            &mut sink,
            BIFROST_WIRE_MAJOR,
            BIFROST_WIRE_MINOR,
            FEATURE_BASELINE,
            &[
                (b"host_pid", SelfFieldOwned::U64(53413)),
                (b"flag", SelfFieldOwned::Bool(true)),
            ],
        )
        .unwrap();
        sink.written()
    };
    let view = decode_hello(&buf[..written]).unwrap();
    assert_eq!(view.wire_major, BIFROST_WIRE_MAJOR);
    let fields: Vec<_> = view.fields().map(|r| r.unwrap()).collect();
    assert_eq!(fields.len(), 2);
}

#[test]
fn profile_sample_roundtrip_empty() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_profile_sample(&mut sink, 1234, 5678, 2, 0, &[]).unwrap();
    let view = decode_profile_sample(&sink).unwrap();
    assert_eq!(view.pid, 1234);
    assert_eq!(view.tid, 5678);
    assert_eq!(view.cpu_id, 2);
    assert_eq!(view.flags, 0);
    assert_eq!(view.num_frames, 0);
    assert!(view.frames().next().is_none());
}

#[test]
fn profile_sample_roundtrip_with_stack() {
    use bifrost_wire::*;
    let pcs: [u64; 4] = [
        0xffff_ff80_0010_0000, // kernel VA
        0xffff_ff80_0010_0080,
        0xffff_ff80_0011_0000,
        0xffff_ff80_0012_0000,
    ];
    let mut sink = Vec::<u8>::new();
    encode_profile_sample(
        &mut sink,
        53413,
        53413,
        0,
        PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT,
        &pcs,
    )
    .unwrap();
    let view = decode_profile_sample(&sink).unwrap();
    assert_eq!(view.pid, 53413);
    assert_eq!(view.flags, PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT);
    assert_eq!(view.num_frames, 4);
    let collected: Vec<u64> = view.frames().collect();
    assert_eq!(collected, pcs.to_vec());
}

#[test]
fn profile_sample_truncated_header() {
    use bifrost_wire::*;
    // 19 bytes; needs at least 20 for the fixed header.
    let buf = [0u8; 19];
    match decode_profile_sample(&buf) {
        Err(WireError::Truncated {
            at: "profile-sample-header",
            ..
        }) => {}
        other => panic!(
            "expected profile-sample-header truncated error, got {:?}",
            other
        ),
    }
}

#[test]
fn profile_sample_truncated_frames() {
    use bifrost_wire::*;
    // Header says num_frames=3 but only 2 frames-worth of bytes follow.
    let mut buf: Vec<u8> = Vec::with_capacity(36);
    buf.extend_from_slice(&1u32.to_le_bytes()); // pid
    buf.extend_from_slice(&1u32.to_le_bytes()); // tid
    buf.extend_from_slice(&0u32.to_le_bytes()); // cpu
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&3u32.to_le_bytes()); // num_frames=3
    buf.extend_from_slice(&[0u8; 16]); // 2 frames worth
    match decode_profile_sample(&buf) {
        Err(WireError::Truncated {
            at: "profile-sample-frames",
            need: 44,
            have: 36,
        }) => {}
        other => panic!(
            "expected profile-sample-frames truncated error, got {:?}",
            other
        ),
    }
}

#[test]
fn profile_sample_too_many_frames_rejected() {
    use bifrost_wire::*;
    let big = vec![0u64; MAX_PROFILE_FRAMES + 1];
    let mut sink = Vec::<u8>::new();
    match encode_profile_sample(&mut sink, 0, 0, 0, 0, &big) {
        Err(WireError::Truncated {
            at: "profile-sample-num-frames",
            ..
        }) => {}
        other => panic!("expected num-frames-cap rejection, got {:?}", other),
    }
}

#[test]
fn profile_sample_into_slice_sink() {
    use bifrost_wire::*;
    // Bound the slice at exactly the encoded size for a 32-frame
    // sample: 20 (header) + 32*8 = 276 bytes.
    let mut buf = [0u8; 276];
    let pcs: Vec<u64> = (0..32).map(|i| 0x1000 + i as u64 * 0x40).collect();
    let written = {
        let mut sink = SliceSink::new(&mut buf);
        encode_profile_sample(&mut sink, 1, 1, 0, 0, &pcs).unwrap();
        sink.written()
    };
    assert_eq!(written, 276);
    let view = decode_profile_sample(&buf[..written]).unwrap();
    let collected: Vec<u64> = view.frames().collect();
    assert_eq!(collected, pcs);
}

#[test]
fn profile_sample_flags_labels() {
    use bifrost_wire::*;
    assert_eq!(profile_sample_flags_label(0), "");
    assert_eq!(
        profile_sample_flags_label(PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT),
        "kernel"
    );
    assert_eq!(
        profile_sample_flags_label(PROFILE_SAMPLE_FLAG_STACK_TRUNCATED),
        "truncated"
    );
    assert_eq!(
        profile_sample_flags_label(
            PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT | PROFILE_SAMPLE_FLAG_STACK_TRUNCATED
        ),
        "kernel,truncated"
    );
}

#[test]
fn field_relocs_roundtrip_empty() {
    use bifrost_wire::*;
    let mut sink = Vec::<u8>::new();
    encode_field_relocs(&mut sink, &[]).unwrap();
    let iter = decode_field_relocs(&sink).unwrap();
    let collected: Vec<_> = iter.collect();
    assert!(collected.is_empty());
}

#[test]
fn field_relocs_roundtrip_mixed_kinds() {
    use bifrost_wire::*;
    let inputs = &[
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
    ];
    let mut sink = Vec::<u8>::new();
    encode_field_relocs(&mut sink, inputs).unwrap();

    let mut iter = decode_field_relocs(&sink).unwrap();
    let r0 = iter.next().unwrap().unwrap();
    assert_eq!(r0.insn_idx, 8);
    assert_eq!(r0.access_kind, FIELD_RELOC_OFFSET);
    assert_eq!(r0.byte_off_in_insn, 4);
    assert_eq!(r0.struct_name, b"task_struct");
    assert_eq!(r0.field_name, b"comm");

    let r1 = iter.next().unwrap().unwrap();
    assert_eq!(r1.access_kind, FIELD_RELOC_SIZE);
    assert_eq!(r1.struct_name, b"mm_struct");
    assert_eq!(r1.field_name, b"start_brk");

    let r2 = iter.next().unwrap().unwrap();
    assert_eq!(r2.access_kind, FIELD_RELOC_EXISTS);
    assert_eq!(r2.field_name, b"android_kabi_reserved1");
    assert!(iter.next().is_none());
}

#[test]
fn field_relocs_truncated_count() {
    // Less than 4 bytes ⇒ truncated count header.
    let buf = [0u8; 3];
    match decode_field_relocs(&buf) {
        Err(WireError::Truncated {
            at: "field-relocs-count",
            ..
        }) => {}
        other => panic!("expected field-relocs-count truncated, got {:?}", other),
    }
}

#[test]
fn field_relocs_truncated_record_header() {
    // Count says 1 but only 6 bytes follow (need 8 for record header).
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 6]);
    let mut iter = decode_field_relocs(&buf).unwrap();
    match iter.next().unwrap() {
        Err(WireError::Truncated {
            at: "field-reloc-record-header",
            ..
        }) => {}
        other => panic!("expected record-header truncated, got {:?}", other),
    }
    // Subsequent next() returns None after a failure.
    assert!(iter.next().is_none());
}

#[test]
fn field_relocs_truncated_names() {
    // Header says struct_name_len=4, field_name_len=4, but no name bytes.
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&8u32.to_le_bytes()); // insn_idx
    buf.push(bifrost_wire::FIELD_RELOC_OFFSET);
    buf.push(4); // byte_off
    buf.push(4); // struct_name_len
    buf.push(4); // field_name_len
    // missing 8 bytes of name payload
    let mut iter = decode_field_relocs(&buf).unwrap();
    match iter.next().unwrap() {
        Err(WireError::Truncated {
            at: "field-reloc-names",
            ..
        }) => {}
        other => panic!("expected names truncated, got {:?}", other),
    }
}

#[test]
fn field_relocs_empty_struct_name_rejected() {
    let mut sink = Vec::<u8>::new();
    let inputs = &[FieldRelocInput {
        insn_idx: 0,
        access_kind: bifrost_wire::FIELD_RELOC_OFFSET,
        byte_off_in_insn: 0,
        struct_name: "",
        field_name: "x",
    }];
    match encode_field_relocs(&mut sink, inputs) {
        Err(WireError::Truncated {
            at: "field-reloc-struct-name-len",
            ..
        }) => {}
        other => panic!("expected struct-name-len reject, got {:?}", other),
    }
}

#[test]
fn field_relocs_oversized_field_name_rejected() {
    let mut sink = Vec::<u8>::new();
    let big = "x".repeat(bifrost_wire::FIELD_RELOC_NAME_MAX + 1);
    let inputs = &[FieldRelocInput {
        insn_idx: 0,
        access_kind: bifrost_wire::FIELD_RELOC_OFFSET,
        byte_off_in_insn: 0,
        struct_name: "task_struct",
        field_name: big.as_str(),
    }];
    match encode_field_relocs(&mut sink, inputs) {
        Err(WireError::Truncated {
            at: "field-reloc-field-name-len",
            ..
        }) => {}
        other => panic!("expected field-name-len reject, got {:?}", other),
    }
}

#[test]
fn field_reloc_kind_labels() {
    use bifrost_wire::*;
    assert_eq!(field_reloc_kind_label(FIELD_RELOC_OFFSET), "offset");
    assert_eq!(field_reloc_kind_label(FIELD_RELOC_SIZE), "size");
    assert_eq!(field_reloc_kind_label(FIELD_RELOC_EXISTS), "exists");
    assert_eq!(field_reloc_kind_label(99), "???");
}

#[test]
fn field_relocs_into_slice_sink() {
    use bifrost_wire::*;
    // Bound the slice at the encoded size for a 2-record sample
    // with short names — exercises the no_std path.
    let mut buf = [0u8; 256];
    let written = {
        let mut sink = SliceSink::new(&mut buf);
        encode_field_relocs(
            &mut sink,
            &[
                FieldRelocInput {
                    insn_idx: 0,
                    access_kind: FIELD_RELOC_OFFSET,
                    byte_off_in_insn: 4,
                    struct_name: "task",
                    field_name: "pid",
                },
                FieldRelocInput {
                    insn_idx: 16,
                    access_kind: FIELD_RELOC_SIZE,
                    byte_off_in_insn: 4,
                    struct_name: "task",
                    field_name: "comm",
                },
            ],
        )
        .unwrap();
        sink.written()
    };
    let mut iter = decode_field_relocs(&buf[..written]).unwrap();
    let r0 = iter.next().unwrap().unwrap();
    assert_eq!(r0.struct_name, b"task");
    assert_eq!(r0.field_name, b"pid");
    let r1 = iter.next().unwrap().unwrap();
    assert_eq!(r1.field_name, b"comm");
}

#[test]
fn wrapper_with_field_relocs_roundtrip() {
    use bifrost_wire::*;
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        target_name: "do_sys_openat2",
        probe_type: 6, // FENTRY
        trailer: TrailerSpec::None,
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[],
        field_relocs: &[
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
                struct_name: "task_struct",
                field_name: "pid",
            },
        ],
    })
    .unwrap();
    drop(b);

    let mut iter = decode_bfr7(&sink).unwrap();
    let p = iter.next().unwrap().unwrap();
    // Encoder set the FIELD_RELOCS_PRESENT bit.
    assert!(p.flags & PROGRAM_FLAG_FIELD_RELOCS_PRESENT != 0);
    // Field-relocs body parses via the standalone decode.
    let mut fr_iter = decode_field_relocs(p.field_relocs_bytes).unwrap();
    let r0 = fr_iter.next().unwrap().unwrap();
    assert_eq!(r0.struct_name, b"task_struct");
    assert_eq!(r0.field_name, b"comm");
    let r1 = fr_iter.next().unwrap().unwrap();
    assert_eq!(r1.access_kind, FIELD_RELOC_SIZE);
    assert_eq!(r1.field_name, b"pid");
    assert!(fr_iter.next().is_none());
}

#[test]
fn wrapper_without_field_relocs_unchanged_shape() {
    // Verify that programs with empty field_relocs neither set the
    // flag bit nor append a field-relocs section — old decoders
    // see byte-equivalent output.
    use bifrost_wire::*;
    let schema = empty_schema_bytes();
    let mut sink = Vec::<u8>::new();
    let mut b = WrapperBuilder::new(&mut sink, 1).unwrap();
    b.push_program(&ProgramSpec {
        target_name: "do_sys_openat2",
        probe_type: 6,
        trailer: TrailerSpec::None,
        schema_bytes: &schema,
        maps: &[],
        insns: &[],
        kfunc_relocs: &[],
        field_relocs: &[],
    })
    .unwrap();
    drop(b);

    let p = decode_bfr7(&sink).unwrap().next().unwrap().unwrap();
    assert_eq!(p.flags & PROGRAM_FLAG_FIELD_RELOCS_PRESENT, 0);
    assert!(p.field_relocs_bytes.is_empty());
}
