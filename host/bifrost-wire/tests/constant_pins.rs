// Wire-format constant pins.  Lives in `tests/` rather than
// `#[cfg(test)] mod tests` inside lib.rs so the canonical
// lib.rs file is pure constants — vendored sites can symlink it
// without asking kernel-rust to parse a `mod tests` block (which
// would pull in `assert_eq!` and other std-only macros that
// the kernel rust ecosystem doesn't ship).

use bifrost_wire::*;

#[test]
fn bfr7_magic_pinned() {
    assert_eq!(&BFR7_MAGIC, b"BFR7");
    assert_eq!(BFR7_MAGIC_LE, 0x37524642);
    assert_eq!(u32::from_le_bytes(BFR7_MAGIC), BFR7_MAGIC_LE);
}

#[test]
fn probe_types_pinned() {
    assert_eq!(PROBE_TYPE_NONE, 0xff);
    assert_eq!(PROBE_TYPE_UPROBE, 2);
    assert_eq!(PROBE_TYPE_URETPROBE, 3);
    assert_eq!(PROBE_TYPE_UPROBE_BY_SYM, 4);
    assert_eq!(PROBE_TYPE_URETPROBE_BY_SYM, 5);
    assert_eq!(PROBE_TYPE_FENTRY, 6);
    assert_eq!(PROBE_TYPE_FEXIT, 7);
    assert_eq!(PROBE_TYPE_TRACEPOINT, 8);
    assert_eq!(PROBE_TYPE_USDT, 9);
}

#[test]
fn max_probe_slots_pinned() {
    // Soft-cap mirror of `SLOT_CAPACITY` in
    // drivers/bifrost/bifrost.rs.  After Phase C's heap migration
    // the driver allocates a `KVec<BifrostSlot>` of this size at
    // module init; growing the cap is a one-line bump in both
    // sources, no per-slot static fan-out to keep in sync.
    assert_eq!(MAX_PROBE_SLOTS, 256);
}

#[test]
fn agg_kinds_pinned() {
    assert_eq!(AGG_KIND_SUM, 0);
    assert_eq!(AGG_KIND_MIN, 1);
    assert_eq!(AGG_KIND_MAX, 2);
    assert_eq!(AGG_KIND_AVG, 3);
    assert_eq!(AGG_KIND_STDDEV, 4);
    assert_eq!(AGG_KIND_LQUANTIZE, 5);
    assert_eq!(AGG_KIND_LLQUANTIZE, 6);
}

#[test]
fn probe_ids_pinned() {
    assert_eq!(VMA_TABLE_PROBE_ID, 0xFFFFFFFF);
    assert_eq!(AGG_SNAPSHOT_PROBE_ID, 0xFFFFFFFD);
    assert_eq!(SYM_TABLE_PROBE_ID, 0xFFFFFFFC);
    // Historical alias kept for guest-side back-compat.
    assert_eq!(SYM_TABLE_PROBE_MAGIC, SYM_TABLE_PROBE_ID);
}

#[test]
fn probe_ids_distinct() {
    let ids = [
        VMA_TABLE_PROBE_ID,
        AGG_SNAPSHOT_PROBE_ID,
        SYM_TABLE_PROBE_ID,
    ];
    for (i, a) in ids.iter().enumerate() {
        for b in &ids[i + 1..] {
            assert_ne!(a, b, "probe-id collision: {:#x}", a);
        }
    }
}

#[test]
fn d4_kinds_pinned() {
    assert_eq!(D4_KIND_LOAD_PROG, 1);
    assert_eq!(D4_KIND_OBSERVER_ATTACH, 2);
    assert_eq!(D4_KIND_OBSERVER_DETACH, 3);
    assert_eq!(D4_KIND_RSP_OK, 100);
    assert_eq!(D4_KIND_RSP_ERR, 101);
    assert_eq!(D4_KIND_AGG_PUSH, 102);
    assert_eq!(D4_KIND_RECORD_PUSH, 103);
    assert_eq!(D4_KIND_LOAD_PROG_STATUS, 104);
    assert_eq!(D4_KIND_SELF_TRACE_PUSH, 105);
    assert_eq!(D4_KIND_PAD, 255);
}

#[test]
fn self_trace_constants_pinned() {
    // Self-trace probe IDs — must stay distinct from VMA / AGG /
    // SYM probe IDs and from each other.  Renumbering one
    // silently routes events to the wrong layer's renderer.
    assert_eq!(SELF_TRACE_DRIVER_PROBE_ID, 0xFFFFFFFB);
    assert_eq!(SELF_TRACE_LIBKRUN_PROBE_ID, 0xFFFFFFFA);
    assert_eq!(SELF_TRACE_CLI_PROBE_ID, 0xFFFFFFF9);
    // Subsystems — append-only; never reuse a discriminant.
    assert_eq!(SELF_SUBSYS_LOADPROG, 1);
    assert_eq!(SELF_SUBSYS_SLOT, 2);
    assert_eq!(SELF_SUBSYS_UPROBE, 3);
    assert_eq!(SELF_SUBSYS_FBT, 4);
    assert_eq!(SELF_SUBSYS_TRACEPT, 5);
    assert_eq!(SELF_SUBSYS_USDT, 6);
    assert_eq!(SELF_SUBSYS_AGG, 7);
    assert_eq!(SELF_SUBSYS_RECORD, 8);
    assert_eq!(SELF_SUBSYS_OBSERVER, 9);
    assert_eq!(SELF_SUBSYS_CONTROL, 10);
    assert_eq!(SELF_SUBSYS_PARSE, 11);
    assert_eq!(SELF_SUBSYS_LOWER, 12);
    assert_eq!(SELF_SUBSYS_RENDER, 13);
    // Levels — same shape as `tracing::Level`.
    assert_eq!(SELF_LEVEL_TRACE, 0);
    assert_eq!(SELF_LEVEL_DEBUG, 1);
    assert_eq!(SELF_LEVEL_INFO, 2);
    assert_eq!(SELF_LEVEL_WARN, 3);
    assert_eq!(SELF_LEVEL_ERROR, 4);
    // Field types — first four for v1.  Adding a new type means
    // appending; the decoder forward-compats unknown types as
    // Bytes (rolling-upgrade friendly).
    assert_eq!(SELF_FIELD_U64, 0);
    assert_eq!(SELF_FIELD_I64, 1);
    assert_eq!(SELF_FIELD_BYTES, 2);
    assert_eq!(SELF_FIELD_BOOL, 3);
}

#[test]
fn self_trace_probe_ids_distinct_from_other_probe_ids() {
    // Cross-check: self-trace IDs must not collide with the
    // existing VMA / AGG / SYM probe IDs.  All five live in the
    // same u32 namespace and a collision would silently misroute.
    let all = [
        VMA_TABLE_PROBE_ID,
        AGG_SNAPSHOT_PROBE_ID,
        SYM_TABLE_PROBE_ID,
        SELF_TRACE_DRIVER_PROBE_ID,
        SELF_TRACE_LIBKRUN_PROBE_ID,
        SELF_TRACE_CLI_PROBE_ID,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "probe-id collision: {:#x}", a);
        }
    }
}

#[test]
fn loadprog_status_pinned() {
    // Pinned because the values flow across the wire and a silent
    // renumber would silently miscategorize per-program failures
    // (turning a real verifier_fail into a phantom slot_exhausted,
    // for instance).  Add new variants by appending; never reuse
    // a value.
    assert_eq!(RSP_LOADPROG_STATUS_OK, 0);
    assert_eq!(RSP_LOADPROG_STATUS_SLOT_EXHAUSTED, 1);
    assert_eq!(RSP_LOADPROG_STATUS_JIT_FAIL, 2);
    assert_eq!(RSP_LOADPROG_STATUS_BTF_RESOLVE_FAIL, 3);
    assert_eq!(RSP_LOADPROG_STATUS_VERIFIER_FAIL, 4);
    assert_eq!(RSP_LOADPROG_STATUS_TARGET_NOT_FOUND, 5);
    assert_eq!(RSP_LOADPROG_STATUS_OTHER, 99);
}

#[test]
fn shmem_record_layout_pinned() {
    assert_eq!(SHMEM_MAGIC, 0x48534642);
    // V5: per-class drop attribution.  Per-CPU state is 128 bytes
    // to hold `dropped_records[4]` and `dropped_bytes[4]` arrays
    // indexed by SHMEM_DROP_CLASS_*.
    assert_eq!(SHMEM_VERSION, 5);
    assert_eq!(SHMEM_NUM_CPUS_MAX, 16);
    assert_eq!(SHMEM_PER_CPU_STATE_OFF, 128);
    assert_eq!(SHMEM_PER_CPU_STATE_STRIDE, 128);
    assert_eq!(SHMEM_RECORD_HDR_SIZE, 8);
    assert_eq!(SHMEM_RECORD_FLAG_READY, 1);
    assert_eq!(SHMEM_RECORD_FLAG_PADDING, 2);
    assert_eq!(SHMEM_RECORD_MAX_PAYLOAD, 65536);
}

#[test]
fn shmem_drop_class_pinned() {
    // Per-class drop attribution.  Mirror of
    // `BIFROST_DROP_CLASS_*` in kernel/bpf/helpers.c.  Renumbering
    // any of these silently mis-attributes drops to the wrong
    // workload class — append-only, never reuse.
    assert_eq!(SHMEM_DROP_CLASS_PRINCIPAL, 0);
    assert_eq!(SHMEM_DROP_CLASS_AGG, 1);
    assert_eq!(SHMEM_DROP_CLASS_STKSTR, 2);
    assert_eq!(SHMEM_DROP_CLASS_DBLERR, 3);
    assert_eq!(SHMEM_DROP_CLASS_MAX, 4);
}

#[test]
fn observer_hello_kinds_pinned() {
    // CMD-side HELLO and RSP-side HELLO_ACK numeric values flow
    // across the wire and back; renumbering either silently breaks
    // capability negotiation across mismatched binaries.  Allocate
    // new control-ring kinds by appending; never reuse.
    assert_eq!(D4_KIND_OBSERVER_HELLO, 4);
    assert_eq!(D4_KIND_OBSERVER_HELLO_ACK, 106);
}

#[test]
fn wire_version_seed_pinned() {
    // The seed values are part of the wire ABI: a CLI rebuilt against
    // a different `BIFROST_WIRE_MAJOR` will refuse to talk to a driver
    // pinned at the old major.  Bumping these is intentional; the
    // pin catches accidental edits.
    assert_eq!(BIFROST_WIRE_MAJOR, 1);
    assert_eq!(BIFROST_WIRE_MINOR, 0);
}

#[test]
fn feature_bits_pinned() {
    // Each FEATURE_* value is a bit position — the value (1 << N)
    // is what's serialized in the HELLO/HELLO_ACK feature_bits u64.
    // Renaming a bit is fine; renumbering one silently corrupts
    // capability negotiation across mismatched binaries.  Allocate
    // new bits by appending; never reuse a position.
    assert_eq!(FEATURE_HANDSHAKE_V1, 1 << 0);
    assert_eq!(FEATURE_EXTENSIBLE_RECORDS, 1 << 1);

    assert_eq!(FEATURE_LOADPROG_STATUS, 1 << 16);
    assert_eq!(FEATURE_SELF_TRACE_EMIT, 1 << 17);
    assert_eq!(FEATURE_USDT, 1 << 18);
    assert_eq!(FEATURE_FBT, 1 << 19);
    assert_eq!(FEATURE_RAWTP, 1 << 20);
    assert_eq!(FEATURE_UPROBE_BY_SYM, 1 << 21);
}

#[test]
fn feature_baseline_covers_current_features() {
    // The baseline is the union of every FEATURE_* the current
    // codebase produces or consumes.  When a new feature lands,
    // its bit should be added to BASELINE in the same change so
    // current-generation peers advertise it by default.
    let expected = FEATURE_HANDSHAKE_V1
        | FEATURE_EXTENSIBLE_RECORDS
        | FEATURE_LOADPROG_STATUS
        | FEATURE_SELF_TRACE_EMIT
        | FEATURE_USDT
        | FEATURE_FBT
        | FEATURE_RAWTP
        | FEATURE_UPROBE_BY_SYM;
    assert_eq!(FEATURE_BASELINE, expected);
}

#[test]
fn hello_reject_reasons_pinned() {
    // A renumber here would silently miscategorize handshake
    // refusals (turning a real wire_major_mismatch into a phantom
    // observer_busy, for instance).  0 is reserved for "accepted".
    assert_eq!(HELLO_REJECT_WIRE_MAJOR_MISMATCH, 1);
    assert_eq!(HELLO_REJECT_MISSING_REQUIRED_FEATURE, 2);
    assert_eq!(HELLO_REJECT_OBSERVER_BUSY, 3);
    assert_eq!(HELLO_REJECT_OTHER, 99);
}

#[test]
fn profile_sample_kind_pinned() {
    // CMD/RSP-side D4_KIND for profile-N samples.  Renumbering
    // silently misroutes the stream — a CLI pinned to 107 would
    // suddenly start decoding a different record's bytes as a
    // ProfileSampleView.
    assert_eq!(D4_KIND_PROFILE_SAMPLE, 107);
    assert_eq!(PROFILE_SAMPLE_PROBE_ID, 0xFFFFFFF8);
}

#[test]
fn profile_sample_flags_pinned() {
    // Each PROFILE_SAMPLE_FLAG_* is a bit position in the per-sample
    // flags u32.  Bit values flow across the wire; renumbering would
    // silently re-interpret kernel samples as user, etc.
    assert_eq!(PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT, 1 << 0);
    assert_eq!(PROFILE_SAMPLE_FLAG_STACK_TRUNCATED, 1 << 1);
    assert_eq!(PROFILE_SAMPLE_FLAG_STACK_INCOMPLETE, 1 << 2);
}

#[test]
fn profile_sample_max_frames_pinned() {
    // The cap bounds the per-sample emit buffer at the libkrun side
    // and the frame-iter capacity at the CLI side.  Tunable upward
    // intentionally; the pin catches accidental edits.
    assert_eq!(MAX_PROFILE_FRAMES, 256);
}

#[test]
fn multi_observer_and_profile_n_features_pinned() {
    // FEATURE_MULTI_OBSERVER occupies the next bit after the Phase B/H
    // record-kind block (bits 16..21).  FEATURE_PROFILE_N opens the
    // provider-catalog tier at bit 32.  Renumbering either changes
    // what a peer's HELLO advertises and silently mis-negotiates.
    assert_eq!(FEATURE_MULTI_OBSERVER, 1 << 22);
    assert_eq!(FEATURE_PROFILE_N, 1 << 32);
    // Neither is in the BASELINE — both are forward-looking
    // capabilities that today's peers don't yet advertise.
    assert_eq!(FEATURE_BASELINE & FEATURE_MULTI_OBSERVER, 0);
    assert_eq!(FEATURE_BASELINE & FEATURE_PROFILE_N, 0);
}

#[test]
fn profile_sample_probe_id_distinct_from_other_probe_ids() {
    // Cross-check: PROFILE_SAMPLE_PROBE_ID must not collide with the
    // existing reserved IDs in the same u32 namespace.
    let all = [
        VMA_TABLE_PROBE_ID,
        AGG_SNAPSHOT_PROBE_ID,
        SYM_TABLE_PROBE_ID,
        SELF_TRACE_DRIVER_PROBE_ID,
        SELF_TRACE_LIBKRUN_PROBE_ID,
        SELF_TRACE_CLI_PROBE_ID,
        PROFILE_SAMPLE_PROBE_ID,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "probe-id collision: {:#x}", a);
        }
    }
}

#[test]
fn field_reloc_access_kinds_pinned() {
    // Wire-level discriminants — renumbering would silently
    // re-interpret an OFFSET reloc as a SIZE one (or worse), and
    // every program patched after the rename would read garbage.
    assert_eq!(FIELD_RELOC_OFFSET, 0);
    assert_eq!(FIELD_RELOC_SIZE, 1);
    assert_eq!(FIELD_RELOC_EXISTS, 2);
}

#[test]
fn field_reloc_name_max_pinned() {
    // u8 length prefix on the wire; bumping the cap is a wire change
    // (move to u16 length prefix).  The pin catches accidental edits
    // that would silently truncate names without a wire bump.
    assert_eq!(FIELD_RELOC_NAME_MAX, 255);
}

#[test]
fn program_flag_field_relocs_present_pinned() {
    // Reserves bit 8 of BifrostProgramHeader::flags for the
    // Phase N.2 wrapper-body integration.  Today's WrapperBuilder
    // doesn't set the bit; old decoders ignore it.  Renumbering
    // collides with probe_type (low byte) or some future extension
    // bit and silently mis-routes.
    assert_eq!(PROGRAM_FLAG_FIELD_RELOCS_PRESENT, 1 << 8);
    // Must NOT collide with the probe_type byte (low 8 bits).
    assert_eq!(PROGRAM_FLAG_FIELD_RELOCS_PRESENT & 0xff, 0);
}

#[test]
fn feature_btf_field_reloc_pinned() {
    // Bit 33 — provider-catalog tier (32..47), one above
    // FEATURE_PROFILE_N.  Today's BASELINE does NOT include this
    // bit; peers must opt in explicitly.
    assert_eq!(FEATURE_BTF_FIELD_RELOC, 1 << 33);
    assert_eq!(FEATURE_BASELINE & FEATURE_BTF_FIELD_RELOC, 0);
}
