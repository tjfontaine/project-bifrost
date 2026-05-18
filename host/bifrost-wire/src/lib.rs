// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// Wire-format contract for the Bifrost semantic protocol.
//
// ## Protocol arc
//
// A bifrost session has four temporal phases:
//
//   1. *HELLO handshake.*  Observer side sends
//      `D4_KIND_OBSERVER_HELLO`; the driver replies with
//      `D4_KIND_HELLO_ACK` carrying `(wire_major, wire_minor,
//      feature_bits)`.  `wire_major` mismatch refuses the session;
//      `wire_minor` is informational and `feature_bits` is the
//      canonical capability vocabulary.  A `CANONICAL_SHA256` pin
//      catches same-major drift in the core schema.
//
//   2. *LOAD_PROG cohort.*  The CLI builds a BFR7 wrapper
//      bundling one or more eBPF programs (and the per-program
//      probe-type discriminants); libkrun ferries the bytes
//      opaquely.  The driver replies with `RSP_OK` synchronously
//      once the wrapper parses.  Per-program attach status arrives
//      asynchronously as `D4_KIND_LOAD_PROG_STATUS` once every
//      slot has resolved, carrying a `[u8; num_progs]` array of
//      `RSP_LOADPROG_STATUS_*` codes so partial failures cannot
//      hide behind the synchronous RSP_OK.
//
//   3. *Record streaming.*  BPF programs produce records into a
//      per-CPU SHMEM ringbuf using the SPSC handshake described
//      in `host/bifrost/src/control_shmem.rs`; an asynchronous
//      push channel (`D4_KIND_AGG_PUSH`, `D4_KIND_RECORD_PUSH`,
//      `D4_KIND_SELF_TRACE_PUSH`) carries pre-formatted text
//      lines that bypass the rate-limited uprobe path so high-
//      rate records still reach the CLI reliably.
//
//   4. *Drop accounting and trailer.*  Each per-CPU sub-ring
//      maintains 4-element drop arrays indexed by
//      `SHMEM_DROP_CLASS_*` (PRINCIPAL / AGG / STKSTR / DBLERR),
//      so the host can attribute which workload class is
//      overflowing.  At termination the CLI snapshots the
//      headers, dumps any pending xagg state, and tears the
//      session down — there is no explicit GOODBYE; the rings
//      simply stop being read.
//
// ## Why the codec lives in sibling files
//
// `codec_*.rs` files split the codec by record kind (`codec_load
// _prog.rs`, `codec_hello.rs`, ...).  Encode functions own the
// allocation; decode functions return *view* types that borrow
// the input buffer rather than copying it, so a record passes
// from on-the-wire bytes to the CLI's renderer without an
// allocation per record.  The borrow lifetime ties every field
// of a `RecordView` back to the original `&[u8]`.
//
// ## Canonical source
//
// This file is the **canonical** source.  Other layers consume
// it:
//
//   guest kernel module:
//     third_party/linux-bifrost/drivers/bifrost/wire.rs
//       — VENDORED COPY with a SHA-pinned header.  The kernel
//         build runs inside a krunvm with only libkrunfw/ mounted,
//         so a symlink to host/bifrost-wire/src/lib.rs would not
//         resolve at build time.  Vendoring + SHA pin gives the
//         same anti-drift guarantee with manual sync discipline;
//         the pin is audited by scripts/check-proto-drift.sh.
//
//   libkrun (vmm/devices crate):
//     Does **not** consume this file.  The libkrun-side virtio
//     adapter at third_party/smolvm/libkrun/src/devices/src/
//     virtio/conduit/mod.rs treats Bifrost LOAD_PROG payloads as
//     opaque bytes; only the **generic** virtio-conduit transport
//     constants (KIND_*, ring layout) cross the libkrun boundary,
//     and those live in host/virtio-conduit/, not here.
//
// Tests for the constants live in
// `host/bifrost-wire/tests/constant_pins.rs` (out of this file
// so kernel-rust isn't asked to parse a `mod tests` block that
// references std-only macros).
//
// Dual SPDX header: Apache-2.0 (host crate convention) OR
// GPL-2.0 (kernel module requirement).  An interface-contract
// constants file with no executable code is small and uses no
// proprietary APIs; dual-licensing avoids a copyright headache
// when the same bytes ship in both licensing contexts.
//
// `#![no_std]` so this lives equally well in the host CLI's full
// std crate and the guest kernel module.
//
// Visibility: `pub` is correct on the canonical/host side (the
// crate root re-exports it).  Kernel-rust warns "unreachable pub
// item" on inner modules — the guest's `mod wire;` declaration
// adds `#[allow(unreachable_pub)]` to suppress it.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

// =====================================================================
// BFR7 wrapper magic.  The first four bytes of every BFR7 wire payload.
// =====================================================================

/// "BFR7" little-endian.  Per the host emit at
/// `host/bifrost/src/cli/wrapper.rs::build_wrapper_bytes` and
/// the libkrun parse at
/// `third_party/smolvm/libkrun/src/devices/src/virtio/bifrost/
/// payload.rs::parse_wrapper_with_btf`.
pub const BFR7_MAGIC: [u8; 4] = *b"BFR7";

/// Same value as `BFR7_MAGIC` interpreted as a little-endian u32,
/// for callers that prefer a numeric magic check.  `0x37524642` =
/// '7','R','F','B' read low-to-high.
pub const BFR7_MAGIC_LE: u32 = u32::from_le_bytes(*b"BFR7");

/// Opaque CLI-built LOAD_PROG batch. This wraps one or more guest
/// LOAD_PROG payloads that are already in the kernel driver's inner
/// command format, allowing the VMM to ferry bytes without parsing
/// BFR7 or record schemas.
pub const LOAD_PROG_BATCH_MAGIC: [u8; 4] = *b"BLP3";
pub const LOAD_PROG_BATCH_MAGIC_LE: u32 = u32::from_le_bytes(*b"BLP3");

// =====================================================================
// Per-program probe-type discriminants.  Low byte of the BFR7
// wrapper's `flags` field.
// =====================================================================

/// Sentinel for an unused slot — `BIFROST_PROBE_TYPES` defaults to
/// this so that the cleanup walker (which iterates
/// `0..BIFROST_NUM_KPROBES`) can no-op on slots that were
/// allocated but never registered.  No live probe ever takes this
/// value.
pub const PROBE_TYPE_NONE: u8 = 0xff;
// PROBE_TYPE_KPROBE (0) and PROBE_TYPE_KRETPROBE (1) retired from
// the kernel-side dispatch: kprobe int3 attach is no longer the
// canonical kernel-function probe shape in bifrost — fbt
// (FENTRY/FEXIT trampoline) covers regular functions and
// tracepoints (PROBE_TYPE_TRACEPOINT) reach the notrace-marked
// targets that kprobe used to.
//
// Wire-format compatibility: the codec in `codec.rs` and the
// `wrapper_golden.rs` test fixtures still accept probe_type 0/1
// with an empty trailer. This is *decode-only compatibility* so
// older recorded BFR7 wrappers (and the canonical minimal golden)
// remain parseable; no live host path produces a 0/1 wrapper and
// the kernel has no dispatch arm for them. Treat 0/1 the same way
// you would treat any retired-but-grandfathered enum value: do
// not introduce new producers.
pub const PROBE_TYPE_UPROBE: u8 = 2;
pub const PROBE_TYPE_URETPROBE: u8 = 3;
/// Kernel-resolved uprobes: the host CLI sends just (basename,
/// symbol_name) in the BFR7 trailer; the driver finds the matching
/// running task by comm, grabs its exe_file, parses ELF, computes
/// the file offset itself, then registers the uprobe.
pub const PROBE_TYPE_UPROBE_BY_SYM: u8 = 4;
pub const PROBE_TYPE_URETPROBE_BY_SYM: u8 = 5;
/// Function-boundary tracing via the BPF trampoline (BPF_TRACE_FENTRY/
/// FEXIT).
pub const PROBE_TYPE_FENTRY: u8 = 6;
pub const PROBE_TYPE_FEXIT: u8 = 7;
/// Raw tracepoint attach via `bpf_probe_register` against the
/// per-event `bpf_raw_event_map` resolved by `bpf_get_raw_tracepoint`.
pub const PROBE_TYPE_TRACEPOINT: u8 = 8;
/// Soft cap on the number of probe slots the driver can register
/// concurrently.  The driver's slot table is a heap-allocated
/// `KVec<BifrostSlot>`; this constant is
/// the initial capacity sized at module load.  Mirrors
/// `SLOT_CAPACITY` in
/// `third_party/linux-bifrost/drivers/bifrost/bifrost.rs`.
///
/// The CLI's preflight check still uses this value to refuse
/// over-cap wrappers before LOAD_PROG so the user gets a fast,
/// actionable failure rather than a per-program SLOT_EXHAUSTED
/// trickle.  Bumping this to a larger soft cap (or wiring the
/// driver to grow on demand) is now a one-line change since the
/// underlying storage is heap-backed.
pub const MAX_PROBE_SLOTS: usize = 256;

/// Userspace statically-defined tracing — `usdt:<domain>:<binary>:
/// <provider>:<probe>`. Wire shape is a uprobe at a host-resolved
/// file offset plus a `ref_ctr_offset` (the `.note.stapsdt`
/// semaphore offset). The kernel atomically increments the
/// semaphore on attach so the SDT probe body actually fires; without
/// this, postgres-style `STAP_PROBE` macros short-circuit when no
/// consumer is registered.  Trailer (after the 36-byte BFR7 program
/// header):
///
///   u32 path_len, path_bytes (≤256), u64 file_offset, u64 ref_ctr_offset
///
/// One D clause may expand to multiple LOAD_PROG entries — a single
/// USDT probe name can have multiple call sites in `.note.stapsdt`,
/// each gets its own registration.
pub const PROBE_TYPE_USDT: u8 = 9;

/// Profile-timer attach.  The host emits `profile:::tick-Nms` /
/// `profile:::tick-Nsec` clauses as a BPF_PROG_TYPE_PERF_EVENT
/// program; the guest module opens one per-CPU
/// `perf_event_create_kernel_counter` of type PERF_TYPE_SOFTWARE /
/// PERF_COUNT_SW_CPU_CLOCK with `sample_period = period_ns`, and
/// attaches the BPF program via the perf_event ioctl
/// (`PERF_EVENT_IOC_SET_BPF`).  Trailer (after the 36-byte BFR7
/// program header):
///
///   u64 period_ns
///
/// Needed for the one-shared-clause demo shape
/// (`profile:::tick-100ms { @latency = quantize(...); }` routed to
/// every kernel, no per-OS clause split).
pub const PROBE_TYPE_PROFILE_TIMER: u8 = 10;

// =====================================================================
// Aggregation-kind discriminants.  Stored in the per-map flags
// byte; the guest's snapshot worker dispatches reduce-by-kind.
// =====================================================================

pub const AGG_KIND_SUM: u8 = 0;
pub const AGG_KIND_MIN: u8 = 1;
pub const AGG_KIND_MAX: u8 = 2;
pub const AGG_KIND_AVG: u8 = 3;
/// `stddev()` aggregation. Per-CPU slot is
/// `[n:u64][sum:u64][sum_of_squares:u64]` (value_size = 24);
/// snapshot rows carry the full 24 bytes so the host xagg
/// renderer can compute
/// `sqrt((sum_sq * n - sum*sum) / (n * (n-1)))` at render time.
pub const AGG_KIND_STDDEV: u8 = 4;
/// `lquantize()` aggregation. Linear-bucket histogram — per-CPU
/// slot is a single u64 bucket counter; map is a PERCPU_ARRAY of
/// 64 buckets keyed on `bucket_id: u32`.  Bucket boundaries
/// (`base`, `step`, `levels`) live in `xagg::LquantizeParams`
/// registered at clause-parse time and applied at render time.
pub const AGG_KIND_LQUANTIZE: u8 = 5;
/// `llquantize()` aggregation. Log-linear-bucket histogram —
/// map shape matches `AGG_KIND_LQUANTIZE`; bucket boundaries
/// (`factor`, `low_mag`, `high_mag`, `steps_per_mag`) live in
/// `xagg::LlquantizeParams`.
pub const AGG_KIND_LLQUANTIZE: u8 = 6;
/// `quantize()` aggregation (power-of-two histogram).
/// Map shape is `BPF_MAP_TYPE_PERCPU_ARRAY` with key=u32 0 and
/// value=`DTRACE_QUANTIZE_NBUCKETS * sizeof(u64) = 1016` bytes —
/// one slot per bucket.  The BPF lowering looks up the single
/// per-CPU value array, indexes by computed bucket-id, and atomic-
/// adds 1.  The kernel-side snapshot writer ships ONE row per
/// (name, user-key) with the full 1016-byte bucket array as the
/// value, which the host decodes via `decode_quantize_buckets`.
/// User-key (empty for `@latency = quantize(...)`) lives at the
/// `k_size`/`key_bytes` slot just like scalar aggs.
pub const AGG_KIND_QUANTIZE: u8 = 7;
/// Number of buckets in a DTrace `quantize()` aggregation —
/// `sizeof(u64) * NBBY - 1` per `sys/dtrace.h` on a 64-bit kernel
/// (NBBY=8 → 63 zero-bucket index + 64 positive buckets = 127).
pub const DTRACE_QUANTIZE_NBUCKETS: usize = 127;
/// Per-CPU value size for the Linux quantize map: 127 u64 buckets.
pub const QUANTIZE_VALUE_SIZE: u32 = (DTRACE_QUANTIZE_NBUCKETS * 8) as u32;

// =====================================================================
// SHMEM record probe-id magics.  Stored at offset 4 of every
// SHMEM record header; the libkrun-side consumer routes on these
// before schema dispatch.
// =====================================================================

/// Per-process VMA-table push from the guest's uprobe-register path.
pub const VMA_TABLE_PROBE_ID: u32 = 0xFFFFFFFF;

/// Aggregation-snapshot record.
pub const AGG_SNAPSHOT_PROBE_ID: u32 = 0xFFFFFFFD;

// =====================================================================
// AGG_SNAPSHOT schema versioning + per-row kind discriminant.
//
// Schema v1 stamps a `dtbar_action`-equivalent byte into every per-
// entry row so the host no longer has to infer the aggregation kind
// from a regex over the user's D source (the
// `cli::agg_decl` scanner).  The schema version lives in the
// previously-reserved u64 at sub-header offset 16.
//
// Kernel writers (FreeBSD `bifrost_conduit_publish_agg_snapshot`,
// Linux `agg_snapshot::push_agg_snapshot`) translate their internal
// action discriminants to these stable wire values.  The host's
// `cli::orchestrate::ingest_agg_snapshot` detects the schema and
// dispatches accordingly.
// =====================================================================

/// Schema version stamped at AGG_SNAPSHOT sub-header offset 16.
///   v0 = legacy per-row `{ fd, k_size, key, v_size, value }`
///   v1 = per-row `{ fd, kind, reserved[3], k_size, key, v_size, value }`
pub const AGG_SNAPSHOT_SCHEMA_V0: u64 = 0;
pub const AGG_SNAPSHOT_SCHEMA_V1: u64 = 1;

/// Per-row kind discriminant for schema v1+.  Stable across kernels
/// — both the FreeBSD bridge and the Linux agg snapshotter
/// translate to these values when writing the wire.
pub const AGG_SNAPSHOT_ROW_KIND_UNKNOWN: u8 = 0;
pub const AGG_SNAPSHOT_ROW_KIND_COUNT: u8 = 1;
pub const AGG_SNAPSHOT_ROW_KIND_SUM: u8 = 2;
pub const AGG_SNAPSHOT_ROW_KIND_MIN: u8 = 3;
pub const AGG_SNAPSHOT_ROW_KIND_MAX: u8 = 4;
pub const AGG_SNAPSHOT_ROW_KIND_AVG: u8 = 5;
pub const AGG_SNAPSHOT_ROW_KIND_STDDEV: u8 = 6;
pub const AGG_SNAPSHOT_ROW_KIND_QUANTIZE: u8 = 7;
pub const AGG_SNAPSHOT_ROW_KIND_LQUANTIZE: u8 = 8;
pub const AGG_SNAPSHOT_ROW_KIND_LLQUANTIZE: u8 = 9;

/// Per-binary function-symbol-table push from the guest's
/// uprobe-register path.  See drivers/bifrost/bifrost_helpers.c
/// for the body wire format.
pub const SYM_TABLE_PROBE_ID: u32 = 0xFFFFFFFC;

/// Historical alias for `SYM_TABLE_PROBE_ID`.  The `_MAGIC` suffix
/// predates the canonical `_ID` rename; existing guest-side call
/// sites still reference the old name.  Kept as a compile-time
/// alias (same bytes, just two paths to the value) so we don't
/// have to rename every reference site at once.
pub const SYM_TABLE_PROBE_MAGIC: u32 = SYM_TABLE_PROBE_ID;

// =====================================================================
// Self-trace probe IDs (Bifrost-on-Bifrost diagnostics).  Reserved
// IDs at the top of the u32 namespace, just below the existing
// *_PROBE_ID range, so user records can never collide.
//
// Records with these probe IDs ride the same SHMEM ringbuf as
// user trace records — the only thing that distinguishes them is
// the probe_id at offset 4 of the record header.  The host CLI's
// `--trace-self` flag filters records on these IDs and renders
// them to stderr instead of stdout.
//
// The body wire format (decoded by `bifrost_wire::codec::self_trace`)
// is a structured event:
//   u8  level                       (SELF_LEVEL_*)
//   u8  subsystem                   (SELF_SUBSYS_*)
//   u16 num_fields
//   u16 msg_len
//   [u8; msg_len] msg               (UTF-8 short summary, ≤ 256 bytes)
//   field × num_fields:
//     u16 key_len
//     [u8; key_len] key             (UTF-8 short identifier)
//     u8  value_type                (SELF_FIELD_*)
//     u16 value_len                 (always present even for U64/I64)
//     [u8; value_len] value
//
// "msg" is a short summary; fields carry structured key=value
// payload.  Avoids the eternal "did the message text change?"
// diff problem.
// =====================================================================

/// Self-trace event from the guest kernel module.
pub const SELF_TRACE_DRIVER_PROBE_ID: u32 = 0xFFFFFFFB;
/// Self-trace event from the libkrun virtio bifrost device.
pub const SELF_TRACE_LIBKRUN_PROBE_ID: u32 = 0xFFFFFFFA;
/// Self-trace event from the host CLI.
pub const SELF_TRACE_CLI_PROBE_ID: u32 = 0xFFFFFFF9;
/// Profile-N sampling probe.  Records carry a periodic
/// stack snapshot of the running vcpu, captured by libkrun on a
/// timer interrupt rather than by an in-guest probe — that's the
/// hypervisor's superpower.  Body wire format:
///
/// ```text
///   [u32 pid]                 guest task pid (0 = idle / no current)
///   [u32 tid]                 guest task tid
///   [u32 cpu_id]              vcpu index
///   [u32 flags]               bit 0 = sample taken in kernel context;
///                             bits 1..31 reserved (zero on emit).
///   [u32 num_frames]
///   [u64 frame_pc; num_frames]
/// ```
///
/// `frame_pc` values are guest-side instruction pointers — kernel VAs
/// or user VAs — that the host CLI symbolicates via kallsyms (kernel)
/// or the per-task symtab side-channel (user).  `flags & 1 == 1`
/// short-circuits to kernel-symbol lookup; otherwise the
/// pid → exe_file → BFD-resolved VMA table mapping wins.
pub const PROFILE_SAMPLE_PROBE_ID: u32 = 0xFFFFFFF8;

// Subsystem tags — closed enum, every layer agrees on these names.
// Allocate by appending; never reuse a discriminant.
pub const SELF_SUBSYS_LOADPROG: u8 = 1;
pub const SELF_SUBSYS_SLOT: u8 = 2;
pub const SELF_SUBSYS_UPROBE: u8 = 3;
pub const SELF_SUBSYS_FBT: u8 = 4;
pub const SELF_SUBSYS_TRACEPT: u8 = 5;
pub const SELF_SUBSYS_USDT: u8 = 6;
pub const SELF_SUBSYS_AGG: u8 = 7;
pub const SELF_SUBSYS_RECORD: u8 = 8;
pub const SELF_SUBSYS_OBSERVER: u8 = 9;
pub const SELF_SUBSYS_CONTROL: u8 = 10;
pub const SELF_SUBSYS_PARSE: u8 = 11;
pub const SELF_SUBSYS_LOWER: u8 = 12;
pub const SELF_SUBSYS_RENDER: u8 = 13;

// Levels — same shape and ordering as `tracing::Level`.
pub const SELF_LEVEL_TRACE: u8 = 0;
pub const SELF_LEVEL_DEBUG: u8 = 1;
pub const SELF_LEVEL_INFO: u8 = 2;
pub const SELF_LEVEL_WARN: u8 = 3;
pub const SELF_LEVEL_ERROR: u8 = 4;

// Field value types — only four for v1 (covers slot/lease IDs,
// counts, byte strings for target names, and bool flags).  Add a
// new type by appending; never reuse a discriminant.
pub const SELF_FIELD_U64: u8 = 0;
pub const SELF_FIELD_I64: u8 = 1;
pub const SELF_FIELD_BYTES: u8 = 2;
pub const SELF_FIELD_BOOL: u8 = 3;

/// Maximum body size of a single self-trace event, including the
/// per-event header bytes (level + subsys + num_fields + msg_len)
/// but not the SHMEM record header.  Bounds the on-stack scratch
/// the driver-side encoder can use without an allocator.  Tunable
/// upward if a future event needs to ride a larger payload.
pub const SELF_TRACE_MAX_BODY: usize = 4096;

/// Profile-sample flag bits.  Stored in the `flags` u32
/// of the per-sample header.  Allocate by appending; never reuse a
/// bit position.
///
/// `KERNEL_CONTEXT` ⇒ the sample was taken while the vcpu was in
/// kernel mode (EL1 on aarch64).  Frame_pc values are kernel VAs;
/// host CLI symbolicates via kallsyms.  Absent ⇒ user mode (EL0);
/// frame_pc values are user VAs and resolve via the per-task symtab
/// side-channel.
pub const PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT: u32 = 1 << 0;
/// `STACK_TRUNCATED` ⇒ the walker hit `MAX_PROFILE_FRAMES` before
/// reaching the end of the chain.  Renders as a `…` ellipsis at
/// the top of the rendered stack.
pub const PROFILE_SAMPLE_FLAG_STACK_TRUNCATED: u32 = 1 << 1;
/// `STACK_INCOMPLETE` ⇒ a frame-pointer dereference faulted before
/// reaching a known terminator.  Walker stopped early; the rendered
/// stack is what it had.  Distinguishes "deep stack" from "couldn't
/// walk further."
pub const PROFILE_SAMPLE_FLAG_STACK_INCOMPLETE: u32 = 1 << 2;

// =====================================================================
// BTF-CO-RE field relocations — driver-VMM binding durability
// across kernel versions.
//
// Today bifrost reads kernel struct fields at hardcoded offsets that
// match the bundled 6.12.76 kernel.  When upstream kernels shift a
// `task_struct` member (or any other live struct), our reads silently
// pick up the wrong bytes.  CO-RE solves this the libbpf way:
//
//   1. Lowering records "this load reads `struct.field`" as a
//      relocation rather than a hardcoded offset.
//   2. At LOAD_PROG time, libkrun walks the relocations, looks up
//      each (struct, field) pair in the guest's live BTF, and
//      patches the resolved offset into the eBPF instruction stream.
//
// One reloc record is `(insn_idx, access_kind, byte_off_in_insn,
// struct_name, field_name)`:
//   - `insn_idx`            byte offset of the eBPF instruction in
//                           the program body (always a multiple of 8).
//   - `access_kind`         FIELD_RELOC_*, below.  Determines what
//                           the patcher writes — an offset, a size,
//                           or a 0/1 existence flag.
//   - `byte_off_in_insn`    byte offset within the 8-byte eBPF
//                           instruction where the patched value lands.
//                           For LDX/STX `imm` patches this is 4; for
//                           BPF_MOV64_IMM-style sequences it varies.
//   - `struct_name`         BTF type name to look up.
//   - `field_name`          field within the struct.  Today: simple
//                           name; nested paths like "mm.start_brk"
//                           are a future extension.
// =====================================================================

/// Patcher writes the resolved field offset (in bytes) into the
/// instruction at `byte_off_in_insn`.  Width is 4 bytes (sign-extended
/// to 32 bits if the field offset overflows u16, which it shouldn't
/// for any realistic struct).
pub const FIELD_RELOC_OFFSET: u8 = 0;
/// Patcher writes the resolved field size (in bytes).  Useful for
/// programs that adapt their read width to the kernel's storage
/// (e.g. a counter that's u32 on one kernel and u64 on another).
pub const FIELD_RELOC_SIZE: u8 = 1;
/// Patcher writes 1 if the field exists in the live BTF, 0 if not.
/// Lets a program optionally branch on availability — the libbpf
/// `bpf_core_field_exists` analog.
pub const FIELD_RELOC_EXISTS: u8 = 2;

/// Maximum length of a struct or field name in a field-reloc record.
/// 255 because `name_len` is encoded as `u8`; bumping to a wider
/// length prefix would be a future wire change.
pub const FIELD_RELOC_NAME_MAX: usize = 255;

/// Per-program flag bit (in `BifrostProgramHeader::flags` bits 8..31)
/// signaling that the program body carries a field-reloc section
/// after the kfunc-relocs section.  Old decoders ignore the bit and
/// stop after kfunc-relocs; new decoders read the field-reloc
/// section.  The body integration is wired separately; this constant
/// reserves the bit so the bit position is pinned now.
pub const PROGRAM_FLAG_FIELD_RELOCS_PRESENT: u32 = 1 << 8;

/// Maximum stack frames in a single profile-N sample.
/// Bounds the per-sample emit buffer at roughly 16 + 8*MAX bytes;
/// the libkrun-side sampler walks the guest stack until it hits
/// this cap or fails a frame-pointer dereference.  256 frames at
/// 8 bytes each plus the 16-byte header = 2064 bytes per sample;
/// a 997-Hz sampler running for ten seconds at full depth is
/// roughly 20 MB of records, well within the per-record SHMEM
/// budget once batched.
pub const MAX_PROFILE_FRAMES: usize = 256;

// =====================================================================
// Control-ring D4 message kinds.  Cmd ring (host → libkrun)
// carries the request kinds (1..3); rsp ring (libkrun → host)
// carries the response/push kinds (100..103) plus padding (255).
// =====================================================================

pub const D4_KIND_LOAD_PROG: u32 = 1;
pub const D4_KIND_OBSERVER_ATTACH: u32 = 2;
pub const D4_KIND_OBSERVER_DETACH: u32 = 3;
/// Observer→driver capability handshake.  Sent on the cmd ring after
/// OBSERVER_ATTACH, before the first LOAD_PROG.  Body is the codec
/// output of `bifrost_wire::codec::encode_hello` —
/// `[u32 wire_major][u32 wire_minor][u64 feature_bits][u16 num_fields]
/// [fields...]`.  This is the driver↔VMM binding spine:
/// `CANONICAL_SHA256` keeps catching exact wire-body drift; HELLO
/// adds capability negotiation on top of that pin so optional record
/// kinds (self-trace emit, future profile-N samples, future hyp:::
/// records) can be feature-gated rather than version-pinned.  Driver
/// replies with `D4_KIND_OBSERVER_HELLO_ACK` carrying its own
/// (wire_major, wire_minor, feature_bits) plus an `accepted` flag.
pub const D4_KIND_OBSERVER_HELLO: u32 = 4;
pub const D4_KIND_RSP_OK: u32 = 100;
pub const D4_KIND_RSP_ERR: u32 = 101;

// =====================================================================
// Per-program LOAD_PROG status codes.  RSP_OK responses to LOAD_PROG
// requests carry a payload `[u32 num_progs LE] [u8; num_progs]`,
// where each byte is one of the constants below — one entry per
// program in the wrapper, in the same order they appeared.  Empty
// payloads (the legacy "no per-program statuses") are still legal
// for non-LOAD_PROG response kinds (OBSERVER_ATTACH/DETACH); LOAD_PROG
// responses always carry the array.
//
// Every program reports its own per-program status, so a partial
// failure in one slot of a multi-program LOAD_PROG cohort does not
// disappear behind the single RSP_OK that libkrun emits on
// successful wrapper parse.  A guest-side condition like
// "MAX_KPROBES exceeded" surfaces as the explicit `SLOT_EXHAUSTED`
// status for the affected slot rather than a silent drop.
// =====================================================================

/// Program registered successfully.
pub const RSP_LOADPROG_STATUS_OK: u8 = 0;
/// Driver hit the slot cap mid-wrapper.  Program was dropped; the
/// CLI's preflight (host/bifrost/src/cli/runtime.rs) is the
/// fast-path; this is the protocol-level fallback.
pub const RSP_LOADPROG_STATUS_SLOT_EXHAUSTED: u8 = 1;
/// JIT failed to compile the eBPF program.
pub const RSP_LOADPROG_STATUS_JIT_FAIL: u8 = 2;
/// Kfunc reloc resolved no matching BTF id (typically a kernel
/// version skew between the host CLI's reference and the guest's
/// vmlinux).
pub const RSP_LOADPROG_STATUS_BTF_RESOLVE_FAIL: u8 = 3;
/// eBPF verifier rejected the program.
pub const RSP_LOADPROG_STATUS_VERIFIER_FAIL: u8 = 4;
/// Probe target (uprobe symbol, fbt function, raw tracepoint event)
/// not found in the running guest.
pub const RSP_LOADPROG_STATUS_TARGET_NOT_FOUND: u8 = 5;
/// Catch-all for failures not yet categorized.  When a new failure
/// mode is identified, allocate a new constant rather than abusing
/// this one; this slot is for "happens once, debug later" cases.
pub const RSP_LOADPROG_STATUS_OTHER: u8 = 99;
/// Unsolicited push: libkrun pushes serialised guest-aggregation
/// snapshot rows. Carries one or more pre-formatted
/// `##xagg-guest##|name|key|value` lines for the bifrost CLI to
/// feed straight into its xagg parser. Bypasses the
/// bifrost_event_received pid-uprobe (which rate-limits silently
/// at high call rates), so guest aggs reach the CLI reliably.
pub const D4_KIND_AGG_PUSH: u32 = 102;
/// Unsolicited push: batched per-fire record lines (rendered
/// `<label> <body>` strings). Same wire format as AGG_PUSH; the
/// difference is content (printable record stream rather than
/// xagg markers). Replaces the bifrost_event_received uprobe as
/// the high-rate record channel.
pub const D4_KIND_RECORD_PUSH: u32 = 103;
/// Unsolicited push: per-program LOAD_PROG status array, emitted by
/// libkrun once the guest has finished processing every program in
/// the corresponding LOAD_PROG cohort.  Body is the codec output of
/// `bifrost_wire::codec::encode_loadprog_status` —
/// `[u32 LE num_progs][u8; num_progs status]` with status values
/// from the `RSP_LOADPROG_STATUS_*` table.  `seq` echoes the
/// original LOAD_PROG request's seq so the host CLI can correlate.
///
/// Distinct from `RSP_OK`'s payload because `RSP_OK` is emitted
/// **synchronously** by libkrun the moment the wrapper parses
/// cleanly — long before the guest's worker has actually attached
/// anything.  Per-program status arrives asynchronously after
/// attach.  Separate kinds keep the temporal model honest.
pub const D4_KIND_LOAD_PROG_STATUS: u32 = 104;
/// Unsolicited self-trace event push from libkrun (or, in a future
/// phase, the guest driver via libkrun's record-forwarding path).
/// Body wire format:
///
/// ```text
///   [u32 layer_probe_id LE]   one of SELF_TRACE_DRIVER_PROBE_ID /
///                             SELF_TRACE_LIBKRUN_PROBE_ID /
///                             SELF_TRACE_CLI_PROBE_ID
///   [encode_event output]     SELF_LEVEL_* + SELF_SUBSYS_* + msg +
///                             fields, per `bifrost_wire::codec::
///                             encode_event`
/// ```
///
/// Records arrive asynchronously and unrelated to any cmd-side seq;
/// `seq` is always 0.  CLI consumes via `--trace-self[=level]`,
/// rendering each event as `[layer/subsys/level] msg {key=val,…}`.
pub const D4_KIND_SELF_TRACE_PUSH: u32 = 105;
/// Driver→observer reply to `D4_KIND_OBSERVER_HELLO`.  Body is the
/// codec output of `bifrost_wire::codec::encode_hello_ack` —
/// `[u8 accepted][u8 reject_reason][u32 wire_major][u32 wire_minor]
/// [u64 feature_bits][u16 num_fields][fields...]`.
///
/// `accepted=1, reject_reason=0`  — driver accepts the connection;
///                                  `feature_bits` is the intersection
///                                  the driver actually supports.
/// `accepted=0, reject_reason=*`  — driver refuses; `reject_reason`
///                                  is one of `HELLO_REJECT_*` and
///                                  the optional `reason` field
///                                  carries human-readable detail.
///
/// `seq` echoes the original HELLO request's seq.
pub const D4_KIND_OBSERVER_HELLO_ACK: u32 = 106;
/// Unsolicited push from libkrun — one profile-N sample.
/// Body is the codec output of
/// `bifrost_wire::codec::encode_profile_sample`:
/// `[u32 pid][u32 tid][u32 cpu_id][u32 flags][u32 num_frames]
///  [u64 frame_pc; num_frames]`.  `seq` is always 0 (unsolicited).
/// libkrun pushes one of these per timer-driven vcpu sample at the
/// configured profile frequency.  Records ride the same rsp ring as
/// LOAD_PROG_STATUS / SELF_TRACE_PUSH; CLI fan-out keys on
/// `PROFILE_SAMPLE_PROBE_ID` after stripping the SHMEM record header.
pub const D4_KIND_PROFILE_SAMPLE: u32 = 107;
pub const D4_KIND_PAD: u32 = 255;

// =====================================================================
// Wire-format version + feature-bit registry — the capability
// handshake.  Driver and CLI exchange (wire_major, wire_minor,
// feature_bits) at OBSERVER_HELLO time:
//
//   wire_major  Breaking-change version.  Mismatch ⇒ HELLO_ACK refuses
//               with HELLO_REJECT_WIRE_MAJOR_MISMATCH.  Bumped when
//               an existing record kind's body layout changes
//               incompatibly, or a required field is removed.  The
//               CANONICAL_SHA256 pin catches same-major drift in the
//               core schema; this is the coarser knob for cross-major
//               upgrades.
//
//   wire_minor  Additive-change version.  Bumped when a new
//               D4_KIND_* lands or a new optional field is added.
//               Mismatch is fine — the smaller side just doesn't
//               emit/consume the new thing.  Driver and CLI both
//               advertise their own minor; the *negotiated* minor
//               is min(driver, cli) and is rarely consulted directly
//               (feature_bits are the canonical capability vocabulary).
//
//   feature_bits  Bitset of FEATURE_*.  Driver advertises what it
//               can produce/consume; CLI advertises the same.  The
//               negotiated set is bitwise-AND.  The CLI must skip
//               record kinds whose feature bit isn't in the
//               negotiated set; the driver must not push them.
// =====================================================================

/// Current wire_major.  Bump on incompatible body-layout changes.
pub const BIFROST_WIRE_MAJOR: u32 = 1;
/// Current wire_minor.  Bump on additive D4_KIND or feature-bit
/// additions; never reset on minor releases of the same major.
pub const BIFROST_WIRE_MINOR: u32 = 0;

// Feature bits.  Allocate by appending; never reuse.  Each describes
// one capability either side can advertise.  When a new optional
// record kind lands, allocate a new FEATURE_* and gate its
// production/consumption on the negotiated bit.
//
// Bits 0..15 reserved for "core protocol" features (handshake itself,
// extensible record discipline).  Bits 16..31 for record-kind
// capabilities (self-trace emit, LOADPROG_STATUS, etc).  Bits 32..47 for
// future provider catalog (profile-N, stable proc:::, sched:::, io:::,
// syscall:::).  Bits 48+ reserved.

/// The peer speaks the OBSERVER_HELLO handshake itself.  Always set
/// in any HELLO/HELLO_ACK from a peer that knows about this protocol;
/// absence (e.g., legacy peer that ignores HELLO) is sensed by
/// timeout, not by inspecting this bit.
pub const FEATURE_HANDSHAKE_V1: u64 = 1 << 0;
/// The peer accepts varint-keyed extension fields on every record
/// kind that supports them (HELLO, HELLO_ACK; future LOADPROG,
/// SELF_TRACE).  Required for forward-compat across minor versions.
pub const FEATURE_EXTENSIBLE_RECORDS: u64 = 1 << 1;

/// The peer produces/consumes per-program LOAD_PROG status pushes
/// (`D4_KIND_LOAD_PROG_STATUS`, codec-encoded via
/// `encode_loadprog_status`).
pub const FEATURE_LOADPROG_STATUS: u64 = 1 << 16;
/// The peer produces/consumes structured self-trace events
/// (`D4_KIND_SELF_TRACE_PUSH`).
pub const FEATURE_SELF_TRACE_EMIT: u64 = 1 << 17;
/// The peer produces/consumes USDT-shape probes
/// (`PROBE_TYPE_USDT`).
pub const FEATURE_USDT: u64 = 1 << 18;
/// The peer produces/consumes FBT-shape probes
/// (`PROBE_TYPE_FENTRY/FEXIT`).
pub const FEATURE_FBT: u64 = 1 << 19;
/// The peer produces/consumes raw tracepoint probes
/// (`PROBE_TYPE_TRACEPOINT`).
pub const FEATURE_RAWTP: u64 = 1 << 20;
/// The peer produces/consumes uprobe-by-symbol probes
/// (`PROBE_TYPE_UPROBE_BY_SYM/URETPROBE_BY_SYM`).
pub const FEATURE_UPROBE_BY_SYM: u64 = 1 << 21;
/// The peer registers an explicit observer_id at HELLO time and
/// supports concurrent observers fanned out per id.
/// Today's libkrun does NOT advertise this — it's the forward
/// commitment.  When a peer advertises this bit, every record on
/// the rsp ring is keyed by observer_id and the slot table accepts
/// non-overlapping LOAD_PROG ownership across observers.
pub const FEATURE_MULTI_OBSERVER: u64 = 1 << 22;
/// The peer produces/consumes timer-driven profile-N samples
/// (`D4_KIND_PROFILE_SAMPLE`, `PROFILE_SAMPLE_PROBE_ID`) —
/// the hypervisor-only superpower.  When set on the libkrun side,
/// the device runs a vcpu sampler at the negotiated frequency and
/// pushes samples through the bifrost rsp ring.
pub const FEATURE_PROFILE_N: u64 = 1 << 32;
/// The peer produces/consumes BTF-CO-RE field relocations.
/// When negotiated, BFR7 wrappers carry a per-program field-reloc
/// section that the libkrun-side patcher resolves against guest BTF
/// at LOAD_PROG time, replacing hardcoded struct field offsets with
/// kernel-version-specific values.  Forward-looking; today's libkrun
/// does NOT advertise this — the codec is laid down ahead of the
/// patcher that consumes it.
pub const FEATURE_BTF_FIELD_RELOC: u64 = 1 << 33;

/// Mask covering the features any current-generation peer is
/// expected to advertise.  CLIs and drivers built off this codebase
/// should set every bit here in their HELLO; older peers may set a
/// subset.  Used at validation time to detect "peer is too old to
/// be useful" rather than per-feature.
pub const FEATURE_BASELINE: u64 = FEATURE_HANDSHAKE_V1
    | FEATURE_EXTENSIBLE_RECORDS
    | FEATURE_LOADPROG_STATUS
    | FEATURE_SELF_TRACE_EMIT
    | FEATURE_USDT
    | FEATURE_FBT
    | FEATURE_RAWTP
    | FEATURE_UPROBE_BY_SYM;

// HELLO_ACK reject reasons.  Allocate by appending; never reuse.
// `0` is the success sentinel — `accepted=1, reject_reason=0`.

/// Driver and CLI disagree on `wire_major`.  No graceful path; the
/// observer must either downgrade or refuse to attach.
pub const HELLO_REJECT_WIRE_MAJOR_MISMATCH: u8 = 1;
/// Driver doesn't advertise a feature the CLI declared as required
/// (a HELLO field carrying `required_features: u64`).  CLI should
/// either drop the requirement or refuse to attach.
pub const HELLO_REJECT_MISSING_REQUIRED_FEATURE: u8 = 2;
/// Driver is busy with another observer that hasn't yielded.
/// Multi-observer fan-out eliminates this; today's slot table is 1-at-a-time.
pub const HELLO_REJECT_OBSERVER_BUSY: u8 = 3;
/// Catch-all for failures the driver hasn't classified.  Use the
/// reason field for diagnostic detail; allocate a new constant if
/// the failure mode recurs.
pub const HELLO_REJECT_OTHER: u8 = 99;

// =====================================================================
// SHMEM record-header layout.
// =====================================================================

/// Magic value the guest writes at SHMEM offset 0 immediately before
/// sending `SHMEM_INIT`/ready notification so the host can confirm it
/// sees the same memory. ASCII `BFSH` interpreted as little-endian.
pub const SHMEM_MAGIC: u32 = 0x48534642;
/// Layout version stored next to `SHMEM_MAGIC`. Bump when the SHMEM
/// header layout changes incompatibly.
///
/// - V4: per-CPU principal buffer carve.  The 6 MB ring splits
///   into `SHMEM_NUM_CPUS_MAX` sub-rings of `per_cpu_ring_len`
///   each, with one cache line of producer / consumer / drop
///   state per CPU at offset 128.
/// - V5: per-CPU state entry widens from 64 B to 128 B to carry
///   per-class drop arrays (`SHMEM_DROP_CLASS_*`) indexed by
///   PRINCIPAL / AGG / STKSTR / DBLERR.
pub const SHMEM_VERSION: u32 = 5;
/// Cap on per-CPU sub-rings. Hosts with more CPUs than the cap
/// share a sub-ring (`smp_processor_id() % num_cpus` selection
/// at reserve time). Cross-layer drift pinned in
/// `third_party/linux-bifrost/drivers/bifrost/shmem_layout.rs`
/// as `SHMEM_NUM_CPUS_MAX` and `BIFROST_NUM_CPUS_MAX` in
/// `kernel/bpf/helpers.c`.
pub const SHMEM_NUM_CPUS_MAX: u32 = 16;
/// Byte offset of the per-CPU state array within the SHMEM
/// header page. Each entry is one cache line.
pub const SHMEM_PER_CPU_STATE_OFF: u32 = 128;
/// Stride between successive CPU state entries. V5 widens this
/// from 64 to 128 bytes to fit the per-class drop arrays.
pub const SHMEM_PER_CPU_STATE_STRIDE: u32 = 128;

/// Drop-class identifiers.  The host CLI uses these to attribute
/// which workload class is overflowing its sub-ring.
pub const SHMEM_DROP_CLASS_PRINCIPAL: u32 = 0;
pub const SHMEM_DROP_CLASS_AGG: u32 = 1;
pub const SHMEM_DROP_CLASS_STKSTR: u32 = 2;
pub const SHMEM_DROP_CLASS_DBLERR: u32 = 3;
pub const SHMEM_DROP_CLASS_MAX: u32 = 4;
/// 8-byte record header: u32 size, u32 flags.
pub const SHMEM_RECORD_HDR_SIZE: usize = 8;
pub const SHMEM_RECORD_FLAG_READY: u32 = 1;
pub const SHMEM_RECORD_FLAG_PADDING: u32 = 1 << 1;
pub const SHMEM_RECORD_MAX_PAYLOAD: usize = 65536;

// =====================================================================
// Typed wire-format structs.  Behind the `zerocopy_repr` feature
// so the guest kernel module — which symlinks/vendors this same
// lib.rs but can't pull crates outside the kernel-rust ecosystem
// — keeps compiling.  The host CLI and libkrun enable the feature.
//
// These let `wrapped.extend_from_slice(&header.to_le_bytes())`
// patterns become typed, with the layout pinned by `#[repr(C)]`
// and `#[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]`.
//
// Adding more here as the wire-format surface grows is the
// migration path away from byte-by-byte assembly in
// `host/bifrost/src/cli/wrapper.rs::build_wrapper_bytes`.  Each
// struct moved here = one less hand-rolled `to_le_bytes()` chain
// + one more compile-time-verified layout.
// =====================================================================

#[cfg(feature = "zerocopy_repr")]
pub mod typed {
    //! Zerocopy-derived structs mirroring the BFR7 wire-format
    //! headers.  All `#[repr(C, packed)]` so the in-memory layout
    //! matches the wire byte-for-byte; the zerocopy traits gate
    //! safe transmute via `IntoBytes` (write side) / `FromBytes`
    //! (read side).

    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    /// Re-export so consumers can call `.as_bytes()` without
    /// pulling `zerocopy` into their own Cargo.toml.
    pub use zerocopy::IntoBytes as IntoWireBytes;

    /// First 8 bytes of every BFR7 wire payload.
    /// Wire layout (LE):
    ///   [u8;4 magic][u32 num_progs]
    #[derive(Copy, Clone, Debug, IntoBytes, FromBytes, KnownLayout, Immutable)]
    #[repr(C, packed)]
    pub struct BifrostWrapperHeader {
        pub magic: [u8; 4],
        pub num_progs: u32,
    }

    impl BifrostWrapperHeader {
        pub const fn new(num_progs: u32) -> Self {
            Self {
                magic: super::BFR7_MAGIC,
                num_progs,
            }
        }
    }

    /// 36-byte per-program header in the BFR7 wrapper.
    /// Wire layout (LE):
    ///   [u8;32 target_name_nul_padded][u32 flags]
    /// `flags` low byte = probe_type (PROBE_TYPE_* discriminant).
    #[derive(Copy, Clone, Debug, IntoBytes, FromBytes, KnownLayout, Immutable)]
    #[repr(C, packed)]
    pub struct BifrostProgramHeader {
        pub target_name: [u8; 32],
        pub flags: u32,
    }

    impl BifrostProgramHeader {
        /// Build with a NUL-padded target name.  Names longer than
        /// 31 bytes are silently truncated (one byte reserved for
        /// the trailing NUL).
        pub fn new(target_name: &str, probe_type: u8) -> Self {
            let mut name = [0u8; 32];
            let bytes = target_name.as_bytes();
            let copy = bytes.len().min(31);
            name[..copy].copy_from_slice(&bytes[..copy]);
            Self {
                target_name: name,
                flags: probe_type as u32,
            }
        }
    }

    /// 8-byte SHMEM record header.
    /// Wire layout (LE):
    ///   [u32 size][u32 flags]
    /// `flags` is `SHMEM_RECORD_FLAG_READY | SHMEM_RECORD_FLAG_PADDING`.
    #[derive(Copy, Clone, Debug, IntoBytes, FromBytes, KnownLayout, Immutable)]
    #[repr(C, packed)]
    pub struct ShmemRecordHeader {
        pub size: u32,
        pub flags: u32,
    }
}

#[cfg(feature = "codec")]
pub mod codec;

// DOF-generic envelopes.  These live
// alongside the legacy BFR7 constants; the legacy values remain
// decodable so transition-era recordings still render, but new host
// production paths emit `DTRACE_SESSION_V1` envelopes and SHMEM v6
// semantic records exclusively.
pub mod session_envelope;
pub mod shmem_v6;
