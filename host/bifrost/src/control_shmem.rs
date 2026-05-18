// SPDX-License-Identifier: Apache-2.0
//
// Client-side helpers for the libkrun control SHM endpoint.
//
// libkrun's virtio conduit publishes a POSIX shm object at
// `/conduit-<pid>` at startup.  This module gives bifrost CLI a
// safe way to open that region, verify its header, and push
// commands into the SPSC ring.
//
// ## Conceptual model: SPSC ring state machine
//
// Both the cmd ring (CLI → conduit) and the data ring (BPF →
// CLI) are single-producer/single-consumer byte streams with a
// 64-bit monotonically-increasing `producer_pos` and
// `consumer_pos`.  Each record occupies `size` bytes (8-byte
// aligned), preceded by an 8-byte header carrying `size` and a
// `flags` word that doubles as the visibility marker.
//
// A producer commits a record in three steps:
//
//   1. *Claim.*  `atomic64_cmpxchg(producer_pos, cur, cur + size)`
//      reserves a logical position range.  Failure means a
//      concurrent claim won; retry from the new `cur`.
//   2. *Mark busy.*  Write `size` into the header, then store
//      `flags = 0` (busy) with `WRITE_ONCE`.  At this point the
//      consumer can see the position advance but must NOT read the
//      record body — the body bytes have not been written yet.
//   3. *Publish.*  Write the body, then `smp_store_release` the
//      ready marker (`READY` or `READY | PADDING`) into `flags`.
//      The release-store makes every preceding body write visible
//      to any consumer that subsequently observes the marker with
//      an acquire-load.
//
// The consumer mirrors this with acquire-loads in the opposite
// order:
//
//   - `producer_pos` acquire-load decides the end of the readable
//     range.
//   - For each record in `[consumer_pos, producer_pos)`, acquire-
//     load `flags`.  If it is still 0 (busy), the producer's
//     release-store has not landed yet; stop walking and retry on
//     the next snapshot rather than reading garbage.
//
// ## Wraparound: KIND_PAD records
//
// When an entry would split across the ring's end the producer
// first writes a `KIND_PAD` entry consuming the remaining tail,
// advances `producer_pos` to the next ring boundary, then writes
// the real entry from offset 0.  The consumer recognises
// `KIND_PAD` and skips — there is no special wraparound state
// machine; pads are records like any other.
//
// ## Memory-ordering rationale
//
// The pairing is the standard release/acquire SPSC handshake:
// every byte written *before* the producer's release-store
// happens-before any byte observed by a consumer whose acquire-
// load returns the same marker.  No full barrier is needed
// because there is exactly one producer and exactly one consumer
// per ring — the cumulativity-of-stores property the standard
// gives release/acquire is sufficient.  A `SeqCst` barrier would
// be wasted: there is no third party whose observations need to
// be globally ordered against either side.
//
// ## V4/V5 layout (per-CPU sub-rings, per-class drop counters)
//
// The data ring is carved into `num_cpus` equal-size sub-rings.
// Each BPF program picks a sub-ring via
// `smp_processor_id() % num_cpus`; the consumer round-robins.
// Drop counters are 4-element arrays indexed by
// `bifrost_wire::SHMEM_DROP_CLASS_*` so the host can attribute
// overflow to a workload class (PRINCIPAL / AGG / STKSTR /
// DBLERR).

//! Wire layout matches `ControlShmHdrLayout` in
//! `third_party/smolvm/libkrun/src/devices/src/virtio/conduit/control.rs`.
//! Keep them in sync — there's no cross-crate header to share, so
//! changes to one side need a matching tweak here.
//!
//! ## Command/response wire format
//!
//! Both rings are SPSC byte streams. Each entry is preceded by a
//! 16-byte header:
//!
//! ```text
//!   offset  size  field
//!   ──────  ────  ───────────────────────────────────
//!   0       4     kind   (CmdKind / RspKind)
//!   4       4     len    (payload bytes after this header,
//!                         NOT including 8-byte align padding)
//!   8       8     seq    (monotonic, for request/response correlation)
//!  16       len   payload (variable)
//!  16+len   pad   to 16-byte alignment
//! ```
//!
//! Wraparound: if an entry would split across the ring's end the
//! producer first writes a `KIND_PAD` entry consuming the
//! remaining tail, advances `producer_pos` to the next ring
//! boundary, then writes the real entry from offset 0. Consumer
//! recognises `KIND_PAD` and skips.

use std::ffi::{CString, NulError};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

/// Errors from opening + driving the libkrun control-SHM endpoint.
/// Each variant captures a distinct failure mode along the
/// shm_open → mmap → header-validate → ring-push pipeline.  The
/// CLI surfaces these strings directly, so the `Display`
/// (#[error("...")]) text is what the user reads.
#[derive(Debug, Error)]
pub enum ControlShmError {
    #[error("shm name: {0}")]
    BadShmName(#[source] NulError),
    #[error(
        "no libkrun control endpoint at /conduit-{0}: process not running, \
         or built without virtio conduit, or VIRTIO_CONDUIT_CONTROL_SHM=0"
    )]
    EndpointMissing(u32),
    #[error(
        "permission denied opening /conduit-{0}: bifrost CLI must run with the \
         same uid as the libkrun process (typically root)"
    )]
    PermissionDenied(u32),
    #[error("shm_open(/conduit-{pid}): {source}")]
    ShmOpen {
        pid: u32,
        #[source]
        source: io::Error,
    },
    #[error("fstat: {0}")]
    Fstat(#[source] io::Error),
    #[error("mmap control shm")]
    MmapFailed,
    #[error("control shm at /conduit-{pid}: {reason} (not a conduit endpoint?)")]
    HeaderDecode { pid: u32, reason: String },
    #[error("control shm region_size mismatch: hdr={hdr} fstat={fstat}")]
    RegionSizeMismatch { hdr: u64, fstat: usize },
    #[error("control shm version mismatch: got {got} want {want}")]
    VersionMismatch { got: u32, want: u32 },
    #[error("control shm pid mismatch: got {got} want {want}")]
    PidMismatch { got: u32, want: u32 },
    #[error("cmd entry too large: {entry} bytes, ring is {ring} bytes")]
    CmdEntryTooLarge { entry: usize, ring: usize },
    #[error("cmd ring full: free={free}, need={need} (incl. {pad}-byte PAD wraparound)")]
    CmdRingFullWithPad {
        free: usize,
        need: usize,
        pad: usize,
    },
    #[error("cmd ring full: free={free}, need={need}")]
    CmdRingFull { free: usize, need: usize },
    #[error("rsp entry overruns ring: head_off={head_off} len={len} ring_len={ring_len}")]
    RspEntryOverrun {
        head_off: usize,
        len: u32,
        ring_len: usize,
    },
    #[error("bad magic: got 0x{got:016x} want 0x{want:016x}")]
    BadMagic { got: u64, want: u64 },
}

/// Ring entry kinds. Producer→consumer (cmd ring) uses values
/// 1..99; consumer→producer (rsp ring) uses 100..199. KIND_PAD
/// (255) is shared and means "skip remaining tail of ring,
/// resume from offset 0 in the data area."
///
/// `KIND_LOAD_PROG` is the host-CLI alias for the conduit's
/// `KIND_CTRL_PAYLOAD_REQ` request/response transport kind. The
/// conduit treats the body as opaque, appends an LE seq trailer for
/// the guest to echo, and routes the matching `OP_CTRL_RESPONSE`
/// event back as `KIND_RSP_PAYLOAD`. The host CLI owns the
/// higher-level opcode (`BifrostCmd.op`) and status framing
/// (`i32 status, u16 detail_len, [u8;detail_len] detail`) inside
/// the body — the transport never inspects it.
///
/// Post-DOF-generic rebuild: the host emits one `BifrostCmd.op = 3`
/// (`BIFROST_CMD_OP_DTRACE_SESSION`) payload per session, body shape
/// `[BifrostCmd hdr][DTRACE_SESSION_V1 envelope (96 bytes)][DOF bytes]`.
/// The guest worker dispatches on `op == 3` to drive
/// `bifrost_dtrace_lower::session::drive` against its local
/// `KernelAdapter`. The transport kind stays `KIND_LOAD_PROG` (= 2)
/// because the conduit recognises only `KIND_CTRL_PAYLOAD` and
/// `KIND_CTRL_PAYLOAD_REQ`; introducing a new transport kind would
/// have been a layer violation (the conduit is OS-agnostic by
/// design — `host/virtio-conduit/src/shmem/consumer.rs` rejects
/// anything else with `KIND_RSP_ERR "unknown cmd"`).
pub const KIND_LOAD_PROG: u32 = 2;

pub const KIND_RSP_OK: u32 = 100;
pub const KIND_RSP_ERR: u32 = 101;
/// Opaque guest response delivered through the conduit's
/// `OP_CTRL_RESPONSE` event. The body is whatever the guest wrote;
/// for `KIND_LOAD_PROG` the body is
/// `[i32 status LE][u16 detail_len LE][u8; detail_len] detail`.
pub const KIND_RSP_PAYLOAD: u32 = 104;
/// Unsolicited push from the libkrun side carrying serialised
/// guest-aggregation snapshot rows. Payload format:
///
/// ```text
///   [u32 num_lines]
///   for each line:
///     [u32 line_len]
///     [u8  line_bytes...] // already-formatted "##xagg-guest##|name|key|value"
/// ```
///
/// Lines feed straight into the bifrost CLI's existing
/// `try_parse_xagg_line`, bypassing the rate-limited
/// `bifrost_event_received` pid-uprobe path. seq is always 0 for
/// unsolicited pushes (the matching cmd-side seq counter starts at
/// 1, so 0 is unused as a request seq).
pub const KIND_AGG_PUSH: u32 = 102;
/// Unsolicited push carrying batched per-fire record lines from the
/// guest's BPF programs. Same `[u32 num_lines][u32 line_len][bytes]`
/// payload format as `KIND_AGG_PUSH`, just a different stream:
/// these lines are the rendered per-event messages (e.g.
/// `guest_kernel:do_sys_openat2:entry vmid=0 probe_id=2 …`) that
/// the legacy `bifrost_event_received` pid-uprobe path was losing
/// at high rate. Lines arrive ready-to-print on stdout (no special
/// parsing needed).
pub const KIND_RECORD_PUSH: u32 = 103;
/// Unsolicited self-trace event push from a transport peer. Body is
/// `[u32 layer_probe_id LE][body
/// bytes]` where the body is the codec output of
/// `bifrost_wire::codec::encode_event`.  Mirrors
/// `bifrost_wire::D4_KIND_SELF_TRACE_PUSH`.  CLI consumes via
/// `--trace-self[=level]` and renders to stderr as
/// `[layer/subsys/level] msg {key=val,…}`.  seq is always 0
/// (unsolicited).
pub const KIND_SELF_TRACE_PUSH: u32 = 105;
/// Profiling — unsolicited push from libkrun, one profile-N sample.
/// Body is `[u32 PROFILE_SAMPLE_PROBE_ID][encode_profile_sample]`.
/// `seq` is always 0.  Mirrors `bifrost_wire::D4_KIND_PROFILE_SAMPLE`.
pub const KIND_PROFILE_SAMPLE: u32 = 107;

pub const KIND_PAD: u32 = 255;

/// Decode the body of a `KIND_RSP_PAYLOAD` response delivered by the
/// guest in reply to a `KIND_LOAD_PROG` request. The body layout is
/// `[i32 status LE][u16 detail_len LE][u8; detail_len] detail`. The
/// conduit forwards these bytes verbatim — interpretation lives here
/// in the host CLI, not in the transport layer.
///
/// Returns `(status, detail)` where `detail` is `None` when
/// `detail_len == 0` and `Some(string)` otherwise. The string is
/// decoded with `from_utf8_lossy` so non-UTF-8 detail still surfaces
/// rather than being dropped.
pub fn decode_load_prog_status(body: &[u8]) -> Result<(i32, Option<String>), String> {
    if body.len() < 6 {
        return Err(format!(
            "expected at least 6 bytes (status + detail_len), got {}",
            body.len()
        ));
    }
    let status = i32::from_le_bytes(body[0..4].try_into().unwrap());
    let detail_len = u16::from_le_bytes(body[4..6].try_into().unwrap()) as usize;
    if body.len() < 6 + detail_len {
        return Err(format!(
            "detail_len {} exceeds body remainder {}",
            detail_len,
            body.len() - 6
        ));
    }
    let detail = if detail_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(&body[6..6 + detail_len]).into_owned())
    };
    Ok((status, detail))
}

/// Byte size of the ring entry header (kind + len + seq).
pub const RING_HDR_SIZE: usize = 16;

/// Entries align to 16 bytes — keeps payload pointers aligned for
/// any reasonable consumer-side cast (the Rust side never casts;
/// we keep alignment for symmetry with the libkrun-side handler).
pub const RING_ENTRY_ALIGN: usize = 16;

#[inline]
fn align_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

// Ring entry headers cross the libkrun ↔ bifrost boundary. The
// conduit contract pins them as explicit little-endian (see
// `docs/virtio-conduit.md` § "Wire byte order"); use these helpers
// instead of `read_unaligned`/`write_unaligned` so the byte image is
// portable to a big-endian guest.
#[inline]
unsafe fn write_u32_le(dst: *mut u8, val: u32) {
    let bytes = val.to_le_bytes();
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 4) };
}

#[inline]
unsafe fn write_u64_le(dst: *mut u8, val: u64) {
    let bytes = val.to_le_bytes();
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 8) };
}

#[inline]
unsafe fn read_u32_le(src: *const u8) -> u32 {
    let mut buf = [0u8; 4];
    unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), 4) };
    u32::from_le_bytes(buf)
}

#[inline]
unsafe fn read_u64_le(src: *const u8) -> u64 {
    let mut buf = [0u8; 8];
    unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), 8) };
    u64::from_le_bytes(buf)
}

const CONTROL_SHM_MAGIC: u64 = 0x4c54435f_54434642; // "BFCT_CTL"
const CONTROL_SHM_VERSION: u32 = 1;
pub const CONTROL_CAP_LOAD_PROG: u64 = 1 << 0;
pub const CONTROL_CAP_DATA_SHM: u64 = 1 << 1;
pub const CONTROL_WAKE_COUNTER: u32 = 2;
const CONTROL_DATA_SHM_META_OFF: usize = 128;

/// Decoded header from a libkrun control SHM endpoint.
#[derive(Debug, Clone)]
pub struct ControlShmHeader {
    pub pid: u32,
    pub version: u32,
    pub region_size: u64,
    pub caps: u64,
    pub cmd_ring_off: u64,
    pub cmd_ring_len: u64,
    pub rsp_ring_off: u64,
    pub rsp_ring_len: u64,
    pub data_shm_name_off: u64,
    pub data_shm_name_len: u32,
    pub data_shm_protocol_version: u32,
    pub data_shm_size: u64,
    pub data_wakeup_mode: u32,
    pub data_wake_counter_off: u64,
}

impl ControlShmHeader {
    pub fn supports_load_prog(&self) -> bool {
        self.caps & CONTROL_CAP_LOAD_PROG != 0
    }

    pub fn supports_data_shm(&self) -> bool {
        self.caps & CONTROL_CAP_DATA_SHM != 0
    }

    /// Deterministic path of the conduit's wake FIFO. The conduit
    /// `ControlShmView::open_wake_fifo` derives it from the libkrun
    /// pid; bifrost-side derives the same name here.
    pub fn wake_fifo_path(&self) -> String {
        format!("/tmp/bifrost-wake-{}", self.pid)
    }
}

/// Owned attached handle. Drop munmaps the region (does NOT
/// shm_unlink — the libkrun process owns the lifecycle).
pub struct ControlShmAttachment {
    name: CString,
    base: *mut u8,
    size: usize,
    pub header: ControlShmHeader,
}

unsafe impl Send for ControlShmAttachment {}
unsafe impl Sync for ControlShmAttachment {}

/// One per-CPU sub-ring state read from the SHMEM header. The V4
/// layout carves the 6 MB ringbuf into `num_cpus` equal-size
/// sub-rings; the producer (BPF program) picks its sub-ring via
/// `smp_processor_id() % num_cpus`, the consumer (host renderer)
/// round-robins drain.
///
/// `dropped_records` / `dropped_bytes` are 4-element arrays indexed
/// by `bifrost_wire::SHMEM_DROP_CLASS_*` so the host can attribute
/// which workload class (PRINCIPAL / AGG / STKSTR / DBLERR) is
/// overflowing the sub-ring.
#[derive(Clone, Copy, Debug, Default)]
pub struct PerCpuShmemState {
    pub producer_pos: u64,
    pub consumer_pos: u64,
    pub dropped_records: [u64; 4],
    pub dropped_bytes: [u64; 4],
}

impl PerCpuShmemState {
    /// Sum of `dropped_records` across all classes. Provided for
    /// call sites that only want the aggregate (legacy reporting,
    /// "ring is overloaded" gates).
    pub fn dropped_records_total(&self) -> u64 {
        self.dropped_records.iter().copied().sum()
    }
    /// Sum of `dropped_bytes` across all classes.
    pub fn dropped_bytes_total(&self) -> u64 {
        self.dropped_bytes.iter().copied().sum()
    }
}

pub struct DataShmSnapshot {
    pub name: String,
    pub size: usize,
    pub magic: u32,
    pub version: u32,
    pub ringbuf_off: u64,
    pub ringbuf_len: u64,
    /// V4: per-CPU sub-ring carve. `per_cpu[cpu]` holds the
    /// producer/consumer/drops for CPU `cpu`'s sub-ring; the
    /// sub-ring's payload region starts at
    /// `ringbuf_off + cpu * per_cpu_ring_len`.
    pub num_cpus: u32,
    pub per_cpu_ring_len: u64,
    pub per_cpu: Vec<PerCpuShmemState>,
    /// Aggregated cursors for callers that need a single
    /// "where's the ring" view. `producer_pos` is the sum of
    /// per-CPU producers (gives total bytes claimed across all
    /// sub-rings); `consumer_pos` is the sum of per-CPU
    /// consumers. These are *not* meaningful for advancing a
    /// single ring — use the per-CPU fields for that.
    pub producer_pos: u64,
    pub consumer_pos: u64,
    pub btf_off: u64,
    pub btf_len: u64,
    pub ksyms_off: u64,
    pub ksyms_len: u64,
    /// Aggregate drop counters (sum of all classes, summed across
    /// every CPU). Kept for the existing CLI bifrost_drops /
    /// dropped_bytes display lines. For per-class detail see
    /// `dropped_records_by_class` / `dropped_bytes_by_class`.
    pub dropped_records: u64,
    pub dropped_bytes: u64,
    /// Per-class drop totals, summed across CPUs.  Index by
    /// `bifrost_wire::SHMEM_DROP_CLASS_*`.
    pub dropped_records_by_class: [u64; 4],
    pub dropped_bytes_by_class: [u64; 4],
    pub wake_counter: u64,
}

pub struct RawDataRecordHeader {
    pub logical_pos: u64,
    pub ring_off: usize,
    pub size: u32,
    pub flags: u32,
    pub vmid: Option<u32>,
    pub probe_id: Option<u32>,
    pub gns: Option<u64>,
    pub word3: Option<u64>,
}

pub struct RawDataRecord {
    pub header: RawDataRecordHeader,
    pub payload: Vec<u8>,
}

pub struct DataShmAttachment {
    name: String,
    base: *mut u8,
    size: usize,
}

unsafe impl Send for DataShmAttachment {}
unsafe impl Sync for DataShmAttachment {}

impl DataShmAttachment {
    /// Construct a DataShmAttachment over caller-owned memory for
    /// integration tests. The caller MUST keep the backing buffer
    /// alive for at least as long as the attachment, and MUST
    /// populate the V5 header (magic / version / num_cpus /
    /// per_cpu_state_off / per_cpu_ring_len / per_cpu_state_stride)
    /// at the offsets the snapshot reader expects. Production code
    /// goes through `ControlShmAttachment::open_data_shm` which
    /// performs the shm_open + header validation. This bypass is
    /// only `#[doc(hidden)]` because tests under `tests/` are out-
    /// of-crate and need a public entry point; it carries no real
    /// safety guarantees and isn't part of the supported API.
    #[doc(hidden)]
    pub unsafe fn from_raw_for_test(base: *mut u8, size: usize, name: String) -> Self {
        Self { name, base, size }
    }
}

impl ControlShmAttachment {
    /// Open `/conduit-<pid>`, mmap the full region, and verify the
    /// header. Errors are returned with enough context to
    /// distinguish "no libkrun running with this pid" from "wrong
    /// version" / "magic mismatch" / "permission denied".
    ///
    /// vhost-user fallback: when `/conduit-<target_pid>` doesn't
    /// exist AND the operator built libkrun with the
    /// `vhost-user` Cargo feature, the conduit SHM is owned by
    /// the conduit-backend daemon process, not the libkrun VM
    /// process. The user habitually passes the libkrun PID
    /// (`-p $smolvm_pid`); falling back to enumerate observable
    /// conduits and using the single hit lets the same command
    /// work transparently across the in-VM and vhost-user transports.
    /// If multiple conduits are observable we refuse to guess
    /// and surface the original EndpointMissing error so the
    /// caller passes the right PID explicitly.
    pub fn open(target_pid: u32) -> Result<Self, ControlShmError> {
        match Self::open_exact(target_pid) {
            Err(ControlShmError::EndpointMissing(_)) => {
                let observable = enumerate_observable();
                if observable.len() == 1 {
                    let (alt_pid, _) = observable[0];
                    if alt_pid != target_pid {
                        eprintln!(
                            "[bifrost] no /conduit-{target_pid}; falling \
                             back to single observable conduit \
                             /conduit-{alt_pid} (likely owned by \
                             conduit-backend daemon)"
                        );
                        return Self::open_exact(alt_pid);
                    }
                }
                Err(ControlShmError::EndpointMissing(target_pid))
            }
            other => other,
        }
    }

    fn open_exact(target_pid: u32) -> Result<Self, ControlShmError> {
        let name = CString::new(format!("/conduit-{}", target_pid))
            .map_err(ControlShmError::BadShmName)?;
        let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR, 0) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOENT) => return Err(ControlShmError::EndpointMissing(target_pid)),
                Some(libc::EACCES) => return Err(ControlShmError::PermissionDenied(target_pid)),
                _ => {
                    return Err(ControlShmError::ShmOpen {
                        pid: target_pid,
                        source: err,
                    });
                }
            }
        }
        // Stat to learn the region size (libkrun ftruncate'd it).
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(ControlShmError::Fstat(err));
        }
        let size = st.st_size as usize;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };
        if base == libc::MAP_FAILED {
            return Err(ControlShmError::MmapFailed);
        }
        let base = base as *mut u8;

        // Decode header. The C-side layout is repr(C), so we mirror
        // it field-by-field rather than transmute (less hidden
        // padding surprises).
        let header = match unsafe { ControlShmHeader::decode(base as *const u8) } {
            Ok(h) => h,
            Err(e) => {
                unsafe { libc::munmap(base as *mut _, size) };
                return Err(ControlShmError::HeaderDecode {
                    pid: target_pid,
                    reason: e.to_string(),
                });
            }
        };

        if header.region_size != size as u64 {
            unsafe { libc::munmap(base as *mut _, size) };
            return Err(ControlShmError::RegionSizeMismatch {
                hdr: header.region_size,
                fstat: size,
            });
        }
        if header.version != CONTROL_SHM_VERSION {
            unsafe { libc::munmap(base as *mut _, size) };
            return Err(ControlShmError::VersionMismatch {
                got: header.version,
                want: CONTROL_SHM_VERSION,
            });
        }
        if header.pid != target_pid {
            unsafe { libc::munmap(base as *mut _, size) };
            return Err(ControlShmError::PidMismatch {
                got: header.pid,
                want: target_pid,
            });
        }

        Ok(ControlShmAttachment {
            name,
            base,
            size,
            header,
        })
    }

    pub fn data_shm_name(&self) -> Option<String> {
        if !self.header.supports_data_shm() || self.header.data_shm_name_len == 0 {
            return None;
        }
        let off = self.header.data_shm_name_off as usize;
        let len = self.header.data_shm_name_len as usize;
        if off.checked_add(len)? > self.size {
            return None;
        }
        let bytes = unsafe { std::slice::from_raw_parts(self.base.add(off), len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn open_data_shm(&self) -> Result<Option<DataShmAttachment>, ControlShmError> {
        let Some(name) = self.data_shm_name() else {
            return Ok(None);
        };
        let cname = CString::new(name.clone()).map_err(ControlShmError::BadShmName)?;
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0) };
        if fd < 0 {
            return Err(ControlShmError::ShmOpen {
                pid: self.header.pid,
                source: io::Error::last_os_error(),
            });
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(ControlShmError::Fstat(err));
        }
        let size = st.st_size as usize;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };
        if base == libc::MAP_FAILED {
            return Err(ControlShmError::MmapFailed);
        }
        Ok(Some(DataShmAttachment {
            name,
            base: base as *mut u8,
            size,
        }))
    }

    pub fn data_wake_counter(&self) -> Option<u64> {
        if self.header.data_wake_counter_off == 0 {
            return None;
        }
        let off = self.header.data_wake_counter_off as usize;
        if off.checked_add(8)? > self.size {
            return None;
        }
        let p = unsafe { self.base.add(off) as *const std::sync::atomic::AtomicU64 };
        Some(unsafe { (*p).load(std::sync::atomic::Ordering::Acquire) })
    }
}

impl DataShmAttachment {
    /// Snapshot the data-SHM header.  Mutable cursors (`producer_pos`,
    /// `consumer_pos`) are read with `Ordering::Acquire` so subsequent
    /// reads of the ringbuf body are synchronized-with the guest's
    /// `Release`-store on the producer side.  Immutable fields (offsets
    /// and caps set once at SHMEM_INIT) use plain memcpy.
    ///
    /// The Acquire matters on arm64: without it the host could observe
    /// a freshly-advanced `producer_pos` paired with stale record bytes
    /// that the producer's release-store has not yet published.
    pub fn snapshot(&self, wake_counter: u64) -> DataShmSnapshot {
        let read_u32 = |off: usize| -> u32 {
            let mut buf = [0u8; 4];
            unsafe {
                std::ptr::copy_nonoverlapping(self.base.add(off), buf.as_mut_ptr(), 4);
            }
            u32::from_le_bytes(buf)
        };
        let read_u64 = |off: usize| -> u64 {
            let mut buf = [0u8; 8];
            unsafe {
                std::ptr::copy_nonoverlapping(self.base.add(off), buf.as_mut_ptr(), 8);
            }
            u64::from_le_bytes(buf)
        };
        let read_atomic_u64 = |off: usize| -> u64 {
            let p = unsafe { self.base.add(off) as *const std::sync::atomic::AtomicU64 };
            unsafe { (*p).load(std::sync::atomic::Ordering::Acquire) }
        };

        // V4 header layout: per-CPU state lives at
        // `per_cpu_state_off + cpu * per_cpu_state_stride`. The
        // cap is `num_cpus` (per the SHMEM_INIT-time choice; see
        // bifrost_set_shmem_ringbuf in kernel/bpf/helpers.c).
        let num_cpus = read_u32(80);
        let per_cpu_state_stride = read_u32(84);
        let per_cpu_ring_len = read_u64(88);
        let per_cpu_state_off = read_u64(96);

        let num_cpus_safe = num_cpus.min(bifrost_wire::SHMEM_NUM_CPUS_MAX) as usize;
        let stride = if per_cpu_state_stride == 0 {
            bifrost_wire::SHMEM_PER_CPU_STATE_STRIDE as usize
        } else {
            per_cpu_state_stride as usize
        };
        let base_off = if per_cpu_state_off == 0 {
            bifrost_wire::SHMEM_PER_CPU_STATE_OFF as u64
        } else {
            per_cpu_state_off
        } as usize;

        let mut per_cpu = Vec::with_capacity(num_cpus_safe);
        let mut producer_total = 0u64;
        let mut consumer_total = 0u64;
        let mut dropped_records_by_class = [0u64; 4];
        let mut dropped_bytes_by_class = [0u64; 4];
        // V5: each per-CPU state entry is 80 useful bytes
        // (16 cursors + 32 dropped_records + 32 dropped_bytes),
        // rounded up to a 128-byte stride. We need 80 bytes
        // worth available in the mapped region to read a full
        // entry; older V4 layouts (64-byte stride, single
        // dropped_records/dropped_bytes pair) are no longer
        // supported — version is gate-checked at attach time.
        for cpu in 0..num_cpus_safe {
            let cpu_off = base_off + cpu * stride;
            if cpu_off + 80 > self.size {
                break;
            }
            let mut dropped_records = [0u64; 4];
            let mut dropped_bytes = [0u64; 4];
            for c in 0..4 {
                dropped_records[c] = read_u64(cpu_off + 16 + 8 * c);
                dropped_bytes[c] = read_u64(cpu_off + 48 + 8 * c);
            }
            let state = PerCpuShmemState {
                producer_pos: read_atomic_u64(cpu_off),
                consumer_pos: read_atomic_u64(cpu_off + 8),
                dropped_records,
                dropped_bytes,
            };
            producer_total = producer_total.wrapping_add(state.producer_pos);
            consumer_total = consumer_total.wrapping_add(state.consumer_pos);
            for c in 0..4 {
                dropped_records_by_class[c] =
                    dropped_records_by_class[c].saturating_add(dropped_records[c]);
                dropped_bytes_by_class[c] =
                    dropped_bytes_by_class[c].saturating_add(dropped_bytes[c]);
            }
            per_cpu.push(state);
        }
        let dropped_records_total: u64 = dropped_records_by_class.iter().copied().sum();
        let dropped_bytes_total: u64 = dropped_bytes_by_class.iter().copied().sum();

        DataShmSnapshot {
            name: self.name.clone(),
            size: self.size,
            magic: read_u32(0),
            version: read_u32(4),
            ringbuf_off: read_u64(16),
            ringbuf_len: read_u64(24),
            num_cpus,
            per_cpu_ring_len,
            per_cpu,
            producer_pos: producer_total,
            consumer_pos: consumer_total,
            btf_off: read_u64(32),
            btf_len: read_u64(40),
            ksyms_off: read_u64(48),
            ksyms_len: read_u64(56),
            dropped_records: dropped_records_total,
            dropped_bytes: dropped_bytes_total,
            dropped_records_by_class,
            dropped_bytes_by_class,
            wake_counter,
        }
    }

    /// Compute the byte offset of CPU `cpu`'s `consumer_pos` slot
    /// in the SHMEM header. Helper for `store_consumer_pos_cpu`.
    fn per_cpu_state_off_for(snap: &DataShmSnapshot, cpu: u32) -> Option<usize> {
        let stride = if snap.per_cpu_ring_len == 0 {
            return None;
        } else {
            bifrost_wire::SHMEM_PER_CPU_STATE_STRIDE as usize
        };
        let base_off = bifrost_wire::SHMEM_PER_CPU_STATE_OFF as usize;
        Some(base_off + (cpu as usize) * stride)
    }

    /// Store `pos` into the per-CPU `consumer_pos` for sub-ring
    /// `cpu`. Returns None if `cpu` is out of range or the slot
    /// would land outside the mapped region.
    pub fn store_consumer_pos_cpu(&self, snap: &DataShmSnapshot, cpu: u32, pos: u64) -> Option<()> {
        if cpu >= snap.num_cpus {
            return None;
        }
        let cpu_off = Self::per_cpu_state_off_for(snap, cpu)?;
        let consumer_off = cpu_off.checked_add(8)?;
        if consumer_off.checked_add(8)? > self.size {
            return None;
        }
        let p = unsafe { self.base.add(consumer_off) as *const std::sync::atomic::AtomicU64 };
        unsafe {
            (*p).store(pos, std::sync::atomic::Ordering::Release);
        }
        Some(())
    }

    /// Legacy single-ring entry point; advances CPU 0's
    /// consumer cursor. Retained for the few call sites that
    /// haven't been moved to the per-CPU API. New code should
    /// use `store_consumer_pos_cpu`.
    pub fn store_consumer_pos(&self, pos: u64) -> Option<()> {
        let snap = self.snapshot(0);
        self.store_consumer_pos_cpu(&snap, 0, pos)
    }

    pub fn record_headers(&self, limit: usize) -> Vec<RawDataRecordHeader> {
        let snap = self.snapshot(0);
        self.record_headers_between(snap.consumer_pos, snap.producer_pos, limit)
    }

    pub fn record_headers_between(
        &self,
        start_pos: u64,
        end_pos: u64,
        limit: usize,
    ) -> Vec<RawDataRecordHeader> {
        self.records_between(start_pos, end_pos, limit)
            .into_iter()
            .map(|rec| rec.header)
            .collect()
    }

    pub fn read_region_bytes(&self, off: u64, len: u64) -> Option<Vec<u8>> {
        let off = off as usize;
        let len = len as usize;
        if len == 0 || off.checked_add(len)? > self.size {
            return None;
        }
        let mut out = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.add(off), out.as_mut_ptr(), len);
        }
        Some(out)
    }

    /// Walk records in a specific per-CPU sub-ring. `cpu` selects
    /// the sub-ring; `start_pos` and `end_pos` are logical positions
    /// in that sub-ring's own position space.
    pub fn records_between_cpu(
        &self,
        cpu: u32,
        start_pos: u64,
        end_pos: u64,
        limit: usize,
        snap: &DataShmSnapshot,
    ) -> Vec<RawDataRecord> {
        if cpu >= snap.num_cpus || snap.per_cpu_ring_len == 0 {
            return Vec::new();
        }
        let ring_off = (snap.ringbuf_off + (cpu as u64) * snap.per_cpu_ring_len) as usize;
        let ring_len = snap.per_cpu_ring_len as usize;
        if ring_off >= self.size {
            return Vec::new();
        }
        self.records_between_in_ring(ring_off, ring_len, start_pos, end_pos, limit)
    }

    /// Legacy single-ring entry point — operates on CPU 0's
    /// sub-ring. Retained for `record_headers` and `bifrost data`
    /// callers that haven't been wired to the per-CPU API.
    pub fn records_between(
        &self,
        start_pos: u64,
        end_pos: u64,
        limit: usize,
    ) -> Vec<RawDataRecord> {
        let snap = self.snapshot(0);
        self.records_between_cpu(0, start_pos, end_pos, limit, &snap)
    }

    fn records_between_in_ring(
        &self,
        ring_off: usize,
        ring_len: usize,
        mut start_pos: u64,
        end_pos: u64,
        limit: usize,
    ) -> Vec<RawDataRecord> {
        if start_pos == end_pos {
            return Vec::new();
        }
        let mut out = Vec::new();
        if ring_len == 0 || ring_off >= self.size {
            return out;
        }
        if end_pos.saturating_sub(start_pos) > ring_len as u64 {
            start_pos = end_pos.saturating_sub(ring_len as u64);
        }
        let mut pos = start_pos;
        while pos != end_pos && out.len() < limit {
            let rel = (pos as usize) % ring_len;
            // The kernel-side producer order is:
            //   atomic64_cmpxchg(producer_pos, cur, new_pos)    // claim
            //   rec_hdr[0] = size                               // body length
            //   WRITE_ONCE(rec_hdr[1], 0)                       // busy
            //   <write body>
            //   smp_store_release(&rec_hdr[1], READY [| PADDING])
            //
            // Read flags FIRST with Acquire semantics — it pairs with the
            // producer's smp_store_release.  When the load returns 0 the
            // record body and size are not yet published; we must stop the
            // walk and retry on the next snapshot rather than reading a
            // garbage `size` and advancing past valid records.
            // Record header is 8 bytes (size:u32, flags:u32) at `rel`;
            // ring_len is 8-byte aligned, so rel+4 cannot straddle the
            // wraparound — a simple add suffices.
            let flags_addr =
                unsafe { self.base.add(ring_off + rel + 4) as *const std::sync::atomic::AtomicU32 };
            // Spin briefly on a busy record (claimed-but-not-yet-
            // published).  The producer commits the body in tens of
            // nanoseconds; spinning here keeps us from giving up on a
            // record whose body lands a moment later.  Breaking out
            // on every transient busy stalls the consumer forever
            // under high-rate fbt traffic because the head of the
            // ring is almost always being written to.
            let mut flags = unsafe { (*flags_addr).load(std::sync::atomic::Ordering::Acquire) };
            let mut spins = 0u32;
            while flags == 0 && spins < 1024 {
                std::hint::spin_loop();
                flags = unsafe { (*flags_addr).load(std::sync::atomic::Ordering::Acquire) };
                spins += 1;
            }
            if flags == 0 {
                // Body still not published after the spin budget. Stop
                // here so the caller knows to set consumer_pos to `pos`
                // (not past it) — we'll retry next pass.
                break;
            }
            let Some(hdr) = self.read_ring_bytes(ring_off, ring_len, rel, 8) else {
                break;
            };
            let size = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            // flags was loaded above with Acquire; re-derive from `hdr`
            // for compatibility with the downstream RawDataRecordHeader
            // struct shape.
            let _ = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
            let payload_head = if size >= 24 {
                self.read_ring_bytes(ring_off, ring_len, rel + 8, 24)
            } else {
                None
            };
            let payload = self
                .read_ring_bytes(ring_off, ring_len, rel + 8, size as usize)
                .unwrap_or_default();
            let (vmid, probe_id, gns, word3) = if let Some(bytes) = payload_head {
                (
                    Some(u32::from_le_bytes(bytes[0..4].try_into().unwrap())),
                    Some(u32::from_le_bytes(bytes[4..8].try_into().unwrap())),
                    Some(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
                    Some(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
                )
            } else {
                (None, None, None, None)
            };
            let header = RawDataRecordHeader {
                logical_pos: pos,
                ring_off: rel,
                size,
                flags,
                vmid,
                probe_id,
                gns,
                word3,
            };
            out.push(RawDataRecord { header, payload });
            let advance = (8 + size as usize + 7) & !7;
            if advance == 0 || advance > ring_len {
                break;
            }
            pos = pos.wrapping_add(advance as u64);
            if pos > end_pos {
                break;
            }
        }
        out
    }

    fn read_ring_bytes(
        &self,
        ring_off: usize,
        ring_len: usize,
        rel: usize,
        len: usize,
    ) -> Option<Vec<u8>> {
        if ring_len == 0 || len > ring_len || ring_off.checked_add(ring_len)? > self.size {
            return None;
        }
        let rel = rel % ring_len;
        let first = len.min(ring_len - rel);
        let mut out = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.add(ring_off + rel), out.as_mut_ptr(), first);
            if first < len {
                std::ptr::copy_nonoverlapping(
                    self.base.add(ring_off),
                    out.as_mut_ptr().add(first),
                    len - first,
                );
            }
        }
        Some(out)
    }
}

impl Drop for DataShmAttachment {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut _, self.size);
        }
    }
}

/// Enumerate observable conduit processes by probing the POSIX
/// shm namespace for `/conduit-<pid>` entries that match our
/// header magic. Returns Vec<(pid, header)> for each reachable
/// endpoint.
///
/// macOS shm namespace lives in `/var/run/com.apple.systemstats/`
/// in some configurations and is otherwise opaque (shm_open
/// names live in a kernel-side hash that isn't exposed via the
/// filesystem). We instead probe candidate pids: walk the host's
/// process list (via `ps -A -o pid=`), shm_open the matching
/// names, keep the ones with a valid header.
pub fn enumerate_observable() -> Vec<(u32, ControlShmHeader)> {
    use std::process::Command;
    let mut out = Vec::new();
    let ps = match Command::new("/bin/ps").args(["-A", "-o", "pid="]).output() {
        Ok(o) => o,
        Err(_) => return out,
    };
    for line in String::from_utf8_lossy(&ps.stdout).lines() {
        let pid_str = line.trim();
        if pid_str.is_empty() {
            continue;
        }
        if let Ok(pid) = pid_str.parse::<u32>()
            && let Ok(att) = ControlShmAttachment::open_exact(pid)
        {
            out.push((pid, att.header.clone()));
        }
    }
    out
}

impl ControlShmAttachment {
    /// Pointer to the cmd_producer_pos atomic counter (offset 64
    /// in the header, per the documented layout).
    pub fn cmd_producer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(64) as *const AtomicU64) }
    }
    /// Pointer to the cmd_consumer_pos atomic counter (offset 72).
    pub fn cmd_consumer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(72) as *const AtomicU64) }
    }
    /// Pointer to the rsp_producer_pos atomic counter (offset 80).
    pub fn rsp_producer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(80) as *const AtomicU64) }
    }
    /// Pointer to the rsp_consumer_pos atomic counter (offset 88).
    pub fn rsp_consumer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(88) as *const AtomicU64) }
    }
    /// Push a command into the cmd_ring. The payload bytes are
    /// copied into the ring; the ring's producer_pos advances by
    /// `RING_HDR_SIZE + align_up(payload.len(), RING_ENTRY_ALIGN)`.
    /// On wraparound, a `KIND_PAD` entry is inserted to skip the
    /// tail.
    ///
    /// Returns the seq the command was tagged with so the caller
    /// can match a response from the rsp_ring.
    ///
    /// Errors when the ring is full (consumer hasn't drained
    /// enough) or the entry size exceeds the ring's capacity (in
    /// which case the wire format itself can't deliver this
    /// payload — fail fast rather than spin).
    pub fn push_cmd(&self, kind: u32, payload: &[u8]) -> Result<u64, ControlShmError> {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);

        let entry_total = RING_HDR_SIZE + align_up(payload.len(), RING_ENTRY_ALIGN);
        let ring_off = self.header.cmd_ring_off as usize;
        let ring_len = self.header.cmd_ring_len as usize;
        if entry_total > ring_len {
            return Err(ControlShmError::CmdEntryTooLarge {
                entry: entry_total,
                ring: ring_len,
            });
        }

        let prod = self.cmd_producer_pos().load(Ordering::Relaxed);
        let cons = self.cmd_consumer_pos().load(Ordering::Acquire);
        let used = prod.wrapping_sub(cons) as usize;
        let free = ring_len.saturating_sub(used);

        let head_off = (prod as usize) % ring_len;
        let tail_remaining = ring_len - head_off;

        // Decide if we need a PAD entry to skip the tail.
        let (write_off, advance) = if entry_total > tail_remaining {
            // Need PAD + then real entry from offset 0.
            let needed = tail_remaining + entry_total;
            if needed > free {
                return Err(ControlShmError::CmdRingFullWithPad {
                    free,
                    need: needed,
                    pad: tail_remaining,
                });
            }
            // Write PAD header with len=tail_remaining-RING_HDR_SIZE
            // (covers the tail bytes the consumer should skip).
            unsafe {
                let p = self.base.add(ring_off + head_off);
                write_u32_le(p, KIND_PAD);
                write_u32_le(p.add(4), (tail_remaining - RING_HDR_SIZE) as u32);
                write_u64_le(p.add(8), 0);
            }
            (0usize, tail_remaining + entry_total)
        } else {
            if entry_total > free {
                return Err(ControlShmError::CmdRingFull {
                    free,
                    need: entry_total,
                });
            }
            (head_off, entry_total)
        };

        // Write the real entry header + payload.
        unsafe {
            let p = self.base.add(ring_off + write_off);
            write_u32_le(p, kind);
            write_u32_le(p.add(4), payload.len() as u32);
            write_u64_le(p.add(8), seq);
            if !payload.is_empty() {
                std::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    p.add(RING_HDR_SIZE),
                    payload.len(),
                );
            }
        }
        self.cmd_producer_pos()
            .fetch_add(advance as u64, Ordering::Release);
        Ok(seq)
    }

    /// Poll the rsp_ring for a response with the given seq (or
    /// any if `wanted_seq` is None). Blocks up to `timeout` polling
    /// every 5 ms.
    ///
    /// The deadline is honored even when the ring is busy: if a
    /// steady stream of non-matching entries (e.g. unsolicited
    /// KIND_AGG_PUSH from a live trace) hits the rsp_ring while we
    /// are waiting on a specific seq, we still bail at the deadline
    /// instead of livelocking on the entry-decode loop. This is the
    /// bug that surfaced as redis-uprobe's "bifrost CLI hung past
    /// its own 2-second timeout" sweep flake.
    ///
    /// Returns Ok(Some((kind, seq, payload))) on success,
    /// Ok(None) on timeout, Err on a malformed entry.
    pub fn poll_rsp(
        &self,
        wanted_seq: Option<u64>,
        timeout: std::time::Duration,
    ) -> Result<Option<(u32, u64, Vec<u8>)>, ControlShmError> {
        let ring_off = self.header.rsp_ring_off as usize;
        let ring_len = self.header.rsp_ring_len as usize;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // Deadline check at the TOP of the loop, so a busy ring
            // (entries streaming but none matching `wanted_seq`)
            // can't starve the timeout. See doc comment above.
            if std::time::Instant::now() > deadline {
                return Ok(None);
            }
            let prod = self.rsp_producer_pos().load(Ordering::Acquire);
            let cons = self.rsp_consumer_pos().load(Ordering::Relaxed);
            if prod != cons {
                let head_off = (cons as usize) % ring_len;
                // Read entry header.
                let (kind, len, seq) = unsafe {
                    let p = self.base.add(ring_off + head_off);
                    (read_u32_le(p), read_u32_le(p.add(4)), read_u64_le(p.add(8)))
                };
                if kind == KIND_PAD {
                    // Skip tail.
                    let tail = ring_len - head_off;
                    self.rsp_consumer_pos()
                        .fetch_add(tail as u64, Ordering::Release);
                    continue;
                }
                let entry_total = RING_HDR_SIZE + align_up(len as usize, RING_ENTRY_ALIGN);
                if head_off + entry_total > ring_len {
                    return Err(ControlShmError::RspEntryOverrun {
                        head_off,
                        len,
                        ring_len,
                    });
                }
                let payload = unsafe {
                    let p = self.base.add(ring_off + head_off + RING_HDR_SIZE);
                    std::slice::from_raw_parts(p as *const u8, len as usize).to_vec()
                };
                self.rsp_consumer_pos()
                    .fetch_add(entry_total as u64, Ordering::Release);
                if wanted_seq.is_some() && wanted_seq != Some(seq) {
                    // Not ours — drop and keep polling.
                    continue;
                }
                return Ok(Some((kind, seq, payload)));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// Non-blocking drain: pop every entry currently sitting in the
    /// rsp_ring and return them in arrival order. Used by the
    /// run-loop to pick up unsolicited pushes (KIND_AGG_PUSH) that
    /// libkrun emits at its own cadence — `poll_rsp` would block
    /// waiting for a matching seq, which doesn't fit a "drain
    /// whatever's there each tick" pattern.
    pub fn drain_rsp_ring(&self) -> Vec<(u32, u64, Vec<u8>)> {
        let ring_off = self.header.rsp_ring_off as usize;
        let ring_len = self.header.rsp_ring_len as usize;
        let mut out = Vec::new();
        loop {
            let prod = self.rsp_producer_pos().load(Ordering::Acquire);
            let cons = self.rsp_consumer_pos().load(Ordering::Relaxed);
            if prod == cons {
                break;
            }
            let head_off = (cons as usize) % ring_len;
            let (kind, len, seq) = unsafe {
                let p = self.base.add(ring_off + head_off);
                (read_u32_le(p), read_u32_le(p.add(4)), read_u64_le(p.add(8)))
            };
            if kind == KIND_PAD {
                let tail = ring_len - head_off;
                self.rsp_consumer_pos()
                    .fetch_add(tail as u64, Ordering::Release);
                continue;
            }
            let entry_total = RING_HDR_SIZE + align_up(len as usize, RING_ENTRY_ALIGN);
            if head_off + entry_total > ring_len {
                // Malformed — bail rather than corrupting the ring.
                break;
            }
            let payload = unsafe {
                let p = self.base.add(ring_off + head_off + RING_HDR_SIZE);
                std::slice::from_raw_parts(p as *const u8, len as usize).to_vec()
            };
            self.rsp_consumer_pos()
                .fetch_add(entry_total as u64, Ordering::Release);
            out.push((kind, seq, payload));
        }
        out
    }
}

impl Drop for ControlShmAttachment {
    fn drop(&mut self) {
        unsafe {
            if !self.base.is_null() {
                libc::munmap(self.base as *mut _, self.size);
            }
        }
        // No shm_unlink — that's libkrun's job.
        let _ = &self.name; // suppress unused
    }
}

impl ControlShmHeader {
    /// Decode bytes from `*const u8` at the beginning of a mapped
    /// control SHM region. Returns `Err` with a human-readable
    /// reason when the magic doesn't match the conduit layout —
    /// callers should surface that directly rather than re-deriving
    /// "this isn't ours" from a downstream geometry check.
    unsafe fn decode(p: *const u8) -> Result<Self, ControlShmError> {
        let read_u64 = |off: usize| -> u64 {
            let mut buf = [0u8; 8];
            unsafe {
                std::ptr::copy_nonoverlapping(p.add(off), buf.as_mut_ptr(), 8);
            }
            u64::from_le_bytes(buf)
        };
        let read_u32 = |off: usize| -> u32 {
            let mut buf = [0u8; 4];
            unsafe {
                std::ptr::copy_nonoverlapping(p.add(off), buf.as_mut_ptr(), 4);
            }
            u32::from_le_bytes(buf)
        };
        let magic = read_u64(0);
        if magic != CONTROL_SHM_MAGIC {
            return Err(ControlShmError::BadMagic {
                got: magic,
                want: CONTROL_SHM_MAGIC,
            });
        }
        Ok(ControlShmHeader {
            version: read_u32(8),
            pid: read_u32(12),
            region_size: read_u64(16),
            caps: read_u64(24),
            cmd_ring_off: read_u64(32),
            cmd_ring_len: read_u64(40),
            rsp_ring_off: read_u64(48),
            rsp_ring_len: read_u64(56),
            data_shm_name_off: read_u64(CONTROL_DATA_SHM_META_OFF),
            data_shm_name_len: read_u32(CONTROL_DATA_SHM_META_OFF + 8),
            data_shm_protocol_version: read_u32(CONTROL_DATA_SHM_META_OFF + 12),
            data_shm_size: read_u64(CONTROL_DATA_SHM_META_OFF + 16),
            data_wakeup_mode: read_u32(CONTROL_DATA_SHM_META_OFF + 24),
            data_wake_counter_off: read_u64(CONTROL_DATA_SHM_META_OFF + 32),
        })
    }
}
