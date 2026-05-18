// SPDX-License-Identifier: Apache-2.0
//
// Control-SHM cmd/rsp ring semantics.
//
// ## Conceptual model
//
// The conduit publishes a single POSIX SHM region per session
// carrying two single-producer/single-consumer rings:
//
//   - *cmd ring* (`cmd_ring_off..+cmd_ring_len`): observer →
//     conduit.  The CLI side is the producer; libkrun is the
//     consumer.
//   - *rsp ring* (`rsp_ring_off..+rsp_ring_len`): conduit →
//     observer.  libkrun produces, the CLI consumes.
//
// Each entry is a 16-byte aligned record with a 16-byte header
// (`[u32 kind][u32 len][u64 seq]`) followed by `len` payload bytes
// padded out to the alignment.  `producer_pos` and `consumer_pos`
// are monotonically increasing logical byte counters; ring offset
// is `pos % ring_len`.
//
// ## PAD on wraparound
//
// When an entry would split across the ring's end the producer
// first writes a `KIND_PAD` entry consuming the remaining tail,
// advances `producer_pos` to the next ring boundary, then writes
// the real entry from offset 0.  The consumer reads `KIND_PAD`
// like any other entry and skips it.  There is no special wrap
// state — pads are records.
//
// ## Transport opacity
//
// libkrun and this module treat command payloads as **opaque
// bytes**.  Only the generic transport kinds (`KIND_CTRL_PAYLOAD`,
// `KIND_RSP_OK`, `KIND_RSP_ERR`, `KIND_PAD`) and the byte-order
// of header fields are visible at this layer; the bifrost
// semantic protocol (BFR7 wrappers, LOAD_PROG cohorts, agg pushes)
// rides inside the `KIND_CTRL_PAYLOAD` body and is decoded by the
// bifrost-wire crate.  This boundary keeps the conduit free to
// carry any future protocol that happens to fit the same envelope
// without growing dispatch in libkrun.
//
// ## Sequence-number invariants
//
// Every request carries a monotonically-increasing `seq`.
// Responses echo the request's seq so the observer can pair them
// even if the conduit reorders responses across kinds (it
// currently does not, but the protocol does not require ordered
// delivery).  An unsolicited push (`AGG_PUSH`, `RECORD_PUSH`,
// `SELF_TRACE_PUSH`) sets `seq = 0` to mark it as not paired with
// any request.
//
// ## Wake FIFO
//
// A FIFO at a deterministic path (`/tmp/bifrost-wake-<pid>`)
// supplements busy-polling: producers `write(1)` a single byte
// when they advance `producer_pos`, so a blocked reader on the
// FIFO wakes promptly even if it is sleeping in `read()` instead
// of spinning on the SHM cursor.  Wake bytes are advisory; they
// do not carry the position update — readers always re-snapshot
// the SHM header.

use std::ffi::CString;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;

/// Default control-SHM size. The ring is intentionally roomy because
/// host commands can carry opaque CLI-built guest commands. Override via
/// the VIRTIO_CONDUIT_CONTROL_SHM_SIZE env var if needed.
pub const CONTROL_SHM_DEFAULT_SIZE: usize = 1024 * 1024;
pub const CONTROL_SHM_HDR_SIZE: usize = 4096;
pub const CONTROL_SHM_MAGIC: u64 = 0x4c54435f_54434642;
pub const CONTROL_SHM_VERSION: u32 = 1;
pub const CONTROL_CAP_CTRL_PAYLOAD: u64 = 1 << 0;
pub const CONTROL_CAP_DATA_SHM: u64 = 1 << 1;
pub const CONTROL_DATA_SHM_META_OFF: usize = 128;
pub const CONTROL_DATA_SHM_NAME_OFF: usize = 256;
pub const CONTROL_DATA_SHM_NAME_MAX: usize = 128;
pub const CONTROL_DATA_SHM_PROTOCOL_VERSION: u32 = 1;
pub const CONTROL_WAKE_COUNTER: u32 = 2;
pub const CONTROL_DATA_WAKE_COUNTER_OFF: usize = 192;

/// Fixed cmd-ring length. Single-entry overhead: the largest opaque
/// CLI-built command must fit twice over (tail remaining + entry,
/// since `push_cmd` emits a PAD on wraparound). 64 KB comfortably
/// accommodates current host-built LOAD_PROG payloads.
pub const CONTROL_CMD_RING_LEN: usize = 64 * 1024;
/// Minimum rsp-ring length: one page. The actual rsp ring grows to
/// consume whatever remains after `CONTROL_SHM_HDR_SIZE +
/// CONTROL_CMD_RING_LEN`.
pub const CONTROL_RSP_RING_MIN_LEN: usize = 4096;
/// Absolute minimum control-SHM size that admits a usable ring pair.
/// Smaller sizes are rejected by [`ControlShm::create`] before any
/// subtraction or mmap so corrupted env-var input cannot underflow
/// the ring layout math.
pub const CONTROL_SHM_MIN_SIZE: usize =
    CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN + CONTROL_RSP_RING_MIN_LEN;

// Control-ring command/response kinds still needed by the conduit.
// Domain-specific payload kinds are intentionally not re-exported here;
// libkrun should not dispatch on tracing semantics.
pub use crate::wire::{
    KIND_CTRL_PAYLOAD, KIND_CTRL_PAYLOAD_REQ, KIND_PAD, KIND_RSP_ERR, KIND_RSP_OK,
    KIND_RSP_PAYLOAD, OP_CTRL_RESPONSE, OP_DATA_SHM_READY,
};
pub const CONTROL_RING_HDR_SIZE: usize = 16;
pub const CONTROL_RING_ENTRY_ALIGN: usize = 16;

/// Resolved control-SHM layout for a given region size.
///
/// Computed by [`compute_ring_layout`] without touching `mmap` so the
/// sizing rules are testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingLayout {
    pub cmd_ring_off: usize,
    pub cmd_ring_len: usize,
    pub rsp_ring_off: usize,
    pub rsp_ring_len: usize,
}

/// Compute the cmd/rsp ring offsets and lengths from a control-SHM
/// region size. Returns `Err` on any size that cannot satisfy the
/// header + cmd-ring + minimum-rsp-ring layout.
///
/// The conduit contract pins:
/// - `cmd_ring_off` at `CONTROL_SHM_HDR_SIZE`,
/// - `cmd_ring_len` at [`CONTROL_CMD_RING_LEN`],
/// - `rsp_ring_off` immediately after the cmd ring,
/// - `rsp_ring_len` to whatever remains, rounded down to a 4 KB
///   multiple, with a [`CONTROL_RSP_RING_MIN_LEN`] floor.
pub fn compute_ring_layout(size: usize) -> Result<RingLayout, String> {
    if size < CONTROL_SHM_MIN_SIZE {
        return Err(format!(
            "control SHM size {} < minimum {} (hdr {} + cmd_ring {} + rsp_ring {})",
            size,
            CONTROL_SHM_MIN_SIZE,
            CONTROL_SHM_HDR_SIZE,
            CONTROL_CMD_RING_LEN,
            CONTROL_RSP_RING_MIN_LEN,
        ));
    }
    let cmd_ring_off = CONTROL_SHM_HDR_SIZE;
    let cmd_ring_len = CONTROL_CMD_RING_LEN;
    let rsp_ring_off = cmd_ring_off + cmd_ring_len;
    let rsp_ring_len = (size - rsp_ring_off) & !0xfff;
    if rsp_ring_len < CONTROL_RSP_RING_MIN_LEN {
        return Err(format!(
            "control SHM size {} leaves rsp_ring_len {} below minimum {}",
            size, rsp_ring_len, CONTROL_RSP_RING_MIN_LEN
        ));
    }
    Ok(RingLayout {
        cmd_ring_off,
        cmd_ring_len,
        rsp_ring_off,
        rsp_ring_len,
    })
}

// Control-SHM header field offsets (matches docs/virtio-conduit.md).
// All multi-byte fields are explicit little-endian — see
// `docs/virtio-conduit.md` § "Wire byte order". Encode/decode via
// `to_le_bytes` / `from_le_bytes` so the transport stays portable
// to a big-endian guest.
const HDR_OFF_MAGIC: usize = 0;
const HDR_OFF_VERSION: usize = 8;
const HDR_OFF_PID: usize = 12;
const HDR_OFF_REGION_SIZE: usize = 16;
const HDR_OFF_CAPS: usize = 24;
const HDR_OFF_CMD_RING_OFF: usize = 32;
const HDR_OFF_CMD_RING_LEN: usize = 40;
const HDR_OFF_RSP_RING_OFF: usize = 48;
const HDR_OFF_RSP_RING_LEN: usize = 56;

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

pub struct ControlShmView {
    pub base: *mut u8,
    pub region_size: usize,
    pub cmd_ring_off: usize,
    pub cmd_ring_len: usize,
    pub rsp_ring_off: usize,
    pub rsp_ring_len: usize,
    /// Cross-process wake FIFO. Opened write-only with
    /// O_NONBLOCK at attachment time. Each
    /// `increment_data_wake_counter` writes one byte; bifrost-side
    /// readers wake via poll/kqueue on the matching read fd. The
    /// path is `/tmp/bifrost-wake-<pid>` (deterministic from the
    /// libkrun pid so the renderer can derive it without a
    /// control-SHM publish). The write is non-blocking — if no
    /// reader is attached the byte is silently dropped and the
    /// existing wake_counter polling still drives the renderer.
    wake_fifo_fd: AtomicI32,
}

unsafe impl Send for ControlShmView {}
unsafe impl Sync for ControlShmView {}

#[inline]
fn ring_align_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

impl ControlShmView {
    fn cmd_producer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(64) as *const AtomicU64) }
    }
    fn cmd_consumer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(72) as *const AtomicU64) }
    }
    fn rsp_producer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(80) as *const AtomicU64) }
    }
    fn rsp_consumer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.base.add(88) as *const AtomicU64) }
    }

    pub fn drain_cmds(&self) -> Vec<(u32, u64, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            let prod = self.cmd_producer_pos().load(Ordering::Acquire);
            let cons = self.cmd_consumer_pos().load(Ordering::Relaxed);
            if prod == cons {
                break;
            }
            let head_off = (cons as usize) % self.cmd_ring_len;
            let (kind, len, seq) = unsafe {
                let p = self.base.add(self.cmd_ring_off + head_off);
                (read_u32_le(p), read_u32_le(p.add(4)), read_u64_le(p.add(8)))
            };
            if kind == KIND_PAD {
                let tail = self.cmd_ring_len - head_off;
                self.cmd_consumer_pos()
                    .fetch_add(tail as u64, Ordering::Release);
                continue;
            }
            let entry_total =
                CONTROL_RING_HDR_SIZE + ring_align_up(len as usize, CONTROL_RING_ENTRY_ALIGN);
            if head_off + entry_total > self.cmd_ring_len {
                break;
            }
            let payload = unsafe {
                let p = self
                    .base
                    .add(self.cmd_ring_off + head_off + CONTROL_RING_HDR_SIZE);
                std::slice::from_raw_parts(p as *const u8, len as usize).to_vec()
            };
            self.cmd_consumer_pos()
                .fetch_add(entry_total as u64, Ordering::Release);
            out.push((kind, seq, payload));
        }
        out
    }

    pub fn push_rsp(&self, kind: u32, seq: u64, payload: &[u8]) -> Result<(), String> {
        let entry_total =
            CONTROL_RING_HDR_SIZE + ring_align_up(payload.len(), CONTROL_RING_ENTRY_ALIGN);
        if entry_total > self.rsp_ring_len {
            return Err("rsp too large".into());
        }
        let prod = self.rsp_producer_pos().load(Ordering::Relaxed);
        let cons = self.rsp_consumer_pos().load(Ordering::Acquire);
        let free = self
            .rsp_ring_len
            .saturating_sub((prod.wrapping_sub(cons)) as usize);
        let head_off = (prod as usize) % self.rsp_ring_len;
        let tail_remaining = self.rsp_ring_len - head_off;
        let (write_off, advance) = if entry_total > tail_remaining {
            if tail_remaining + entry_total > free {
                return Err("full".into());
            }
            unsafe {
                let p = self.base.add(self.rsp_ring_off + head_off);
                write_u32_le(p, KIND_PAD);
                write_u32_le(p.add(4), (tail_remaining - CONTROL_RING_HDR_SIZE) as u32);
                write_u64_le(p.add(8), 0);
            }
            (0, tail_remaining + entry_total)
        } else {
            if entry_total > free {
                return Err("full".into());
            }
            (head_off, entry_total)
        };
        unsafe {
            let p = self.base.add(self.rsp_ring_off + write_off);
            write_u32_le(p, kind);
            write_u32_le(p.add(4), payload.len() as u32);
            write_u64_le(p.add(8), seq);
            if !payload.is_empty() {
                std::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    p.add(CONTROL_RING_HDR_SIZE),
                    payload.len(),
                );
            }
        }
        self.rsp_producer_pos()
            .fetch_add(advance as u64, Ordering::Release);
        Ok(())
    }

    pub fn publish_data_shm(&self, name: &str, size: usize) -> Result<(), String> {
        let bytes = name.as_bytes();
        if bytes.len() > CONTROL_DATA_SHM_NAME_MAX {
            return Err(format!("data SHM name too long: {} bytes", bytes.len()));
        }
        if CONTROL_DATA_SHM_NAME_OFF + CONTROL_DATA_SHM_NAME_MAX > CONTROL_SHM_HDR_SIZE {
            return Err("data SHM name storage exceeds control header".into());
        }
        unsafe {
            let dst = self.base.add(CONTROL_DATA_SHM_NAME_OFF);
            std::ptr::write_bytes(dst, 0, CONTROL_DATA_SHM_NAME_MAX);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());

            // Caps is an LE-encoded u64 in the header. Read-modify-write
            // so we keep the documented byte order regardless of host.
            let caps_ptr = self.base.add(HDR_OFF_CAPS);
            let caps = read_u64_le(caps_ptr) | CONTROL_CAP_DATA_SHM;
            write_u64_le(caps_ptr, caps);
            let meta = self.base.add(CONTROL_DATA_SHM_META_OFF);
            write_u64_le(meta, CONTROL_DATA_SHM_NAME_OFF as u64);
            write_u32_le(meta.add(8), bytes.len() as u32);
            write_u32_le(meta.add(12), CONTROL_DATA_SHM_PROTOCOL_VERSION);
            write_u64_le(meta.add(16), size as u64);
            write_u32_le(meta.add(24), CONTROL_WAKE_COUNTER);
            write_u32_le(meta.add(28), 0);
            write_u64_le(meta.add(32), CONTROL_DATA_WAKE_COUNTER_OFF as u64);
            let wake_counter = self.base.add(CONTROL_DATA_WAKE_COUNTER_OFF) as *mut AtomicU64;
            (*wake_counter).store(0, Ordering::Release);
        }
        Ok(())
    }

    pub fn increment_data_wake_counter(&self) {
        unsafe {
            let wake_counter = self.base.add(CONTROL_DATA_WAKE_COUNTER_OFF) as *const AtomicU64;
            (*wake_counter).fetch_add(1, Ordering::Release);
        }
        // Also poke the wake FIFO so any blocked reader on the
        // bifrost side wakes immediately rather than waiting for its
        // next 250 µs poll cycle. Best-effort: lazy-open if not yet
        // ready, drop EAGAIN/EPIPE silently.
        self.poke_wake_fifo();
    }

    /// Create + open the wake FIFO at
    /// `/tmp/bifrost-wake-<pid>` write-only with O_NONBLOCK.
    /// Called once at attachment. The FIFO may already exist
    /// (recreated from a prior libkrun run with the same pid);
    /// mkfifo's EEXIST is tolerated. Open returns ENXIO if no
    /// reader is attached yet — that's fine, `poke_wake_fifo`
    /// retries lazily.
    pub fn open_wake_fifo(&self, pid: u32) {
        let path = format!("/tmp/bifrost-wake-{}\0", pid);
        unsafe {
            // mkfifo(path, 0o600) — owner-only RW. Ignore EEXIST.
            let rc = libc::mkfifo(path.as_ptr() as *const libc::c_char, 0o600);
            if rc < 0 {
                let err = *libc::__error();
                if err != libc::EEXIST {
                    log::warn!(
                        "virtio-conduit: mkfifo({}) failed: errno={}",
                        path.trim_end_matches('\0'),
                        err
                    );
                    return;
                }
            }
            let fd = libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_NONBLOCK,
            );
            if fd < 0 {
                // ENXIO means "no reader yet" — fine. Retry on
                // next wake.
                return;
            }
            self.wake_fifo_fd.store(fd, Ordering::Release);
        }
    }

    fn poke_wake_fifo(&self) {
        let fd = self.wake_fifo_fd.load(Ordering::Acquire);
        if fd < 0 {
            return;
        }
        let byte: u8 = 1;
        unsafe {
            // Non-blocking write of a single byte. EAGAIN means
            // the reader hasn't drained; the wake_counter polling
            // covers us in that case. EPIPE means the reader
            // dropped; close + reset so the next attach reopens.
            let n = libc::write(fd, &byte as *const u8 as *const _, 1);
            if n < 0 {
                let err = *libc::__error();
                if err == libc::EPIPE {
                    libc::close(fd);
                    self.wake_fifo_fd.store(-1, Ordering::Release);
                }
            }
        }
    }
}

pub struct ControlShm {
    pub name: CString,
    pub base: *mut u8,
    pub size: usize,
    pub view: Arc<ControlShmView>,
}

unsafe impl Send for ControlShm {}
unsafe impl Sync for ControlShm {}

impl ControlShm {
    pub fn create() -> Result<Option<Self>, String> {
        if std::env::var_os("VIRTIO_CONDUIT_CONTROL_SHM").as_deref()
            == Some(std::ffi::OsStr::new("0"))
        {
            return Ok(None);
        }
        let pid = std::process::id();
        let size = std::env::var("VIRTIO_CONDUIT_CONTROL_SHM_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(CONTROL_SHM_DEFAULT_SIZE);
        // Compute the ring layout up front so an out-of-range
        // `VIRTIO_CONDUIT_CONTROL_SHM_SIZE` is rejected before we
        // shm_open / ftruncate anything. The previous gate
        // `size < CONTROL_SHM_HDR_SIZE * 2` admitted sizes that
        // underflowed `usable - cmd_ring_len`.
        let layout = compute_ring_layout(size)?;
        let name = CString::new(format!("/conduit-{}", pid)).map_err(|e| e.to_string())?;
        unsafe {
            libc::shm_unlink(name.as_ptr());
        }
        let fd = unsafe {
            libc::shm_open(
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
            let err = std::io::Error::last_os_error().to_string();
            unsafe {
                libc::close(fd);
                libc::shm_unlink(name.as_ptr());
            }
            return Err(err);
        }
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
        unsafe {
            libc::close(fd);
        }
        if base == libc::MAP_FAILED {
            unsafe {
                libc::shm_unlink(name.as_ptr());
            }
            return Err("mmap failed".into());
        }
        let base = base as *mut u8;
        let RingLayout {
            cmd_ring_off,
            cmd_ring_len,
            rsp_ring_off,
            rsp_ring_len,
        } = layout;
        unsafe {
            write_u64_le(base.add(HDR_OFF_MAGIC), CONTROL_SHM_MAGIC);
            write_u32_le(base.add(HDR_OFF_VERSION), CONTROL_SHM_VERSION);
            write_u32_le(base.add(HDR_OFF_PID), pid);
            write_u64_le(base.add(HDR_OFF_REGION_SIZE), size as u64);
            write_u64_le(base.add(HDR_OFF_CAPS), CONTROL_CAP_CTRL_PAYLOAD);
            write_u64_le(base.add(HDR_OFF_CMD_RING_OFF), cmd_ring_off as u64);
            write_u64_le(base.add(HDR_OFF_CMD_RING_LEN), cmd_ring_len as u64);
            write_u64_le(base.add(HDR_OFF_RSP_RING_OFF), rsp_ring_off as u64);
            write_u64_le(base.add(HDR_OFF_RSP_RING_LEN), rsp_ring_len as u64);
            std::ptr::write_bytes(base.add(CONTROL_DATA_SHM_META_OFF), 0, 48);
            std::ptr::write_bytes(base.add(CONTROL_DATA_WAKE_COUNTER_OFF), 0, 8);
        }
        let view = Arc::new(ControlShmView {
            base,
            region_size: size,
            cmd_ring_off,
            cmd_ring_len,
            rsp_ring_off,
            rsp_ring_len,
            wake_fifo_fd: AtomicI32::new(-1),
        });
        // Open the wake FIFO for write. The FIFO path is
        // deterministic from pid so bifrost-side renderers can
        // derive it without a control-SHM publish. mkfifo +
        // open(O_WRONLY | O_NONBLOCK); if no reader is attached
        // yet, open returns ENXIO and we leave the fd at -1 —
        // the first wake retries lazily. Already-existing FIFOs
        // from prior runs at the same pid are reused.
        view.open_wake_fifo(pid);
        Ok(Some(ControlShm {
            name,
            base,
            size,
            view,
        }))
    }
}

impl Drop for ControlShm {
    fn drop(&mut self) {
        unsafe {
            if !self.base.is_null() {
                libc::munmap(self.base as *mut std::ffi::c_void, self.size);
            }
            libc::shm_unlink(self.name.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    // KIND_* values are part of the host/VMM control-ring wire
    // compatibility contract. Pin only the commands/responses libkrun
    // still understands as a conduit.
    use super::*;

    #[test]
    fn control_kind_request_values_pinned() {
        assert_eq!(KIND_CTRL_PAYLOAD, 1);
        assert_eq!(KIND_CTRL_PAYLOAD_REQ, 2);
    }

    #[test]
    fn control_kind_response_values_pinned() {
        assert_eq!(KIND_RSP_OK, 100);
        assert_eq!(KIND_RSP_ERR, 101);
        assert_eq!(KIND_RSP_PAYLOAD, 104);
        assert_eq!(KIND_PAD, 255);
    }

    #[test]
    fn event_op_values_pinned() {
        assert_eq!(OP_DATA_SHM_READY, 8);
        assert_eq!(OP_CTRL_RESPONSE, 9);
    }

    #[test]
    fn control_kind_request_and_response_distinct() {
        // Requests and responses share the same ring; if a value
        // collides the receiver mis-dispatches.
        let req = [KIND_CTRL_PAYLOAD, KIND_CTRL_PAYLOAD_REQ];
        let rsp = [KIND_RSP_OK, KIND_RSP_ERR, KIND_RSP_PAYLOAD, KIND_PAD];
        for r in &req {
            for s in &rsp {
                assert_ne!(r, s, "control kind collision: {} == {}", r, s);
            }
        }
    }

    #[test]
    fn ring_layout_rejects_below_minimum_size() {
        // CONTROL_SHM_MIN_SIZE - 1 must be rejected, with a message
        // mentioning the minimum so the operator can fix the env var.
        let err = compute_ring_layout(CONTROL_SHM_MIN_SIZE - 1).unwrap_err();
        assert!(
            err.contains("minimum"),
            "expected 'minimum' in error, got: {err}"
        );

        // Zero, the page size, and just-below-min are all rejected.
        assert!(compute_ring_layout(0).is_err());
        assert!(compute_ring_layout(CONTROL_SHM_HDR_SIZE).is_err());
        assert!(compute_ring_layout(CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN).is_err());
    }

    #[test]
    fn ring_layout_default_size_round_trips() {
        let layout = compute_ring_layout(CONTROL_SHM_DEFAULT_SIZE).unwrap();
        assert_eq!(layout.cmd_ring_off, CONTROL_SHM_HDR_SIZE);
        assert_eq!(layout.cmd_ring_len, CONTROL_CMD_RING_LEN);
        assert_eq!(
            layout.rsp_ring_off,
            CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN
        );
        // rsp_ring fills the remaining size, page-aligned.
        let expected_rsp =
            (CONTROL_SHM_DEFAULT_SIZE - CONTROL_SHM_HDR_SIZE - CONTROL_CMD_RING_LEN) & !0xfff;
        assert_eq!(layout.rsp_ring_len, expected_rsp);
        assert!(layout.rsp_ring_len >= CONTROL_RSP_RING_MIN_LEN);
    }

    #[test]
    fn ring_layout_minimum_size_accepted() {
        let layout = compute_ring_layout(CONTROL_SHM_MIN_SIZE).unwrap();
        assert_eq!(layout.rsp_ring_len, CONTROL_RSP_RING_MIN_LEN);
    }

    /// Mock backing for a ring's bytes plus its 4 producer/consumer
    /// atomics. Used to exercise `push_rsp` PAD wraparound without
    /// requiring `shm_open`/mmap (so the test is hermetic and works
    /// in CI sandboxes).
    struct MockShm {
        bytes: Vec<u8>,
    }

    impl MockShm {
        fn with_rsp_len(rsp_len: usize) -> Self {
            // Layout: 4 KB header (atomics live at byte 64/72/80/88),
            // then cmd_ring (size doesn't matter for these tests),
            // then rsp_ring at `CONTROL_SHM_HDR_SIZE + cmd_ring_len`.
            let cmd_len = CONTROL_CMD_RING_LEN;
            let total = CONTROL_SHM_HDR_SIZE + cmd_len + rsp_len;
            Self {
                bytes: vec![0u8; total],
            }
        }
        fn view(&mut self, rsp_len: usize) -> ControlShmView {
            ControlShmView {
                base: self.bytes.as_mut_ptr(),
                region_size: self.bytes.len(),
                cmd_ring_off: CONTROL_SHM_HDR_SIZE,
                cmd_ring_len: CONTROL_CMD_RING_LEN,
                rsp_ring_off: CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN,
                rsp_ring_len: rsp_len,
                wake_fifo_fd: AtomicI32::new(-1),
            }
        }
    }

    #[test]
    fn push_rsp_emits_pad_on_wraparound() {
        // Minimum-aligned rsp ring: just big enough for one large
        // entry plus a wraparound PAD plus a second entry. The
        // consumer is simulated as ack'ing the first entry so the
        // second push has enough free bytes to materialise the PAD
        // + new entry, exercising the wraparound branch in push_rsp.
        let rsp_len = 4096; // page; multiple of 16
        let mut shm = MockShm::with_rsp_len(rsp_len);
        let view = shm.view(rsp_len);

        // First entry: 4000-byte body → 4016-byte entry. Leaves 80
        // bytes tail (less than the second entry's 96 bytes ⇒ wrap).
        let first_body_len = 4000;
        let big = vec![0xabu8; first_body_len];
        view.push_rsp(KIND_RSP_OK, 1, &big).unwrap();

        // Simulate the guest having drained that entry so the ring
        // is logically empty. push_rsp's wraparound branch then has
        // enough free bytes for the PAD + the new entry.
        view.rsp_consumer_pos()
            .fetch_add(4016u64, Ordering::Release);

        // Second entry: 80-byte body → 96-byte entry. tail_remaining
        // is 80 ⇒ entry_total(96) > tail_remaining(80) so push_rsp
        // emits a PAD covering the 80-byte tail and writes the new
        // entry at offset 0.
        let second_body_len = 80;
        let second = vec![0xcdu8; second_body_len];
        view.push_rsp(KIND_RSP_OK, 2, &second).unwrap();

        // The PAD should sit at the previous producer offset (4016).
        let pad_off_in_ring = 4016;
        let kind_pad = u32::from_le_bytes(
            shm.bytes[CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN + pad_off_in_ring
                ..CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN + pad_off_in_ring + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(kind_pad, KIND_PAD, "PAD emitted at wraparound");

        // The second entry must restart at the ring head (offset 0).
        let kind2 = u32::from_le_bytes(
            shm.bytes[CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN
                ..CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(kind2, KIND_RSP_OK, "second entry restarts at ring head");
        let seq2 = u64::from_le_bytes(
            shm.bytes[CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN + 8
                ..CONTROL_SHM_HDR_SIZE + CONTROL_CMD_RING_LEN + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(seq2, 2);
    }

    #[test]
    fn push_rsp_rejects_entry_larger_than_ring() {
        let rsp_len = 4096;
        let mut shm = MockShm::with_rsp_len(rsp_len);
        let view = shm.view(rsp_len);
        let huge = vec![0u8; rsp_len]; // entry_total > rsp_ring_len
        let err = view.push_rsp(KIND_RSP_OK, 1, &huge).unwrap_err();
        assert_eq!(err, "rsp too large");
    }
}
