// SPDX-License-Identifier: Apache-2.0
//
// conduit-backend — vhost-user backend exposing the bifrost
// conduit transport.
//
// PIPELINE
// --------
//
//     bifrost CLI ── control SHM ── ConduitCore (here)
//                                       │
//                                       │   vhost-user UNIX socket
//                                       └──────────────────────────┐
//                                                                  ▼
//                                                          libkrun generic
//                                                          vhost-user-device
//                                                          frontend
//                                                          OR QEMU
//                                                          vhost-user-test-device
//
// The conduit protocol semantics (control SHM ring layout,
// KIND_* entries, OP_DATA_SHM_READY, wake-counter polling) are
// unchanged from the in-process transport. The transport that carries virtqueue
// descriptor bytes between the guest and `ConduitCore` swaps
// from "in-process libkrun adapter" to "vhost-user socket".
//
// QEMU compatibility
// ------------------
//
// Stock QEMU can provide a generic vhost-user virtio-mmio frontend, but it
// does not expose Bifrost's libkrun virtio-shmem region extension. When the
// guest falls back to publishing PFNs for its vmalloc SHMEM buffer, this
// backend adapts that legacy DATA_SHM_READY payload by mirroring those guest
// pages into the POSIX data SHM that the host CLI already knows how to map.
// The transport stays stock QEMU; the compatibility boundary lives here.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::Parser;
use log::{error, info, warn};
use std::os::fd::AsRawFd;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost::vhost_user::Listener;
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringT};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_queue::QueueOwnedT;
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

// The conduit core uses libkrun's own EventFd type rather than
// vmm-sys-util's. Alias it locally so the adapter's
// `control_queue_event` signature matches the trait.
use utils::eventfd::EventFd as UtilsEventFd;

// Conduit constants, re-exported from the shared crate so both
// the libkrun side and this backend agree.
use krun_virtio_conduit::{
    ConduitCore, ControlQueue, DoorbellQueue, EventQueue, VirtioShmRegionInfo,
    VIRTIO_SHM_REGION_SIZE, VQ_CTRL, VQ_DOORBELL, VQ_EVENT,
};

const CONDUIT_NUM_QUEUES: usize = 3;
const CONDUIT_QUEUE_SIZE: usize = 1024;
const SHMEM_PAGE_SIZE: usize = 4096;
const SHMEM_HDR_LEN: usize = 4096;
const SHMEM_NUM_CPUS_MAX: u32 = 16;
const SHMEM_PER_CPU_STATE_OFF: usize = 128;
const SHMEM_PER_CPU_STATE_STRIDE: usize = 128;
const SHMEM_HDR_OFF_NUM_CPUS: usize = 80;
const SHMEM_HDR_OFF_STATE_STRIDE: usize = 84;
const SHMEM_HDR_OFF_STATE_OFF: usize = 96;
const OP_DATA_SHM_READY: u32 = 8;

struct LegacyPfnShmem {
    pages: Vec<u64>,
    region_size: usize,
}

impl LegacyPfnShmem {
    // QEMU's stock vhost-user-test-device has no virtio-mmio shared-memory
    // region hook. The guest therefore allocates normal RAM pages and sends
    // their PFNs; the backend mirrors only the Bifrost data-SHM contract into
    // the host-visible POSIX SHM instead of asking QEMU to grow a Bifrost
    // extension.
    fn ptr_for_offset(&self, off: usize) -> Option<*mut u8> {
        if off >= self.region_size {
            return None;
        }
        let page = off / SHMEM_PAGE_SIZE;
        let page_off = off % SHMEM_PAGE_SIZE;
        let base = *self.pages.get(page)?;
        Some((base as usize + page_off) as *mut u8)
    }

    fn copy_guest_to_host(&self, dst: *mut u8, dst_size: usize) {
        let copy_len = self.region_size.min(dst_size);
        if copy_len == 0 || self.pages.is_empty() {
            return;
        }

        for page in 1..self.pages.len() {
            let off = page * SHMEM_PAGE_SIZE;
            if off >= copy_len {
                break;
            }
            let len = SHMEM_PAGE_SIZE.min(copy_len - off);
            unsafe {
                std::ptr::copy_nonoverlapping(self.pages[page] as *const u8, dst.add(off), len);
            }
        }

        let first_len = SHMEM_PAGE_SIZE.min(copy_len);
        unsafe {
            std::ptr::copy_nonoverlapping(self.pages[0] as *const u8, dst, first_len);
        }
    }

    fn copy_consumer_positions_to_guest(&self, src: *mut u8, src_size: usize) {
        if src_size < SHMEM_HDR_LEN || self.region_size < SHMEM_HDR_LEN {
            return;
        }

        let read_u32 = |off: usize| -> Option<u32> {
            if off.checked_add(4)? > src_size {
                return None;
            }
            let mut buf = [0u8; 4];
            unsafe {
                std::ptr::copy_nonoverlapping(src.add(off), buf.as_mut_ptr(), 4);
            }
            Some(u32::from_le_bytes(buf))
        };
        let read_u64 = |off: usize| -> Option<u64> {
            if off.checked_add(8)? > src_size {
                return None;
            }
            let mut buf = [0u8; 8];
            unsafe {
                std::ptr::copy_nonoverlapping(src.add(off), buf.as_mut_ptr(), 8);
            }
            Some(u64::from_le_bytes(buf))
        };

        let num_cpus = read_u32(SHMEM_HDR_OFF_NUM_CPUS)
            .unwrap_or(0)
            .min(SHMEM_NUM_CPUS_MAX);
        let stride = match read_u32(SHMEM_HDR_OFF_STATE_STRIDE).unwrap_or(0) as usize {
            0 => SHMEM_PER_CPU_STATE_STRIDE,
            n => n,
        };
        let state_off = match read_u64(SHMEM_HDR_OFF_STATE_OFF).unwrap_or(0) as usize {
            0 => SHMEM_PER_CPU_STATE_OFF,
            n => n,
        };

        for cpu in 0..num_cpus as usize {
            let Some(consumer_off) = state_off
                .checked_add(cpu.saturating_mul(stride))
                .and_then(|off| off.checked_add(8))
            else {
                break;
            };
            if consumer_off
                .checked_add(8)
                .map_or(true, |end| end > src_size)
            {
                break;
            }
            let Some(dst) = self.ptr_for_offset(consumer_off) else {
                break;
            };
            unsafe {
                let src_atomic = &*(src.add(consumer_off) as *const std::sync::atomic::AtomicU64);
                let dst_atomic = &*(dst as *const std::sync::atomic::AtomicU64);
                let pos = src_atomic.load(std::sync::atomic::Ordering::Acquire);
                dst_atomic.store(pos, std::sync::atomic::Ordering::Release);
            }
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "conduit-backend",
    about = "vhost-user backend for the bifrost conduit transport"
)]
struct Args {
    /// UNIX socket path the VMM will connect to.
    #[arg(long, short = 's')]
    socket: PathBuf,

    /// Data SHM region size in bytes.
    #[arg(long, default_value_t = VIRTIO_SHM_REGION_SIZE)]
    data_shm_size: usize,

    /// Remove an existing socket file before bind. Off by default;
    /// the launcher is responsible for socket lifecycle.
    #[arg(long, default_value_t = false)]
    force_socket: bool,
}

/// Data-id passed to vhost-user-backend's epoll worker for the
/// consumer-wakeup fd. Must be > num_queues (3) per the
/// `register_listener` contract.
const CONSUMER_WAKEUP_ID: u16 = 4;

struct ConduitBackend {
    /// Bits acknowledged by the frontend.
    acked_features: u64,
    /// EVENT_IDX feature toggle from the frontend.
    event_idx: bool,
    /// Guest memory atom the frontend last published via
    /// `SET_MEM_TABLE`. Populated by `update_memory`; required
    /// before `handle_event` can do anything meaningful.
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// The conduit's host-side protocol core. The same object
    /// the in-tree libkrun adapter held; only the transport
    /// underneath has changed.
    core: Arc<Mutex<ConduitCore>>,
    /// Data SHM file. Held for the lifetime of the backend so the
    /// underlying POSIX SHM stays alive. Passed to the frontend
    /// via `get_shared_object` when it negotiates the
    /// virtio-shmem-region capability.
    data_shm: Arc<std::fs::File>,
    /// Published POSIX-SHM name for the data region. Mirrors the
    /// conduit's `/conduit-data-<pid>` convention so the bifrost
    /// CLI can find it via the existing control-SHM header path.
    #[allow(dead_code)]
    data_shm_name: String,
    /// Exit signal — written when the daemon should shut down.
    exit_event: EventFd,
    /// "Wake VQ_CTRL processing" eventfd. The conduit's consumer
    /// thread (inside ConduitCore, started on DATA_SHM_READY)
    /// writes to this when it queues a new payload onto
    /// pending_payloads. The vhost-user-backend worker has its
    /// read end registered via `register_listener`, so the write
    /// fires `handle_event(CONSUMER_WAKEUP_ID, …)` which then
    /// calls `process_control_queue` against the VQ_CTRL vring.
    consumer_wakeup: Arc<UtilsEventFd>,
    data_shm_host_addr: u64,
    data_shm_size: usize,
    legacy_shmem: Option<LegacyPfnShmem>,
}

// Adapters that translate vhost-user-backend's `VringRwLock`
// into the ControlQueue / EventQueue / DoorbellQueue traits the
// generic ConduitCore consumes. The shape mirrors the in-tree
// libkrun adapter at
// third_party/smolvm/libkrun/src/devices/src/virtio/conduit/mod.rs,
// substituting vhost-user-backend's vring API for libkrun's
// DeviceQueue.

struct CtrlQueueAdapter<'a> {
    vring: &'a VringRwLock,
    mem: &'a GuestMemoryMmap,
}

impl ControlQueue for CtrlQueueAdapter<'_> {
    fn write_next_with<F>(&mut self, payload: F) -> bool
    where
        F: FnOnce() -> Vec<u8>,
    {
        let mut guard = self.vring.get_mut();
        let queue = guard.get_queue_mut();
        let mut iter = match queue.iter(self.mem) {
            Ok(iter) => iter,
            Err(err) => {
                log::warn!("conduit-backend: ctrl queue.iter: {err}");
                return false;
            }
        };
        let Some(chain) = iter.next() else {
            return false;
        };
        let head = chain.head_index();
        let mut written = 0u32;
        for desc in chain.writable() {
            let payload = payload();
            if let Err(err) = self.mem.write_slice(&payload, desc.addr()) {
                log::warn!("conduit-backend: ctrl write_slice: {err}");
                break;
            }
            written += payload.len() as u32;
            break;
        }
        drop(iter);
        if let Err(err) = guard.add_used(head, written) {
            log::warn!("conduit-backend: ctrl add_used: {err:?}");
            return false;
        }
        drop(guard);
        if let Err(err) = self.vring.signal_used_queue() {
            log::warn!("conduit-backend: ctrl signal_used_queue: {err}");
        }
        true
    }
}

struct EventQueueAdapter<'a> {
    vring: &'a VringRwLock,
    mem: &'a GuestMemoryMmap,
    ctrl_event: Arc<UtilsEventFd>,
}

impl EventQueue for EventQueueAdapter<'_> {
    fn read_next(&mut self) -> Option<Vec<u8>> {
        let mut guard = self.vring.get_mut();
        let queue = guard.get_queue_mut();
        let mut iter = queue.iter(self.mem).ok()?;
        let chain = iter.next()?;
        let head = chain.head_index();
        let mut read_len = 0u32;
        let mut out = Vec::new();
        for desc in chain.readable() {
            let start = out.len();
            out.resize(start + desc.len() as usize, 0);
            if let Err(err) = self.mem.read_slice(&mut out[start..], desc.addr()) {
                log::warn!("conduit-backend: event read_slice: {err}");
                break;
            }
            read_len += desc.len();
        }
        drop(iter);
        if let Err(err) = guard.add_used(head, read_len) {
            log::warn!("conduit-backend: event add_used: {err:?}");
            return None;
        }
        drop(guard);
        if let Err(err) = self.vring.signal_used_queue() {
            log::warn!("conduit-backend: event signal_used_queue: {err}");
        }
        Some(out)
    }

    fn control_queue_event(&self) -> Option<Arc<UtilsEventFd>> {
        Some(self.ctrl_event.clone())
    }
}

struct DoorbellQueueAdapter<'a> {
    vring: &'a VringRwLock,
    mem: &'a GuestMemoryMmap,
}

impl DoorbellQueue for DoorbellQueueAdapter<'_> {
    fn consume_next(&mut self) -> bool {
        let mut guard = self.vring.get_mut();
        let queue = guard.get_queue_mut();
        let mut iter = match queue.iter(self.mem) {
            Ok(iter) => iter,
            Err(err) => {
                log::warn!("conduit-backend: doorbell queue.iter: {err}");
                return false;
            }
        };
        let Some(chain) = iter.next() else {
            return false;
        };
        let head = chain.head_index();
        drop(iter);
        if let Err(err) = guard.add_used(head, 0) {
            log::warn!("conduit-backend: doorbell add_used: {err:?}");
            return false;
        }
        drop(guard);
        if let Err(err) = self.vring.signal_used_queue() {
            log::warn!("conduit-backend: doorbell signal_used_queue: {err}");
        }
        true
    }
}

impl ConduitBackend {
    fn sync_legacy_consumer_positions_to_guest(&self) {
        if let Some(shmem) = self.legacy_shmem.as_ref() {
            shmem.copy_consumer_positions_to_guest(
                self.data_shm_host_addr as *mut u8,
                self.data_shm_size,
            );
        }
    }

    fn sync_legacy_guest_to_data_shm(&self) {
        if let Some(shmem) = self.legacy_shmem.as_ref() {
            shmem.copy_guest_to_host(self.data_shm_host_addr as *mut u8, self.data_shm_size);
        }
    }

    fn adapt_legacy_data_shm_ready(&mut self, mem: &GuestMemoryMmap, buf: &mut [u8]) {
        if buf.len() < 24 {
            return;
        }
        let op = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if op != OP_DATA_SHM_READY {
            return;
        }

        let region_size = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let n_pages = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        if n_pages == 0 {
            return;
        }
        let Some(pfn_bytes) = n_pages.checked_mul(8) else {
            warn!("conduit-backend: DATA_SHM_READY PFN count overflows: {n_pages}");
            return;
        };
        let Some(total_len) = 24usize.checked_add(pfn_bytes) else {
            warn!("conduit-backend: DATA_SHM_READY length overflows: {n_pages}");
            return;
        };
        if total_len > buf.len() {
            warn!(
                "conduit-backend: DATA_SHM_READY truncated: have={} need={}",
                buf.len(),
                total_len
            );
            return;
        }
        if region_size > self.data_shm_size {
            warn!(
                "conduit-backend: DATA_SHM_READY region too large: requested={} mirror={}",
                region_size, self.data_shm_size
            );
            return;
        }
        let Some(covered) = n_pages.checked_mul(SHMEM_PAGE_SIZE) else {
            warn!("conduit-backend: DATA_SHM_READY page span overflows: {n_pages}");
            return;
        };
        if covered < region_size {
            warn!(
                "conduit-backend: DATA_SHM_READY PFNs cover {} bytes, need {}",
                covered, region_size
            );
            return;
        }

        let mut pages = Vec::with_capacity(n_pages);
        for i in 0..n_pages {
            let off = 24 + i * 8;
            let pfn = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            let Some(gpa) = pfn.checked_mul(SHMEM_PAGE_SIZE as u64) else {
                warn!("conduit-backend: DATA_SHM_READY PFN overflows: {pfn:#x}");
                return;
            };
            let host = match mem.get_host_address(GuestAddress(gpa)) {
                Ok(ptr) => ptr as u64,
                Err(err) => {
                    warn!(
                        "conduit-backend: DATA_SHM_READY cannot resolve pfn={:#x} gpa={:#x}: {:?}",
                        pfn, gpa, err
                    );
                    return;
                }
            };
            pages.push(host);
        }

        self.legacy_shmem = Some(LegacyPfnShmem { pages, region_size });
        self.sync_legacy_guest_to_data_shm();
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        info!(
            "conduit-backend: DATA_SHM_READY adapted {} PFNs into CLI data-SHM mirror ({} bytes)",
            n_pages, region_size
        );
    }
}

impl VhostUserBackendMut for ConduitBackend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        CONDUIT_NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        CONDUIT_QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // Advertise virtio 1.0+, plus VHOST_USER_F_PROTOCOL_FEATURES
        // (bit 30). The vhost-user-backend crate's GET_FEATURES
        // handler returns this verbatim — it does NOT auto-OR the
        // protocol bit, so the master would otherwise reject any
        // subsequent get_protocol_features call. Other conduit-
        // specific virtio features OR in here as needed.
        (1u64 << VIRTIO_F_VERSION_1) | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        // SHARED_OBJECT covers the virtio-shmem-region capability
        // we'll need for the 16 MB data SHM. REPLY_ACK is auto-
        // added by vhost-user-backend even if not listed here.
        VhostUserProtocolFeatures::SHARED_OBJECT
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> std::io::Result<()> {
        // The guest just published a memory table. The vhost-user
        // library has already turned the fds into a
        // GuestMemoryAtomic for us; store it for descriptor
        // translation in `handle_event` once that path is wired.
        info!("update_memory: received guest memory atom");
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        _evset: EventSet,
        vrings: &[Self::Vring],
        _thread_id: usize,
    ) -> std::io::Result<()> {
        // device_event indexes into the queues we registered:
        // 0 = VQ_CTRL, 1 = VQ_EVENT, 2 = VQ_DOORBELL.
        let Some(mem_atom) = self.mem.as_ref().cloned() else {
            warn!("handle_event before update_memory; dropping");
            return Ok(());
        };
        let mem = mem_atom.memory();

        self.sync_legacy_consumer_positions_to_guest();
        match device_event as usize {
            VQ_CTRL => {
                let vring = &vrings[VQ_CTRL];
                let mut adapter = CtrlQueueAdapter { vring, mem: &*mem };
                let mut core = self.core.lock().unwrap();
                core.process_control_queue(&mut adapter);
            }
            VQ_EVENT => {
                // ConduitCore needs an EventFd to write to when
                // the consumer thread queues a new payload onto
                // pending_payloads. We pass the same wakeup fd
                // that the daemon's epoll worker has registered
                // via register_listener so the write fires
                // handle_event(CONSUMER_WAKEUP_ID), which loops
                // back into process_control_queue against the
                // VQ_CTRL vring.
                let vring = &vrings[VQ_EVENT];
                let mut adapter = EventQueueAdapter {
                    vring,
                    mem: &*mem,
                    ctrl_event: self.consumer_wakeup.clone(),
                };
                let ctrl_event = adapter.control_queue_event();
                let mut bufs = Vec::new();
                while let Some(mut buf) = adapter.read_next() {
                    self.adapt_legacy_data_shm_ready(&*mem, &mut buf);
                    bufs.push(buf);
                }
                let mut core = self.core.lock().unwrap();
                for buf in bufs {
                    core.handle_event_buffer(&buf, ctrl_event.clone());
                }
            }
            VQ_DOORBELL => {
                self.sync_legacy_guest_to_data_shm();
                let vring = &vrings[VQ_DOORBELL];
                let mut adapter = DoorbellQueueAdapter { vring, mem: &*mem };
                let core = self.core.lock().unwrap();
                core.process_doorbell_queue(&mut adapter);
            }
            // CONSUMER_WAKEUP_ID: the consumer thread queued a
            // payload on pending_payloads and signalled us. Drain
            // the wakeup eventfd and re-run process_control_queue
            // so the payload reaches the guest's next available
            // VQ_CTRL descriptor.
            x if x == CONSUMER_WAKEUP_ID as usize => {
                let _ = self.consumer_wakeup.read();
                let vring = &vrings[VQ_CTRL];
                let mut adapter = CtrlQueueAdapter { vring, mem: &*mem };
                let mut core = self.core.lock().unwrap();
                core.process_control_queue(&mut adapter);
            }
            other => {
                warn!("handle_event for unknown queue index {other}");
            }
        }
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        // Hand the daemon a clone of our exit eventfd so a write
        // to the wrapper's exit signal terminates the worker.
        self.exit_event.try_clone().ok()
    }

    fn get_shared_object(
        &mut self,
        _uuid: vhost::vhost_user::message::VhostUserSharedMsg,
    ) -> std::io::Result<std::fs::File> {
        // The frontend is asking for the virtio-shmem-region fd
        // for the conduit's data SHM. We dup the underlying file
        // so the frontend can mmap a fresh fd while we keep our
        // own reference alive. The UUID is currently unused —
        // bifrost only exposes one shared object, so we hand it
        // back unconditionally. If we ever multiplex multiple
        // shared objects, the UUID is the discriminator.
        use std::os::fd::{AsRawFd, FromRawFd};
        let dup = unsafe { libc::dup(self.data_shm.as_raw_fd()) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(dup) })
    }
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // vhost-user uses SIGPIPE on broken sockets — ignore it
    // process-wide so the daemon doesn't die when the VMM
    // disconnects. (macOS does not have MSG_NOSIGNAL; this is
    // the equivalent guard.)
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let args = Args::parse();

    if args.force_socket && args.socket.exists() {
        if let Err(err) = std::fs::remove_file(&args.socket) {
            error!("remove stale socket {}: {}", args.socket.display(), err);
            return ExitCode::FAILURE;
        }
    }

    let (data_shm, data_shm_name) = match krun_virtio_conduit::create_data_shm(args.data_shm_size) {
        Ok(pair) => pair,
        Err(err) => {
            error!("create_data_shm failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    info!("data SHM: {} ({} bytes)", data_shm_name, args.data_shm_size);

    let exit_event = match EventFd::new(0) {
        Ok(efd) => efd,
        Err(err) => {
            error!("create exit eventfd: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Map the data SHM file into the backend's address space so
    // ConduitCore can write the wake counter and the shmem_consumer
    // thread can drain records. The guest_addr is not known to the
    // backend (libkrun side decides the GPA the guest sees); leave
    // it at 0 — ConduitCore uses host_addr for the wake counter
    // and the producer/consumer state lives entirely in shared
    // memory keyed off it.
    let host_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            args.data_shm_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            std::os::fd::AsRawFd::as_raw_fd(&data_shm),
            0,
        )
    };
    if host_addr == libc::MAP_FAILED {
        error!("mmap data SHM: {}", std::io::Error::last_os_error());
        return ExitCode::FAILURE;
    }

    let core = Arc::new(Mutex::new(ConduitCore::new()));
    core.lock().unwrap().set_virtio_shm_region(
        VirtioShmRegionInfo {
            host_addr: host_addr as u64,
            guest_addr: 0,
            size: args.data_shm_size,
        },
        Some(&data_shm_name),
    );

    let consumer_wakeup = match UtilsEventFd::new(utils::eventfd::EFD_NONBLOCK) {
        Ok(e) => Arc::new(e),
        Err(err) => {
            error!("create consumer_wakeup eventfd: {err}");
            return ExitCode::FAILURE;
        }
    };

    let backend = Arc::new(Mutex::new(ConduitBackend {
        acked_features: 0,
        event_idx: false,
        mem: None,
        core,
        data_shm: Arc::new(data_shm),
        data_shm_name,
        exit_event,
        consumer_wakeup: consumer_wakeup.clone(),
        data_shm_host_addr: host_addr as u64,
        data_shm_size: args.data_shm_size,
        legacy_shmem: None,
    }));

    // GuestMemoryAtomic is required by the daemon constructor
    // even before the frontend has sent SET_MEM_TABLE; start
    // empty.
    let mem = GuestMemoryAtomic::new(GuestMemoryMmap::new());

    let mut daemon = match VhostUserDaemon::new("bifrost-conduit".to_owned(), backend, mem) {
        Ok(d) => d,
        Err(err) => {
            error!("VhostUserDaemon::new: {err:?}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match Listener::new(&args.socket, /*unlink=*/ args.force_socket) {
        Ok(l) => l,
        Err(err) => {
            error!("Listener::new {}: {err:?}", args.socket.display());
            return ExitCode::FAILURE;
        }
    };

    info!("listening on {}", args.socket.display());
    if let Err(err) = daemon.start(listener) {
        error!("daemon.start: {err:?}");
        return ExitCode::FAILURE;
    }

    // Register the consumer-wakeup eventfd with the daemon's
    // epoll worker so the consumer thread can wake up VQ_CTRL
    // processing without going through the master/guest kick
    // path. The handler slot index is the queue index data
    // delivered to handle_event; values above num_queues are
    // free-form per register_listener's contract.
    for handler in daemon.get_epoll_handlers() {
        if let Err(err) = handler.register_listener(
            consumer_wakeup.as_raw_fd(),
            vmm_sys_util::epoll::EventSet::IN,
            CONSUMER_WAKEUP_ID as u64,
        ) {
            error!("register consumer wakeup fd: {err:?}");
            return ExitCode::FAILURE;
        }
    }

    if let Err(err) = daemon.wait() {
        error!("daemon.wait: {err:?}");
        return ExitCode::FAILURE;
    }
    info!("conduit-backend exiting cleanly");
    ExitCode::SUCCESS
}
