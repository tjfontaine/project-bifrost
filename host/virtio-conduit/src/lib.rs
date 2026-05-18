// SPDX-License-Identifier: Apache-2.0
//
// Reusable virtio conduit core.
//
// This crate owns the generic control/data SHM protocol, opaque
// control-payload lifecycle, doorbell wake accounting, and data-SHM
// worker. VMM-specific adapters provide virtio-mmio registration,
// guest-memory descriptor copying, IRQ signaling, and event-manager
// integration.

pub mod control;
pub mod data_shm;
pub mod shmem;
pub mod wire;

pub use data_shm::create_data_shm;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use shmem::{shmem_consumer_thread, HostShmem, ShmemConsumerCtx};
use utils::eventfd::EventFd;

pub const TYPE_CONDUIT: u32 = 42;
pub const VQ_CTRL: usize = 0;
pub const VQ_EVENT: usize = 1;
pub const VQ_DOORBELL: usize = 2;
pub const VIRTIO_SHM_REGION_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct VirtioShmRegionInfo {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

pub struct ConduitCore {
    avail_features: u64,
    acked_features: u64,
    initial_payload_sent: bool,
    pending_payloads: Arc<Mutex<VecDeque<(u64, Vec<u8>)>>>,
    shmem: Option<Arc<HostShmem>>,
    shmem_consumer_running: Arc<AtomicBool>,
    doorbell_eventfd: Arc<EventFd>,
    control_shm: Option<control::ControlShm>,
    virtio_shm_region: Option<VirtioShmRegionInfo>,
}

pub trait ControlQueue {
    fn write_next_with<F>(&mut self, payload: F) -> bool
    where
        F: FnOnce() -> Vec<u8>;
}

pub trait EventQueue {
    fn read_next(&mut self) -> Option<Vec<u8>>;
    fn control_queue_event(&self) -> Option<Arc<EventFd>>;
}

pub trait DoorbellQueue {
    fn consume_next(&mut self) -> bool;
}

impl ConduitCore {
    pub fn new() -> Self {
        Self {
            avail_features: 0,
            acked_features: 0,
            initial_payload_sent: false,
            pending_payloads: Arc::new(Mutex::new(VecDeque::new())),
            shmem: None,
            shmem_consumer_running: Arc::new(AtomicBool::new(false)),
            doorbell_eventfd: Arc::new(
                EventFd::new(utils::eventfd::EFD_NONBLOCK).expect("doorbell eventfd"),
            ),
            control_shm: match control::ControlShm::create() {
                Ok(control_shm) => control_shm,
                Err(err) => {
                    log::error!("virtio-conduit host: control SHM disabled: {err}");
                    None
                }
            },
            virtio_shm_region: None,
        }
    }

    pub fn id(&self) -> &str {
        "conduit"
    }

    pub fn avail_features(&self) -> u64 {
        self.avail_features
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }

    pub fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    pub fn shm_region(&self) -> Option<&VirtioShmRegionInfo> {
        self.virtio_shm_region.as_ref()
    }

    pub fn set_virtio_shm_region(&mut self, region: VirtioShmRegionInfo, host_name: Option<&str>) {
        log::info!(
            "virtio-conduit host: virtio SHM region exposed guest_addr=0x{:x} host_addr=0x{:x} size={}",
            region.guest_addr,
            region.host_addr,
            region.size
        );
        if let (Some(control_shm), Some(name)) = (&self.control_shm, host_name) {
            if let Err(err) = control_shm.view.publish_data_shm(name, region.size) {
                log::warn!(
                    "virtio-conduit host: failed to publish data SHM metadata: {}",
                    err
                );
            }
        }
        self.virtio_shm_region = Some(region);
    }

    pub fn should_process_ctrl(&self) -> bool {
        // Only process VQ_CTRL when we have a real payload to
        // deliver. The previous version sent a HOST_PING on the
        // first kick to "prime" the driver, but the guest's
        // bifrost driver only re-posts the VQ_CTRL buffer after
        // processing an op==LOAD_PROG (per
        // control_reply.rs::complete_load_prog_with_detail).
        // Sending HOST_PING permanently consumes the one
        // pre-posted buffer the driver posts at init, and any
        // subsequent real payload has no descriptor to land in.
        // The in-tree adapter happened to skirt this
        // because libkrun's polly didn't fire the initial kick
        // before the CLI's first push; the vhost-user
        // backend worker is more eager and surfaces the bug.
        self.pending_payloads
            .lock()
            .map(|q| !q.is_empty())
            .unwrap_or(false)
    }

    pub fn next_control_payload(&mut self) -> Option<Vec<u8>> {
        let entry = self
            .pending_payloads
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front());
        entry.map(|(_, payload)| {
            self.initial_payload_sent = true;
            payload
        })
    }

    pub fn process_control_queue<Q: ControlQueue>(&mut self, queue: &mut Q) -> bool {
        // Re-check pending_payloads per iteration: once the queue is
        // drained we MUST stop, otherwise every empty descriptor on
        // VQ_CTRL gets a junk payload (the historic HOST_PING fallback)
        // that the guest kernel rejects with "payload too short",
        // flooding the event_vq with spurious responses and racing the
        // real reply for the queued DOF.  Per commit f3f34c5 the
        // device-side gate `should_process_ctrl` already returns false
        // on empty, but the inner loop kept writing fallback payloads
        // until the descriptor ring was full.  Symptom: one real
        // LOAD_PROG produced 15 "payload too short" responses + one
        // lost real response; the real DOF's task was never able to
        // publish its reply because the queue was already saturated.
        let mut used = false;
        loop {
            // Snapshot payload BEFORE asking the queue for a slot —
            // we don't want to consume a queue slot only to find the
            // pending queue is empty.
            let Some(payload) = self.next_control_payload() else {
                break;
            };
            let wrote = queue.write_next_with(|| payload.clone());
            if !wrote {
                // Queue full — push the payload back so we try again
                // next time process_control_queue runs.
                if let Ok(mut q) = self.pending_payloads.lock() {
                    q.push_front((0, payload));
                }
                break;
            }
            used = true;
        }
        used
    }

    pub fn process_event_queue<Q: EventQueue>(&mut self, queue: &mut Q) -> bool {
        let mut used = false;
        while let Some(buf) = queue.read_next() {
            self.handle_event_buffer(&buf, queue.control_queue_event());
            used = true;
        }
        used
    }

    pub fn process_doorbell_queue<Q: DoorbellQueue>(&self, queue: &mut Q) -> bool {
        let mut used = false;
        while queue.consume_next() {
            used = true;
        }
        self.notify_doorbell();
        used
    }

    pub fn handle_event_buffer(&mut self, buf: &[u8], vq_ctrl_event: Option<Arc<EventFd>>) {
        if buf.len() < 8 {
            return;
        }
        // All multi-byte fields on the event virtqueue are explicit
        // little-endian — see `docs/virtio-conduit.md`. Avoid
        // `from_ne_bytes` so the conduit stays portable to a BE host.
        let op = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if op == control::OP_CTRL_RESPONSE && buf.len() >= 12 {
            // Generic request/response delivery. The conduit does not
            // inspect or transform the body — it just forwards the
            // opaque bytes to the host CLI keyed by `seq`. Any higher-
            // level status/detail framing is owned by the host CLI and
            // the guest driver, never by the conduit.
            //
            // Wire: `u32 op, u64 seq, [u8; rest] body`.
            let seq = u64::from_le_bytes(buf[4..12].try_into().unwrap());
            let body = &buf[12..];
            if let Some(control_shm) = self.control_shm.as_ref() {
                if let Err(err) = control_shm
                    .view
                    .push_rsp(control::KIND_RSP_PAYLOAD, seq, body)
                {
                    log::warn!(
                        "virtio-conduit host: failed to publish ctrl response seq={seq}: {err}"
                    );
                }
            }
            return;
        }
        if op != control::OP_DATA_SHM_READY || buf.len() < 12 {
            return;
        }

        let region_size = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let wire_n_pages = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        let mut host_shmem = None;
        if wire_n_pages == 0 {
            match self.virtio_shm_region.as_ref() {
                Some(region) if region_size <= region.size => {
                    host_shmem = Some(HostShmem::contiguous(
                        region.host_addr as *mut u8,
                        region_size,
                    ));
                }
                Some(region) => {
                    log::error!(
                        "virtio-conduit host: DATA_SHM_READY virtio SHM size mismatch requested={} available={}",
                        region_size,
                        region.size
                    );
                }
                None => {
                    log::error!(
                        "virtio-conduit host: DATA_SHM_READY requested virtio SHM but no region is configured"
                    );
                }
            }
        } else {
            log::error!(
                "virtio-conduit host: rejecting legacy PFN DATA_SHM_READY ({} pages); virtio SHM is required",
                wire_n_pages
            );
        }

        if let Some(host_shmem) = host_shmem {
            log::info!(
                "virtio-conduit host: DATA_SHM_READY accepted virtio SHM ({} bytes)",
                region_size
            );
            let shmem_arc = Arc::new(host_shmem);
            self.shmem = Some(shmem_arc);
            if !self.shmem_consumer_running.swap(true, Ordering::SeqCst) {
                let ctx = ShmemConsumerCtx {
                    running: self.shmem_consumer_running.clone(),
                    doorbell_eventfd: self.doorbell_eventfd.clone(),
                    control_shm: self.control_shm.as_ref().map(|c| c.view.clone()),
                    pending_payloads: self.pending_payloads.clone(),
                    vq_ctrl_event,
                };
                std::thread::spawn(move || shmem_consumer_thread(ctx));
            }
        }
    }

    pub fn doorbell_eventfd(&self) -> Arc<EventFd> {
        self.doorbell_eventfd.clone()
    }

    pub fn notify_doorbell(&self) {
        let _ = self.doorbell_eventfd.write(1);
    }

    pub fn stop(&self) {
        self.shmem_consumer_running.store(false, Ordering::SeqCst);
        self.notify_doorbell();
    }
}

impl Default for ConduitCore {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Send for ConduitCore {}
unsafe impl Sync for ConduitCore {}
