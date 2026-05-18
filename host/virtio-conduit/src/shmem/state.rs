// SPDX-License-Identifier: Apache-2.0
//
// SHMEM region holder and conduit worker context struct.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::control::ControlShmView;
use utils::eventfd::EventFd;

#[derive(Debug)]
pub struct HostShmem {
    pub base: *mut u8,
    pub region_size: usize,
}

impl HostShmem {
    pub fn contiguous(base: *mut u8, region_size: usize) -> Self {
        Self { base, region_size }
    }
}

unsafe impl Send for HostShmem {}
unsafe impl Sync for HostShmem {}

pub struct ShmemConsumerCtx {
    pub running: Arc<AtomicBool>,
    pub doorbell_eventfd: Arc<EventFd>,
    pub control_shm: Option<Arc<ControlShmView>>,
    pub pending_payloads: Arc<std::sync::Mutex<std::collections::VecDeque<(u64, Vec<u8>)>>>,
    /// VQ_CTRL queue event fd. After queuing host-provided opaque
    /// control bytes, the worker writes here to wake the conduit
    /// device's process_ctrl(), which pops the next guest-provided
    /// VQ_CTRL inbuf and writes those bytes to it.
    pub vq_ctrl_event: Option<Arc<EventFd>>,
}
