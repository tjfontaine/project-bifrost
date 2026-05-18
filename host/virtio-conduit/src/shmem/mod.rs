// SPDX-License-Identifier: Apache-2.0
//
// Virtio conduit SHMEM module.
//
// Submodules:
//   - state.rs    : HostShmem (contiguous virtio-SHM backing + accessors)
//                   and ShmemConsumerCtx.
//   - consumer.rs : the control/wakeup conduit worker.
//
// Public re-exports below preserve the pre-split API
// (`super::shmem::HostShmem`, `super::shmem::ShmemConsumerCtx`,
// `super::shmem::shmem_consumer_thread`).

pub mod consumer;
pub mod state;

pub use state::{HostShmem, ShmemConsumerCtx};

pub use consumer::shmem_consumer_thread;
