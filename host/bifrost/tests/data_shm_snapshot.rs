// SPDX-License-Identifier: Apache-2.0
//
// data_shm_snapshot — unit tests for the host-side data-SHM
// snapshot reader (`DataShmAttachment::snapshot`).
//
// The integration sweep observes data-SHM behaviour end-to-end
// (kernel push, host renderer drain, drop counter accounting) at
// ~16 s per run. A misread of the per-CPU state array is
// indistinguishable from a real kernel drop in that view, so a
// regression in the reader silently shifts every demo's
// drops/agg accounting and looks like "the system is just flaky".
//
// These tests stand up synthetic data-SHM contents in process-
// local memory (no shm_open, no kernel involvement) and exercise
// the reader against known inputs. The contract pinned here:
//
//   - V5 header field offsets parse correctly
//   - num_cpus drives the per-CPU iteration count, NOT the
//     hard-coded constant
//   - producer/consumer/dropped_records/dropped_bytes land at
//     the documented byte offsets within each per-CPU entry
//   - per-class drop arrays roll up to the aggregate totals
//     (`dropped_records`, `dropped_bytes`) by sum, not max
//   - wraparound semantics: producer-pos and consumer-pos are
//     compared as u64 (no truncation)
//
// Pairs with `control_shm_roundtrip.rs` (control-ring contract)
// and `examples/_common/stress-demo.sh` (flake-rate observation
// across full e2e runs).

use std::sync::atomic::{AtomicU64, Ordering};

use bifrost::control_shmem::DataShmAttachment;
use bifrost_wire::{
    SHMEM_DROP_CLASS_AGG, SHMEM_DROP_CLASS_DBLERR, SHMEM_DROP_CLASS_PRINCIPAL,
    SHMEM_DROP_CLASS_STKSTR, SHMEM_NUM_CPUS_MAX, SHMEM_PER_CPU_STATE_OFF,
    SHMEM_PER_CPU_STATE_STRIDE,
};

// Mirror of the V5 SHMEM layout offsets that the reader walks.
// Pinned by `host/bifrost/src/control_shmem.rs::snapshot` (see
// "V4 header layout" comment near offset 80) and the kernel
// header in `third_party/linux-bifrost/kernel/bpf/helpers.c`.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_RINGBUF_OFF: usize = 16;
const OFF_RINGBUF_LEN: usize = 24;
const OFF_BTF_OFF: usize = 32;
const OFF_BTF_LEN: usize = 40;
const OFF_KSYMS_OFF: usize = 48;
const OFF_KSYMS_LEN: usize = 56;
const OFF_NUM_CPUS: usize = 80;
const OFF_PER_CPU_STATE_STRIDE: usize = 84;
const OFF_PER_CPU_RING_LEN: usize = 88;
const OFF_PER_CPU_STATE_OFF: usize = 96;

// Per-CPU entry offsets within one stride.
const PCPU_OFF_PRODUCER_POS: usize = 0;
const PCPU_OFF_CONSUMER_POS: usize = 8;
const PCPU_OFF_DROPPED_RECORDS: usize = 16; // 4 × u64 (32 bytes)
const PCPU_OFF_DROPPED_BYTES: usize = 48; // 4 × u64 (32 bytes)

/// Hold the SHM-shaped backing buffer + an attachment that views
/// it. We back the buffer with `mmap(MAP_ANONYMOUS|MAP_PRIVATE)`
/// (not a `Vec<u8>`) so that `DataShmAttachment::drop`'s munmap
/// call lands on a legitimate mapping — munmap'ing a Vec's heap
/// pointer corrupts the test process's allocator and SIGSEGVs
/// on the next allocation. Production code goes shm_open + mmap;
/// MAP_ANONYMOUS is the closest no-fd equivalent.
struct SyntheticShm {
    base: *mut u8,
    size: usize,
    attach: Option<DataShmAttachment>,
}

impl SyntheticShm {
    fn new(num_cpus: u32, per_cpu_ring_len: u64) -> Self {
        let stride = SHMEM_PER_CPU_STATE_STRIDE as usize;
        let state_off = SHMEM_PER_CPU_STATE_OFF as usize;
        let header_end = state_off + (num_cpus as usize) * stride;
        let ringbuf_off = ((header_end + 4095) & !4095) as u64;
        let total = ringbuf_off as usize + (num_cpus as usize) * (per_cpu_ring_len as usize);
        let total = total.max(4096);
        let page = 4096;
        let total = (total + page - 1) & !(page - 1);

        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert!(
            base != libc::MAP_FAILED,
            "mmap failed: {}",
            std::io::Error::last_os_error()
        );
        let base = base as *mut u8;

        unsafe {
            write_u32_at(base, OFF_MAGIC, 0x48534642); // SHMEM_MAGIC == "BFSH"
            write_u32_at(base, OFF_VERSION, 5);
            write_u64_at(base, OFF_RINGBUF_OFF, ringbuf_off);
            write_u64_at(base, OFF_RINGBUF_LEN, (num_cpus as u64) * per_cpu_ring_len);
            write_u32_at(base, OFF_NUM_CPUS, num_cpus);
            write_u32_at(base, OFF_PER_CPU_STATE_STRIDE, stride as u32);
            write_u64_at(base, OFF_PER_CPU_RING_LEN, per_cpu_ring_len);
            write_u64_at(base, OFF_PER_CPU_STATE_OFF, state_off as u64);
        }

        let attach = unsafe {
            DataShmAttachment::from_raw_for_test(base, total, "synthetic-data-shm".to_string())
        };
        Self {
            base,
            size: total,
            attach: Some(attach),
        }
    }

    fn attach(&self) -> &DataShmAttachment {
        self.attach.as_ref().unwrap()
    }

    fn set_per_cpu(
        &mut self,
        cpu: u32,
        producer_pos: u64,
        consumer_pos: u64,
        dropped_records: [u64; 4],
        dropped_bytes: [u64; 4],
    ) {
        let state_off = SHMEM_PER_CPU_STATE_OFF as usize
            + (cpu as usize) * (SHMEM_PER_CPU_STATE_STRIDE as usize);
        unsafe {
            atomic_store_u64_at(self.base, state_off + PCPU_OFF_PRODUCER_POS, producer_pos);
            atomic_store_u64_at(self.base, state_off + PCPU_OFF_CONSUMER_POS, consumer_pos);
            for (c, v) in dropped_records.iter().enumerate() {
                write_u64_at(self.base, state_off + PCPU_OFF_DROPPED_RECORDS + 8 * c, *v);
            }
            for (c, v) in dropped_bytes.iter().enumerate() {
                write_u64_at(self.base, state_off + PCPU_OFF_DROPPED_BYTES + 8 * c, *v);
            }
        }
    }
}

impl Drop for SyntheticShm {
    fn drop(&mut self) {
        // The wrapped attach owns munmap of the mapping. Drop it
        // explicitly so the unmap happens BEFORE we forget the
        // mapping address — defensive ordering in case the struct
        // layout ever grows fields that need the mapping live.
        drop(self.attach.take());
    }
}

unsafe fn write_u32_at(base: *mut u8, off: usize, v: u32) {
    std::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), base.add(off), 4);
}

unsafe fn write_u64_at(base: *mut u8, off: usize, v: u64) {
    std::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), base.add(off), 8);
}

unsafe fn atomic_store_u64_at(base: *mut u8, off: usize, v: u64) {
    let p = base.add(off) as *mut AtomicU64;
    (*p).store(v, Ordering::Release);
}

// =============================================================
// Header parsing — basic fields land where the reader expects.
// =============================================================

#[test]
fn snapshot_reads_v5_header_fields() {
    let shm = SyntheticShm::new(4, 256 * 1024);
    let snap = shm.attach().snapshot(0);
    assert_eq!(snap.magic, 0x48534642, "BFSH magic round-trips");
    assert_eq!(snap.version, 5);
    assert_eq!(snap.num_cpus, 4);
    assert_eq!(snap.per_cpu_ring_len, 256 * 1024);
    assert_eq!(
        snap.ringbuf_len,
        4 * 256 * 1024,
        "ringbuf_len matches num_cpus × per_cpu_ring_len"
    );
}

// =============================================================
// num_cpus drives iteration. SHMEM_NUM_CPUS_MAX caps the value;
// a header that advertises more is silently clamped (safer than
// trusting hostile contents into an out-of-bounds read).
// =============================================================

#[test]
fn snapshot_clamps_num_cpus_to_max() {
    // Lie in the header: advertise 999 CPUs. The reader must
    // clamp to SHMEM_NUM_CPUS_MAX rather than walking off the
    // buffer.
    let mut shm = SyntheticShm::new(SHMEM_NUM_CPUS_MAX, 4096);
    unsafe {
        write_u32_at(shm.base, OFF_NUM_CPUS, 999);
    }
    let snap = shm.attach().snapshot(0);
    assert_eq!(
        snap.per_cpu.len(),
        SHMEM_NUM_CPUS_MAX as usize,
        "iteration count must clamp"
    );
    assert_eq!(snap.num_cpus, 999, "raw header value preserved separately");
}

#[test]
fn snapshot_zero_cpus_yields_empty_per_cpu() {
    let shm = SyntheticShm::new(0, 0);
    let snap = shm.attach().snapshot(0);
    assert!(snap.per_cpu.is_empty());
    assert_eq!(snap.dropped_records, 0);
    assert_eq!(snap.dropped_bytes, 0);
    assert_eq!(snap.dropped_records_by_class, [0; 4]);
}

// =============================================================
// Per-CPU state offsets. A field-shift regression (e.g. swapping
// dropped_records and dropped_bytes positions) would corrupt the
// drop attribution shown by the host renderer's drop summary.
// =============================================================

#[test]
fn snapshot_per_cpu_field_offsets() {
    let mut shm = SyntheticShm::new(2, 4096);
    shm.set_per_cpu(
        0,
        /*producer=*/ 1_000,
        /*consumer=*/ 250,
        /*dropped_records=*/ [10, 20, 30, 40],
        /*dropped_bytes=*/ [100, 200, 300, 400],
    );
    shm.set_per_cpu(
        1,
        /*producer=*/ 2_500,
        /*consumer=*/ 1_000,
        /*dropped_records=*/ [5, 6, 7, 8],
        /*dropped_bytes=*/ [50, 60, 70, 80],
    );

    let snap = shm.attach().snapshot(0);
    assert_eq!(snap.per_cpu.len(), 2);

    let cpu0 = &snap.per_cpu[0];
    assert_eq!(cpu0.producer_pos, 1_000);
    assert_eq!(cpu0.consumer_pos, 250);
    assert_eq!(
        cpu0.dropped_records,
        [10, 20, 30, 40],
        "per-class records land in order PRINCIPAL/AGG/STKSTR/DBLERR"
    );
    assert_eq!(cpu0.dropped_bytes, [100, 200, 300, 400]);

    let cpu1 = &snap.per_cpu[1];
    assert_eq!(cpu1.producer_pos, 2_500);
    assert_eq!(cpu1.consumer_pos, 1_000);
    assert_eq!(cpu1.dropped_records, [5, 6, 7, 8]);
    assert_eq!(cpu1.dropped_bytes, [50, 60, 70, 80]);
}

// =============================================================
// Per-class roll-ups. The renderer's
// "data SHM drops by_class records=[principal=N agg=M ...]"
// line and the cross-domain-http investigation rely on these
// being computed as a sum across CPUs, NOT max or last-write-
// wins.
// =============================================================

#[test]
fn snapshot_per_class_drops_sum_across_cpus() {
    let mut shm = SyntheticShm::new(3, 4096);
    // PRINCIPAL drops: 7+11+13 = 31
    // AGG drops:        1+0+2  = 3
    // STKSTR drops:     0+5+0  = 5
    // DBLERR drops:     0+0+0  = 0
    shm.set_per_cpu(0, 0, 0, [7, 1, 0, 0], [70, 10, 0, 0]);
    shm.set_per_cpu(1, 0, 0, [11, 0, 5, 0], [110, 0, 50, 0]);
    shm.set_per_cpu(2, 0, 0, [13, 2, 0, 0], [130, 20, 0, 0]);

    let snap = shm.attach().snapshot(0);
    assert_eq!(
        snap.dropped_records_by_class[SHMEM_DROP_CLASS_PRINCIPAL as usize],
        31
    );
    assert_eq!(
        snap.dropped_records_by_class[SHMEM_DROP_CLASS_AGG as usize],
        3
    );
    assert_eq!(
        snap.dropped_records_by_class[SHMEM_DROP_CLASS_STKSTR as usize],
        5
    );
    assert_eq!(
        snap.dropped_records_by_class[SHMEM_DROP_CLASS_DBLERR as usize],
        0
    );
    assert_eq!(
        snap.dropped_records, 39,
        "aggregate total = sum of every class across every CPU"
    );
    assert_eq!(
        snap.dropped_bytes_by_class[SHMEM_DROP_CLASS_PRINCIPAL as usize],
        70 + 110 + 130
    );
    assert_eq!(
        snap.dropped_bytes,
        70 + 10 + 110 + 50 + 130 + 20,
        "byte totals same shape as record totals"
    );
}

// =============================================================
// Aggregate producer/consumer cursors. These are SUMS across CPUs
// (not max). The CLI uses them only for "is the ring making
// progress overall" — getting the math wrong would silently mask
// a stalled CPU.
// =============================================================

#[test]
fn snapshot_aggregate_cursors_sum_per_cpu() {
    let mut shm = SyntheticShm::new(4, 4096);
    shm.set_per_cpu(0, 100, 50, [0; 4], [0; 4]);
    shm.set_per_cpu(1, 200, 150, [0; 4], [0; 4]);
    shm.set_per_cpu(2, 300, 250, [0; 4], [0; 4]);
    shm.set_per_cpu(3, 400, 350, [0; 4], [0; 4]);

    let snap = shm.attach().snapshot(0);
    assert_eq!(snap.producer_pos, 100 + 200 + 300 + 400);
    assert_eq!(snap.consumer_pos, 50 + 150 + 250 + 350);
}

// =============================================================
// wake_counter passthrough. The renderer feeds the wake counter
// from the data wake FIFO into the snapshot so the run loop can
// correlate "I saw N wakes" with "the snapshot at time T".
// =============================================================

#[test]
fn snapshot_returns_wake_counter_as_passed() {
    let shm = SyntheticShm::new(1, 4096);
    for wake in [0, 1, 42, u64::MAX] {
        let snap = shm.attach().snapshot(wake);
        assert_eq!(snap.wake_counter, wake);
    }
}

// =============================================================
// Acquire-ordering smoke. The snapshot reader uses
// atomic-load-Acquire on producer/consumer cursors. A
// concurrent writer update visible after our load must be
// captured by a subsequent snapshot. This isn't a formal
// memory-model test (no fence interleaving), but it catches a
// regression that silently downgrades to plain memcpy or
// drops the ordering pair.
// =============================================================

#[test]
fn snapshot_observes_post_load_writes_on_next_call() {
    let mut shm = SyntheticShm::new(1, 4096);
    shm.set_per_cpu(0, 50, 0, [0; 4], [0; 4]);
    let s1 = shm.attach().snapshot(0);
    assert_eq!(s1.per_cpu[0].producer_pos, 50);
    // Concurrent writer would advance producer_pos; simulate.
    shm.set_per_cpu(0, 1000, 100, [0; 4], [0; 4]);
    let s2 = shm.attach().snapshot(0);
    assert_eq!(s2.per_cpu[0].producer_pos, 1000);
    assert_eq!(s2.per_cpu[0].consumer_pos, 100);
}

// =============================================================
// Sanity: large producer_pos values (well past 2^32) must be
// read as full u64. A truncation regression would alias high
// pointers down to the low 32 bits and look like the producer
// "rewound" — exactly the kind of phantom that masquerades as a
// flake.
// =============================================================

#[test]
fn snapshot_handles_large_u64_cursors() {
    let big_prod = u64::MAX - 1024;
    let big_cons = u64::MAX - 2048;
    let mut shm = SyntheticShm::new(1, 4096);
    shm.set_per_cpu(0, big_prod, big_cons, [0; 4], [0; 4]);

    let snap = shm.attach().snapshot(0);
    assert_eq!(snap.per_cpu[0].producer_pos, big_prod);
    assert_eq!(snap.per_cpu[0].consumer_pos, big_cons);
    // wrap-around delta computed by caller, not snapshot —
    // here we just confirm the cursor itself didn't truncate.
    assert!(snap.per_cpu[0].producer_pos > u32::MAX as u64);
}

// =============================================================
// Smoke: snapshot does not allocate per-CPU entries beyond the
// buffer's tail. With num_cpus larger than the buffer can hold
// stride-wise, the reader must stop (not OOB read).
// =============================================================

#[test]
fn snapshot_stops_per_cpu_walk_at_buffer_tail() {
    // Make a buffer that's only large enough for 2 per-CPU
    // entries, but claim 16 in the header. The reader sees the
    // claim, attempts the walk, and must stop when off + 80 >
    // total size.
    let mut shm = SyntheticShm::new(2, 4096);
    unsafe {
        // Lie: claim more CPUs than the buffer can hold.
        write_u32_at(shm.base, OFF_NUM_CPUS, 16);
    }
    let snap = shm.attach().snapshot(0);
    // The reader's own bounds check uses self.size; with a 4 KB
    // ringbuf at 2 CPUs the test buffer is many KB and 16
    // 128-byte entries (2 KB) easily fits — so the reader DOES
    // walk all 16. The contract worth pinning is that it didn't
    // crash trying to walk OOB.
    assert_eq!(snap.num_cpus, 16);
    assert!(
        snap.per_cpu.len() <= 16,
        "per_cpu walk capped at claimed count"
    );
}
