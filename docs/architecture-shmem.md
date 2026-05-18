# bifrost SHMEM-backed data plane

**Status:** Production data plane. Layered on the generic
[virtio-conduit transport contract](virtio-conduit.md); this
document describes only the **Bifrost-specific** record layout
and consumption rules.

Records flow through the SHMEM event ringbuf, consumed directly by
the host's data-plane consumer — no virtqueue cycles for any
record. BTF + kallsyms read straight out of SHMEM at boot (no
chunked op=4/op=5). VMA tables emitted once per (tgid, exec_id)
via `bifrost_kfunc_publish_vma_table` (no per-fire 2.5 KB bloat).

The conduit's doorbell worker blocks on `kqueue`/`poll` against a
host-side `EventFd` with a 1 ms timeout. BPF programs fire
`bifrost_kfunc_shmem_kick` after each submit (rate-limited: only
when consumer-distance > 4 KB) so the host wakes from the
doorbell within the HVF MMIO trap budget (~3–11 µs measured).

The user-visible CLI direct-render thread is **not** wake-driven —
see [Latency model](#latency-model) below for the cadence
breakdown. The legacy `op=3` / `op=4` / `op=5` / `op=7` virtqueue
record-transport paths are deleted.

## Why

The pre-SHMEM path costs three copies for every byte of every record:

1. BPF program writes to the kernel BPF ringbuf (kernel-allocated pages).
2. The guest module's worker thread consumes from that ringbuf via
   `bifrost_ringbuf_consume` and copies records into a side
   `event_buf`.
3. The worker pushes `event_buf` into virtio via
   `virtqueue_add_inbuf`; the VMM copies again into the host-mapped
   descriptor; the host parses.

We pay one interrupt + descriptor cycle per chunk for things that
are conceptually shared memory:

- BTF (~4.6 MB) shipped as ~70 chunks once at boot.
- kallsyms (~1.5 MB) similar.
- gustack records (now 2.5 KB each because of the Tier 3 VMA
  side-trip) on every probe fire.

Plus polling latency: between a probe firing and the host renderer
seeing the record we wait for the worker thread's drain tick, which
is on the order of 5–10 ms.

The SHMEM-backed redesign lifts the data plane onto a single
guest-physical region that both sides see directly. No virtqueue
cycle for record payloads. No worker drain. Latency floor drops to
microseconds (Phase 4).

## High-level shape

A 16 MB SHMEM region is exposed to the guest as **virtio
shared-memory region 0** through the conduit's virtio-mmio device
(`VIRTIO_SHM_REGION_SIZE = 16 MB`). The libkrun adapter publishes
the host-mapped virtual address through `mem.get_host_address(...)`;
the conduit's `ConduitCore::set_virtio_shm_region` records the host
VA / guest PA / size triple and forwards it (via the control SHM
header) to any host observer that wants to attach.

A legacy **vmalloc + per-page PFN ferry** path was the Phase 1
transport: the guest allocated 16 MB via `vmalloc` and ferried the
4096-entry PFN array through `SHMEM_INIT` (`n_pages > 0`). The host
then walked each PFN through `mem.get_host_address(GuestAddress(pfn
* 4096))` and held a `Vec<*mut u8>` indexed by SHMEM page number.
This path was kept while the virtio shared-memory exposure was
being shaken out; it is now **rejected at the conduit event
handler** (`ConduitCore::handle_event_buffer`) and the guest
unconditionally uses the virtio shared-memory region. The legacy
branch survives as a documented compatibility surface but is not
exercised by any shipping configuration.

```
SHMEM region (16 MB total, page-aligned, guest-physically contiguous):

  +---------------------------------+   offset 0
  | Header page (4 KB):             |
  |   magic (u32 = 0x42465348 'BFSH')
  |   version (u32 = 1)             |
  |   ringbuf_off, ringbuf_len      |
  |   vma_cache_off, vma_cache_len  |
  |   btf_off, btf_len              |
  |   ksyms_off, ksyms_len          |
  |   doorbell                      |
  |   generation, flags             |
  +---------------------------------+   offset 4 KB
  | Event ringbuf (~12 MB):         |
  |   producer_pos (atomic u64)     |
  |   consumer_pos (atomic u64)     |
  |   data[N]    (cache-line aligned record stream)
  +---------------------------------+
  | VMA cache region (~1 MB):       |
  |   open-addressed hash:          |
  |     key = (tgid << 32 | exec_id)
  |     val = offset into a strings/entry blob
  +---------------------------------+
  | BTF region (~5 MB)              |
  +---------------------------------+
  | Kallsyms region (~2 MB)         |
  +---------------------------------+
```

Sizes are sketches; final layout is in `Header` once committed.

## Historical phase summary

The SHMEM data plane landed in five phases between the initial
ringbuf-via-virtqueue era and the current direct-mapped region.
The prose below is **historical context**, not current behavior.
For the current behavior read the sections above this one.

### Phase 1 — SHMEM region establishment

Originally `vmalloc`-backed with a PFN-array `SHMEM_INIT` op (see
"vmalloc + per-page PFN ferry" note above). The current canonical
transport is the virtio shared-memory region; the PFN path
remains as a legacy compatibility branch that the conduit
rejects.

### Phase 2 — SHMEM event ringbuf

Established the kfunc-driven reserve/submit pair
(`bifrost_kfunc_shmem_reserve`, `bifrost_kfunc_shmem_submit`),
registered with the kernel verifier via a `special_kfunc_list`
entry so the verifier types the reserve kfunc's `void *` return as
`PTR_TO_MEM`. Lowering uses these kfuncs uniformly today;
`LoweringOpts::shmem_{reserve,submit}_kfunc_btf_id` are populated
unconditionally and the legacy BPF ringbuf paths have been
deleted.

### Phase 3 — SHMEM-resident BTF, kallsyms, VMA cache

Replaced chunked `op=4 SEND_BTF` and `op=5 SEND_KSYMS` virtqueue
transports with direct in-SHMEM reads. Added
`bifrost_kfunc_publish_vma_table` (atomic test-and-set on a
"seen" bitmap) so each `(tgid, exec_id)` publishes a VMA table
exactly once per process lifetime.

### Doorbells

`VQ_DOORBELL` (queue index 2 on the conduit's virtio-mmio device)
is the guest → host wake notification path. The libkrun conduit
adapter's `Subscriber::process` handles `vq_doorbell` fd events:
drains returned descriptors back to the queue and signals the
host-side doorbell `EventFd` owned by `ConduitCore`.

The conduit's doorbell worker (`host/virtio-conduit/src/shmem/consumer.rs`)
waits on the eventfd via `kevent` (macOS kqueue, `EVFILT_READ`) or
`poll(2)` (Linux) with a 1 ms timeout. On wake it drains the
eventfd and increments the control-SHM `data_wake_counter` with
`Ordering::Release`. The wake counter is a host-side advisory hint
— the durable hand-off is the per-record `READY` flag plus the
producer/consumer cursors.

The Bifrost-side BPF kfunc `bifrost_kfunc_shmem_kick(void)` is
rate-limited: it only invokes the kernel-registered kick callback
when `producer_pos - consumer_pos > 4 KB` (≈6–8 typical records),
so a hot probe loop doesn't pay an MMIO trap per submit. The
guest driver wires the kick callback at probe time
(`bifrost_set_doorbell_callback`); the callback reposts a small
outbuf and calls `virtqueue_kick(vq_doorbell)`.

Lowering: every `emit_record_submit` emits an extra
`kfunc_call(kick)` when
`LoweringOpts::shmem_kick_kfunc_btf_id` is set; the kfunc itself
decides whether to fire.

## Latency model

Three measurements are easy to confuse. Pull them apart.

### 1. HVF MMIO doorbell trap cost

Guest-side `virtqueue_kick` → host-side wake on the doorbell
`EventFd`. One-shot spike (64 iterations, guest-side timed):

| | ns |
|---|---|
| min | 2 333 |
| **median** | **3 333** |
| avg | 3 873 |
| max | 11 291 |

This is the **wake-latency floor**, not the user-visible latency.
It bounds how fast the conduit can know "the guest has new data".

### 2. Conduit consumer wake cadence

The conduit's doorbell worker thread `wait_for_doorbell` sleeps at
most 1 ms; on kick it returns within doorbell-trap-cost +
syscall-return (~3–15 µs). On a true idle interval longer than
1 ms it falls through the timeout fallback. After every wake (kick
or timeout-with-pending) it increments `data_wake_counter`.

### 3. CLI direct-render record visibility latency

The user-visible number. Implemented in
`host/bifrost/src/cli/runtime.rs::run_attach_trace` as a dedicated
render thread that **polls** the data SHM rather than waiting on
the doorbell. Cadence:

- **Baseline: 10 ms.** Sleep 10 ms, then `data.snapshot(0)` and
  compare `producer_pos` + drop counters. If `producer` did not
  advance, the next sleep stays at 10 ms.
- **Drop-detection fast path: 250 µs.** When the renderer observes
  a `dropped_records` or `dropped_bytes` increment, it switches
  the sleep to 250 µs so it drains the ring faster. Falls back to
  10 ms once a polled snapshot reports no producer advance.
- **Per-pass drain limit: 65536 records.** Generous — a 6 MB ring
  at ~32 B/record holds ~200K records; 65536 covers one full ring
  worth of records per wake-up. The renderer never crosses past a
  busy (claimed-but-not-yet-published) slot — `records_between`
  stops at the first busy record and the renderer retries on the
  next pass without advancing `consumer_pos` over it.

**Practical implication.** Under steady load the user observes
records within 10 ms of the BPF program submitting them. Burst
workloads that overflow the ring trigger the 250 µs drain. The CLI
renderer is *not* doorbell-driven; the doorbell drives the
conduit's wake-counter, which is currently advisory data for
observers (`bifrost data <pid>` surfaces it, and the eventually
wake-aware renderer will read it).

Microsecond claims for "record visibility" should always be
qualified — they describe the doorbell trap cost only, not the
end-to-end render latency. Fresh end-to-end measurements are
captured for each build.

### Historical benchmark (libkrun-side consumer, retired)

The libkrun process used to host the record-rendering consumer
itself. Sample one-second rollups from that era are kept here for
reference; modern record traffic terminates in the bifrost CLI:

```
SHMEM stats  401 rec/s ( 401 records in 1.00s) | lat avg=0us max=  3us
SHMEM stats  882 rec/s ( 882 records in 1.00s) | lat avg=0us max=713us
SHMEM stats 1369 rec/s (1369 records in 1.00s) | lat avg=0us max=  0us
SHMEM stats  788 rec/s ( 789 records in 1.00s) | lat avg=0us max=  0us
```

The "latency avg=0us" reading is arithmetic 0 because the
consumer kept pace inside the libkrun process, so
`(host_now - host_t0) - (guest_gns - guest_t0) ≈ 0` modulo µs of
clock skew. The 713-µs spike during the 882 rec/s window is the
libkrun-side consumer hitting its busy-poll budget once before a
kick fired. These numbers do **not** describe the current CLI
direct renderer.

## Memory ordering

Both sides are arm64. The guest BPF program is the producer; the
host renderer is the consumer.

- **Producer:** atomic CAS on `producer_pos` to claim space.
  Record body writes are normal stores. `submit` publishes via
  release-store on the per-record header (sets the "ready" bit
  with `ATOMIC_RELEASE`).
- **Consumer:** acquire-load on `producer_pos` to know how far to
  walk. Per-record header acquire-load gates payload reads.
  Advance `consumer_pos` with release-store.

The kernel side uses `smp_load_acquire` / `smp_store_release`. The
host Rust side uses `Ordering::Acquire` / `Ordering::Release`.

We need to validate this empirically with a stress test before
trusting it under load — cross-process arm64 memory-ordering bugs
are easy to write and hard to spot.

## Wire format details

### Header (4 KB, page 0 of SHMEM)

```rust
#[repr(C)]
struct Header {
    magic: u32,            // 'BFSH' = 0x48534642 LE
    version: u32,          // 1
    region_len: u64,       // total SHMEM bytes (e.g. 16 MB)

    ringbuf_off: u64,      // typically 4 KB
    ringbuf_len: u64,      // typically 12 MB
    vma_cache_off: u64,
    vma_cache_len: u64,
    btf_off: u64,
    btf_len: u64,
    ksyms_off: u64,
    ksyms_len: u64,

    // Cursors: producer is BPF program (guest); consumer is host
    // renderer thread. Placed in Header (page 0) so they share a
    // cache line with the doorbell — minimizes traffic.
    producer_pos: AtomicU64,
    consumer_pos: AtomicU64,

    // Phase 4: host MMIO-traps writes to this address.
    doorbell: AtomicU32,
    _pad: [u8; ...],
}
```

### Ringbuf record format

```
+-------+-------+----------------------+
| len   | flags | payload bytes        |
| u32   | u32   | (correlation + body) |
+-------+-------+----------------------+
```

`flags` low bit is `READY` — set by `_submit`, cleared in the
free space. Consumer must `acquire`-load and check before reading
payload.

### `SHMEM_INIT` op

```
[u32 op=8][u32 region_size][u32 n_pages]
[u32 magic][u32 version][u32 reserved]
[u64 pfns × n_pages]
```

Sent guest → host on the event queue at module init. The current
shipping behavior is `n_pages == 0`, which signals that the guest
has initialised the virtio shared-memory region the conduit
already published and is ready to receive `LOAD_PROG` payloads.
`n_pages > 0` is the legacy vmalloc/PFN ferry; the conduit
currently logs and rejects it.

## What we're explicitly NOT doing

- **Vsock for the data plane.** Agent vsock socket stays for
  command pushdown (`bifrost exec`), but we won't drag it into
  record transport.
- **Backwards compatibility.** Each phase deletes the path it
  replaces in the same change. No feature flags after Phase 1's
  initial transition window.
- **virtio-fs / virtio-vhost integration.** Out of scope; we own
  this device end-to-end and don't need to plug into existing
  ecosystems.
