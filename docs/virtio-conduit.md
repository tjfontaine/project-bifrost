# Virtio-conduit transport contract

The `host/virtio-conduit` crate is a **generic** control/data shared-memory
transport between a libkrun-style VMM and the application that drives it.
Bifrost uses it as a substrate for tracing, but the conduit itself does
not know what Bifrost is. This document specifies what the conduit
guarantees so reviewers can tell what is transport and what is Bifrost
application protocol.

The implementation crates are:

- `host/virtio-conduit/` — the canonical generic core. Owned by the
  application process (the bifrost CLI in this repository). Provides
  `ControlShm` (POSIX SHM control plane), `ConduitCore` (virtqueue
  glue), and the data-SHM consumer worker.
- `third_party/smolvm/libkrun/src/devices/src/virtio/conduit/` — a thin
  libkrun adapter that registers a virtio-mmio device, plumbs the three
  virtqueues, hands the data virtio shared-memory region to
  `ConduitCore`, and forwards opaque control payloads.

The conduit must not know:

- BFR7 wrapper bytes, program counts, or eBPF instruction sequences.
- Probe IDs, schemas, or any record body shape.
- BTF, kallsyms, VMA tables, or symbol caches.
- DTrace rendering, aggregation snapshot formats, or self-trace events.
- Any per-record Bifrost status code beyond opaque payload forwarding.

Anything in `host/virtio-conduit/` that mentions one of those concepts
by name is a defect: file an issue and lift it into the host or
guest-driver layer.

## Device model

| Field | Value |
| --- | --- |
| Bus | virtio-mmio (libkrun adapter exposes it) |
| Device type | `42` (experimental — not an OASIS-assigned ID) |
| Queue count | 3 |
| Queue 0 (`VQ_CTRL`) | host → guest opaque control payloads |
| Queue 1 (`VQ_EVENT`) | guest → host status / readiness events |
| Queue 2 (`VQ_DOORBELL`) | guest → host wake notification for the data SHM |
| Shared-memory region 0 | data SHM, default `VIRTIO_SHM_REGION_SIZE = 16 MB` |

The libkrun adapter is responsible for:

- registering the device on virtio-mmio,
- copying descriptors between guest memory and the conduit's payload
  buffers,
- signalling IRQ on used-ring updates,
- bridging the doorbell virtqueue kick to a host-side `EventFd` that
  the conduit worker can wait on,
- exposing the data shared-memory region as a regular virtio
  shared-memory region.

The conduit core owns everything above the descriptor copy: control SHM
lifecycle, opaque payload queuing, doorbell wake accounting, and the
data-SHM worker thread.

## Wire byte order

All multi-byte fields on the conduit transport are **explicit
little-endian**. Code uses `u{8,16,32,64}::{to,from}_le_bytes`; do not
use `to_ne_bytes`/`from_ne_bytes` for any field that crosses the
process boundary. Both currently supported guest architectures
(x86_64, aarch64) are little-endian; the explicit LE rule keeps the
transport portable if a big-endian guest is ever added.

This applies to:

- Control SHM header and ring entry headers.
- Event-queue payloads decoded by `ConduitCore::handle_event_buffer`.
- Data-SHM record headers (defined in `host/bifrost-wire`, consumed by
  the conduit only as opaque bytes plus an 8-byte header).

The only host-endian field allowed is the eventfd value written into
`doorbell_eventfd` — that is an OS object, not a transport field.

## Control SHM

The application creates a POSIX SHM object named `/conduit-<pid>` (pid
of the application process) with mode `0600`. Permissions are
restrictive on purpose: the control SHM exposes a 1 MB ring pair that
relays opaque control payloads, and any reader can race the legitimate
consumer.

Lifetime is owned by the host (`ControlShm::drop` calls
`shm_unlink`). On startup `ControlShm::create` calls `shm_unlink` of
the same name first to clear a stale file left by a previous crashed
process; an unlinked SHM remains mapped until the last fd is closed,
so existing consumers are unaffected by the unlink.

### Sizing

```text
CONTROL_SHM_HDR_SIZE          = 4096  // header page
CONTROL_CMD_RING_LEN          = 64 KB
CONTROL_RSP_RING_MIN_LEN      = 4 KB
CONTROL_SHM_MIN_SIZE          = 4 KB + 64 KB + 4 KB = 73728 bytes
CONTROL_SHM_DEFAULT_SIZE      = 1 MB
```

`compute_ring_layout(size)` is the canonical sizing function. It
rejects any `size < CONTROL_SHM_MIN_SIZE` and returns a `RingLayout`
with:

- `cmd_ring_off = 4096`,
- `cmd_ring_len = 64 KB`,
- `rsp_ring_off = 4096 + 64 KB`,
- `rsp_ring_len = (size - rsp_ring_off) & ~0xfff`.

`ControlShm::create` calls `compute_ring_layout` **before** any
`shm_open` / `ftruncate` so a malformed
`VIRTIO_CONDUIT_CONTROL_SHM_SIZE` environment variable cannot cause an
underflow or surprise allocation.

### Header (first page)

```text
0  u64  magic    = 0x4c54435f_54434642  // "BFCT_CTL" LE
8  u32  version  = 1
12 u32  pid                              // owner process pid
16 u64  region_size
24 u64  caps                              // capability bitmap
32 u64  cmd_ring_off
40 u64  cmd_ring_len
48 u64  rsp_ring_off
56 u64  rsp_ring_len
64 u64  cmd_producer_pos                  // host-writer cursor
72 u64  cmd_consumer_pos                  // guest-side / VMM-reader cursor
80 u64  rsp_producer_pos                  // VMM-writer cursor
88 u64  rsp_consumer_pos                  // host-side reader cursor
…  reserved / zero
128 u64  data_shm_name_off                // bytes into header where name lives
136 u32  data_shm_name_len
140 u32  data_shm_protocol_version         = CONTROL_DATA_SHM_PROTOCOL_VERSION
144 u64  data_shm_size                    // bytes
152 u32  data_wakeup_mode                 = CONTROL_WAKE_COUNTER (2)
156 u32  reserved
160 u64  data_wake_counter_off            = CONTROL_DATA_WAKE_COUNTER_OFF
192 u64  data_wake_counter (atomic)
256 u8;128 data_shm_name                  // NUL-padded POSIX SHM name
```

Capability bits:

```text
CONTROL_CAP_CTRL_PAYLOAD = 1 << 0   // command/response forwarding ready
CONTROL_CAP_DATA_SHM     = 1 << 1   // data SHM metadata published
```

### Ring entry layout

Both rings use the same 16-byte entry header followed by an aligned
payload:

```text
0  u32  kind      // KIND_CTRL_PAYLOAD / KIND_RSP_OK / KIND_RSP_ERR / KIND_PAD
4  u32  len       // payload length in bytes
8  u64  seq       // application-defined sequence
16 u8;len payload // padded to CONTROL_RING_ENTRY_ALIGN
```

Pinned constants:

```text
CONTROL_RING_HDR_SIZE     = 16
CONTROL_RING_ENTRY_ALIGN  = 16
```

Entry total = `CONTROL_RING_HDR_SIZE + ring_align_up(len, 16)`. Both
ring lengths are 16-aligned by construction (cmd is a power of two,
rsp is page-aligned).

Producer/consumer indices are `u64` monotone counters mod the ring
length. The producer publishes with `Ordering::Release` after writing
the entry; the consumer reads with `Ordering::Acquire`. Free space is
`ring_len - (producer - consumer)`.

### PAD entries

If the next entry to publish would cross the ring tail, the producer
writes a `KIND_PAD` entry covering the remaining tail bytes and
publishes the real entry at offset 0. PAD entries carry `kind =
KIND_PAD`, `len = tail_bytes - CONTROL_RING_HDR_SIZE`, and `seq = 0`.
Consumers skip PAD entries by advancing the cursor by the remaining
tail without reading payload.

The producer pre-checks free space before emitting the PAD; if the PAD
plus the new entry exceed the available free bytes the producer
returns "full" without writing anything.

### Error behaviour

`push_rsp` and `push_cmd` return:

- `Err("rsp too large" | "cmd too large")` if `entry_total >
  ring_len`. The application should size the ring before attempting.
- `Err("full")` if free space cannot fit `PAD + entry` (wrap) or
  `entry` (no wrap). The application retries after the consumer
  catches up.

`drain_cmds` walks at most one wraparound per call. Malformed entries
(`len > ring_len - CONTROL_RING_HDR_SIZE`) cause the drain to stop;
the caller decides whether to abort or treat the ring as poisoned.

## Data SHM

The data SHM is a virtio shared-memory region that the libkrun adapter
maps both sides of via `mem.get_host_address(...)` and presents to the
guest through the virtio-mmio shared-memory registers. The conduit
core records the host-VA / guest-PA / size triple and ignores the
contents.

Default size: `VIRTIO_SHM_REGION_SIZE = 16 MB`. The conduit publishes
the region size and POSIX SHM name (host side) in the control SHM
header at offsets 128/256 once the region is exposed.

### Wake-counter semantics

The control SHM header carries a `data_wake_counter: AtomicU64` at
`CONTROL_DATA_WAKE_COUNTER_OFF = 192`. The host worker:

1. Waits on the doorbell `EventFd` (kqueue on macOS, poll on Linux)
   with a bounded 1 ms timeout.
2. On a wake, drains the eventfd.
3. Increments `data_wake_counter` with `Ordering::Release`.

The application's data-SHM renderer reads `data_wake_counter` as a
hint that the producer has new records to drain. The counter is
**advisory**; missing a wake event does not corrupt data because the
record ring's per-record `READY` flag plus the producer/consumer
cursors carry the durable hand-off.

Wake-counter polling cadence is described in
[`architecture-shmem.md`](architecture-shmem.md).

### Event-vq opcodes

The conduit defines a small set of transport-level event-vq opcodes
in `host/virtio-conduit/src/wire.rs`. The guest emits them, and the
conduit consumes them without inspecting any higher-level body.

- **`OP_DATA_SHM_READY` (8)** — data-SHM ready notification. Wire:
  `u32 op, u32 region_size, u32 wire_n_pages`.
  - `wire_n_pages == 0` (preferred): the guest reports that the
    virtio shared-memory region is initialised at `region_size`
    bytes. The conduit binds the host-side region and spawns the
    data-SHM worker.
  - `wire_n_pages > 0`: legacy vmalloc-PFN ferry. Logged and
    rejected; kept as a documented compatibility surface.
- **`OP_CTRL_RESPONSE` (9)** — request/response delivery for a prior
  `KIND_CTRL_PAYLOAD_REQ` cmd. Wire: `u32 op, u64 seq, [u8; rest]
  body`. The conduit routes the body verbatim to the rsp ring as
  `(KIND_RSP_PAYLOAD, seq, body)`. Higher-level interpretation of
  the body (status codes, detail strings, etc.) lives in the
  consumer, never in the conduit.

### Control-ring entry kinds

- `KIND_CTRL_PAYLOAD` (1) — fire-and-forget. The conduit forwards
  the body to the guest, then auto-acks via `KIND_RSP_OK`.
- `KIND_CTRL_PAYLOAD_REQ` (2) — request/response. The conduit
  appends an 8-byte LE seq trailer to the body before forwarding,
  and does not auto-ack. The matching response arrives later as
  `KIND_RSP_PAYLOAD` via `OP_CTRL_RESPONSE`.
- `KIND_RSP_OK` (100) — transport-level ack.
- `KIND_RSP_ERR` (101) — transport-level error (unknown cmd kind);
  body is a UTF-8 reason string.
- `KIND_RSP_PAYLOAD` (104) — opaque guest response body for a prior
  `KIND_CTRL_PAYLOAD_REQ`. The conduit does not inspect or
  transform the bytes.

The conduit must not interpret SHMEM record contents and must not
peek inside ctrl payloads in either case. Earlier revisions decoded
specific Bifrost opcodes (LOAD_PROG `op=2`, LOAD_PROG_STATUS
`op=9`); that policy bleed is removed — the host CLI signals
request/response intent through `KIND_CTRL_PAYLOAD_REQ`, and the
guest answers through `OP_CTRL_RESPONSE` with an opaque body.

## Security and lifecycle boundaries

- POSIX SHM name: `/conduit-<pid>`, mode `0600`, owned by the
  application process.
- Concurrency: control SHM is a single-producer / single-consumer
  contract per ring (`cmd_ring`: host writes, guest reads through
  libkrun; `rsp_ring`: libkrun writes, host reads). Multiple host
  observers requires a separate channel and is out of scope for the
  generic conduit.
- Unlink behaviour: the application unlinks the SHM name on `Drop`.
  The mmap stays valid as long as either side holds an fd; consumers
  must tolerate unlink while the region is still mapped.
- The conduit never `fork`s or `exec`s. Privilege follows the
  invoking process.

## Cross-references

- [docs/architecture.md](architecture.md) — overall pipeline.
- [docs/architecture-shmem.md](architecture-shmem.md) — data SHM
  layout and Bifrost record format.
- [docs/bifrost-protocol-inventory.md](bifrost-protocol-inventory.md)
  — inventory of remaining Bifrost surfaces that ride the conduit.
- `host/virtio-conduit/src/control.rs` — `ControlShm`,
  `ControlShmView`, `compute_ring_layout`.
- `host/virtio-conduit/src/lib.rs` — `ConduitCore`,
  `handle_event_buffer`.
- `host/virtio-conduit/src/shmem/consumer.rs` — the doorbell wake
  worker.
- `third_party/smolvm/libkrun/src/devices/src/virtio/conduit/mod.rs`
  — VMM-side adapter.
