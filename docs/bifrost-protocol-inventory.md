# Bifrost Protocol Inventory

This inventory names every Bifrost-specific protocol surface that
crosses the host CLI, libkrun adapter, and guest driver boundary. Use
it alongside [`virtio-conduit.md`](virtio-conduit.md): the conduit
document specifies what the **generic transport** guarantees; this
document enumerates **Bifrost-specific** payload shapes that ride
that transport.

The migration to a generic conduit is complete. Libkrun no longer
parses BFR7, decodes record schemas, walks BTF, or renders trace
output. Anything still on the "libkrun does this" side of the table
below is a defect — file an issue and lift it.

## Transport Surfaces

### Virtio Device

- Device type: internal experimental virtio device ID `42`. Not an
  OASIS-assigned virtio ID; do not describe as standard.
- Queues:
  - `VQ_CTRL` (index 0): host → guest opaque control payloads.
  - `VQ_EVENT` (index 1): guest → host status / control payloads.
  - `VQ_DOORBELL` (index 2): guest → host wake notification for data
    SHM producer progress.
- Shared memory: region ID `0`, default 16 MB
  (`VIRTIO_SHM_REGION_SIZE`), exposed through virtio-mmio
  shared-memory registers.

Classification: **generic conduit transport** owned by
`host/virtio-conduit/` and the thin libkrun adapter at
`third_party/smolvm/libkrun/src/devices/src/virtio/conduit/`. See
[`virtio-conduit.md`](virtio-conduit.md).

### Data SHMEM

The guest initializes the VMM-provided virtio shared-memory region and
publishes the active Bifrost layout in the first page:

| Offset | Field |
|---:|---|
| 0 | `SHMEM_MAGIC` (`0x48534642`, ASCII `BFSH` LE) |
| 4 | `SHMEM_VERSION` (`2`) |
| 16 | ring buffer offset |
| 24 | ring buffer length |
| 32 | producer position |
| 40 | consumer position |
| 48 | BTF blob offset |
| 56 | BTF blob length |
| 64 | kallsyms blob offset |
| 72 | kallsyms blob length |

The guest-side fixed layout is currently:

- header: 4 KB
- event ring: 6 MB
- BTF blob capacity: 6 MB
- kallsyms capacity: 2 MB
- VMA cache: remaining bytes in the 16 MB region

Long-term classification: the region, wakeups, and producer/consumer
mechanics are generic transport. The BTF, kallsyms, VMA, record, stack,
and aggregation contents are Bifrost application protocol.

### `SHMEM_INIT`

Guest-to-host event-queue op `8`.

Current body:

```text
u32 op = 8
u32 region_size
u32 n_pages
u32 magic
u32 version
u32 reserved
u64 pfns[n_pages]
```

`n_pages == 0` is the **shipping** path: a readiness notification for
the virtio shared-memory region. `n_pages > 0` is the legacy
vmalloc/PFN fallback; the conduit logs and rejects it at
`ConduitCore::handle_event_buffer`.

Classification: temporary compatibility. Once the legacy branch is
retired we will rename `SHMEM_INIT` with `n_pages == 0` to a clearer
`SHMEM_READY` op (or document the zero-PFN form as the canonical
shape).

## Control SHM

The host CLI discovers a conduit by opening `/conduit-<pid>`, a named
POSIX SHM object owned by the application process. Header layout and
ring entry shape are owned by the **generic conduit** and specified
in [`virtio-conduit.md`](virtio-conduit.md#control-shm).
Bifrost-specific notes:

- `caps` includes `CONTROL_CAP_CTRL_PAYLOAD` once the cmd/rsp rings
  are live and `CONTROL_CAP_DATA_SHM` once the data SHM metadata is
  published.
- `data_wakeup_mode = CONTROL_WAKE_COUNTER (2)`. The host CLI reads
  `data_wake_counter` at the offset `data_wake_counter_off` as an
  advisory hint; the durable hand-off is the per-record `READY` flag
  in the data ring.

The CLI is currently a **timed-polling** consumer of the data SHM —
see [`architecture.md`](architecture.md#performance) "CLI direct-
render record visibility latency" for the cadence. Eventfd passing
to the CLI render thread is future work and is intentionally not
required for correctness because the wake counter is advisory.

## Control Message Kinds

The control SHM ring carries opaque application payloads. The
conduit dispatches on the `kind` field of the entry header but does
**not** parse payload bytes for any Bifrost-specific kind. Kinds
currently in use:

| Kind | Direction | Payload | Classification |
|---:|---|---|---|
| `1` `KIND_CTRL_PAYLOAD` | CLI to conduit | opaque (e.g. guest LOAD_PROG bytes) | transport |
| `100` `KIND_RSP_OK` | conduit to CLI | request-specific | transport |
| `101` `KIND_RSP_ERR` | conduit to CLI | UTF-8 error | transport |
| `255` `KIND_PAD` | either ring | skip tail | transport |

Earlier iterations layered Bifrost-specific kinds (`LOAD_PROG`,
`AGG_PUSH`, `RECORD_PUSH`, `LOAD_PROG_STATUS`, `SELF_TRACE_PUSH`,
`PROFILE_SAMPLE`, `OBSERVER_*`, …) on top of the same ring; those
have been folded into opaque `CTRL_PAYLOAD` carriage because the
application now owns its own dispatch (status responses come back
via the rsp ring's `KIND_RSP_OK` / `KIND_RSP_ERR` with the same seq).

## Backend Load Payloads

The control ring carries opaque backend load payloads.  Bifrost's
session planner chooses the backend before payload construction:

- **Linux** uses the existing BFR7-derived LOAD_PROG payloads.  This
  is the Linux eBPF compatibility backend.
- **FreeBSD** will use a kernel-consumable native-DTrace session
  payload.  The guest-side consumer is a kernel conduit driver plus a
  narrow DTrace-kernel bridge; no guest userspace agent or guest
  `dtrace(1)` is in the acceptance path.
- **illumos** is planned to use the same native-DTrace backend class
  as FreeBSD, with provider/argument differences isolated behind the
  illumos backend.

The generic conduit remains payload-opaque for every backend.  Any
code below `ConduitCore` that knows whether a payload is Linux eBPF,
FreeBSD DTrace, or illumos DTrace is a layering defect.

## Linux BFR7 Wrapper

BFR7 is built by the host CLI as a CLI-local intermediate for the
Linux backend. It is
**not** sent over any wire that libkrun parses. The CLI decodes its
own BFR7 (via `bifrost_wire::codec::decode_bfr7`), then constructs
per-program guest LOAD_PROG byte payloads in
`host/bifrost/src/cli/direct_load.rs` and pushes them through the
conduit's cmd ring as opaque `KIND_CTRL_PAYLOAD` entries.

The wrapper carries:

- magic `BFR7`
- program count
- per-program target name and flags
- encoded record schema
- map declarations and aggregation metadata
- eBPF program bytes
- probe-type-specific trailer data (host-resolved uprobe, kernel-
  resolved uprobe, USDT)
- kfunc and field relocation metadata

Classification: Bifrost application protocol, host-CLI-internal. The
guest driver consumes the **derived LOAD_PROG payload**, not BFR7
directly. The wire byte order is explicit little-endian (the
emitter uses `to_le_bytes`; the guest parser uses
`u{32,64}::from_le_bytes` through `read_u{32,64}_le_unaligned`).

## SHMEM Record Kinds

Every SHMEM record starts with an 8-byte header:

```text
u32 size
u32 flags
```

`flags` currently uses:

- `1`: record ready
- `2`: padding record

The payload's probe ID at payload offset 4 controls libkrun routing:

| Probe ID | Meaning | Current libkrun behavior |
|---:|---|---|
| `0xFFFFFFFF` | VMA table push | update VMA cache |
| `0xFFFFFFFD` | aggregation snapshot | decode/render xagg rows |
| `0xFFFFFFFC` | pushed symbol table | update pushed symtab cache |
| `0xFFFFFFFB` | guest self-trace | route/render self-trace |
| `0xFFFFFFFA` | libkrun self-trace | route/render self-trace |
| `0xFFFFFFF9` | CLI self-trace | route/render self-trace |
| `0xFFFFFFF8` | profile sample | decode/render profile sample |
| `1..N` | user trace records | schema decode and stack/symbol rendering |

Long-term classification: Bifrost application protocol. The generic
conduit should not know these IDs.

## Semantic State Still in libkrun

None. All of the BFR7 / schema / BTF / VMA / record / aggregation /
self-trace state previously hosted in libkrun's
`devices/src/virtio/bifrost/` directory has been removed. The
shipping VMM-side code is `third_party/smolvm/libkrun/src/devices/src/virtio/conduit/mod.rs`
plus the generic `host/virtio-conduit/` crate; neither imports
`bifrost_wire` symbols or parses Bifrost record kinds.

What the VMM-side adapter is allowed to keep:

- virtio-mmio device construction/registration
- virtqueue descriptor copies
- virtio shared-memory region exposure
- doorbell `EventFd` plumbing into the conduit core
- libkrun event-manager subscription/cleanup

A defect under this rule is anything in
`third_party/smolvm/libkrun/src/` referencing `BFR7`,
`bifrost_wire`, a Bifrost record probe ID, or rendering trace
output. `scripts/check-crate-graph.sh` enforces the dependency
side of this rule by refusing any `bifrost`-package dependency in
`krun-devices`.
