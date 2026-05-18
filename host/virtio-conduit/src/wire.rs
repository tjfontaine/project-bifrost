// SPDX-License-Identifier: Apache-2.0
//
// Minimal host-control wire for the virtio conduit.
// libkrun only needs the control command/response discriminants needed
// to forward opaque payloads between host control SHM and virtqueues.
// Higher-level payload schemas, negotiation, and status semantics
// are owned by users of the conduit, not by the VMM.
//
// Control-SHM ring entry kinds (host → guest):
//
//   KIND_CTRL_PAYLOAD (1)       fire-and-forget opaque payload.
//                               The conduit forwards the body to the
//                               guest verbatim and auto-acks with
//                               `KIND_RSP_OK` once dispatched.
//
//   KIND_CTRL_PAYLOAD_REQ (2)   request/response opaque payload.
//                               The conduit appends an 8-byte LE
//                               seq trailer after the body so the
//                               guest can echo it back. The conduit
//                               does NOT auto-ack — the host CLI
//                               waits on the matching response,
//                               which arrives as `KIND_RSP_PAYLOAD`
//                               via the event-vq → rsp-ring path.
//
// Control-SHM ring entry kinds (guest → host):
//
//   KIND_RSP_OK (100)           transport-level ack of a fire-and-
//                               forget `KIND_CTRL_PAYLOAD`. Body
//                               empty.
//   KIND_RSP_ERR (101)          transport-level error (e.g. unknown
//                               cmd kind). Body is a UTF-8 reason.
//   KIND_RSP_PAYLOAD (104)      opaque guest response body delivered
//                               for a prior `KIND_CTRL_PAYLOAD_REQ`,
//                               matched by seq. The conduit does not
//                               inspect or transform the bytes.
//
// Event-vq opcodes (guest → host, conduit-defined transport events):
//
//   OP_DATA_SHM_READY (8)       data-SHM ready notification.
//                               Wire: `u32 op, u32 region_size,
//                               u32 wire_n_pages`. The conduit
//                               binds the host-side virtio SHM
//                               region for the requested size and
//                               spawns the data-SHM worker.
//   OP_CTRL_RESPONSE (9)        request/response delivery.
//                               Wire: `u32 op, u64 seq, [u8; rest]
//                               body`. The conduit routes the body
//                               verbatim to the rsp ring as
//                               `(KIND_RSP_PAYLOAD, seq, body)`.

pub const KIND_CTRL_PAYLOAD: u32 = 1;
pub const KIND_CTRL_PAYLOAD_REQ: u32 = 2;
pub const KIND_RSP_OK: u32 = 100;
pub const KIND_RSP_ERR: u32 = 101;
pub const KIND_RSP_PAYLOAD: u32 = 104;
pub const KIND_PAD: u32 = 255;

pub const OP_DATA_SHM_READY: u32 = 8;
pub const OP_CTRL_RESPONSE: u32 = 9;
