// SPDX-License-Identifier: Apache-2.0
//
// Generic conduit control/wakeup worker.
//
// This thread intentionally does not decode entries from the data SHM
// ring, nor does it interpret the bytes inside ctrl payloads. The host
// CLI owns the payload format and advances the data-ring consumer
// cursor directly. libkrun remains responsible for control-SHM command
// draining, opaque payload forwarding (with an LE seq trailer appended
// for `KIND_CTRL_PAYLOAD_REQ` so the guest can echo it back through
// `OP_CTRL_RESPONSE`), and doorbell wake accounting.

use std::sync::atomic::Ordering;

use super::state::ShmemConsumerCtx;
#[cfg(target_os = "macos")]
fn wait_for_doorbell(fd: i32) {
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
        return;
    }
    let kev = libc::kevent {
        ident: fd as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 0,
        udata: core::ptr::null_mut(),
    };
    unsafe {
        libc::kevent(kq, &kev, 1, core::ptr::null_mut(), 0, core::ptr::null());
        let mut events = [libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: core::ptr::null_mut(),
        }];
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        let _ = libc::kevent(kq, core::ptr::null(), 0, events.as_mut_ptr(), 1, &timeout);
        libc::close(kq);
    }
}

#[cfg(not(target_os = "macos"))]
fn wait_for_doorbell(fd: i32) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let _ = unsafe { libc::poll(&mut pfd as *mut _, 1, 1) };
}

fn drain_doorbell(fd: i32) -> bool {
    let mut buf = [0u8; 8];
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 8) > 0 }
}

pub fn shmem_consumer_thread(ctx: ShmemConsumerCtx) {
    log::info!("virtio-conduit host: conduit worker thread started");
    use std::os::unix::io::AsRawFd;
    let doorbell_fd = ctx.doorbell_eventfd.as_raw_fd();

    while ctx.running.load(Ordering::SeqCst) {
        if let Some(view) = ctx.control_shm.as_ref() {
            for (kind, seq, payload) in view.drain_cmds() {
                match kind {
                    crate::control::KIND_CTRL_PAYLOAD => {
                        // Fire-and-forget: forward as-is, auto-ack the
                        // host CLI once the payload is queued for the
                        // guest. No body inspection.
                        if let Ok(mut q) = ctx.pending_payloads.lock() {
                            q.push_back((seq, payload));
                        }
                        if let Some(evt) = ctx.vq_ctrl_event.as_ref() {
                            let _ = evt.write(1);
                        }
                        let _ = view.push_rsp(crate::control::KIND_RSP_OK, seq, &[]);
                    }
                    crate::control::KIND_CTRL_PAYLOAD_REQ => {
                        // Request/response: append an 8-byte LE seq
                        // trailer so the guest can echo it back via
                        // `OP_CTRL_RESPONSE`. Do not auto-ack — the
                        // host CLI is waiting on the matching
                        // `KIND_RSP_PAYLOAD`. The conduit does not
                        // inspect the body.
                        if let Ok(mut q) = ctx.pending_payloads.lock() {
                            let mut payload = payload;
                            payload.extend_from_slice(&seq.to_le_bytes());
                            q.push_back((seq, payload));
                        }
                        if let Some(evt) = ctx.vq_ctrl_event.as_ref() {
                            let _ = evt.write(1);
                        }
                    }
                    other => {
                        // PAINFUL FAILURE — unrecognised conduit-level
                        // cmd kind.  Pre-fix this returned a quiet
                        // KIND_RSP_ERR "unknown cmd" reply, which
                        // looked like "guest rejected the body" at
                        // the host CLI; the actual cause (transport-
                        // layer mis-tagging on the host side) ate
                        // ~15 minutes of debug time during the
                        // DOF-generic cutover.  Conduit only knows
                        // KIND_CTRL_PAYLOAD (1) and
                        // KIND_CTRL_PAYLOAD_REQ (2); any application
                        // opcode (LOAD_PROG, DTRACE_SESSION, …) goes
                        // inside the body as `BifrostCmd.op`.  If we
                        // see anything else here it's a host-CLI bug
                        // — panic so it gets fixed at the source.
                        panic!(
                            "virtio-conduit host: BUG: unknown cmd kind={other} (seq={seq}); \
                             conduit only forwards KIND_CTRL_PAYLOAD (1) and \
                             KIND_CTRL_PAYLOAD_REQ (2). Application opcodes live in the \
                             BifrostCmd body, not the transport kind."
                        );
                    }
                }
            }
        }

        wait_for_doorbell(doorbell_fd);
        if drain_doorbell(doorbell_fd) {
            if let Some(view) = ctx.control_shm.as_ref() {
                view.increment_data_wake_counter();
            }
        }
    }
}

