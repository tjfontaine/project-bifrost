// SPDX-License-Identifier: Apache-2.0
//
// control_shm_roundtrip — focused unit/integration tests for the
// cmd_ring/rsp_ring contract between bifrost CLI (push_cmd /
// poll_rsp) and the conduit-backend (drain_cmds / push_rsp).
//
// The integration sweep already exercises the *happy* roundtrip,
// but two edges were silently failing in production and getting
// reported as e2e "flakes":
//
//   - bifrost CLI hung past its own poll_rsp deadline. Looked
//     like a transport bug; we want to know whether poll_rsp
//     itself can drift past the deadline under any conditions.
//
//   - The CLI fell back to `enumerate_observable` after
//     /conduit-<pid> wasn't found, attaching to an unrelated
//     backend. We don't exercise that path here (it's an
//     attach-time race), but we DO pin the contract that
//     poll_rsp NEVER blocks longer than its passed-in timeout +
//     a small slack, so an unrelated-backend attach manifests
//     as a clean timeout rather than a hang.
//
// All tests share one ControlShm/ControlShmAttachment pair (the
// shm name is /conduit-<pid> and there's only one of us in this
// binary), so they run sequentially and tear the shm down at
// end. Each test resets ring cursors to a known state at the top.

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use bifrost::control_shmem::{
    ControlShmAttachment, KIND_LOAD_PROG, KIND_PAD, KIND_RSP_OK, KIND_RSP_PAYLOAD,
};
use krun_virtio_conduit::control::{ControlShm, ControlShmView, KIND_CTRL_PAYLOAD_REQ};

/// Acquire exclusive use of the shared /conduit-<pid> SHM. Each
/// test in this binary runs against the SAME named POSIX shm
/// object (one per pid), so a global Mutex serializes them. The
/// guard owns the SHM for the test's lifetime; rings are drained
/// at acquire time so each test starts clean regardless of what
/// the previous one left.
fn acquire() -> MutexGuard<'static, SharedShm> {
    use std::sync::OnceLock;
    static ONCE: OnceLock<Mutex<SharedShm>> = OnceLock::new();
    let mtx = ONCE.get_or_init(|| {
        let backend = ControlShm::create()
            .expect("create ControlShm")
            .expect("control shm should be enabled by default");
        let cli = ControlShmAttachment::open(std::process::id())
            .expect("ControlShmAttachment::open for own pid");
        Mutex::new(SharedShm {
            backend_view: backend.view.clone(),
            _keepalive: Box::leak(Box::new(backend)),
            cli,
        })
    });
    // Poisoning is fine here — a panicking test left us with
    // dirty rings, and reset_rings will clean them out. Recover
    // the inner value either way.
    let mut guard = match mtx.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    reset_rings(&mut guard);
    guard
}

struct SharedShm {
    backend_view: Arc<ControlShmView>,
    _keepalive: &'static ControlShm,
    cli: ControlShmAttachment,
}

unsafe impl Send for SharedShm {}
unsafe impl Sync for SharedShm {}

/// Drop everything sitting in the cmd_ring and rsp_ring so the
/// next test starts from a known state. Uses the non-blocking
/// `drain_rsp_ring` rather than `poll_rsp(None, ...)` so a
/// previously poisoned test can't strand us in poll_rsp.
fn reset_rings(shm: &mut SharedShm) {
    let _ = shm.backend_view.drain_cmds();
    let _ = shm.cli.drain_rsp_ring();
}

/// Hard per-test timeout. Cargo's test runner doesn't enforce one
/// — a livelocked test will spin CPU until the entire `cargo
/// test` invocation is killed manually. Wrapping every test body
/// in `with_test_timeout` gives us a deterministic failure mode
/// instead. The first time we ran these tests a `poll_rsp` bug
/// burned 500% CPU for ~4 minutes before we noticed; never again.
///
/// Use as: `with_test_timeout(Duration::from_secs(5), || { ... });`
fn with_test_timeout<F, R>(timeout: Duration, name: &'static str, body: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = body();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => match handle.join() {
            Ok(_) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "test '{}' exceeded its hard timeout of {:?} — likely livelock; \
                 sample the test binary's PID to find the spin loop",
                name, timeout
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Thread panicked without sending a result.
            match handle.join() {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(_) => panic!("test '{}' thread disconnected without result", name),
            }
        }
    }
}

// =============================================================
// Happy path — sanity check the harness itself.
// =============================================================

#[test]
fn push_cmd_then_drain_immediate_ack() {
    with_test_timeout(
        Duration::from_secs(5),
        "push_cmd_then_drain_immediate_ack",
        || {
            let shm = acquire();
            let payload = b"hello".to_vec();
            let seq = shm
                .cli
                .push_cmd(KIND_LOAD_PROG, &payload)
                .expect("push_cmd");

            let drained = shm.backend_view.drain_cmds();
            assert_eq!(drained.len(), 1, "exactly one cmd on the ring");
            let (kind, drained_seq, drained_payload) = &drained[0];
            assert_eq!(*kind, KIND_CTRL_PAYLOAD_REQ);
            assert_eq!(*drained_seq, seq);
            assert_eq!(drained_payload.as_slice(), b"hello");

            shm.backend_view
                .push_rsp(KIND_RSP_OK, seq, &[])
                .expect("push_rsp");

            let rsp = shm
                .cli
                .poll_rsp(Some(seq), Duration::from_secs(1))
                .expect("poll_rsp ok")
                .expect("rsp must arrive");
            assert_eq!(rsp.0, KIND_RSP_OK);
            assert_eq!(rsp.1, seq);
        },
    );
}

// =============================================================
// THE redis-uprobe flake: poll_rsp deadline discipline.
// =============================================================
//
// If poll_rsp can ever block past `timeout + slack`, the CLI's
// "LOAD_PROG 0 timed out" bail never fires — which is exactly
// what we saw on redis-uprobe (16s of dead air ending in
// SIGTERM).

#[test]
fn poll_rsp_returns_none_within_deadline_when_no_data() {
    with_test_timeout(
        Duration::from_secs(5),
        "poll_rsp_returns_none_within_deadline_when_no_data",
        || {
            let shm = acquire();
            let timeout = Duration::from_millis(200);
            let started = Instant::now();
            let res = shm.cli.poll_rsp(Some(42), timeout).expect("poll_rsp ok");
            let elapsed = started.elapsed();

            assert!(res.is_none(), "no producer, poll_rsp must return None");
            // The internal loop polls every 5 ms; allow up to 50 ms of
            // slack for scheduler jitter on a loaded host.
            assert!(
                elapsed < timeout + Duration::from_millis(50),
                "poll_rsp drifted past its deadline: elapsed={:?} timeout={:?}",
                elapsed,
                timeout
            );
            assert!(
                elapsed >= timeout.saturating_sub(Duration::from_millis(10)),
                "poll_rsp returned suspiciously early: elapsed={:?} timeout={:?}",
                elapsed,
                timeout
            );
        },
    );
}

#[test]
fn poll_rsp_picks_up_late_arrival_within_deadline() {
    with_test_timeout(
        Duration::from_secs(5),
        "poll_rsp_picks_up_late_arrival_within_deadline",
        || {
            let shm = acquire();
            let cmd_seq = shm
                .cli
                .push_cmd(KIND_LOAD_PROG, b"pending")
                .expect("push_cmd");
            let _ = shm.backend_view.drain_cmds();

            let backend_view = shm.backend_view.clone();
            let producer = thread::spawn(move || {
                thread::sleep(Duration::from_millis(80));
                backend_view
                    .push_rsp(KIND_RSP_OK, cmd_seq, &[1, 2, 3])
                    .expect("push_rsp");
            });

            let rsp = shm
                .cli
                .poll_rsp(Some(cmd_seq), Duration::from_millis(500))
                .expect("poll_rsp ok")
                .expect("rsp must be picked up within deadline");
            producer.join().unwrap();
            assert_eq!(rsp.1, cmd_seq);
            assert_eq!(rsp.2, vec![1, 2, 3]);
        },
    );
}

// =============================================================
// THE EXACT BUG. A backend that's emitting unsolicited
// non-matching entries (KIND_AGG_PUSH from a live trace,
// KIND_SELF_TRACE_PUSH from CLI self-trace, etc.) must NOT
// starve a `poll_rsp(Some(seq), 2s)` waiting on a specific
// LOAD_PROG ACK. Pre-fix, poll_rsp only checked its deadline in
// the `prod == cons` branch — a steady stream of mismatched
// seqs would walk the entry-decode loop forever.
//
// This test reproduces the livelock: spawn a producer that
// pushes a mismatched-seq response every microsecond, ask
// poll_rsp to wait 150 ms for a seq that never arrives, assert
// it returns None promptly. Without the deadline-at-top-of-loop
// fix this test runs forever (and the surrounding watchdog
// fires).
// =============================================================

#[test]
fn poll_rsp_honors_deadline_under_continuous_non_matching_push() {
    with_test_timeout(
        Duration::from_secs(5),
        "poll_rsp_honors_deadline_under_continuous_non_matching_push",
        || {
            let shm = acquire();
            let wanted = 99_999_u64;

            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_for_producer = stop.clone();
            let backend_view = shm.backend_view.clone();
            let producer = thread::spawn(move || {
                let mut spam_seq: u64 = 1;
                while !stop_for_producer.load(std::sync::atomic::Ordering::Relaxed) {
                    // Best-effort: ring may fill; ignore Err — the
                    // CLI side will drain as it polls.
                    let _ = backend_view.push_rsp(KIND_RSP_OK, spam_seq, &[]);
                    spam_seq = spam_seq.wrapping_add(1);
                    // Stay just below the CLI's 5 ms sleep tick so
                    // the ring isn't empty when poll_rsp checks.
                    thread::sleep(Duration::from_micros(500));
                }
            });

            let timeout = Duration::from_millis(150);
            let started = Instant::now();
            let res = shm
                .cli
                .poll_rsp(Some(wanted), timeout)
                .expect("poll_rsp ok");
            let elapsed = started.elapsed();

            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            producer.join().unwrap();

            assert!(
                res.is_none(),
                "wanted seq never arrived; expected None, got {:?}",
                res.map(|(k, s, _)| (k, s))
            );
            assert!(
                elapsed < timeout + Duration::from_millis(100),
                "poll_rsp livelocked on non-matching entries: elapsed={:?} timeout={:?}",
                elapsed,
                timeout
            );
        },
    );
}

// =============================================================
// Sequence number discipline. The CLI's response loop may see
// rsps for OTHER cmds first (out-of-order ACK, or stale entries
// left by a prior aborted attach). poll_rsp must skip past them.
// =============================================================

#[test]
fn poll_rsp_skips_non_matching_seq_then_finds_target() {
    with_test_timeout(
        Duration::from_secs(5),
        "poll_rsp_skips_non_matching_seq_then_finds_target",
        || {
            let shm = acquire();
            shm.backend_view.push_rsp(KIND_RSP_OK, 100, b"a").unwrap();
            shm.backend_view.push_rsp(KIND_RSP_OK, 200, b"b").unwrap();
            shm.backend_view.push_rsp(KIND_RSP_OK, 300, b"c").unwrap();

            let rsp = shm
                .cli
                .poll_rsp(Some(200), Duration::from_millis(200))
                .expect("poll_rsp ok")
                .expect("matching seq must be found");
            assert_eq!(rsp.1, 200);
            assert_eq!(rsp.2, b"b");

            // poll_rsp pops one entry at a time: seq=100 was
            // consumed-and-discarded en route to seq=200; seq=300
            // is still on the ring (we never asked for it). Drain
            // confirms that one entry remains, with the right seq.
            let leftover = shm
                .cli
                .poll_rsp(None, Duration::from_millis(20))
                .expect("poll_rsp ok")
                .expect("seq=300 should still be on the ring");
            assert_eq!(leftover.1, 300);
            assert_eq!(leftover.2, b"c");

            let truly_empty = shm
                .cli
                .poll_rsp(None, Duration::from_millis(20))
                .expect("poll_rsp ok");
            assert!(
                truly_empty.is_none(),
                "ring should be empty after consuming both, got {:?}",
                truly_empty
            );
        },
    );
}

// =============================================================
// Ring-fill behavior. push_cmd must FAIL with CmdRingFull, not
// silently corrupt — and a subsequent push_cmd after the consumer
// catches up must succeed.
// =============================================================

#[test]
fn push_cmd_returns_full_then_recovers_after_drain() {
    with_test_timeout(
        Duration::from_secs(5),
        "push_cmd_returns_full_then_recovers_after_drain",
        || {
            let shm = acquire();
            let ring_len = shm.cli.header.cmd_ring_len as usize;
            let body = vec![0xab_u8; 4096 - 16];
            let mut pushed = 0;
            loop {
                match shm.cli.push_cmd(KIND_LOAD_PROG, &body) {
                    Ok(_) => pushed += 1,
                    Err(_) => break,
                }
                if pushed > ring_len / 4096 + 4 {
                    panic!("push_cmd should have returned full but kept accepting");
                }
            }
            assert!(pushed >= 1, "should have admitted at least one entry");

            let drained = shm.backend_view.drain_cmds();
            assert_eq!(drained.len(), pushed, "drain count must match push count");

            let seq = shm
                .cli
                .push_cmd(KIND_LOAD_PROG, b"fresh")
                .expect("push_cmd should succeed after drain");
            assert!(seq > 0);
        },
    );
}

// =============================================================
// PAD wraparound. push_cmd at the tail emits a KIND_PAD entry
// and continues at offset 0. drain_cmds must skip the PAD.
// This is the symmetric of the existing push_rsp PAD test in
// virtio-conduit/src/control.rs.
// =============================================================

#[test]
fn drain_cmds_skips_pad_on_wraparound() {
    with_test_timeout(
        Duration::from_secs(5),
        "drain_cmds_skips_pad_on_wraparound",
        || {
            let shm = acquire();
            let ring_len = shm.cli.header.cmd_ring_len as usize;
            let big_body = vec![0u8; 4080];
            let entries_to_wrap = ring_len / 4096;

            for _ in 0..entries_to_wrap {
                let _ = shm.cli.push_cmd(KIND_LOAD_PROG, &big_body).expect("push");
                let _ = shm.backend_view.drain_cmds();
            }
            let seq = shm
                .cli
                .push_cmd(KIND_LOAD_PROG, b"post-wrap")
                .expect("push_cmd post-wrap");
            let drained = shm.backend_view.drain_cmds();
            assert!(
                drained
                    .iter()
                    .any(|(_, s, p)| *s == seq && p == b"post-wrap"),
                "post-wrap entry must be readable; got {:?}",
                drained.iter().map(|(_, s, _)| *s).collect::<Vec<_>>()
            );
        },
    );
}

// =============================================================
// Memory-ordering corner: push_rsp's release-store must be
// observable on a poll_rsp that runs on a DIFFERENT thread. The
// happy-path test runs everything single-threaded — this one
// proves the cross-thread visibility contract holds.
// =============================================================

#[test]
fn poll_rsp_sees_push_from_other_thread() {
    with_test_timeout(
        Duration::from_secs(5),
        "poll_rsp_sees_push_from_other_thread",
        || {
            let shm = acquire();
            let cmd_seq = shm.cli.push_cmd(KIND_LOAD_PROG, b"x").expect("push_cmd");
            let _ = shm.backend_view.drain_cmds();

            let backend_view = shm.backend_view.clone();
            let producer = thread::spawn(move || {
                backend_view
                    .push_rsp(KIND_RSP_PAYLOAD, cmd_seq, b"crossthread")
                    .expect("push_rsp");
            });

            let rsp = shm
                .cli
                .poll_rsp(Some(cmd_seq), Duration::from_millis(500))
                .expect("poll_rsp ok")
                .expect("cross-thread rsp must arrive");
            producer.join().unwrap();
            assert_eq!(rsp.0, KIND_RSP_PAYLOAD);
            assert_eq!(rsp.2, b"crossthread");
        },
    );
}

// =============================================================
// Zero-length payloads — both sides must tolerate empty bodies.
// KIND_RSP_OK without a body is the canonical "ack with no
// detail" reply.
// =============================================================

#[test]
fn zero_length_payload_roundtrip() {
    with_test_timeout(
        Duration::from_secs(5),
        "zero_length_payload_roundtrip",
        || {
            let shm = acquire();
            let seq = shm
                .cli
                .push_cmd(KIND_LOAD_PROG, &[])
                .expect("push_cmd zero-len");
            let drained = shm.backend_view.drain_cmds();
            let entry = drained
                .iter()
                .find(|(_, s, _)| *s == seq)
                .expect("our cmd appears");
            assert!(entry.2.is_empty(), "zero-length cmd body preserved");

            shm.backend_view
                .push_rsp(KIND_RSP_OK, seq, &[])
                .expect("push_rsp zero-len");

            let rsp = shm
                .cli
                .poll_rsp(Some(seq), Duration::from_millis(200))
                .expect("poll_rsp ok")
                .expect("rsp arrives");
            assert_eq!(rsp.0, KIND_RSP_OK);
            assert!(rsp.2.is_empty());
        },
    );
}

// =============================================================
// PAD constants stay distinct from real kinds. A regression that
// reuses KIND_PAD as a real-traffic kind would silently corrupt.
// =============================================================

#[test]
fn kind_pad_distinct_from_real_kinds() {
    let real = [
        KIND_LOAD_PROG,
        KIND_RSP_OK,
        KIND_RSP_PAYLOAD,
        KIND_CTRL_PAYLOAD_REQ,
    ];
    for k in &real {
        assert_ne!(
            *k, KIND_PAD,
            "real wire kind {} must not equal KIND_PAD {}",
            k, KIND_PAD
        );
    }
}
