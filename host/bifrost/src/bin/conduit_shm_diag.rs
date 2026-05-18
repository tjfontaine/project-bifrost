// SPDX-License-Identifier: Apache-2.0
//
// conduit_shm_diag — one-shot transport diagnostic for the
// FreeBSD conduit hang.
//
// What it does:
//   1. Open `/conduit-<pid>` (POSIX SHM owned by conduit-backend).
//   2. Dump the cmd/rsp ring offsets + lens + producer/consumer
//      cursors as the host bifrost sees them.
//   3. Push one synthetic KIND_CTRL_PAYLOAD_REQ entry into the cmd
//      ring (just an 8-byte body, no DOF — the conduit-backend
//      consumer thread should immediately drain it because the
//      worker polls every 1 ms regardless of payload kind).
//   4. Poll the cmd_consumer_pos for up to `--wait-ms`
//      milliseconds, sampling every 100 ms, to see whether the
//      backend ever advances it.
//   5. Poll the rsp_producer_pos for up to the same window — if
//      the backend forwarded to the guest, the guest's response
//      shows up there as KIND_RSP_OK (auto-ack on
//      KIND_CTRL_PAYLOAD) or KIND_RSP_PAYLOAD (LOAD_PROG echo).
//
// If consumer-pos advances but producer-pos never moves, the
// backend's vhost-user → guest virtqueue path is the blocker.
// If consumer-pos doesn't advance either, the backend isn't even
// seeing our push — i.e. host/backend disagree on the cmd_ring
// layout in the same mmap.

use std::time::{Duration, Instant};

use bifrost::control_shmem::{ControlShmAttachment, KIND_LOAD_PROG};

fn usage() -> ! {
    eprintln!("usage: conduit_shm_diag <pid> [--wait-ms N] [--size N] [--drain]");
    eprintln!("  --size N    pad payload to N bytes (default 16)");
    eprintln!("  --drain     poll_rsp to consume our own response so we don't pollute the ring");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let pid: u32 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| usage());
    let mut wait_ms: u64 = 2000;
    let mut size: usize = 16;
    let mut drain = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--wait-ms" => {
                wait_ms = args.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| usage());
            }
            "--size" => {
                size = args.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| usage());
            }
            "--drain" => drain = true,
            _ => usage(),
        }
    }

    let attach = match ControlShmAttachment::open(pid) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("attach to conduit pid {pid}: {e}");
            std::process::exit(1);
        }
    };

    let hdr = &attach.header;
    println!("== /conduit-{pid} header ==");
    println!("  region_size      = {}", hdr.region_size);
    println!("  caps             = {:#x}", hdr.caps);
    println!("  cmd_ring_off     = {}", hdr.cmd_ring_off);
    println!("  cmd_ring_len     = {}", hdr.cmd_ring_len);
    println!("  rsp_ring_off     = {}", hdr.rsp_ring_off);
    println!("  rsp_ring_len     = {}", hdr.rsp_ring_len);

    let cmd_prod_before = attach.cmd_producer_pos().load(std::sync::atomic::Ordering::Acquire);
    let cmd_cons_before = attach.cmd_consumer_pos().load(std::sync::atomic::Ordering::Acquire);
    let rsp_prod_before = attach.rsp_producer_pos().load(std::sync::atomic::Ordering::Acquire);
    let rsp_cons_before = attach.rsp_consumer_pos().load(std::sync::atomic::Ordering::Acquire);
    println!(
        "  cmd cursors      prod={cmd_prod_before} cons={cmd_cons_before}  diff={}",
        cmd_prod_before.wrapping_sub(cmd_cons_before)
    );
    println!(
        "  rsp cursors      prod={rsp_prod_before} cons={rsp_cons_before}  diff={}",
        rsp_prod_before.wrapping_sub(rsp_cons_before)
    );

    // Build a valid NDT v2 header so the kernel parse succeeds and
    // queues bifrost_conduit_run_dtrace_proof — which is where we
    // suspect the hang lives. The body after the 40-byte header is
    // junk DOF; dtrace_bifrost_run_dof will reject inside
    // dtrace_dof_slurp and send a clean error response.
    let mut payload = Vec::with_capacity(size.max(40));
    payload.extend_from_slice(&0x3154_444eu32.to_le_bytes()); // magic NDT1
    payload.extend_from_slice(&2u16.to_le_bytes()); // version 2
    payload.extend_from_slice(&1u16.to_le_bytes()); // op RUN_DOF
    payload.extend_from_slice(&1u16.to_le_bytes()); // os FREEBSD
    payload.extend_from_slice(&0u16.to_le_bytes()); // flags
    payload.extend_from_slice(&40u32.to_le_bytes()); // header_len
    let dof_len = size.saturating_sub(40).max(1) as u32;
    payload.extend_from_slice(&dof_len.to_le_bytes()); // dof_len
    payload.extend_from_slice(&2u32.to_le_bytes()); // probe_id
    payload.extend_from_slice(&0u64.to_le_bytes()); // expected
    payload.extend_from_slice(&0u32.to_le_bytes()); // duration_ms
    payload.extend_from_slice(&0u32.to_le_bytes()); // reserved
    while payload.len() < size {
        payload.push(0xaa);
    }
    // If size < 40 we still send 40 (header).
    if payload.len() < 40 {
        payload.resize(40, 0);
    }
    let seq = match attach.push_cmd(KIND_LOAD_PROG, &payload) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("push_cmd: {e}");
            std::process::exit(1);
        }
    };
    let cmd_prod_after = attach.cmd_producer_pos().load(std::sync::atomic::Ordering::Acquire);
    println!();
    println!("== after push_cmd (seq={seq}, KIND_LOAD_PROG, {}-byte body) ==", payload.len());
    println!(
        "  cmd cursors      prod={cmd_prod_after} cons={} (host advanced prod by {})",
        attach.cmd_consumer_pos().load(std::sync::atomic::Ordering::Acquire),
        cmd_prod_after.wrapping_sub(cmd_prod_before),
    );

    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    let mut last_cons = attach.cmd_consumer_pos().load(std::sync::atomic::Ordering::Acquire);
    let mut last_rsp_prod = attach.rsp_producer_pos().load(std::sync::atomic::Ordering::Acquire);
    println!();
    println!("== polling for {wait_ms}ms (sample every 100ms) ==");
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        let cons = attach.cmd_consumer_pos().load(std::sync::atomic::Ordering::Acquire);
        let rsp_prod = attach.rsp_producer_pos().load(std::sync::atomic::Ordering::Acquire);
        if cons != last_cons || rsp_prod != last_rsp_prod {
            println!(
                "  +{:>4}ms  cmd_cons={cons} (Δ {}), rsp_prod={rsp_prod} (Δ {})",
                (Instant::now() - (deadline - Duration::from_millis(wait_ms))).as_millis(),
                cons.wrapping_sub(last_cons),
                rsp_prod.wrapping_sub(last_rsp_prod),
            );
            last_cons = cons;
            last_rsp_prod = rsp_prod;
        }
    }
    println!();
    println!("== final state ==");
    let cmd_cons_end = attach.cmd_consumer_pos().load(std::sync::atomic::Ordering::Acquire);
    let rsp_prod_end = attach.rsp_producer_pos().load(std::sync::atomic::Ordering::Acquire);
    println!(
        "  cmd_cons advanced by {} (host pushed {} bytes of ring)",
        cmd_cons_end.wrapping_sub(cmd_cons_before),
        cmd_prod_after.wrapping_sub(cmd_prod_before),
    );
    println!(
        "  rsp_prod advanced by {} (a response would mean guest received and replied)",
        rsp_prod_end.wrapping_sub(rsp_prod_before),
    );

    if drain {
        // Drain ALL pending responses, not just our seq.  That way we
        // see "already pending" responses to predecessors, mismatched
        // seqs, etc.
        let mut drained = 0;
        let drain_deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < drain_deadline {
            match attach.poll_rsp(None, Duration::from_millis(50)) {
                Ok(Some((kind, seqv, body))) => {
                    println!(
                        "  drained: kind={kind:#x} seq={seqv} body_len={} first_bytes={:02x?}",
                        body.len(),
                        &body[..body.len().min(48)]
                    );
                    drained += 1;
                }
                _ => break,
            }
        }
        if drained == 0 {
            println!("  drain: no responses in rsp ring (within 500ms)");
        }
    }

    if cmd_cons_end == cmd_cons_before {
        eprintln!();
        eprintln!("DIAGNOSIS: conduit-backend never drained the cmd ring.");
        eprintln!("  Either (a) the consumer thread isn't reading the same SHM bytes the");
        eprintln!("  host wrote, or (b) it's wedged elsewhere. Attach lldb to the backend");
        eprintln!("  pid and check whether the shmem_consumer_thread is in wait_for_doorbell");
        eprintln!("  (healthy idle) or stuck in drain_cmds.");
        std::process::exit(3);
    } else if rsp_prod_end == rsp_prod_before {
        eprintln!();
        eprintln!("DIAGNOSIS: conduit-backend drained the cmd, but no response arrived.");
        eprintln!("  Backend forwarded to vhost-user but the guest virtqueue never produced");
        eprintln!("  a response. Inspect virtio-bus state on the guest side (kgdb).");
        std::process::exit(4);
    } else {
        println!();
        println!("OK: cmd consumed AND rsp produced — the transport is healthy.");
    }
}
