// Attach-mode runtime for the bifrost CLI.
//
// Three top-level entry points, each one a CLI subcommand:
//   - run_ls():           `bifrost ls` — enumerate observable libkrun pids
//   - run_attach():       `bifrost attach <pid> [--raw-ebpf <path>]` — one-shot
//                         control SHM smoke test
//   - run_attach_trace(): `-p <pid> -s <file>` — full attach trace loop;
//                         pushes opaque LOAD_PROG payloads, attaches
//                         in-process libdtrace consumer, drains
//                         records until SIGINT
//
// The trace loop owns SIGINT via `ctrlc_install_flag`, which uses a
// global Once to install the handler exactly once per process.

#![cfg(target_os = "macos")]

use crate::backend::GuestRecordSchema;
use crate::cli::args::{FreebsdDtraceArgs, default_vmlinux};
use crate::cli::direct_load::build_direct_load_progs;
use crate::cli::direct_symbols::{DirectSymbolState, parse_kallsyms_blob};
use crate::cli::trace_render::{
    direct_agg_names, ingest_direct_agg_snapshot, render_direct_schema_record,
    render_self_trace_payload_to_stderr,
};
use crate::cli::wrapper::MapDecl;
use crate::cli::xagg::{
    CrossAggValue, dump_xagg_state, dump_xagg_state_force, try_parse_xagg_line,
};
use crate::cli::xstack::{
    XstackState, dump_xstack_fold, extract_xstack_depth, try_parse_xstack_line,
};
use crate::schema::RecordSchema;
use bifrost_wire::BFR7_MAGIC;

use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::fs;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{error, info, warn};

/// Process-wide running totals for guest-ring drops, populated by
/// the direct-data renderer thread. Read at shutdown to emit a
/// one-line summary next to libdtrace's drop totals so users see
/// "the guest dropped N records" the same way they see "libdtrace
/// dropped M principal records" — instead of having to scrape
/// stderr for transient "[bifrost] data SHM drops" lines.
///
/// Indexed by `bifrost_wire::SHMEM_DROP_CLASS_*` so the summary
/// reports which class (principal events / aggregation snapshots /
/// stack+symtab metadata / double-fault ERROR clauses) starved the
/// ring. The renderer thread writes each class slot from the
/// kernel's per-class atomic arrays.
static SHMEM_DROPPED_RECORDS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static SHMEM_DROPPED_BYTES: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Print a final SHMEM-drop summary, if any drops were observed.
/// No-op on a clean run (drops=0).  Format follows DTrace's
/// `dtrace_consumer::print_drop_summary` taxonomy.  Each class slot
/// holds the running total read from the kernel's per-class atomic
/// array.
pub fn print_shmem_drop_summary() {
    let records: [u64; 4] = [
        SHMEM_DROPPED_RECORDS[0].load(Ordering::Relaxed),
        SHMEM_DROPPED_RECORDS[1].load(Ordering::Relaxed),
        SHMEM_DROPPED_RECORDS[2].load(Ordering::Relaxed),
        SHMEM_DROPPED_RECORDS[3].load(Ordering::Relaxed),
    ];
    let bytes_per_class: [u64; 4] = [
        SHMEM_DROPPED_BYTES[0].load(Ordering::Relaxed),
        SHMEM_DROPPED_BYTES[1].load(Ordering::Relaxed),
        SHMEM_DROPPED_BYTES[2].load(Ordering::Relaxed),
        SHMEM_DROPPED_BYTES[3].load(Ordering::Relaxed),
    ];
    let total: u64 = records.iter().copied().sum();
    let bytes_total: u64 = bytes_per_class.iter().copied().sum();
    if total == 0 && bytes_total == 0 {
        return;
    }
    eprintln!(
        "[bifrost] guest-ring drop summary: drops={} (principal={} agg={} stkstr={} dblerr={}) bytes={}",
        total,
        records[bifrost_wire::SHMEM_DROP_CLASS_PRINCIPAL as usize],
        records[bifrost_wire::SHMEM_DROP_CLASS_AGG as usize],
        records[bifrost_wire::SHMEM_DROP_CLASS_STKSTR as usize],
        records[bifrost_wire::SHMEM_DROP_CLASS_DBLERR as usize],
        bytes_total
    );
}

pub fn run_ls() -> Result<ExitCode> {
    let observed = crate::control_shmem::enumerate_observable();
    if observed.is_empty() {
        warn!("no observable libkrun processes found.");
        info!("  hint: target must run with the bifrost virtio device");
        info!("        and VIRTIO_CONDUIT_CONTROL_SHM != 0 (default enabled).");
        info!("  hint: shm_open requires the same uid as the target,");
        info!("        typically root — try `sudo bifrost ls`.");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "  PID    VERSION   REGION (KB)    CMD_RING (KB)    RSP_RING (KB)    DATA_SHM (KB)    CAPS"
    );
    for (pid, h) in observed {
        let mut caps = Vec::new();
        if h.supports_load_prog() {
            caps.push("LOAD_PROG");
        }
        if h.supports_data_shm() {
            caps.push("DATA_SHM");
        }
        let caps = if caps.is_empty() {
            "(none)".to_string()
        } else {
            caps.join(",")
        };
        println!(
            "  {:<6} {:<9} {:<14} {:<16} {:<16} {:<16} {}",
            pid,
            h.version,
            h.region_size / 1024,
            h.cmd_ring_len / 1024,
            h.rsp_ring_len / 1024,
            h.data_shm_size / 1024,
            caps,
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `bifrost attach <pid>` reads the libkrun control SHM endpoint
/// at `/conduit-<pid>`, prints the header, and sends a no-op
/// LOAD_PROG to verify the cmd/rsp rings work
/// end-to-end. The full attach-mode trace path (real LOAD_PROG
/// payload + trace driver loop) is `run_attach_trace`.
pub fn run_attach(pid: u32, raw_ebpf: Option<&str>) -> Result<ExitCode> {
    use crate::control_shmem::{
        ControlShmAttachment, KIND_LOAD_PROG, KIND_RSP_ERR, KIND_RSP_OK, KIND_RSP_PAYLOAD,
        decode_load_prog_status,
    };

    let attachment =
        ControlShmAttachment::open(pid).map_err(|e| anyhow!("attach to pid {}: {}", pid, e))?;
    let h = &attachment.header;
    println!(
        "bifrost attach pid={} (control SHM at /conduit-{})",
        pid, pid
    );
    println!(
        "  header  version={} region_size={} bytes",
        h.version, h.region_size
    );
    println!(
        "  rings   cmd: {} bytes @ off={:#x}    rsp: {} bytes @ off={:#x}",
        h.cmd_ring_len, h.cmd_ring_off, h.rsp_ring_len, h.rsp_ring_off
    );
    println!(
        "  caps    LOAD_PROG={} DATA_SHM={}",
        if h.supports_load_prog() { "yes" } else { "no" },
        if h.supports_data_shm() { "yes" } else { "no" }
    );
    if let Some(name) = attachment.data_shm_name() {
        println!(
            "  data    shm={} size={} bytes proto={} wake={}",
            name,
            h.data_shm_size,
            h.data_shm_protocol_version,
            match h.data_wakeup_mode {
                crate::control_shmem::CONTROL_WAKE_COUNTER => "counter",
                _ => "unknown",
            }
        );
    }

    let timeout = std::time::Duration::from_millis(500);
    let payload: Vec<u8> = if let Some(path) = raw_ebpf {
        let bytes = fs::read(path).map_err(|e| anyhow!("read {}: {}", path, e))?;
        if bytes.len() < 8 || bytes[..4] != BFR7_MAGIC {
            bail!(
                "{} is not a BFR7 wrapper (got magic {:?}); BFR5/BFR6 retired — rebuild with current CLI",
                path,
                &bytes[..4.min(bytes.len())]
            );
        }
        let kind = std::str::from_utf8(&bytes[..4]).unwrap_or("BFR?");
        println!(
            "  load    pushing {} wrapper from {} ({} bytes)",
            kind,
            path,
            bytes.len()
        );
        bytes
    } else {
        build_attach_ping_payload()
    };
    let load_seq = attachment
        .push_cmd(KIND_LOAD_PROG, &payload)
        .map_err(|e| anyhow!("push LOAD_PROG: {}", e))?;
    let rsp = attachment
        .poll_rsp(Some(load_seq), timeout)
        .map_err(|e| anyhow!("poll rsp: {}", e))?;
    match rsp {
        Some((KIND_RSP_PAYLOAD, seq, payload)) if seq == load_seq => {
            match decode_load_prog_status(&payload) {
                Ok((0, _)) => println!(
                    "  rtt     LOAD_PROG seq={} acked OK (logged on libkrun side; \
                     actual loader plumbing is exercised by attach-mode trace)",
                    seq
                ),
                Ok((status, detail)) => println!(
                    "  rtt     LOAD_PROG seq={} ERR status={} detail={}",
                    seq,
                    status,
                    detail.as_deref().unwrap_or("")
                ),
                Err(err) => println!(
                    "  rtt     LOAD_PROG seq={} ERR malformed response: {}",
                    seq, err
                ),
            }
        }
        Some((KIND_RSP_OK, seq, _)) if seq == load_seq => {
            // Transport-level ack from a fire-and-forget path; treat
            // as success since no body is expected.
            println!("  rtt     LOAD_PROG seq={} acked OK (transport-level)", seq);
        }
        Some((KIND_RSP_ERR, seq, payload)) => {
            println!(
                "  rtt     LOAD_PROG seq={} ERR: {}",
                seq,
                String::from_utf8_lossy(&payload)
            );
        }
        Some((kind, seq, _)) => {
            println!(
                "  rtt     LOAD_PROG unexpected reply kind={:#x} seq={}",
                kind, seq
            );
        }
        None => {
            println!("  rtt     LOAD_PROG timed out after {:?}", timeout);
        }
    }

    println!("  status  conduit command endpoint checked");
    Ok(ExitCode::from(0))
}

pub fn run_freebsd_proof(args: &FreebsdDtraceArgs) -> Result<ExitCode> {
    use crate::backend::{
        GuestBackend, NATIVE_DTRACE_DEFAULT_LABEL, NativeDtraceBackend, NativeDtraceSessionRequest,
    };
    use crate::control_shmem::{ControlShmAttachment, KIND_RSP_PAYLOAD, decode_load_prog_status};

    let attachment = ControlShmAttachment::open(args.pid)
        .map_err(|e| anyhow!("attach to FreeBSD conduit pid {}: {}", args.pid, e))?;
    let data = if args.no_render {
        None
    } else {
        Some(
            attachment
                .open_data_shm()
                .map_err(|e| anyhow!("open FreeBSD data SHM for pid {}: {}", args.pid, e))?
                .ok_or_else(|| {
                    anyhow!("FreeBSD conduit pid {} advertised no data SHM", args.pid)
                })?,
        )
    };
    let start_producers = data.as_ref().map(|data| {
        data.snapshot(attachment.data_wake_counter().unwrap_or(0))
            .per_cpu
            .iter()
            .map(|cpu| cpu.producer_pos)
            .collect::<Vec<_>>()
    });
    let (dof, expected_value, input_label) = load_freebsd_native_dof(args)?;
    let backend = NativeDtraceBackend::freebsd();
    let session = backend.build_session(NativeDtraceSessionRequest::run_dof_session(
        &dof,
        args.probe_id,
        expected_value,
        NATIVE_DTRACE_DEFAULT_LABEL,
    ))?;
    let payload = session.single_payload()?;
    // Generous timeout: the kernel side runs `dtrace_bifrost_run_dof`
    // synchronously — provider enumeration + match + sample window
    // + drain + publish all happen before the RSP is written.
    // 60 s is well above any sane sample window and exposes a real
    // hang as a hang rather than a timeout.
    let timeout = std::time::Duration::from_secs(60);
    let seq = attachment
        .push_cmd(payload.kind, &payload.body)
        .map_err(|e| anyhow!("push FreeBSD native-DTrace session request: {}", e))?;
    let rsp = attachment
        .poll_rsp(Some(seq), timeout)
        .map_err(|e| anyhow!("poll FreeBSD native-DTrace session response: {}", e))?;

    match rsp {
        Some((KIND_RSP_PAYLOAD, rsp_seq, body)) if rsp_seq == seq => {
            let (status, detail) = decode_load_prog_status(&body)
                .map_err(|e| anyhow!("decode FreeBSD native-DTrace session response: {}", e))?;
            if status == 0 {
                println!(
                    "freebsd-proof seq={} status=ok input={} detail={}",
                    seq,
                    input_label,
                    detail.as_deref().unwrap_or("")
                );
                if let (Some(data), Some(start_producers)) = (data.as_ref(), start_producers) {
                    let rendered = render_freebsd_native_records(
                        data,
                        &attachment,
                        &session.record_schemas,
                        start_producers,
                        args.records,
                        std::time::Duration::from_secs(3),
                    )?;
                    if rendered == 0 {
                        bail!("freebsd-proof rendered no native DTrace records from data SHM");
                    }
                }
                Ok(ExitCode::SUCCESS)
            } else {
                bail!(
                    "freebsd-proof seq={} status={} detail={}",
                    seq,
                    status,
                    detail.as_deref().unwrap_or("")
                );
            }
        }
        Some((kind, rsp_seq, _)) => {
            bail!(
                "freebsd-proof unexpected response kind={:#x} seq={} want seq={}",
                kind,
                rsp_seq,
                seq
            );
        }
        None => {
            bail!("freebsd-proof timed out after {:?}", timeout);
        }
    }
}

fn load_freebsd_native_dof(args: &FreebsdDtraceArgs) -> Result<(Vec<u8>, Option<u64>, String)> {
    use crate::backend::FREEBSD_DTRACE_PROOF_VALUE;

    let explicit_expected = args
        .expected
        .as_deref()
        .map(|s| parse_u64_arg(s, "--expected"))
        .transpose()?;

    if let Some(path) = args.dof.as_deref() {
        let dof = fs::read(path).map_err(|e| anyhow!("read FreeBSD DOF {}: {}", path, e))?;
        return Ok((
            normalize_freebsd_dof(dof, path)?,
            explicit_expected,
            format!("dof:{}", path),
        ));
    }

    if let Some(path) = args.source_file.as_deref() {
        let source = fs::read_to_string(path)
            .map_err(|e| anyhow!("read FreeBSD D source {}: {}", path, e))?;
        return Ok((
            compile_freebsd_native_dof(&source, path)?,
            explicit_expected,
            format!("source:{}", path),
        ));
    }

    if let Some(script) = args.script.as_deref() {
        return Ok((
            compile_freebsd_native_dof(script, "inline source")?,
            explicit_expected,
            "source:inline".to_string(),
        ));
    }

    Ok((
        normalize_freebsd_dof(
            decode_hex_fixture(FREEBSD_PROOF_DOF_HEX, "FreeBSD proof DOF")?,
            "built-in FreeBSD proof DOF",
        )?,
        Some(explicit_expected.unwrap_or(FREEBSD_DTRACE_PROOF_VALUE)),
        "builtin-proof-dof".to_string(),
    ))
}

/// Public alias for the FreeBSD/Illumos native-DOF compile path.
/// The orchestrator's N>=2 dispatch builds per-target DOF via this
/// entry rather than reaching for the private helper directly.
pub fn compile_native_dof_public(source: &str, label: &str) -> Result<Vec<u8>> {
    compile_freebsd_native_dof(source, label)
}

fn compile_freebsd_native_dof(source: &str, label: &str) -> Result<Vec<u8>> {
    let mut hdl = crate::dtrace_ffi::DtraceHandle::open().map_err(|e| {
        anyhow!(
            "open libdtrace to compile FreeBSD D source {}: {}. \
             Use --dof with a precompiled FreeBSD-compatible DOF when running without DTrace privileges.",
            label,
            e
        )
    })?;
    let dof = hdl
        .compile_to_dof(source)
        .map_err(|e| anyhow!("compile FreeBSD D source {}: {}", label, e))?;
    normalize_freebsd_dof(dof, label)
}

fn normalize_freebsd_dof(mut dof: Vec<u8>, label: &str) -> Result<Vec<u8>> {
    if dof.len() < crate::DOF_HDR_SIZE {
        bail!("{label} is too short to be a DOF object");
    }
    if &dof[0..4] != crate::DOF_MAG_STRING {
        bail!("{label} has invalid DOF magic");
    }
    if dof[4] != 2 {
        bail!("{label} is not a 64-bit DOF object");
    }
    if dof[5] != 1 {
        bail!("{label} is not little-endian DOF");
    }
    if dof[6] == 0 {
        bail!("{label} has invalid DOF version 0");
    }
    if dof[6] > 2 {
        dof[6] = 2;
    }

    let loadsz = u64::from_le_bytes(dof[40..48].try_into().unwrap()) as usize;
    let filesz = u64::from_le_bytes(dof[48..56].try_into().unwrap()) as usize;
    if loadsz < crate::DOF_HDR_SIZE || loadsz > dof.len() {
        bail!("{label} has invalid DOF load size {}", loadsz);
    }
    let keep_len = if filesz >= loadsz && filesz <= dof.len() {
        filesz
    } else {
        loadsz
    };
    dof.truncate(keep_len);
    crate::Dof::parse(&dof).map_err(|e| anyhow!("{label} failed host DOF parse: {}", e))?;
    Ok(dof)
}

fn parse_u64_arg(s: &str, label: &str) -> Result<u64> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|e| anyhow!("parse {label}={s}: {}", e))
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|e| anyhow!("parse {label}={s}: {}", e))
    }
}

fn render_freebsd_native_records(
    data: &crate::control_shmem::DataShmAttachment,
    attachment: &crate::control_shmem::ControlShmAttachment,
    schemas: &[GuestRecordSchema],
    mut cursors: Vec<u64>,
    limit: usize,
    timeout: std::time::Duration,
) -> Result<usize> {
    let schema_by_probe = schemas
        .iter()
        .map(|schema| (schema.probe_id, schema))
        .collect::<HashMap<_, _>>();
    let deadline = std::time::Instant::now() + timeout;
    let mut rendered = 0usize;
    let mut idle_after_render = 0u8;
    let mut symbols = DirectSymbolState::default();

    while rendered < limit.max(1) {
        let snap = data.snapshot(attachment.data_wake_counter().unwrap_or(0));
        if cursors.len() < snap.per_cpu.len() {
            cursors.resize(snap.per_cpu.len(), 0);
        }

        let mut rendered_this_pass = 0usize;
        for cpu in 0..snap.per_cpu.len() {
            if rendered >= limit.max(1) {
                break;
            }
            let start = cursors[cpu];
            let end = snap.per_cpu[cpu].producer_pos;
            if start == end {
                continue;
            }
            let records = data.records_between_cpu(
                cpu as u32,
                start,
                end,
                limit.max(1).saturating_sub(rendered),
                &snap,
            );
            if let Some(last) = records.last() {
                let advance = (8 + last.header.size as usize + 7) & !7;
                cursors[cpu] = last.header.logical_pos.wrapping_add(advance as u64);
            }
            for rec in records {
                if (rec.header.flags & bifrost_wire::SHMEM_RECORD_FLAG_READY) == 0
                    || (rec.header.flags & bifrost_wire::SHMEM_RECORD_FLAG_PADDING) != 0
                {
                    continue;
                }
                let Some(probe_id) = rec.header.probe_id else {
                    continue;
                };
                let Some(schema) = schema_by_probe.get(&probe_id) else {
                    continue;
                };
                println!(
                    "{} {}",
                    schema.label,
                    render_direct_schema_record(&schema.schema, &rec.payload, &mut symbols)
                );
                rendered += 1;
                rendered_this_pass += 1;
            }
        }

        if rendered > 0 && rendered_this_pass == 0 {
            idle_after_render += 1;
            if idle_after_render >= 2 {
                break;
            }
        } else if rendered_this_pass > 0 {
            idle_after_render = 0;
        }

        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    Ok(rendered)
}

const FREEBSD_PROOF_DOF_HEX: &str = concat!(
    "7f444f460201020208080000000000000000000040000000200000000a0000004000000000000000",
    "06020000000000001307000000000000000000000000000008000000010000000100000000000000",
    "f8010000000000000e00000000000000040000000400000001000000180000008001000000000000",
    "18000000000000000700000004000000010000000400000098010000000000000800000000000000",
    "13000000080000000100000008000000a00100000000000008000000000000000800000001000000",
    "0100000000000000a801000000000000010000000000000006000000040000000100000000000000",
    "ac01000000000000140000000000000005000000080000000100000020000000c001000000000000",
    "200000000000000003000000080000000100000000000000e0010000000000001800000000000000",
    "0100000001000000000000000000000008020000000000000b000000000000001400000001000000",
    "00000000000000001302000000000000000500000000000000000000010000000000000000000000",
    "08000000000000000100002501000023434152544442534600000000000100000800000002000000",
    "030000000400000005000000ffffffff01000000000000000000000000000000e0240a8707000000",
    "01000000ffffffff060000000000000000000000000000000064747261636500424547494e00",
);

fn decode_hex_fixture(hex: &str, label: &str) -> Result<Vec<u8>> {
    let mut nibbles = Vec::with_capacity(hex.len());
    for byte in hex.bytes() {
        if byte.is_ascii_hexdigit() {
            nibbles.push(byte);
        } else if byte.is_ascii_whitespace() {
            continue;
        } else {
            bail!("{label} contains non-hex byte 0x{byte:02x}");
        }
    }
    if nibbles.len() % 2 != 0 {
        bail!("{label} has an odd number of hex digits");
    }

    let mut out = Vec::with_capacity(nibbles.len() / 2);
    for pair in nibbles.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| anyhow!("{label} has invalid hex digit"))?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| anyhow!("{label} has invalid hex digit"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn build_attach_ping_payload() -> Vec<u8> {
    const BPF_MOV64_IMM_R0_0: [u8; 8] = [0xb7, 0, 0, 0, 0, 0, 0, 0];
    const BPF_EXIT: [u8; 8] = [0x95, 0, 0, 0, 0, 0, 0, 0];

    let mut body = Vec::with_capacity(4 + 32 + 4 + 4 + 16 + 4);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut target = [0u8; 32];
    let name = b"sched_switch";
    target[..name.len()].copy_from_slice(name);
    body.extend_from_slice(&target);

    body.extend_from_slice(&(bifrost_wire::PROBE_TYPE_TRACEPOINT as u32).to_le_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(&BPF_MOV64_IMM_R0_0);
    body.extend_from_slice(&BPF_EXIT);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut payload = Vec::with_capacity(8 + body.len());
    payload.extend_from_slice(&crate::control_shmem::KIND_LOAD_PROG.to_le_bytes());
    payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
    payload.extend_from_slice(&body);
    payload
}

pub fn run_data(
    pid: u32,
    record_limit: usize,
    watch_ms: u64,
    interval_ms: u64,
) -> Result<ExitCode> {
    let attachment = crate::control_shmem::ControlShmAttachment::open(pid)
        .map_err(|e| anyhow!("attach to pid {}: {}", pid, e))?;
    let Some(data) = attachment
        .open_data_shm()
        .map_err(|e| anyhow!("open data SHM for pid {}: {}", pid, e))?
    else {
        println!("bifrost data pid={}: no DATA_SHM advertised", pid);
        return Ok(ExitCode::from(2));
    };
    let deadline = if watch_ms == 0 {
        None
    } else {
        Some(std::time::Instant::now() + std::time::Duration::from_millis(watch_ms))
    };
    let interval = std::time::Duration::from_millis(interval_ms.max(1));
    let mut sample_idx = 0u64;
    let mut prev_producer = None;
    loop {
        let snap = data.snapshot(attachment.data_wake_counter().unwrap_or(0));
        if sample_idx == 0 {
            println!("bifrost data pid={} shm={}", pid, snap.name);
            println!(
                "  header  size={} magic=0x{:08x} version={}",
                snap.size, snap.magic, snap.version
            );
            println!(
                "  meta    btf={}@{:#x} ksyms={}@{:#x}",
                snap.btf_len, snap.btf_off, snap.ksyms_len, snap.ksyms_off
            );
        }
        println!(
            "  ring    sample={} off={:#x} len={} producer={} consumer={} wakes={} pending={} bifrost_drops={} dropped_bytes={}",
            sample_idx,
            snap.ringbuf_off,
            snap.ringbuf_len,
            snap.producer_pos,
            snap.consumer_pos,
            snap.wake_counter,
            snap.producer_pos.saturating_sub(snap.consumer_pos),
            snap.dropped_records,
            snap.dropped_bytes
        );
        let records = if let Some(prev) = prev_producer {
            data.record_headers_between(prev, snap.producer_pos, record_limit)
        } else {
            data.record_headers(record_limit)
        };
        if records.is_empty() {
            if prev_producer.is_some() {
                println!("  records none observed since previous sample");
            } else {
                println!("  records none pending between consumer and producer");
            }
        } else {
            let label = if prev_producer.is_some() {
                "observed since previous sample"
            } else {
                "pending headers"
            };
            println!("  records {} (max {})", label, record_limit);
            for rec in records {
                let synopsis = match (rec.vmid, rec.probe_id, rec.gns, rec.word3) {
                    (Some(vmid), Some(probe_id), Some(gns), Some(word3)) => {
                        format!(
                            " vmid={} probe_id={} gns=0x{:x} word3=0x{:x}",
                            vmid, probe_id, gns, word3
                        )
                    }
                    _ => String::new(),
                };
                println!(
                    "    pos={} ring_off={:#x} size={} flags=0x{:x}{}",
                    rec.logical_pos, rec.ring_off, rec.size, rec.flags, synopsis
                );
            }
        }
        prev_producer = Some(snap.producer_pos);
        sample_idx += 1;
        match deadline {
            Some(deadline) if std::time::Instant::now() < deadline => std::thread::sleep(interval),
            Some(_) | None => break,
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Full attach-mode trace. Pushes the just-built wrapper into
/// the target libkrun's control SHM, attaches the in-process
/// libdtrace consumer to the target's pid, and runs the trace
/// loop until SIGINT. The target is already running whatever
/// it's doing — we observe.
pub fn run_attach_trace(
    target_pid: u32,
    programs: &[(
        String,
        RecordSchema,
        Vec<MapDecl>,
        Vec<u8>,
        u8,
        Option<crate::elf_syms::UprobeTarget>,
        Vec<(u32, String)>,
        Vec<crate::cli::wrapper::OwnedFieldReloc>,
        Option<u64>,
    )],
    parsed_source: &crate::parse::Parsed,
    xstack_fold_path: Option<String>,
    preserve: bool,
    btf_bytes: Option<&[u8]>,
    trace_self_level: Option<u8>,
    direct_data_render: bool,
) -> Result<()> {
    use crate::control_shmem::{
        ControlShmAttachment, KIND_AGG_PUSH, KIND_LOAD_PROG, KIND_RECORD_PUSH, KIND_RSP_OK,
        KIND_RSP_PAYLOAD, KIND_SELF_TRACE_PUSH, decode_load_prog_status,
    };

    // Self-trace emit (CLI side): direct-render helper for the
    // CLI's own state transitions.  Skips the shmem ring (no
    // need — we're the CLI, render directly to stderr).  When
    // --trace-self is off (`floor == None`), the closure is a
    // no-op so the wire codec isn't even invoked.
    let cli_self_trace =
        |level: u8,
         subsystem: u8,
         msg: &[u8],
         fields: &[(&[u8], bifrost_wire::codec::SelfFieldOwned<'_>)]| {
            if let Some(floor) = trace_self_level {
                if level < floor {
                    return;
                }
                let mut body = Vec::with_capacity(64);
                if bifrost_wire::codec::encode_event(&mut body, level, subsystem, msg, fields)
                    .is_err()
                {
                    return;
                }
                let mut payload = Vec::with_capacity(4 + body.len());
                payload.extend_from_slice(&bifrost_wire::SELF_TRACE_CLI_PROBE_ID.to_le_bytes());
                payload.extend_from_slice(&body);
                // Reuse the same render helper the shmem-side decoder
                // calls — single rendering format across all three
                // layers, defined once in render_self_trace below.
                render_self_trace_payload_to_stderr(&payload, floor);
            }
        };

    info!("attach-mode trace pid={}", target_pid);
    cli_self_trace(
        bifrost_wire::SELF_LEVEL_INFO,
        bifrost_wire::SELF_SUBSYS_OBSERVER,
        b"attach-mode trace start",
        &[(
            b"pid",
            bifrost_wire::codec::SelfFieldOwned::U64(target_pid as u64),
        )],
    );

    let attachment = Arc::new(
        ControlShmAttachment::open(target_pid)
            .map_err(|e| anyhow!("attach to pid {}: {}", target_pid, e))?,
    );
    info!(
        "control SHM ready: region={} bytes, cmd_ring={} bytes, rsp_ring={} bytes",
        attachment.header.region_size,
        attachment.header.cmd_ring_len,
        attachment.header.rsp_ring_len,
    );

    let timeout = std::time::Duration::from_secs(2);
    let _ = btf_bytes;
    // Preflight: refuse wrappers exceeding the driver's slot cap.
    // The driver allocates exactly MAX_PROBE_SLOTS per-slot
    // consumers + handlers; loading more silently drops the trailing
    // programs at LOAD_PROG time, producing a half-attached trace
    // where the per-fire stream looks correct but agg outputs are
    // empty for the dropped probes.  Better to fail loudly here.
    if programs.len() > bifrost_wire::MAX_PROBE_SLOTS {
        bail!(
            "bifrost: {} programs exceeds the driver's MAX_KPROBES={} \
             cap (each D clause expands to one program per action; \
             multi-action clauses fan out).  Reduce the number of \
             clauses, fold actions into a single clause, or bump \
             MAX_KPROBES in drivers/bifrost/bifrost.rs (and add \
             matching slot N consumers + handlers).",
            programs.len(),
            bifrost_wire::MAX_PROBE_SLOTS,
        );
    }
    let _requested_direct_data_render = direct_data_render;
    let direct_data_render = true;
    // The guest publishes BTF metadata into data-SHM for the
    // post-rebuild adapter to consume directly; the host no longer
    // needs to apply field relocations to pre-lowered eBPF here.
    let _direct_load_btf = attachment
        .open_data_shm()
        .map_err(|e| anyhow!("open data SHM for DTRACE_SESSION_V1 emission: {}", e))?
        .and_then(|data| {
            let snap = data.snapshot(0);
            data.read_region_bytes(snap.btf_off, snap.btf_len)
        });
    // Re-render the parsed bifrost-routed source as a single D
    // script and compile it to DOF via libdtrace. The guest decodes
    // the DOF against bifrost-dtrace-lower and drives its own
    // adapter; the host ships no OS-specific bytecode.
    let mut bifrost_source = String::new();
    for clause in parsed_source.bifrost_clauses() {
        bifrost_source.push_str(&clause.source);
        bifrost_source.push('\n');
    }
    if bifrost_source.trim().is_empty() {
        bail!("bifrost: no bifrost-routed clauses to ship — refusing empty session");
    }
    let dof_bytes = {
        use crate::dtrace_ffi::DtraceHandle;
        let mut hdl = DtraceHandle::open()
            .map_err(|e| anyhow!("open libdtrace for session emission: {}", e))?;
        hdl.compile_to_dof(&bifrost_source)
            .map_err(|e| anyhow!("compile bifrost-routed source to DOF: {}", e))?
    };
    let direct_load = build_direct_load_progs(programs, &dof_bytes)?;
    for (i, &st) in direct_load.statuses.iter().enumerate() {
        if st != bifrost_wire::RSP_LOADPROG_STATUS_OK {
            eprintln!(
                "bifrost: program {}: {}",
                i,
                bifrost_wire::codec::loadprog_status_label(st),
            );
        }
    }
    if direct_load.payloads.is_empty() {
        bail!("bifrost: no LOAD_PROG payloads were buildable");
    }
    info!(
        "pushing {} opaque LOAD_PROG payload(s) through control SHM",
        direct_load.payloads.len(),
    );
    cli_self_trace(
        bifrost_wire::SELF_LEVEL_INFO,
        bifrost_wire::SELF_SUBSYS_LOADPROG,
        b"pushing opaque LOAD_PROG payloads through control SHM",
        &[(
            b"payload_count",
            bifrost_wire::codec::SelfFieldOwned::U64(direct_load.payloads.len() as u64),
        )],
    );
    for (i, payload) in direct_load.payloads.iter().enumerate() {
        let load_seq = attachment
            .push_cmd(KIND_LOAD_PROG, payload)
            .map_err(|e| anyhow!("push DTRACE_SESSION {}: {}", i, e))?;
        match attachment
            .poll_rsp(Some(load_seq), timeout)
            .map_err(|e| anyhow!("poll rsp for DTRACE_SESSION {}: {}", i, e))?
        {
            Some((KIND_RSP_PAYLOAD, _, payload)) => match decode_load_prog_status(&payload) {
                Ok((0, _)) => {}
                Ok((status, detail)) => bail!(
                    "DTRACE_SESSION {} failed: status={} detail={}",
                    i,
                    status,
                    detail.as_deref().unwrap_or("")
                ),
                Err(err) => bail!(
                    "DTRACE_SESSION {} failed: malformed response body: {}",
                    i, err
                ),
            },
            Some((KIND_RSP_OK, _, _)) => {}
            Some((kind, _, payload)) => {
                bail!(
                    "LOAD_PROG {} failed: kind={:#x} msg={}",
                    i,
                    kind,
                    String::from_utf8_lossy(&payload)
                );
            }
            None => bail!("DTRACE_SESSION {} timed out", i),
        }
    }
    info!("LOAD_PROG payloads acked; programs queued");
    cli_self_trace(
        bifrost_wire::SELF_LEVEL_INFO,
        bifrost_wire::SELF_SUBSYS_LOADPROG,
        b"LOAD_PROG payloads acked; programs queued",
        &[],
    );

    let mut host_d = parsed_source.host_script();
    let xstack_enabled = parsed_source
        .clauses
        .iter()
        .any(|c| c.is_bifrost() && extract_xstack_depth(&c.body).is_some());
    if xstack_enabled {
        let depth: u32 = parsed_source
            .clauses
            .iter()
            .filter(|c| c.is_bifrost())
            .filter_map(|c| extract_xstack_depth(&c.body))
            .max()
            .unwrap_or(8);
        host_d.push_str(&format!(
            "\n\n\
             pid$target:libkrun*:bifrost_xstack_dispatch:entry\n\
             {{\n    \
                 bifrost_xseq[arg4] = arg0;\n    \
                 bifrost_xprobe[arg4] = copyinstr(arg1);\n    \
                 bifrost_xgpid[arg4] = arg3;\n\
             }}\n\
             \n\
             pid$target:Hypervisor:hv_vcpu_run:return\n\
             /bifrost_xseq[tid] != 0/\n\
             {{\n    \
                 printf(\"##xstack-pending##|%lld|%s|0x%llx|%lld\\n\", \
                        (long long)bifrost_xseq[tid], \
                        bifrost_xprobe[tid], \
                        (unsigned long long)bifrost_xgpid[tid], \
                        (long long)tid);\n    \
                 printf(\"##xstack-host##|%lld\\n\", (long long)tid);\n    \
                 ustack({});\n    \
                 printf(\"##xstack-end##|%lld\\n\", (long long)tid);\n    \
                 bifrost_xseq[tid] = 0;\n\
             }}\n",
            depth
        ));
    }
    host_d.push_str(
        "\n\n\
         pid$target:libkrun*:bifrost_event_received:entry\n\
         {\n    \
             printf(\"%s %s\\n\", copyinstr(arg0), copyinstr(arg4));\n\
         }\n",
    );
    if host_d.trim().is_empty() {
        host_d.push_str("dtrace:::BEGIN { }\n");
    }
    info!(
        "auto-injected host D ({} bytes); attaching libdtrace in-process to pid={}",
        host_d.len(),
        target_pid
    );

    let stop = Arc::new(AtomicBool::new(false));
    ctrlc_install_flag(stop.clone());
    let xstack_state = Arc::new(std::sync::Mutex::new(XstackState {
        fold_out: xstack_fold_path,
        ..Default::default()
    }));
    let xagg_state: Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), CrossAggValue>>,
    > = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let stop_for_thread = stop.clone();
    let xagg_for_thread = Some(xagg_state.clone());
    let xagg_state_for_dump = xagg_state.clone();
    let xstack_for_thread = if xstack_enabled {
        Some(xstack_state.clone())
    } else {
        None
    };
    let labels_attach: &'static Vec<String> = {
        let labels: Vec<String> = programs
            .iter()
            .map(|(target, _, _, _, probe_type, uprobe, _, _, _)| {
                let pt = match *probe_type {
                    0 | 2 | 4 => "entry",
                    1 | 3 | 5 => "return",
                    9 => "fire",
                    _ => "entry",
                };
                let module = match (*probe_type, uprobe) {
                    (2 | 3, Some(u)) => {
                        format!("guest_user:{}", u.guest_path.trim_start_matches('/'))
                    }
                    (4 | 5, Some(u)) | (9, Some(u)) => {
                        format!("guest_user:{}", u.basename)
                    }
                    _ => "guest_kernel".to_string(),
                };
                format!("{}:{}:{}", module, target, pt)
            })
            .collect();
        Box::leak(Box::new(labels))
    };
    let direct_data_join = if direct_data_render {
        let data = attachment
            .open_data_shm()
            .map_err(|e| anyhow!("open direct data SHM: {}", e))?;
        match data {
            Some(data) => Some({
                let snap = data.snapshot(0);
                let ksyms = data
                    .read_region_bytes(snap.ksyms_off, snap.ksyms_len)
                    .map(|bytes| parse_kallsyms_blob(&bytes))
                    .unwrap_or_default();
                let stop = stop.clone();
                let labels = labels_attach.clone();
                let xagg_state = xagg_state_for_dump.clone();
                let agg_names = direct_agg_names(programs);
                let attachment_for_render = attachment.clone();
                let mut schemas: Vec<Option<RecordSchema>> = vec![None; programs.len() + 1];
                for (i, (_, schema, _, _, _, _, _, _, _)) in programs.iter().enumerate() {
                    schemas[i + 1] = Some(schema.clone());
                }
                std::thread::spawn(move || {
                    info!("direct data-SHM renderer enabled");
                    let mut agg_last: HashMap<(i32, u64), u64> = HashMap::new();
                    let mut symbols = DirectSymbolState {
                        ksyms,
                        ..Default::default()
                    };
                    let mut snap = data.snapshot(0);
                    // Per-CPU principal buffer.  Track
                    // `last_producer` per sub-ring so we don't
                    // re-walk records already drained.  Initial
                    // values are the producer cursors at attach
                    // time — we skip whatever was in the ring
                    // before the trace started.
                    let mut last_producer_pcpu: Vec<u64> =
                        snap.per_cpu.iter().map(|s| s.producer_pos).collect();
                    let mut last_dropped_records = snap.dropped_records;
                    let mut last_dropped_bytes = snap.dropped_bytes;
                    let mut last_wake_counter =
                        attachment_for_render.data_wake_counter().unwrap_or(0);
                    // Wake-aware tight-poll cadence. Both the
                    // baseline and the fast path land at 250 µs:
                    // each iteration the renderer atomically loads
                    // `data_wake_counter` (published by the conduit
                    // doorbell worker on every guest kick) and the
                    // ringbuf `producer_pos`. Either changing
                    // triggers an immediate drain on the same cycle.
                    //
                    // macOS lacks `sem_timedwait`, so a true
                    // cross-process wake-driven Condvar would need
                    // SCM_RIGHTS-passed eventfd or a UNIX FIFO. At
                    // a 250 µs cycle the polling cadence is below
                    // the per-record decode cost of `gustack` / agg
                    // snapshot on Apple Silicon, so the practical
                    // user-visible latency is bounded by the
                    // renderer's drain rate, not the wait. The
                    // ≤ 1 ms timeout-fallback contract is satisfied
                    // with significant headroom.
                    //
                    // Drops/wake-counter/producer movement still
                    // route through the same fast path (no change
                    // in effective cadence today, but the branch is
                    // preserved so future per-CPU-buffer work can
                    // route different ring states distinctly).
                    const SLEEP_FAST_NS: u64 = 250_000; // 250 µs
                    const SLEEP_SLOW_NS: u64 = 250_000; // 250 µs (was 1 ms baseline)
                    let mut sleep_ns: u64 = SLEEP_SLOW_NS;
                    // Open the conduit-published wake FIFO
                    // read-only with O_NONBLOCK. The conduit-side
                    // `ControlShmView::poke_wake_fifo` writes one
                    // byte on every wake increment; bifrost polls
                    // the fd alongside the 250 µs cadence so a
                    // burst of records lands in the renderer's
                    // next iteration without waiting the full
                    // cycle. If the FIFO is unavailable (older
                    // conduit, mkfifo race) fall back to plain
                    // sleep.
                    let wake_fifo_fd: i32 = {
                        let path = attachment_for_render.header.wake_fifo_path();
                        let c_path = match std::ffi::CString::new(path.clone()) {
                            Ok(p) => p,
                            Err(_) => std::ffi::CString::new("").unwrap(),
                        };
                        unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) }
                    };
                    while !stop.load(Ordering::SeqCst) {
                        if wake_fifo_fd >= 0 {
                            // Block for up to sleep_ns on either
                            // poll() readability or timeout. Bound
                            // to 1 ms to satisfy the
                            // "≤ 1 ms timeout fallback" contract.
                            let timeout_ms = ((sleep_ns / 1_000_000).max(1)) as libc::c_int;
                            let mut pfd = libc::pollfd {
                                fd: wake_fifo_fd,
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            unsafe {
                                libc::poll(&mut pfd as *mut _, 1, timeout_ms);
                            }
                            // Drain however many bytes accumulated;
                            // the byte content is not meaningful,
                            // only "something happened".
                            let mut buf = [0u8; 64];
                            unsafe {
                                while libc::read(
                                    wake_fifo_fd,
                                    buf.as_mut_ptr() as *mut _,
                                    buf.len(),
                                ) > 0
                                {}
                            }
                        } else {
                            std::thread::sleep(std::time::Duration::from_nanos(sleep_ns));
                        }
                        let wake_counter = attachment_for_render.data_wake_counter().unwrap_or(0);
                        let wake_advanced = wake_counter != last_wake_counter;
                        last_wake_counter = wake_counter;
                        snap = data.snapshot(wake_counter);

                        // Resize per-CPU tracking if the kernel
                        // chose a different num_cpus than we
                        // initially captured.
                        if last_producer_pcpu.len() != snap.per_cpu.len() {
                            last_producer_pcpu.resize(snap.per_cpu.len(), 0);
                        }

                        if snap.dropped_records != last_dropped_records
                            || snap.dropped_bytes != last_dropped_bytes
                        {
                            let r = &snap.dropped_records_by_class;
                            let b = &snap.dropped_bytes_by_class;
                            eprintln!(
                                "[bifrost] data SHM drops: records={} (+{}) bytes={} (+{}) \
by_class records=[principal={} agg={} stkstr={} dblerr={}] \
bytes=[principal={} agg={} stkstr={} dblerr={}]",
                                snap.dropped_records,
                                snap.dropped_records.saturating_sub(last_dropped_records),
                                snap.dropped_bytes,
                                snap.dropped_bytes.saturating_sub(last_dropped_bytes),
                                r[bifrost_wire::SHMEM_DROP_CLASS_PRINCIPAL as usize],
                                r[bifrost_wire::SHMEM_DROP_CLASS_AGG as usize],
                                r[bifrost_wire::SHMEM_DROP_CLASS_STKSTR as usize],
                                r[bifrost_wire::SHMEM_DROP_CLASS_DBLERR as usize],
                                b[bifrost_wire::SHMEM_DROP_CLASS_PRINCIPAL as usize],
                                b[bifrost_wire::SHMEM_DROP_CLASS_AGG as usize],
                                b[bifrost_wire::SHMEM_DROP_CLASS_STKSTR as usize],
                                b[bifrost_wire::SHMEM_DROP_CLASS_DBLERR as usize],
                            );
                            last_dropped_records = snap.dropped_records;
                            last_dropped_bytes = snap.dropped_bytes;
                            sleep_ns = SLEEP_FAST_NS;
                            for c in 0..4 {
                                SHMEM_DROPPED_RECORDS[c].store(r[c], Ordering::Relaxed);
                                SHMEM_DROPPED_BYTES[c].store(b[c], Ordering::Relaxed);
                            }
                        } else if wake_advanced {
                            sleep_ns = SLEEP_FAST_NS;
                        } else {
                            // Any per-CPU producer movement keeps us
                            // in the fast path; otherwise relax.
                            let any_moved = snap
                                .per_cpu
                                .iter()
                                .zip(last_producer_pcpu.iter())
                                .any(|(p, last)| p.producer_pos != *last);
                            if !any_moved {
                                sleep_ns = SLEEP_SLOW_NS;
                            }
                        }

                        // Drain every per-CPU sub-ring.
                        // Per-cycle drain limit is shared across
                        // sub-rings; with 16 CPUs the cap below
                        // (65536 / num_cpus) keeps a single
                        // long-tail CPU from starving siblings.
                        let num_cpus = snap.per_cpu.len();
                        if num_cpus == 0 {
                            continue;
                        }
                        let per_cpu_limit = (65536 / num_cpus).max(64);
                        let per_cpu_ring_len = snap.per_cpu_ring_len;
                        for cpu in 0..num_cpus {
                            let producer = snap.per_cpu[cpu].producer_pos;
                            let last_producer = last_producer_pcpu[cpu];
                            if producer == last_producer {
                                continue;
                            }
                            let records = data.records_between_cpu(
                                cpu as u32,
                                last_producer,
                                producer,
                                per_cpu_limit,
                                &snap,
                            );
                            let next_pos = if let Some(rec) = records.last() {
                                let advance = (8 + rec.header.size as usize + 7) & !7;
                                rec.header.logical_pos.wrapping_add(advance as u64)
                            } else if per_cpu_ring_len > 0
                                && producer.wrapping_sub(last_producer) >= per_cpu_ring_len
                            {
                                // Producer lapped this CPU's
                                // sub-ring by more than its
                                // length. Resync to half a
                                // sub-ring behind the producer so
                                // the next pass finds records
                                // whose bodies have been fully
                                // published; kernel-side
                                // `dropped_records` counter
                                // already accounts for the loss.
                                producer.wrapping_sub(per_cpu_ring_len / 2)
                            } else {
                                last_producer
                            };
                            last_producer_pcpu[cpu] = next_pos;
                            let _ = data.store_consumer_pos_cpu(&snap, cpu as u32, next_pos);
                            for rec in records {
                                if (rec.header.flags & bifrost_wire::SHMEM_RECORD_FLAG_READY) == 0
                                    || (rec.header.flags & bifrost_wire::SHMEM_RECORD_FLAG_PADDING)
                                        != 0
                                {
                                    continue;
                                }
                                if rec.header.probe_id == Some(bifrost_wire::VMA_TABLE_PROBE_ID) {
                                    symbols.ingest_vma_record(&rec.payload);
                                    continue;
                                }
                                if rec.header.probe_id == Some(bifrost_wire::SYM_TABLE_PROBE_ID) {
                                    symbols.ingest_sym_record(&rec.payload);
                                    continue;
                                }
                                if rec.header.probe_id == Some(bifrost_wire::AGG_SNAPSHOT_PROBE_ID)
                                {
                                    if ingest_direct_agg_snapshot(
                                        &rec.payload,
                                        &agg_names,
                                        &mut agg_last,
                                        &xagg_state,
                                    ) {
                                        dump_xagg_state(&xagg_state);
                                    }
                                    continue;
                                }
                                let Some(probe_id) = rec.header.probe_id.map(|id| id as usize)
                                else {
                                    continue;
                                };
                                if probe_id == 0 {
                                    continue;
                                }
                                let Some(Some(schema)) = schemas.get(probe_id) else {
                                    continue;
                                };
                                let label = labels
                                    .get(probe_id - 1)
                                    .map(String::as_str)
                                    .unwrap_or("guest:event");
                                println!(
                                    "{} {}",
                                    label,
                                    render_direct_schema_record(schema, &rec.payload, &mut symbols)
                                );
                            }
                            // store_consumer_pos_cpu already fired
                            // above, paired with `last_producer_pcpu`
                            // update — storing `producer` here would
                            // let the kernel overwrite a busy record
                            // whose body hasn't landed.
                        }
                    }
                })
            }),
            None => {
                warn!("direct data-SHM renderer requested, but target advertises no data SHM");
                None
            }
        }
    } else {
        None
    };
    let pid_i32 = target_pid as i32;
    let consumer_join = std::thread::spawn(move || {
        let mut consumer = match crate::dtrace_consumer::Consumer::new(pid_i32, &host_d) {
            Ok(c) => c,
            Err(e) => {
                error!("in-process dtrace consumer init failed: {}", e);
                return;
            }
        };
        if let Err(e) = consumer.go() {
            error!("dtrace_go: {}", e);
            return;
        }
        let firing: &'static mut crate::dtrace_consumer::FiringState =
            Box::leak(Box::new(crate::dtrace_consumer::FiringState::default()));
        let firing_ptr: *mut crate::dtrace_consumer::FiringState = firing;
        let labels_ptr: *const Vec<String> = labels_attach;
        let mut rec_ctx = crate::dtrace_consumer::RecCbCtx {
            fp: consumer.sink_fp(),
            target_pid: pid_i32,
            firing: firing_ptr,
            labels: labels_ptr,
        };
        let arg = &mut rec_ctx as *mut _ as *mut std::ffi::c_void;
        let dispatch_line = |line: &str| {
            if line.is_empty() {
                return;
            }
            let consumed_agg = xagg_for_thread
                .as_ref()
                .map(|st| try_parse_xagg_line(line, st))
                .unwrap_or(false);
            let consumed_xs = !consumed_agg
                && xstack_for_thread
                    .as_ref()
                    .map(|st| try_parse_xstack_line(line, st))
                    .unwrap_or(false);
            if !consumed_agg && !consumed_xs {
                println!("{}", line);
            }
        };
        let mut last_status = std::time::Instant::now();
        let status_interval = std::time::Duration::from_millis(250);
        let mut last_dump = std::time::Instant::now();
        let dump_interval = std::time::Duration::from_secs(2);
        loop {
            if stop_for_thread.load(Ordering::SeqCst) {
                break;
            }
            // SAFETY: `arg` outlives this consumer thread.
            let st = unsafe {
                consumer.work_once(
                    crate::dtrace_consumer::probe_cb_assemble,
                    crate::dtrace_consumer::rec_cb_symbolicate,
                    arg,
                )
            };
            consumer.drain_sink(dispatch_line);
            if last_status.elapsed() >= status_interval {
                let _ = unsafe { crate::dtrace_ffi::dtrace_status(consumer.handle()) };
                last_status = std::time::Instant::now();
                if last_dump.elapsed() >= dump_interval {
                    crate::dtrace_consumer::print_drop_summary();
                    dump_xagg_state(&xagg_state_for_dump);
                    last_dump = std::time::Instant::now();
                }
            }
            match st {
                crate::dtrace_ffi::DTRACE_WORKSTATUS_OKAY => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                crate::dtrace_ffi::DTRACE_WORKSTATUS_DONE => break,
                _ => {
                    error!("dtrace_work failed; consumer exiting");
                    break;
                }
            }
        }
        // SAFETY: same as above.
        let _ = unsafe {
            consumer.work_once(
                crate::dtrace_consumer::probe_cb_accept,
                crate::dtrace_consumer::rec_cb_symbolicate,
                arg,
            )
        };
        consumer.drain_sink(dispatch_line);
        let _ = consumer.flush_aggs();
        consumer.drain_sink(dispatch_line);
        let _ = unsafe { crate::dtrace_ffi::dtrace_status(consumer.handle()) };
        crate::dtrace_consumer::print_drop_summary();
        print_shmem_drop_summary();
        info!("consumer thread shutting down; dumping xagg state");
        dump_xagg_state_force(&xagg_state_for_dump);
        info!("consumer thread shutdown complete");
    });

    let render_self_trace = |payload: &[u8], floor: u8| {
        render_self_trace_payload_to_stderr(payload, floor);
    };

    // and apply `f` to each line. Used for both KIND_AGG_PUSH and
    // KIND_RECORD_PUSH which share this wire format.
    let decode_lines = |payload: &[u8], mut f: Box<dyn FnMut(&str) + '_>| {
        if payload.len() < 4 {
            return;
        }
        let n = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut p = 4usize;
        for _ in 0..n {
            if p + 4 > payload.len() {
                break;
            }
            let len =
                u32::from_le_bytes([payload[p], payload[p + 1], payload[p + 2], payload[p + 3]])
                    as usize;
            p += 4;
            if p + len > payload.len() {
                break;
            }
            if let Ok(s) = std::str::from_utf8(&payload[p..p + len]) {
                f(s);
            }
            p += len;
        }
    };
    let drain_pass = |attachment: &ControlShmAttachment| -> bool {
        let drained = attachment.drain_rsp_ring();
        let mut got_agg_push = false;
        for (kind, _seq, payload) in drained {
            match kind {
                KIND_AGG_PUSH => {
                    if direct_data_render {
                        continue;
                    }
                    got_agg_push = true;
                    decode_lines(
                        &payload,
                        Box::new(|line| {
                            let _ = try_parse_xagg_line(line, &xagg_state);
                        }),
                    );
                }
                KIND_RECORD_PUSH => {
                    if direct_data_render {
                        continue;
                    }
                    decode_lines(
                        &payload,
                        Box::new(|line| {
                            if try_parse_xagg_line(line, &xagg_state) {
                                return;
                            }
                            println!("{}", line);
                        }),
                    );
                }
                KIND_SELF_TRACE_PUSH => {
                    // Self-trace emit: render structured self-trace
                    // events from libkrun (and, in a follow-up,
                    // the guest driver) when --trace-self is on.
                    // Body: [u32 layer_probe_id LE][encode_event].
                    if let Some(floor) = trace_self_level {
                        render_self_trace(&payload, floor);
                    }
                }
                _ => {}
            }
        }
        got_agg_push
    };
    while !stop.load(Ordering::SeqCst) {
        if drain_pass(&attachment) {
            dump_xagg_state(&xagg_state);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if drain_pass(&attachment) {
        dump_xagg_state(&xagg_state);
    }
    let _ = consumer_join.join();
    if let Some(join) = direct_data_join {
        let _ = join.join();
    }

    let _ = preserve;
    if drain_pass(&attachment) {
        dump_xagg_state(&xagg_state);
    }
    info!(
        "detached cleanly ({})",
        if preserve {
            "preserve queued programs"
        } else {
            "reap queued programs"
        }
    );

    dump_xstack_fold(&xstack_state);
    dump_xagg_state_force(&xagg_state);

    Ok(())
}

/// Install a SIGINT handler that flips the given AtomicBool to
/// `true`. The main loop in run_attach_trace polls the flag and
/// exits on the next tick. Idempotent (Once-gated install) — only
/// the first call wins; later attempts no-op so multiple
/// run_attach_trace calls in one bifrost run wouldn't deadlock.
pub fn ctrlc_install_flag(flag: Arc<AtomicBool>) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    static mut FLAG_PTR: *const AtomicBool = std::ptr::null();
    ONCE.call_once(|| unsafe {
        // SAFETY: write to FLAG_PTR happens exactly once before
        // any signal can fire (ONCE ensures), and we never read
        // it via a `&` reference — the trampoline dereferences
        // the raw pointer directly, sidestepping the
        // static_mut_refs lint.
        let leaked: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let _ = leaked;
        let raw: *const AtomicBool = Arc::into_raw(flag);
        FLAG_PTR = raw;

        extern "C" fn trampoline(_sig: std::ffi::c_int) {
            unsafe {
                let p = FLAG_PTR;
                if !p.is_null() {
                    (*p).store(true, Ordering::SeqCst);
                }
            }
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = trampoline as *const () as usize;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    });
}

/// `bifrost -l [pattern]` enumerates kprobes in the guest vmlinux
/// without booting anything. Output format mirrors `dtrace -l`
/// (header + space-aligned columns). Optional `pattern` filters
/// by substring match or `*`-glob; patterns containing `:` match
/// against the full probe spec instead of just the function name.
pub fn run_list(pattern: Option<&str>) -> Result<ExitCode> {
    use std::io::Read;
    let path = default_vmlinux();
    let canon = std::path::Path::new(&path);
    if !canon.exists() {
        bail!(
            "vmlinux not found at {}\n\
             fix: build smolvm (cd third_party/smolvm && cargo make build-libkrunfw)\n\
                  or set BIFROST_VMLINUX to an unstripped vmlinux ELF",
            path
        );
    }
    let mut f = std::fs::File::open(canon).map_err(|e| anyhow!("open {}: {}", path, e))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|e| anyhow!("read {}: {}", path, e))?;
    let symtab = crate::elf_syms::SymTab::from_bytes(&bytes)
        .map_err(|e| anyhow!("parse vmlinux symtab: {}", e))?;
    if symtab.is_empty() {
        bail!(
            "{} has no .symtab — likely a stripped image, can't enumerate kprobes",
            path
        );
    }

    println!(
        "{:>4}   {:<12} {:<14} {:>40} NAME",
        "ID", "PROVIDER", "MODULE", "FUNCTION"
    );
    let mut id = 0u32;
    for sym in symtab.iter() {
        if let Some(pat) = pattern {
            let probe_spec = format!("bifrost:guest_kernel:{}:entry", sym.name);
            let needle = pat.trim_start_matches('*').trim_end_matches('*');
            let target = if pat.contains(':') {
                probe_spec.as_str()
            } else {
                sym.name.as_str()
            };
            if !target.contains(needle) {
                continue;
            }
        }
        for variant in &["entry", "return"] {
            id += 1;
            println!(
                "{:>4}   {:<12} {:<14} {:>40} {}",
                id, "bifrost", "guest_kernel", sym.name, variant
            );
        }
    }
    if id == 0 {
        info!("-l: no probes matched pattern {:?}", pattern);
    }
    Ok(ExitCode::SUCCESS)
}
