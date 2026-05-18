// SPDX-License-Identifier: Apache-2.0
//! Multi-target orchestrator entry point.
//!
//! `bifrost orchestrate <plan.yaml>` is the successor to the
//! single-pid `attach`/`freebsd-proof` paths.  This module is the
//! CLI glue between [`plan::Plan`] / [`plan::route_clauses`] (pure
//! data) and the existing per-target backend dispatch (live).
//!
//! ## Status
//!
//! - **--dry-run**: parse plan + D source, resolve per-target clause
//!   routing, print the routing, exit 0.  This is the validation
//!   gate and works without any live VMs.
//! - **Non-dry-run, N=1**: dispatch to the existing `run_attach_trace`
//!   (Linux) or `run_freebsd_proof` (FreeBSD/Illumos) for the single
//!   target.  This is the "degenerate N=1 target" so the existing
//!   demos keep working under the new entry point.
//! - **Non-dry-run, N≥2**: the N≥2 transport plumbing — owning
//!   multiple `ControlShmAttachment`s and feeding the
//!   [`merge::MergedRing`] — drives the multi-target dispatch.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, anyhow, bail};

use crate::backend::GuestOs;
use crate::cli::args::{FreebsdDtraceArgs, OrchestrateArgs};
use crate::cli::runtime::{run_attach_trace, run_freebsd_proof};
use crate::parse;
use crate::plan::{ConduitEndpoint, LauncherSpec, Plan, RoutedPlan, RoutedTarget, route_clauses};

pub fn run_orchestrate(args: &OrchestrateArgs) -> Result<ExitCode> {
    let plan = Plan::load(Path::new(&args.plan_path))?;
    let script = resolve_d_source(&plan, args)?;
    let parsed = parse::parse(&script).map_err(|e| anyhow!("parse D source: {e}"))?;
    let routed = route_clauses(&plan, &parsed)?;

    print_routing(&routed);

    if args.dry_run {
        println!("orchestrate: --dry-run, no conduit touched");
        return Ok(ExitCode::SUCCESS);
    }

    match routed.per_target.len() {
        0 => bail!("plan has zero targets (validated earlier — this is a bug)"),
        1 => dispatch_single_target(&routed.per_target[0], &script),
        _ => dispatch_multi_target(&routed, &parsed),
    }
}

/// Multi-target dispatch: orchestrator owns N `ControlShmAttachment`s + N
/// `DataShmAttachment`s, sends per-target backend payloads, and
/// drains every ring into a single [`merge::MergedRing`].
///
/// Per-target dispatch:
///
/// - `GuestOs::Linux` targets route through
///   [`crate::cli::linux_compile::compile_linux_programs`] to lower
///   their share of the routed D source to a BFR7 wrapper +
///   per-program LOAD_PROG payloads, then push those payloads
///   through the target's control SHM cmd ring.
/// - `GuestOs::FreeBsd` / `GuestOs::Illumos` targets compile via
///   libdtrace and ship one consolidated FreeBSD native-DTrace
///   session payload through the same cmd ring.
///
/// Both paths feed records into the shared MergedRing through the
/// same per-CPU data SHM drain loop.
fn dispatch_multi_target(
    routed: &RoutedPlan<'_>,
    parsed: &parse::Parsed,
) -> Result<ExitCode> {
    use std::time::Duration;

    use crate::control_shmem::ControlShmAttachment;
    use crate::merge::MergedRing;

    for rt in &routed.per_target {
        // macos-host targets carry `conduit: None` by construction
        // (validated in Plan::validate); they're driven through the
        // dtrace(1) text path, not the SHM conduit.
        if rt.target.guest_os == GuestOs::MacosHost {
            continue;
        }
        match rt.target.conduit.as_ref() {
            Some(ConduitEndpoint::Pid(_)) => {}
            Some(_) => bail!(
                "orchestrate N>=2: target `{}` uses a non-pid conduit endpoint; \
                 socket/data_shm endpoints are not yet supported here",
                rt.target.id,
            ),
            None => bail!(
                "orchestrate N>=2: target `{}` missing conduit endpoint",
                rt.target.id,
            ),
        }
    }

    // Spawn any non-Attach launcher up front so we know each
    // target's conduit-backend pid before we try to open its
    // control SHM.  Spawned launchers are tracked here so RAII drops
    // SIGTERM them at end-of-session.  macos-host targets follow a
    // separate spawn path below.
    let project_root = crate::cli::args::find_project_root()
        .ok_or_else(|| anyhow!("cannot resolve BIFROST project root for launcher dispatch"))?;
    let mut spawned: Vec<Option<crate::cli::launcher::SpawnedLauncher>> =
        (0..routed.per_target.len()).map(|_| None).collect();
    for (idx, rt) in routed.per_target.iter().enumerate() {
        if matches!(
            rt.target.launcher,
            LauncherSpec::Attach | LauncherSpec::MacosHostDtrace { .. }
        ) {
            continue;
        }
        let launched = crate::cli::launcher::spawn_target(rt.target, &project_root)?;
        spawned[idx] = Some(launched);
    }

    // Spawn one dtrace(1) child per macos-host target.  Each child
    // gets its own routed per-target source assembled from the
    // clauses route_clauses dispatched here.  The session owns a
    // reader thread that decodes per-fire trace() values + agg
    // snapshot rows on the fly.
    let mut macos_sessions: Vec<Option<crate::cli::macos_host::MacosHostSession>> =
        (0..routed.per_target.len()).map(|_| None).collect();
    for (idx, rt) in routed.per_target.iter().enumerate() {
        if rt.target.guest_os != GuestOs::MacosHost {
            continue;
        }
        let extra_args = match &rt.target.launcher {
            LauncherSpec::MacosHostDtrace { extra_args } => extra_args.clone(),
            _ => Vec::new(),
        };
        let session = crate::cli::macos_host::spawn_macos_host_session(rt, &extra_args)?;
        macos_sessions[idx] = Some(session);
        println!(
            "orchestrate: target `{}` accepted macos-host dtrace session",
            rt.target.id,
        );
    }

    // Open every target's control + data SHM up front.  Any failure
    // aborts the whole plan before we send anything, so partial
    // sessions don't leak.
    let mut targets: Vec<MultiTargetSession> = Vec::with_capacity(routed.per_target.len());
    let target_ids: Vec<String> = routed
        .per_target
        .iter()
        .map(|rt| rt.target.id.clone())
        .collect();
    let mut merger = MergedRing::with_default_lookback(target_ids.iter().cloned());

    for (idx, rt) in routed.per_target.iter().enumerate() {
        if rt.target.guest_os == GuestOs::MacosHost {
            // macos-host: no SHM session; the dtrace child + reader
            // thread already drive this target's contribution.
            continue;
        }
        let pid = match (rt.target.conduit.as_ref(), spawned[idx].as_ref()) {
            // A non-Attach launcher just supplied the real pid; it
            // overrides whatever placeholder the plan held (e.g.
            // `pid: 0`).
            (_, Some(s)) => s.backend_pid,
            (Some(ConduitEndpoint::Pid(pid)), None) => *pid,
            _ => unreachable!("guarded above"),
        };
        let control = ControlShmAttachment::open(pid)
            .map_err(|e| anyhow!("attach target `{}` (pid={pid}): {e}", rt.target.id))?;
        let data = control
            .open_data_shm()
            .map_err(|e| anyhow!("open data SHM for target `{}`: {e}", rt.target.id))?
            .ok_or_else(|| anyhow!("target `{}` advertised no data SHM", rt.target.id))?;
        let start_producers: Vec<u64> = data
            .snapshot(control.data_wake_counter().unwrap_or(0))
            .per_cpu
            .iter()
            .map(|cpu| cpu.producer_pos)
            .collect();
        targets.push(MultiTargetSession {
            id: rt.target.id.clone(),
            control,
            data,
            start_producers,
            agg_names: std::collections::HashMap::new(),
            alive: true,
        });
    }

    // Compile per-target session payload(s).  Per guest_os:
    //
    //   - FreeBSD / Illumos: one libdtrace-compiled native-DTrace
    //     session payload pushed via `KIND_LOAD_PROG`.
    //   - Linux: N BFR7-wrapped opaque LOAD_PROG payloads (one per
    //     lowered eBPF program).  We push each one and check its
    //     accept status independently so we get a per-program error
    //     if a probe fails to attach.
    // The FreeBSD wrapper handles RUN_DOF synchronously: it parses the
    // DOF, allocates state, sleeps for `duration_ms` inside
    // `dtrace_state_go`, drains, publishes records, then writes
    // RSP_LOADPROG_STATUS_OK back through the conduit.  The host's
    // ack timeout therefore has to cover the full sampling window plus
    // setup/teardown overhead — a fixed 5 s was fine when the kernel
    // always used the 500 ms default but starves any plan that asks
    // for a longer window via `duration_ms`.  Linux's path stays at
    // the 5 s floor since the response is synchronous after attach.
    let timeout = Duration::from_secs(5);
    // Targets vector is indexed in the same order as
    // routed.per_target *for non-macos-host entries*.  Map plan-index
    // → targets-vec-index so the agg-name attachment loop below knows
    // which targets-vec slot to write into.
    let mut plan_to_targets_idx: Vec<Option<usize>> = vec![None; routed.per_target.len()];
    {
        let mut next = 0usize;
        for (i, rt) in routed.per_target.iter().enumerate() {
            if rt.target.guest_os == GuestOs::MacosHost {
                continue;
            }
            plan_to_targets_idx[i] = Some(next);
            next += 1;
        }
    }
    for (idx, rt) in routed.per_target.iter().enumerate() {
        match rt.target.guest_os {
            GuestOs::MacosHost => {
                // Already handled above via spawn_macos_host_session;
                // no SHM payload to push.
                continue;
            }
            GuestOs::FreeBsd | GuestOs::Illumos => {
                let session = build_native_session(rt)?;
                let payload = session.single_payload()?;
                let target_ms = rt.target.duration_ms.unwrap_or(0);
                // Budget: base + duration_ms for the in-kernel pause,
                // plus a generous overhead allowance for state setup,
                // probe match, per-CPU drain, and AGG_SNAPSHOT publish.
                // The kernel-side cost grows roughly with CPU count and
                // agg shape, so the 10 s pad is comfortable for the
                // killer demos without making a stuck plan hang for
                // tens of seconds.
                let session_timeout = if target_ms == 0 {
                    timeout + Duration::from_secs(30)
                } else {
                    timeout
                        + Duration::from_millis(target_ms as u64)
                        + Duration::from_secs(30)
                };
                let t_idx = plan_to_targets_idx[idx]
                    .expect("non-macos-host target must have a targets-vec slot");
                push_and_check(
                    &targets[t_idx],
                    &rt.target.id,
                    "native-DTrace session",
                    payload.kind,
                    &payload.body,
                    session_timeout,
                )?;
                // FreeBSD agg-name map: libdtrace assigns aggids
                // 1..N in D-source declaration order.  Scan the
                // per-target source for `@<ident>` declarations
                // and build the aggid→(kind, name) map the host
                // reducer needs to label AGG_SNAPSHOT rows.  Kind
                // defaults to "count" today; future work can teach
                // the scanner to distinguish quantize/lquantize.
                targets[t_idx].agg_names = freebsd_agg_names_from_source(rt);
                println!(
                    "orchestrate: target `{}` accepted native-DTrace session",
                    rt.target.id,
                );
            }
            GuestOs::Linux => {
                let linux = build_linux_payloads(rt)?;
                if linux.payloads.is_empty() {
                    bail!(
                        "target `{}` (linux) produced no DTRACE_SESSION payload",
                        rt.target.id,
                    );
                }
                let t_idx = plan_to_targets_idx[idx]
                    .expect("non-macos-host target must have a targets-vec slot");
                // Stash the per-target fd→(kind, name) agg map so
                // the cross-target reducer can look up agg names by
                // the fake_fd the kernel echoes in AGG_SNAPSHOT
                // entries.
                targets[t_idx].agg_names =
                    crate::cli::trace_render::direct_agg_names(&linux.programs);
                for (i, body) in linux.payloads.iter().enumerate() {
                    let label = format!("DTRACE_SESSION[{}]", i);
                    push_and_check(
                        &targets[t_idx],
                        &rt.target.id,
                        &label,
                        crate::control_shmem::KIND_LOAD_PROG,
                        body,
                        timeout,
                    )?;
                }
                println!(
                    "orchestrate: target `{}` accepted {} Linux DTRACE_SESSION envelope(s)",
                    rt.target.id,
                    linux.payloads.len(),
                );
            }
        }
    }

    // BEGIN-clause printf banners render once before the drain
    // loop starts so any "session N starting" status lines the D
    // source writes land in the expected place in the output
    // stream.  Variable-bearing printf calls are skipped (those
    // need a libdtrace consumer to resolve).
    crate::cli::printa::render_begin_printf(parsed);

    // Drain each target's data SHM into the merger + cross-target
    // agg reducer.  Per-fire records land in the merger (host wall-
    // clock ordered); AGG_SNAPSHOT records (probe_id =
    // AGG_SNAPSHOT_PROBE_ID) feed the reducer instead so the END
    // dump can render one unified table over both kernels'
    // contributions to `@<name>[key]`.
    //
    // Failure isolation: each per-target snapshot is wrapped in
    // catch_unwind, and a target that fails to snapshot — VM died,
    // backend exited, SHM unmapped — is marked dead, logged, and
    // skipped in subsequent passes.  Surviving targets keep
    // draining their own rings.
    let drain_timeout = Duration::from_secs(3);
    let deadline = std::time::Instant::now() + drain_timeout;
    let mut cursors: Vec<Vec<u64>> = targets
        .iter()
        .map(|t| t.start_producers.clone())
        .collect();
    let mut total_rendered = 0usize;
    let mut reducer = crate::merge::CrossTargetAggReducer::new();

    // Round-robin batch size per (target, cpu) step.  Smaller than
    // the original 256 so a high-volume target with many CPUs
    // can't dominate a single pass — at this bound, even a 16-CPU
    // Linux target reads at most 16*64 = 1024 records per cycle
    // before yielding to siblings.  The outer loop's 25 ms cadence
    // keeps the overall throughput comfortably above record-pace
    // for the demos.
    const RR_BATCH: usize = 64;

    while std::time::Instant::now() < deadline {
        // 1. Snapshot every alive target's data SHM up front so the
        //    per-CPU walk below sees a consistent producer_pos
        //    across the round-robin step.  Snapshot failures here
        //    flip the target to dead instead of bailing.
        let snapshots: Vec<Option<crate::control_shmem::DataShmSnapshot>> = (0..targets.len())
            .map(|idx| {
                if !targets[idx].alive {
                    return None;
                }
                let t = &targets[idx];
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    t.data.snapshot(t.control.data_wake_counter().unwrap_or(0))
                })) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        eprintln!(
                            "[orchestrate] target `{}` data SHM unreachable mid-run; \
                             marking dead and continuing with surviving targets",
                            t.id,
                        );
                        targets[idx].alive = false;
                        None
                    }
                }
            })
            .collect();
        // Grow per-target cursors to match the live CPU count.
        for (idx, snap_opt) in snapshots.iter().enumerate() {
            if let Some(snap) = snap_opt
                && cursors[idx].len() < snap.per_cpu.len()
            {
                cursors[idx].resize(snap.per_cpu.len(), 0);
            }
        }
        let max_cpus = snapshots
            .iter()
            .filter_map(|s| s.as_ref().map(|snap| snap.per_cpu.len()))
            .max()
            .unwrap_or(0);

        // 2. Round-robin: outer loop on cpu, inner loop on target.
        //    For each cpu index, read at most RR_BATCH records from
        //    every alive target's matching sub-ring.  That gives
        //    every target equal fair access per micro-step instead
        //    of letting target 0's CPUs all drain before target 1
        //    is visited.
        let mut rendered_this_pass = 0usize;
        for cpu in 0..max_cpus {
            for idx in 0..targets.len() {
                let Some(snap) = snapshots[idx].as_ref() else {
                    continue;
                };
                if cpu >= snap.per_cpu.len() {
                    continue;
                }
                let t = &targets[idx];
                let start = cursors[idx][cpu];
                let end = snap.per_cpu[cpu].producer_pos;
                if start == end {
                    continue;
                }
                let records =
                    t.data
                        .records_between_cpu(cpu as u32, start, end, RR_BATCH, snap);
                if let Some(last) = records.last() {
                    let advance = (8 + last.header.size as usize + 7) & !7;
                    cursors[idx][cpu] = last.header.logical_pos.wrapping_add(advance as u64);
                }
                for rec in records {
                    if (rec.header.flags & bifrost_wire::SHMEM_RECORD_FLAG_READY) == 0
                        || (rec.header.flags & bifrost_wire::SHMEM_RECORD_FLAG_PADDING) != 0
                    {
                        continue;
                    }
                    if rec.header.probe_id == Some(bifrost_wire::AGG_SNAPSHOT_PROBE_ID) {
                        ingest_agg_snapshot(
                            &t.id,
                            &rec.payload,
                            &targets[idx].agg_names,
                            &mut reducer,
                        );
                        continue;
                    }
                    // Stamp the merge timestamp at host ingest time
                    // rather than passing the guest's `gns`.  Each
                    // guest VM has its own gns origin (billions apart
                    // in raw value), so gns-keyed merge would emit
                    // all of one target's records before any of the
                    // other's.  Host wall-clock at ingest gives true
                    // cross-target interleaving; within a target,
                    // ties on host_ns break on `logical_pos`
                    // (producer order) so per-target order is still
                    // preserved.  Push by id because the merger's
                    // source slots are indexed by plan position (so
                    // macos-host targets have their own slot), which
                    // differs from `idx` here (the targets-vec slot,
                    // which skips macos-host entries).
                    let _ = merger.push_by_id(
                        &t.id,
                        current_host_ns(),
                        rec.header.logical_pos,
                        rec.payload,
                    );
                    rendered_this_pass += 1;
                }
            }
        }
        // Drain macos-host events (each session's reader thread
        // pumps decoded per-fire records + agg updates into a
        // bounded queue; we move them into the merger / reducer
        // here under the same wall-clock cadence as the SHM ring
        // drain).
        for sess_opt in macos_sessions.iter_mut() {
            let Some(sess) = sess_opt.as_mut() else {
                continue;
            };
            let events = sess.drain_events();
            for ev in events {
                match ev {
                    crate::cli::macos_host::MacosHostEvent::PerFire { value } => {
                        rendered_this_pass += 1;
                        let payload = crate::cli::macos_host::synth_trace_payload(value);
                        let _ = merger.push_by_id(
                            sess.target_id(),
                            current_host_ns(),
                            0,
                            payload,
                        );
                    }
                    crate::cli::macos_host::MacosHostEvent::AggUpdate {
                        kind,
                        name,
                        key,
                        value,
                    } => {
                        reducer.merge(
                            sess.target_id(),
                            &name,
                            &key,
                            kind,
                            crate::merge::CrossTargetAggValue::Scalar(value),
                        );
                    }
                }
            }
        }
        total_rendered += rendered_this_pass;
        // Emit eligible records as they age out of the lookback.
        let now = current_host_ns();
        for r in merger.drain_eligible(now) {
            print_merged_record(&r);
        }
        if rendered_this_pass == 0 {
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    // Stop every macos-host dtrace child so it prints its final
    // aggregation table, then drain any straggling events into the
    // merger / reducer.  The reader thread completes when dtrace
    // closes its stdout.
    for sess_opt in macos_sessions.iter_mut() {
        if let Some(sess) = sess_opt.as_mut() {
            sess.terminate_and_join();
            for ev in sess.drain_events() {
                match ev {
                    crate::cli::macos_host::MacosHostEvent::PerFire { value } => {
                        let payload = crate::cli::macos_host::synth_trace_payload(value);
                        let _ = merger.push_by_id(
                            sess.target_id(),
                            current_host_ns(),
                            0,
                            payload,
                        );
                    }
                    crate::cli::macos_host::MacosHostEvent::AggUpdate {
                        kind,
                        name,
                        key,
                        value,
                    } => {
                        reducer.merge(
                            sess.target_id(),
                            &name,
                            &key,
                            kind,
                            crate::merge::CrossTargetAggValue::Scalar(value),
                        );
                    }
                }
            }
        }
    }

    // Final reconciliation: flush every buffered record.
    let final_batch = merger.drain_all();
    for r in &final_batch {
        print_merged_record(r);
    }

    // Cross-target aggregation table.  Empty on demos that don't
    // use `@<name>`; on the killer demos this is where the
    // `@rx["linux"] = N, @rx["freebsd"] = M` rows render side by
    // side without needing a host libdtrace consumer.
    //
    // Two-tier rendering:
    //   1. `render_end_printa` walks every END clause in the
    //      parsed source, finds `printa("format", @agg)` calls,
    //      and renders each agg row against the user's format
    //      string (so `printa("%-10s %@d\n", @rx)` lands exactly
    //      as the D source wrote it).
    //   2. Aggregations the user didn't name in any printa fall
    //      through to the reducer's generic `xagg @<name>[key] =
    //      …` dump so they're not silently lost.
    if !reducer.is_empty() {
        println!("orchestrate: cross-target aggregations");
        crate::cli::printa::render_end_printa(&parsed, &reducer);
    }

    let dead: Vec<&str> = targets
        .iter()
        .filter(|t| !t.alive)
        .map(|t| t.id.as_str())
        .collect();
    if !dead.is_empty() {
        println!(
            "orchestrate: {} target(s) died mid-run: {}",
            dead.len(),
            dead.join(", "),
        );
    }
    println!(
        "orchestrate: drained {} records across {} target(s) ({} flushed at session end)",
        total_rendered,
        targets.len(),
        final_batch.len(),
    );
    Ok(ExitCode::SUCCESS)
}

struct MultiTargetSession {
    id: String,
    control: crate::control_shmem::ControlShmAttachment,
    data: crate::control_shmem::DataShmAttachment,
    start_producers: Vec<u64>,
    /// fd→(kind, name) lookup the cross-target agg reducer uses to
    /// resolve AGG_SNAPSHOT entries from this target's data SHM.
    /// Empty for non-Linux targets today (FreeBSD's aggregations
    /// live entirely guest-side under dtrace.ko and don't surface
    /// as AGG_SNAPSHOT records).
    agg_names: std::collections::HashMap<i32, (String, String)>,
    /// Flips to false when the drain loop sees the target's data
    /// SHM go away mid-run — the orchestrator then skips it in
    /// subsequent drain passes instead of bailing the whole
    /// session.
    alive: bool,
}

fn build_native_session(
    rt: &RoutedTarget<'_>,
) -> Result<crate::backend::GuestBackendSession> {
    use crate::backend::{
        GuestBackend, NATIVE_DTRACE_DEFAULT_LABEL, NativeDtraceBackend,
        NativeDtraceSessionRequest,
    };
    // Per-target D source: concatenate every routed clause's source
    // span so each target's libdtrace compile only sees probes it
    // can attach.  The routed clauses already have their probe
    // tuples constrained by route_clauses.
    let mut per_target_source = String::new();
    for rc in &rt.clauses {
        per_target_source.push_str(&rc.clause.source);
        per_target_source.push('\n');
    }
    if per_target_source.trim().is_empty() {
        bail!("target `{}` has no clauses to send", rt.target.id);
    }
    let dof = crate::cli::runtime::compile_native_dof_public(&per_target_source, &rt.target.id)?;
    let backend = NativeDtraceBackend::for_guest(rt.target.guest_os)?;
    let request = NativeDtraceSessionRequest::run_dof_session(
        &dof,
        2, // default probe-id base; refined when richer schema arrives
        None,
        NATIVE_DTRACE_DEFAULT_LABEL,
    )
    .with_duration_ms(rt.target.duration_ms.unwrap_or(0));
    let session = backend.build_session(request)?;
    Ok(session)
}

/// Send one control-SHM payload to a target and verify its response.
/// Used by the Linux LOAD_PROG loop and the FreeBSD native-DTrace
/// session push so both paths surface attach failures the same way.
fn push_and_check(
    session: &MultiTargetSession,
    target_id: &str,
    label: &str,
    kind: u32,
    body: &[u8],
    timeout: std::time::Duration,
) -> Result<()> {
    use crate::control_shmem::{KIND_RSP_OK, KIND_RSP_PAYLOAD, decode_load_prog_status};
    let seq = session
        .control
        .push_cmd(kind, body)
        .map_err(|e| anyhow!("push {label} for target `{target_id}`: {e}"))?;
    let rsp = session
        .control
        .poll_rsp(Some(seq), timeout)
        .map_err(|e| anyhow!("poll {label} response for target `{target_id}`: {e}"))?;
    match rsp {
        Some((KIND_RSP_PAYLOAD, rsp_seq, payload)) if rsp_seq == seq => {
            let (status, detail) = decode_load_prog_status(&payload)
                .map_err(|e| anyhow!("decode {label} response for target `{target_id}`: {e}"))?;
            if status != 0 {
                bail!(
                    "target `{target_id}` rejected {label}: status={status} detail={}",
                    detail.as_deref().unwrap_or(""),
                );
            }
            Ok(())
        }
        Some((KIND_RSP_OK, rsp_seq, _)) if rsp_seq == seq => Ok(()),
        Some((kind, rsp_seq, _)) => bail!(
            "target `{target_id}` unexpected {label} response kind={kind:#x} seq={rsp_seq} want seq={seq}",
        ),
        None => bail!("target `{target_id}` {label} response timed out after {timeout:?}"),
    }
}

struct LinuxBuildResult {
    payloads: Vec<Vec<u8>>,
    programs: Vec<crate::cli::linux_compile::LoweredProgram>,
}

/// Build the FreeBSD per-target aggid→(kind, name) map by walking
/// the per-target D source through the comment- and string-aware
/// scanner in [`crate::cli::agg_decl`].  libdtrace assigns aggids
/// 1..N in the order it first sees each `@<ident>` declaration, so
/// the host derives the same mapping for the kernel-emitted
/// AGG_SNAPSHOT rows (which stamp aggid into the wire-level `fd`
/// slot).
fn freebsd_agg_names_from_source(
    rt: &RoutedTarget<'_>,
) -> std::collections::HashMap<i32, (String, String)> {
    use crate::cli::agg_decl::{agg_id_map, discover_aggs, AggDecl};
    let mut combined: Vec<AggDecl> = Vec::new();
    for rc in &rt.clauses {
        for d in discover_aggs(&rc.clause.body) {
            if combined.iter().any(|x| x.name == d.name) {
                continue;
            }
            combined.push(AggDecl {
                aggid: (combined.len() as i32) + 1,
                ..d
            });
        }
    }
    agg_id_map(&combined)
}

/// Compile one routed Linux target's clauses into a list of opaque
/// LOAD_PROG payload bodies the conduit can ship verbatim. Returns
/// the compiled programs alongside the payloads so the orchestrator
/// can derive the fd→agg-name map for the cross-target reducer.
fn build_linux_payloads(rt: &RoutedTarget<'_>) -> Result<LinuxBuildResult> {
    use crate::cli::direct_load::build_direct_load_progs;
    use crate::cli::linux_compile::{LinuxCompileOpts, compile_linux_programs};

    // Per-target D source: concatenate every routed clause so the
    // Linux compile only sees probes it can attach. Same shape as
    // build_native_session for FreeBSD.
    let mut per_target_source = String::new();
    for rc in &rt.clauses {
        per_target_source.push_str(&rc.clause.source);
        per_target_source.push('\n');
    }
    if per_target_source.trim().is_empty() {
        bail!("target `{}` has no clauses to send", rt.target.id);
    }

    let opts = LinuxCompileOpts::default();
    // The Linux compile is retained as the agg-name / fd / program
    // metadata source — the host's cross-target reducer indexes on
    // it. The eBPF bytecode it produces is no longer shipped
    // anywhere; the guest does its own lowering against the DOF.
    let compiled = compile_linux_programs(&per_target_source, &opts)
        .map_err(|e| anyhow!("compile linux target `{}`: {e}", rt.target.id))?;
    let dof = compile_per_target_dof(&per_target_source, &rt.target.id)?;
    let direct = build_direct_load_progs(&compiled.programs, &dof)
        .map_err(|e| anyhow!("build DTRACE_SESSION_V1 envelope for `{}`: {e}", rt.target.id))?;
    Ok(LinuxBuildResult {
        payloads: direct.payloads,
        programs: compiled.programs,
    })
}

/// Compile a per-target D source string to a DOF blob via the macOS
/// libdtrace producer. The returned bytes are what
/// `direct_load::build_direct_load_progs` packages inside a
/// `DTRACE_SESSION_V1` envelope.
///
/// macOS-only because libdtrace is the host-side producer; this
/// function is referenced from `build_linux_payloads` which is
/// already gated to `cfg(target_os = "macos")` via the module's
/// `cli/mod.rs` declaration.
#[cfg(target_os = "macos")]
fn compile_per_target_dof(source: &str, target_id: &str) -> Result<Vec<u8>> {
    use crate::dtrace_ffi::DtraceHandle;
    let mut hdl = DtraceHandle::open()
        .map_err(|e| anyhow!("open libdtrace for target `{}`: {e}", target_id))?;
    hdl.compile_to_dof(source)
        .map_err(|e| anyhow!("compile D → DOF for target `{}`: {e}", target_id))
}

#[cfg(not(target_os = "macos"))]
fn compile_per_target_dof(_source: &str, target_id: &str) -> Result<Vec<u8>> {
    bail!(
        "DTRACE_SESSION_V1 emission requires libdtrace; not available on this host \
         (target `{}`)",
        target_id
    )
}

/// Decode one AGG_SNAPSHOT data SHM record and fold each `(fd,
/// key, value)` row into the cross-target reducer keyed on the
/// source target's id.  Snapshot wire format (mirrors
/// `trace_render::ingest_direct_agg_snapshot`): 24-byte bifrost
/// record sub-header + u32 num_entries + per-entry { i32 fd, u32
/// k_size, u8;k_size key, u32 v_size, u8;v_size value }.
///
/// `v_size` is variable: scalar aggs ship 8 bytes, `stddev` ships
/// 24 (count, sum, sum-of-squares), and histogram aggs
/// (`quantize`/`lquantize`/`llquantize`) ship a packed `u64` array
/// — one u64 per bucket — so the host can render a faithful
/// distribution instead of a single collapsed scalar.
pub fn ingest_agg_snapshot(
    target_id: &str,
    payload: &[u8],
    agg_names: &std::collections::HashMap<i32, (String, String)>,
    reducer: &mut crate::merge::CrossTargetAggReducer,
) {
    use bifrost_wire::{
        AGG_SNAPSHOT_ROW_KIND_AVG, AGG_SNAPSHOT_ROW_KIND_COUNT, AGG_SNAPSHOT_ROW_KIND_LLQUANTIZE,
        AGG_SNAPSHOT_ROW_KIND_LQUANTIZE, AGG_SNAPSHOT_ROW_KIND_MAX, AGG_SNAPSHOT_ROW_KIND_MIN,
        AGG_SNAPSHOT_ROW_KIND_QUANTIZE, AGG_SNAPSHOT_ROW_KIND_STDDEV, AGG_SNAPSHOT_ROW_KIND_SUM,
        AGG_SNAPSHOT_ROW_KIND_UNKNOWN, AGG_SNAPSHOT_SCHEMA_V0, AGG_SNAPSHOT_SCHEMA_V1,
    };
    use crate::merge::{CrossTargetAggKind, CrossTargetAggValue};
    if payload.len() < 28 || agg_names.is_empty() {
        return;
    }
    // Schema version lives at sub-header offset 16 (the previously-
    // reserved u64).  v0 = legacy `{ fd, k_size, key, v_size, value }`
    // per row, kind inferred from agg_names.  v1 = `{ fd, kind,
    // reserved[3], k_size, key, v_size, value }` — kind stamped at
    // the source.  Reject schemas the host doesn't know rather than
    // mis-decoding silently.
    let schema = u64::from_le_bytes(payload[16..24].try_into().unwrap());
    if schema != AGG_SNAPSHOT_SCHEMA_V0 && schema != AGG_SNAPSHOT_SCHEMA_V1 {
        return;
    }
    let n = u32::from_le_bytes(payload[24..28].try_into().unwrap()) as usize;
    const MAX_KEY_BYTES: usize = 32;
    // Wide enough for the full DTrace quantize bucket array
    // (`DTRACE_QUANTIZE_NBUCKETS = 127 * 8 = 1016 bytes`).  llquantize
    // is parameterized but bounded by `factor` × `nsteps` × 8 in
    // practice, well under 4 KB for any reasonable shape.
    const MAX_VAL_BYTES: usize = 4096;
    // Per-row prefix: 4 bytes fd; under v1 add 4 bytes (kind +
    // 3 reserved) before k_size.
    let per_row_prefix: usize = if schema == AGG_SNAPSHOT_SCHEMA_V1 { 8 } else { 4 };
    let mut p = 28usize;
    for _ in 0..n {
        if payload.len() < p + per_row_prefix + 4 {
            break;
        }
        let fd = i32::from_le_bytes(payload[p..p + 4].try_into().unwrap());
        let wire_kind: u8 = if schema == AGG_SNAPSHOT_SCHEMA_V1 {
            payload[p + 4]
        } else {
            AGG_SNAPSHOT_ROW_KIND_UNKNOWN
        };
        let k_size_off = p + per_row_prefix;
        let k_size =
            u32::from_le_bytes(payload[k_size_off..k_size_off + 4].try_into().unwrap()) as usize;
        if k_size > MAX_KEY_BYTES {
            break;
        }
        let v_size_off = k_size_off + 4 + k_size;
        if payload.len() < v_size_off + 4 {
            break;
        }
        let v_size =
            u32::from_le_bytes(payload[v_size_off..v_size_off + 4].try_into().unwrap()) as usize;
        if v_size == 0 || v_size > MAX_VAL_BYTES {
            break;
        }
        let entry_bytes = per_row_prefix + 4 + k_size + 4 + v_size;
        if payload.len() < p + entry_bytes {
            break;
        }
        let k_bytes = &payload[k_size_off + 4..k_size_off + 4 + k_size];
        let v_bytes = &payload[v_size_off + 4..v_size_off + 4 + v_size];
        p += entry_bytes;

        let Some((kind_str, name)) = agg_names.get(&fd) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        // Render the key as the same string form xagg uses so
        // tabular dumps look canonical across the cross-domain
        // path and the cross-target reducer.
        let key_str = render_agg_key(k_bytes);
        // Schema-v1 row carries the kernel-stamped kind; trust it
        // and skip the source-text inference.  Fall back to the
        // source map for v0 rows or for any v1 row where the
        // kernel emitted UNKNOWN (e.g. a Linux STDDEV from a
        // shape we don't recognize on the wire).
        // Both `kind` (the reducer's grouping discriminant) and
        // `is_llquantize` (which decoder to call) are derived
        // together.  CrossTargetAggKind has a single `Lquantize`
        // variant that covers both lquantize and llquantize on the
        // reducer side (both are bucket histograms; cross-target
        // merging is bucket-wise either way), but the two have
        // different bucket-array layouts so the decoder needs to
        // distinguish.
        let (kind, is_llquantize) = if schema == AGG_SNAPSHOT_SCHEMA_V1
            && wire_kind != AGG_SNAPSHOT_ROW_KIND_UNKNOWN
        {
            match wire_kind {
                AGG_SNAPSHOT_ROW_KIND_COUNT => (CrossTargetAggKind::Count, false),
                AGG_SNAPSHOT_ROW_KIND_SUM => (CrossTargetAggKind::Sum, false),
                AGG_SNAPSHOT_ROW_KIND_MIN => (CrossTargetAggKind::Min, false),
                AGG_SNAPSHOT_ROW_KIND_MAX => (CrossTargetAggKind::Max, false),
                AGG_SNAPSHOT_ROW_KIND_QUANTIZE => (CrossTargetAggKind::Quantize, false),
                AGG_SNAPSHOT_ROW_KIND_LQUANTIZE => (CrossTargetAggKind::Lquantize, false),
                AGG_SNAPSHOT_ROW_KIND_LLQUANTIZE => (CrossTargetAggKind::Lquantize, true),
                // STDDEV / AVG don't have a matching CrossTargetAggKind
                // today; defer to a future iteration.
                AGG_SNAPSHOT_ROW_KIND_AVG | AGG_SNAPSHOT_ROW_KIND_STDDEV => continue,
                _ => continue,
            }
        } else {
            match kind_str.as_str() {
                "count" => (CrossTargetAggKind::Count, false),
                "sum" => (CrossTargetAggKind::Sum, false),
                "min" => (CrossTargetAggKind::Min, false),
                "max" => (CrossTargetAggKind::Max, false),
                "quantize" => (CrossTargetAggKind::Quantize, false),
                "lquantize" => (CrossTargetAggKind::Lquantize, false),
                "llquantize" => (CrossTargetAggKind::Lquantize, true),
                _ => continue, // unhandled shape (stddev / avg); skip
            }
        };
        let value = match kind {
            CrossTargetAggKind::Quantize => decode_quantize_buckets(v_bytes),
            CrossTargetAggKind::Lquantize if is_llquantize => decode_llquantize_buckets(v_bytes),
            CrossTargetAggKind::Lquantize => decode_lquantize_buckets(v_bytes),
            _ => {
                // Scalar aggs decode the leading u64 of the value
                // slot.  `stddev`'s 24-byte triple lands here too if
                // we ever route it through the scalar arm; for now
                // it's rejected above.
                let mut buf = [0u8; 8];
                let take = v_bytes.len().min(8);
                buf[..take].copy_from_slice(&v_bytes[..take]);
                CrossTargetAggValue::Scalar(u64::from_le_bytes(buf) as i64)
            }
        };
        reducer.merge(target_id, name, &key_str, kind, value);
    }
}

/// Walk a DTrace `quantize()` bucket array (u64 per bucket, packed
/// little-endian) and emit a sparse `(bucket_value, count)` histogram.
///
/// DTrace lays buckets out by `DTRACE_QUANTIZE_BUCKETVAL(i)`: bucket
/// `DTRACE_QUANTIZE_ZEROBUCKET` (index 63 on a 64-bit kernel) is
/// `0`, lower indices are `-2^(zero-1-i)`, higher indices are
/// `2^(i-zero-1)`.  We surface each non-zero slot keyed on the
/// power-of-two upper bound so the reducer can merge across
/// targets even when they fire at distinct CPU counts.
fn decode_quantize_buckets(v_bytes: &[u8]) -> crate::merge::CrossTargetAggValue {
    use crate::merge::CrossTargetAggValue;
    let mut buckets = Vec::new();
    // Mirror sys/dtrace.h: NBBY = 8 on every supported arch, so
    // `(sizeof(uint64_t) * NBBY) - 1 = 63` zero-bucket index.
    const ZERO: i64 = 63;
    for (i, chunk) in v_bytes.chunks_exact(8).enumerate() {
        let count = u64::from_le_bytes(chunk.try_into().unwrap());
        if count == 0 {
            continue;
        }
        let idx = i as i64;
        let bucket = if idx < ZERO {
            -(1i64 << (ZERO - 1 - idx))
        } else if idx == ZERO {
            0
        } else {
            1i64 << (idx - ZERO - 1)
        };
        buckets.push((bucket, count));
    }
    buckets.sort_by_key(|(b, _)| *b);
    CrossTargetAggValue::Histogram(buckets)
}

/// Walk a DTrace `llquantize()` (log-linear) bucket array.  Layout
/// per `sys/dtrace.h`:
///   slot 0 = packed params: bits 48..63 = factor, bits 32..47 = low,
///            bits 16..31 = high, bits 0..15 = nsteps.
///   slots 1.. = buckets, indexed by `dtrace_aggregate_llquantize_
///   bucket(factor, low, high, nsteps, value)`.
///
/// We invert the kernel's bucket-index walk to recover each
/// non-zero bucket's *lower bound* and emit `(lower_bound, count)`,
/// matching the convention `decode_lquantize_buckets` uses.  The
/// zero bucket (value < factor^low) surfaces with key 0; the
/// overflow (value >= factor^(high+1)) surfaces with key
/// factor^(high+1).  Cross-target merging works because all
/// contributors of the same `@<name>` share `(factor, low, high,
/// nsteps)` — the bucket boundaries align.
fn decode_llquantize_buckets(v_bytes: &[u8]) -> crate::merge::CrossTargetAggValue {
    use crate::merge::CrossTargetAggValue;
    let chunks: Vec<u64> = v_bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if chunks.is_empty() {
        return CrossTargetAggValue::Histogram(Vec::new());
    }
    let params = chunks[0];
    let factor = ((params >> 48) & 0xFFFF) as i64;
    let low = ((params >> 32) & 0xFFFF) as i64;
    let high = ((params >> 16) & 0xFFFF) as i64;
    let nsteps = (params & 0xFFFF) as i64;
    if factor < 2 || nsteps < factor || nsteps % factor != 0 || low > high {
        // Malformed params — fall back to bucket-index keys so the
        // operator still sees the data shape.
        let mut buckets = Vec::new();
        for (slot, count) in chunks.iter().enumerate().skip(1) {
            if *count == 0 {
                continue;
            }
            buckets.push((slot as i64, *count));
        }
        return CrossTargetAggValue::Histogram(buckets);
    }

    // Compute factor^low (the boundary into bucket 0's upper edge,
    // i.e., the lower bound of bucket 1).  Watch for overflow; if
    // we'd overflow i64, clamp.
    let mut pow_low: i64 = 1;
    for _ in 0..low {
        pow_low = pow_low.saturating_mul(factor);
    }

    // Walk magnitudes [low, high] and emit (lower_bound, count) for
    // every bucket index.  `base` starts at 1 (bucket 0 = zero
    // bucket); within each magnitude we hand out `nbuckets` indices
    // and then advance `base` by `nbuckets - nbuckets/factor`
    // (mirrors `dtrace_aggregate_llquantize_bucket`).  `last` holds
    // factor^m; `this` holds factor^(m+1); `step = this / nbuckets`
    // is the per-bucket width within magnitude m.
    let mut buckets = Vec::new();
    let mut by_idx: std::collections::BTreeMap<i64, u64> = std::collections::BTreeMap::new();
    for (slot, count) in chunks.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        by_idx.insert(slot as i64, *count);
    }

    // Zero bucket = index 0; lower bound 0.
    if let Some(&c) = by_idx.get(&0) {
        buckets.push((0i64, c));
    }

    let mut base: i64 = 1;
    let mut last: i64 = pow_low;
    let mut this: i64 = pow_low.saturating_mul(factor);
    for _m in low..=high {
        let nbuckets = this.min(nsteps);
        if nbuckets <= 0 {
            break;
        }
        let step = this / nbuckets;
        // Each magnitude owns `nbuckets - nbuckets/factor` UNIQUE
        // bucket indices.  The last `nbuckets/factor` positions of
        // `nbuckets` belong to the next magnitude's lower edge —
        // that's the `base += nbuckets - nbuckets/factor` increment
        // in the kernel's `dtrace_aggregate_llquantize_bucket`.
        let owned = nbuckets - nbuckets / factor;
        for sub in 0..owned {
            let idx = base + sub;
            if let Some(&c) = by_idx.get(&idx) {
                let lower_bound = last.saturating_add(step.saturating_mul(sub));
                buckets.push((lower_bound, c));
            }
        }
        base = base.saturating_add(owned);
        last = this;
        this = this.saturating_mul(factor);
    }
    // Overflow bucket = `base` (after the last magnitude); lower
    // bound is `last` (= factor^(high+1) we just rolled past).
    if let Some(&c) = by_idx.get(&base) {
        buckets.push((last, c));
    }

    buckets.sort_by_key(|(b, _)| *b);
    CrossTargetAggValue::Histogram(buckets)
}

/// Walk a DTrace `lquantize()` bucket array.  Layout per
/// sys/dtrace.h: slot 0 holds the packed `(step, levels, base)`
/// parameters; slots 1..levels+1 are the linear buckets; the last
/// slot is the overflow.  We don't need step/levels/base in the
/// reducer (each contributor carries its own buckets), so we surface
/// every non-zero slot keyed on the bucket index relative to base.
fn decode_lquantize_buckets(v_bytes: &[u8]) -> crate::merge::CrossTargetAggValue {
    use crate::merge::CrossTargetAggValue;
    let mut buckets = Vec::new();
    let chunks: Vec<u64> = v_bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if chunks.is_empty() {
        return CrossTargetAggValue::Histogram(buckets);
    }
    // Slot 0 = packed params: bits 0..31 = base, bits 32..47 = levels,
    // bits 48..63 = step.  Bucket bounds = base + step * (slot - 1).
    let params = chunks[0];
    let base = (params & 0xFFFF_FFFF) as i32 as i64;
    let levels = ((params >> 32) & 0xFFFF) as i64;
    let step = ((params >> 48) & 0xFFFF) as i64;
    // Underflow bucket = slot 1 (relative key = base - step).
    // Level buckets = slots 2..levels+1.
    // Overflow bucket = slot levels+2.
    for (slot, count) in chunks.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        let s = slot as i64;
        let key = if s == 1 {
            base - step.max(1) // underflow
        } else if s >= 2 && s <= levels + 1 {
            base + step * (s - 2)
        } else {
            base + step * levels // overflow
        };
        buckets.push((key, *count));
    }
    buckets.sort_by_key(|(b, _)| *b);
    CrossTargetAggValue::Histogram(buckets)
}

/// Render an agg key byte slice as a human-readable string,
/// matching the convention `trace_render::direct_agg_key` uses for
/// the cross-domain path: 8-byte chunks, ASCII-string-shaped slots
/// rendered quoted, integer-shaped slots rendered decimal.
fn render_agg_key(kb: &[u8]) -> String {
    if kb.is_empty() {
        return String::new();
    }
    // Normalize key trailing zero-padding so the cross-target
    // reducer collides keys from Linux (writes exactly n_keys*8
    // bytes per key) with FreeBSD (libdtrace pads keys out to a
    // fixed max-keys width, trailing slots all-zero).  Both
    // kernels' `@x[k] = AGG(...)` with the same k should produce
    // the same canonical key string so the reducer folds them
    // into one row whose contributors map names both targets.
    let trimmed_end = {
        let mut end = kb.len();
        while end >= 8 && kb[end - 8..end].iter().all(|&b| b == 0) {
            end -= 8;
        }
        end
    };
    let kb = &kb[..trimmed_end];
    if kb.is_empty() {
        return String::new();
    }
    kb.chunks(8)
        .map(|c| {
            let mut buf = [0u8; 8];
            buf[..c.len()].copy_from_slice(c);
            let trimmed: &[u8] = {
                let mut end = buf.len();
                while end > 0 && buf[end - 1] == 0 {
                    end -= 1;
                }
                &buf[..end]
            };
            let looks_ascii =
                !trimmed.is_empty() && trimmed.iter().all(|&b| (0x20..=0x7e).contains(&b));
            if looks_ascii {
                format!("\"{}\"", String::from_utf8_lossy(trimmed))
            } else {
                u64::from_le_bytes(buf).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn current_host_ns() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn print_merged_record(r: &crate::merge::TaggedRecord) {
    // The native-DTrace v1 record layout: 24-byte sub-header (vmid
    // u32, probe_id u32, gns u64, word3 u64) followed by an
    // 8-byte u64 trace() value.  Skip the sub-header so the demo
    // output prints the trace value directly.  Schema-tagged
    // decoding (richer types) lands with the cross-target schema/agg
    // reducer.
    const SUBHDR_LEN: usize = 24;
    const TRACE_LEN: usize = 8;
    if r.payload.len() >= SUBHDR_LEN + TRACE_LEN
        && let Ok(bytes) = r.payload[SUBHDR_LEN..SUBHDR_LEN + TRACE_LEN].try_into()
    {
        let probe_id = u32::from_le_bytes(r.payload[4..8].try_into().unwrap_or([0; 4]));
        let value = u64::from_le_bytes(bytes);
        println!(
            "[{}] gns={:#x} probe_id={} value={:#x}",
            r.target_id, r.gns, probe_id, value,
        );
    } else {
        println!(
            "[{}] gns={:#x} bytes={} {:02x?}",
            r.target_id,
            r.gns,
            r.payload.len(),
            &r.payload[..r.payload.len().min(16)],
        );
    }
}

fn resolve_d_source(plan: &Plan, args: &OrchestrateArgs) -> Result<String> {
    if let Some(inline) = args.script_text.as_deref() {
        return Ok(inline.to_string());
    }
    if let Some(path) = args.source_file.as_deref() {
        return fs::read_to_string(path).map_err(|e| anyhow!("read D source {path}: {e}"));
    }
    if let Some(inline) = plan.script.as_deref() {
        return Ok(inline.to_string());
    }
    if let Some(path) = plan.script_file.as_deref() {
        return fs::read_to_string(path)
            .map_err(|e| anyhow!("read plan D source {}: {e}", path.display()));
    }
    bail!(
        "no D source — plan {:?} has no inline `script` or `script_file`, and no -s/-n override was given",
        args.plan_path,
    );
}

fn print_routing(routed: &RoutedPlan<'_>) {
    println!("orchestrate: routed {} target(s)", routed.per_target.len());
    for rt in &routed.per_target {
        let endpoint = describe_endpoint(rt.target.conduit.as_ref());
        let launcher = describe_launcher(&rt.target.launcher);
        println!(
            "  target id={:<12} guest_os={:<8} conduit={:<32} launcher={}",
            rt.target.id,
            rt.target.guest_os.name(),
            endpoint,
            launcher,
        );
        if rt.clauses.is_empty() {
            println!("    (no clauses)");
        } else {
            for rc in &rt.clauses {
                let specs: Vec<String> =
                    rc.specs.iter().map(|spec| spec.render()).collect();
                println!("    clause: {}", specs.join(", "));
            }
        }
    }
}

fn describe_endpoint(endpoint: Option<&ConduitEndpoint>) -> String {
    match endpoint {
        Some(ConduitEndpoint::Pid(pid)) => format!("pid={pid}"),
        Some(ConduitEndpoint::Socket(p)) => format!("socket={}", p.display()),
        Some(ConduitEndpoint::DataShmName(name)) => format!("data-shm={name}"),
        None => "<no conduit (macos-host dtrace)>".to_string(),
    }
}

fn describe_launcher(spec: &LauncherSpec) -> &'static str {
    match spec {
        LauncherSpec::Smolvm { .. } => "smolvm",
        LauncherSpec::QemuFreebsd { .. } => "qemu-freebsd",
        LauncherSpec::Attach => "attach (external)",
        LauncherSpec::MacosHostDtrace { .. } => "macos-host-dtrace",
    }
}

fn dispatch_single_target(rt: &RoutedTarget<'_>, _script: &str) -> Result<ExitCode> {
    let target = rt.target;
    // Single-target macos-host orchestrate just runs the dtrace
    // child to completion and prints its output verbatim.  No SHM
    // session, no LOAD_PROG handshake.
    if target.guest_os == GuestOs::MacosHost {
        let extra_args = match &target.launcher {
            LauncherSpec::MacosHostDtrace { extra_args } => extra_args.clone(),
            _ => Vec::new(),
        };
        let mut session = crate::cli::macos_host::spawn_macos_host_session(rt, &extra_args)?;
        println!(
            "orchestrate: target `{}` accepted macos-host dtrace session",
            target.id,
        );
        // Brief sample window — single-target is a degenerate
        // path; the killer demos go through dispatch_multi_target.
        // Drain events incrementally so anything dtrace emits
        // while the sample window is open lands in the merged
        // output stream instead of getting stuck behind the
        // terminate_and_join below.
        let sample =
            std::time::Duration::from_millis(target.duration_ms.unwrap_or(500) as u64);
        let mut reducer = crate::merge::CrossTargetAggReducer::new();
        let deadline = std::time::Instant::now() + sample;
        while std::time::Instant::now() < deadline {
            for ev in session.drain_events() {
                match ev {
                    crate::cli::macos_host::MacosHostEvent::PerFire { value } => {
                        println!("[{}] value={:#x}", target.id, value);
                    }
                    crate::cli::macos_host::MacosHostEvent::AggUpdate {
                        kind,
                        name,
                        key,
                        value,
                    } => {
                        reducer.merge(
                            &target.id,
                            &name,
                            &key,
                            kind,
                            crate::merge::CrossTargetAggValue::Scalar(value),
                        );
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        session.terminate_and_join();
        for ev in session.drain_events() {
            match ev {
                crate::cli::macos_host::MacosHostEvent::PerFire { value } => {
                    println!("[{}] value={:#x}", target.id, value);
                }
                crate::cli::macos_host::MacosHostEvent::AggUpdate {
                    kind,
                    name,
                    key,
                    value,
                } => {
                    reducer.merge(
                        &target.id,
                        &name,
                        &key,
                        kind,
                        crate::merge::CrossTargetAggValue::Scalar(value),
                    );
                }
            }
        }
        if !reducer.is_empty() {
            println!("orchestrate: cross-target aggregations");
            reducer.dump();
        }
        return Ok(ExitCode::SUCCESS);
    }
    let pid = match target.conduit.as_ref() {
        Some(ConduitEndpoint::Pid(pid)) => *pid,
        Some(ConduitEndpoint::Socket(_)) | Some(ConduitEndpoint::DataShmName(_)) => bail!(
            "orchestrate N=1: only `pid`-shaped conduit endpoints are wired today; \
             socket/data_shm_name endpoints land with the multi-target path"
        ),
        None => bail!("orchestrate N=1: target missing conduit endpoint"),
    };
    if !matches!(target.launcher, LauncherSpec::Attach) {
        bail!(
            "orchestrate N=1: only `launcher: attach` is wired today; \
             smolvm/qemu-freebsd launcher dispatch lands with the multi-target path"
        );
    }

    match target.guest_os {
        GuestOs::MacosHost => unreachable!("handled above"),
        GuestOs::Linux => {
            // The existing run_attach_trace pulls its source from
            // Args, not from a free string. For now, surface a clear
            // diagnostic that the Linux N=1 dispatch needs the wider
            // Args plumbing.
            let _ = run_attach_trace; // silence unused warning until Linux N=1 dispatch lands
            bail!(
                "orchestrate N=1 Linux dispatch is not yet wired through run_attach_trace; \
                 use `bifrost attach {pid}` directly for now"
            );
        }
        GuestOs::FreeBsd | GuestOs::Illumos => {
            // Compile the target's clauses through the existing
            // freebsd-proof path. We need a source file because the
            // existing API takes a path; reusing the plan's
            // script_file is the simplest correct shape.
            let source_file = target
                .script_file
                .as_ref()
                .or(rt.target.script_file.as_ref());
            let inline = rt
                .target
                .script
                .clone()
                .or_else(|| target.script.clone());
            let freebsd_args = FreebsdDtraceArgs {
                pid,
                dof: None,
                source_file: source_file.map(|p| p.to_string_lossy().into_owned()),
                script: inline,
                expected: None,
                probe_id: 2,
                records: 8,
                no_render: false,
            };
            run_freebsd_proof(&freebsd_args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::wrapper::MapDecl;
    use crate::merge::{CrossTargetAggKind, CrossTargetAggReducer, CrossTargetAggValue};

    /// Build an AGG_SNAPSHOT payload with the exact byte layout
    /// the bifrost kernel module emits.  Used to exercise the
    /// cross-target reducer without standing up a live VM.
    ///
    /// `entries` is a list of `(fake_fd, key_bytes, value_u64)`
    /// tuples.  The 24-byte bifrost record sub-header is filled
    /// with zeroes since `ingest_agg_snapshot` only reads from
    /// offset 24 onward.
    fn build_agg_snapshot_payload(entries: &[(i32, &[u8], u64)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + entries.len() * 32);
        // 24-byte sub-header (vmid u32, probe_id u32, gns u64, word3 u64) — zeros.
        out.extend_from_slice(&[0u8; 24]);
        // u32 num_entries
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (fd, key, value) in entries {
            out.extend_from_slice(&fd.to_le_bytes());
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(&8u32.to_le_bytes()); // v_size
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// Build an AGG_SNAPSHOT payload carrying one variable-width value
    /// row. `value_bytes` lands verbatim in the row's value slot, so
    /// callers can hand-craft quantize/lquantize bucket arrays.
    fn build_agg_snapshot_payload_with_value(
        fd: i32,
        key: &[u8],
        value_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + value_bytes.len());
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&fd.to_le_bytes());
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(value_bytes);
        out
    }

    fn count_agg_names_for(fd: i32, name: &str) -> std::collections::HashMap<i32, (String, String)> {
        let mut m = std::collections::HashMap::new();
        m.insert(fd, ("count".to_string(), name.to_string()));
        m
    }

    #[test]
    fn ingest_agg_snapshot_decodes_kernel_wire_format() {
        // Single-target snapshot with one count() row keyed on the
        // string "linux".
        let payload = build_agg_snapshot_payload(&[(200, b"linux\0\0\0", 42)]);
        let names = count_agg_names_for(200, "rx");
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("linux-vm", &payload, &names, &mut reducer);

        let rows: Vec<_> = reducer
            .rows()
            .map(|(n, k, c)| (n.to_string(), k.to_string(), c.value.clone()))
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "rx");
        assert!(rows[0].1.contains("linux"));
        assert_eq!(rows[0].2, CrossTargetAggValue::Scalar(42));
    }

    #[test]
    fn ingest_agg_snapshot_folds_distinct_keys_across_targets() {
        // The canonical killer-demo shape: linux emits @rx["linux"]
        // = 42, freebsd emits @rx["freebsd"] = 17.  Both rows
        // should survive in the reducer as distinct keys.
        let linux_payload = build_agg_snapshot_payload(&[(200, b"linux\0\0\0", 42)]);
        let freebsd_payload = build_agg_snapshot_payload(&[(200, b"freebsd\0", 17)]);
        let names = count_agg_names_for(200, "rx");

        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("linux-vm", &linux_payload, &names, &mut reducer);
        ingest_agg_snapshot("freebsd-vm", &freebsd_payload, &names, &mut reducer);

        let rows: Vec<_> = reducer
            .rows()
            .map(|(n, k, c)| (n.to_string(), k.to_string(), c.value.clone()))
            .collect();
        assert_eq!(rows.len(), 2, "got rows: {:?}", rows);
        // Two rows, one per kernel.  Sorted alphabetically by key.
        let values: Vec<CrossTargetAggValue> = rows.iter().map(|r| r.2.clone()).collect();
        assert!(values.contains(&CrossTargetAggValue::Scalar(42)));
        assert!(values.contains(&CrossTargetAggValue::Scalar(17)));
    }

    #[test]
    fn ingest_agg_snapshot_folds_same_key_additively_across_targets() {
        // If both targets contributed to the SAME (agg, key) row
        // — e.g. a kernel-agnostic key like a tcp port number —
        // they fold additively.  This is the count() / sum()
        // semantics from `CrossTargetAggReducer::merge`.
        let mut payload = Vec::new();
        let mut linux_payload = Vec::new();
        let mut freebsd_payload = Vec::new();
        let port_key: &[u8] = &80u64.to_le_bytes();
        let _ = std::mem::replace(
            &mut payload,
            build_agg_snapshot_payload(&[(300, port_key, 100)]),
        );
        let _ = std::mem::replace(
            &mut linux_payload,
            build_agg_snapshot_payload(&[(300, port_key, 100)]),
        );
        let _ = std::mem::replace(
            &mut freebsd_payload,
            build_agg_snapshot_payload(&[(300, port_key, 50)]),
        );
        let mut names = std::collections::HashMap::new();
        names.insert(300, ("count".to_string(), "by_port".to_string()));

        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("linux-vm", &linux_payload, &names, &mut reducer);
        ingest_agg_snapshot("freebsd-vm", &freebsd_payload, &names, &mut reducer);

        let rows: Vec<_> = reducer
            .rows()
            .map(|(n, k, c)| (n.to_string(), k.to_string(), c.value.clone(), c.contributors.len()))
            .collect();
        assert_eq!(rows.len(), 1, "got rows: {:?}", rows);
        assert_eq!(rows[0].2, CrossTargetAggValue::Scalar(150));
        assert_eq!(rows[0].3, 2, "both targets recorded as contributors");
    }

    #[test]
    fn ingest_agg_snapshot_ignores_unknown_fd() {
        // fds the per-target agg-name map doesn't recognize get
        // silently dropped — typically agg rows for a different
        // target's program that wandered into our session.
        let payload = build_agg_snapshot_payload(&[(999, b"x", 1)]);
        let names = count_agg_names_for(200, "rx");
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("a-vm", &payload, &names, &mut reducer);
        assert!(reducer.is_empty());
    }

    #[test]
    fn ingest_agg_snapshot_skips_empty_name() {
        // Programs without a `@<name>` (anonymous aggs) ship an
        // empty name slot; the reducer can't render them so we
        // skip rather than crash.
        let payload = build_agg_snapshot_payload(&[(200, b"k", 1)]);
        let mut names = std::collections::HashMap::new();
        names.insert(200, ("count".to_string(), "".to_string()));
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("a-vm", &payload, &names, &mut reducer);
        assert!(reducer.is_empty());
    }

    #[test]
    fn ingest_agg_snapshot_decodes_full_quantize_bucket_array() {
        // Build a real quantize() bucket array: 127 u64 slots laid
        // out per DTRACE_QUANTIZE_BUCKETVAL.  Zero bucket is at
        // index 63.  Populate three non-empty slots:
        //   idx 63 = bucket 0   (count = 5)
        //   idx 64 = bucket 1   (count = 7)
        //   idx 66 = bucket 4   (count = 3)
        const NBUCKETS: usize = 127;
        let mut buckets = vec![0u64; NBUCKETS];
        buckets[63] = 5;
        buckets[64] = 7;
        buckets[66] = 3;
        let mut value_bytes = Vec::with_capacity(NBUCKETS * 8);
        for b in &buckets {
            value_bytes.extend_from_slice(&b.to_le_bytes());
        }
        let payload =
            build_agg_snapshot_payload_with_value(400, b"slow\0\0\0\0", &value_bytes);
        let mut names = std::collections::HashMap::new();
        names.insert(400, ("quantize".to_string(), "latency".to_string()));
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("a-vm", &payload, &names, &mut reducer);

        let cell = reducer.rows().next().unwrap().2;
        assert_eq!(cell.kind, CrossTargetAggKind::Quantize);
        match &cell.value {
            CrossTargetAggValue::Histogram(b) => {
                assert_eq!(b, &vec![(0, 5), (1, 7), (4, 3)]);
            }
            other => panic!("expected histogram, got {:?}", other),
        }
    }

    #[test]
    fn ingest_agg_snapshot_decodes_quantize_negative_buckets() {
        // Mid-bucket indices below the zero bucket are negative
        // powers of two: idx 62 = -1, idx 61 = -2, ...
        const NBUCKETS: usize = 127;
        let mut buckets = vec![0u64; NBUCKETS];
        buckets[60] = 4; // bucket value = -(1<<2) = -4
        buckets[63] = 1; // zero
        let mut value_bytes = Vec::with_capacity(NBUCKETS * 8);
        for b in &buckets {
            value_bytes.extend_from_slice(&b.to_le_bytes());
        }
        let payload =
            build_agg_snapshot_payload_with_value(400, b"k\0\0\0\0\0\0\0", &value_bytes);
        let mut names = std::collections::HashMap::new();
        names.insert(400, ("quantize".to_string(), "latency".to_string()));
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("a-vm", &payload, &names, &mut reducer);
        let cell = reducer.rows().next().unwrap().2;
        match &cell.value {
            CrossTargetAggValue::Histogram(b) => {
                assert_eq!(b, &vec![(-4, 4), (0, 1)]);
            }
            other => panic!("expected histogram, got {:?}", other),
        }
    }

    #[test]
    fn ingest_agg_snapshot_merges_quantize_across_targets() {
        // Linux and FreeBSD both contribute to the same agg
        // `@latency[probename]` with bucket counts at distinct
        // buckets.  The reducer should produce the union.
        const NBUCKETS: usize = 127;

        let mut linux_buckets = vec![0u64; NBUCKETS];
        linux_buckets[63] = 5; // bucket 0
        linux_buckets[64] = 7; // bucket 1
        let mut linux_value = Vec::new();
        for b in &linux_buckets {
            linux_value.extend_from_slice(&b.to_le_bytes());
        }

        let mut freebsd_buckets = vec![0u64; NBUCKETS];
        freebsd_buckets[64] = 4; // overlap bucket 1
        freebsd_buckets[66] = 9; // bucket 4
        let mut freebsd_value = Vec::new();
        for b in &freebsd_buckets {
            freebsd_value.extend_from_slice(&b.to_le_bytes());
        }

        let linux_payload =
            build_agg_snapshot_payload_with_value(500, b"hot\0\0\0\0\0", &linux_value);
        let freebsd_payload =
            build_agg_snapshot_payload_with_value(500, b"hot\0\0\0\0\0", &freebsd_value);
        let mut names = std::collections::HashMap::new();
        names.insert(500, ("quantize".to_string(), "latency".to_string()));

        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("linux", &linux_payload, &names, &mut reducer);
        ingest_agg_snapshot("freebsd", &freebsd_payload, &names, &mut reducer);

        let cell = reducer.rows().next().unwrap().2;
        match &cell.value {
            CrossTargetAggValue::Histogram(b) => {
                // bucket 0: linux only (5)
                // bucket 1: linux 7 + freebsd 4 = 11
                // bucket 4: freebsd only (9)
                assert_eq!(b, &vec![(0, 5), (1, 11), (4, 9)]);
            }
            other => panic!("expected histogram, got {:?}", other),
        }
        // Per-target contributions stored for renderers.
        assert_eq!(cell.contributors.len(), 2);
    }

    #[test]
    fn ingest_agg_snapshot_decodes_lquantize_buckets() {
        // lquantize(0, 100, 10): base=0, step=10, levels=10 → slots:
        //   slot 0 = packed params
        //   slot 1 = underflow
        //   slot 2..11 = buckets at 0, 10, 20, ..., 90
        //   slot 12 = overflow
        // Encode: base=0, levels=10, step=10
        let params: u64 = (10u64 << 48) | (10u64 << 32) | 0u64;
        let mut chunks = vec![params];
        chunks.extend(std::iter::repeat(0u64).take(12));
        chunks[3] = 4; // bucket value = base + step * (3-2) = 10
        chunks[5] = 8; // bucket value = base + step * 3 = 30
        chunks[12] = 2; // overflow = base + step * levels = 100

        let mut value_bytes = Vec::with_capacity(chunks.len() * 8);
        for c in &chunks {
            value_bytes.extend_from_slice(&c.to_le_bytes());
        }
        let payload =
            build_agg_snapshot_payload_with_value(600, b"k\0\0\0\0\0\0\0", &value_bytes);
        let mut names = std::collections::HashMap::new();
        names.insert(600, ("lquantize".to_string(), "ms".to_string()));
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("a-vm", &payload, &names, &mut reducer);
        let cell = reducer.rows().next().unwrap().2;
        match &cell.value {
            CrossTargetAggValue::Histogram(b) => {
                assert_eq!(b, &vec![(10, 4), (30, 8), (100, 2)]);
            }
            other => panic!("expected histogram, got {:?}", other),
        }
    }

    #[test]
    fn ingest_agg_snapshot_rejects_oversized_value() {
        // A value bigger than MAX_VAL_BYTES (4096) should be skipped
        // rather than panic.  Hand-craft an oversize claim.
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 24]);
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&200i32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes()); // k_size 0
        payload.extend_from_slice(&5000u32.to_le_bytes()); // v_size > MAX
        // No actual value bytes; the decoder should bail without
        // reading past the buffer.
        let names = count_agg_names_for(200, "rx");
        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("a-vm", &payload, &names, &mut reducer);
        assert!(reducer.is_empty());
    }

    #[test]
    fn ingest_agg_snapshot_full_killer_demo_path() {
        // End-to-end pin of the killer demo's cross-kernel @rx
        // shape:
        //   tracepoint:guest:net:netif_receive_skb
        //     { @rx["linux"] = count(); }   -> linux target emits 42
        //   fbt:kernel:tcp_input:entry
        //     { @rx["freebsd"] = count(); } -> freebsd target emits 17
        //
        // Verifies: two-row cross-kernel table, deterministic
        // ordering (alphabetic on key), each target's
        // contribution recorded, kind = Count, additive fold
        // semantics across same-key contributions.
        let linux_payload = build_agg_snapshot_payload(&[(200, b"linux\0\0\0", 42)]);
        let freebsd_payload = build_agg_snapshot_payload(&[(200, b"freebsd\0", 17)]);
        let names = count_agg_names_for(200, "rx");

        let mut reducer = CrossTargetAggReducer::new();
        ingest_agg_snapshot("linux", &linux_payload, &names, &mut reducer);
        ingest_agg_snapshot("freebsd", &freebsd_payload, &names, &mut reducer);

        let rows: Vec<_> = reducer.rows().collect();
        assert_eq!(rows.len(), 2);
        // BTreeMap iteration is ordered by key (agg_name, key_tuple):
        // both have agg_name "rx"; "\"freebsd\"" sorts before
        // "\"linux\"".
        assert_eq!(rows[0].0, "rx");
        assert!(rows[0].1.contains("freebsd"));
        assert_eq!(rows[0].2.value, CrossTargetAggValue::Scalar(17));
        assert_eq!(rows[1].0, "rx");
        assert!(rows[1].1.contains("linux"));
        assert_eq!(rows[1].2.value, CrossTargetAggValue::Scalar(42));

        // Once the FreeBSD kernel-side AGG_SNAPSHOT pump lands,
        // this is the exact path the live demo flows through.
        // Print the printa-rendered output for human review.
        let parsed = crate::parse::parse(
            r#"END { printa("%-10s %@d\n", @rx); }"#,
        )
        .expect("parse");
        crate::cli::printa::render_end_printa(&parsed, &reducer);
        // Silent on `cargo test`; visible on `cargo test --
        // --nocapture`.  The actual asserts live above.
        let _ = MapDecl { // silence unused import warning
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            fake_fd: 0,
            name: String::new(),
        };
    }
}
