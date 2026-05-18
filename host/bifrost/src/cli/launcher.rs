// SPDX-License-Identifier: Apache-2.0
//! Multi-target launcher orchestration — spawn smolvm / qemu-freebsd VMs
//! from `bifrost orchestrate` so the acceptance spec literal
//! ("`bifrost orchestrate plan.yaml` spawns both VMs") holds.
//!
//! For each non-`Attach` target in the plan, the orchestrator now
//! invokes the launcher script directly (rather than requiring a
//! surrounding run.sh to boot the VMs and stuff pids into the plan).
//! Today we cover the steps that have a stable contract across all
//! launchers:
//!
//!   1. Set per-target env vars so the launcher writes its
//!      conduit-backend pid + control SHM name into target-scoped
//!      paths under `$BIFROST_LAUNCH_DIR` (default `/tmp`).
//!   2. Spawn the launcher script as a background child.
//!   3. Poll the `CONDUIT_BACKEND_PID_FILE` until the launcher
//!      writes the conduit-backend pid (the value that goes into
//!      `ConduitEndpoint::Pid`).
//!   4. Wait for an optional `ready_marker` substring in the
//!      launcher log (e.g. `login:` for the FreeBSD path).
//!
//! What we deliberately don't do here (yet): the FreeBSD launcher's
//! EFI-loader QMP preload sequence (typing `load
//! /boot/kernel/kernel`, etc.). The existing run.sh in
//! `examples/cross-kernel-fbsd-x2` handles that via `nc -U` against
//! the QMP socket; the cleanest follow-up is a thin Rust QMP client
//! that drives the same sequence, but that lands as its own
//! sub-step alongside the live killer demos.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};

use crate::plan::{ConduitEndpoint, LauncherSpec, Target};

/// One running launcher subprocess + the addressing the orchestrator
/// needs to talk to its conduit-backend.
pub struct SpawnedLauncher {
    pub target_id: String,
    pub child: Child,
    pub backend_pid: u32,
    pub backend_pid_file: PathBuf,
    pub launch_log: PathBuf,
    pub qmp_socket: Option<PathBuf>,
}

impl Drop for SpawnedLauncher {
    fn drop(&mut self) {
        // Best-effort: kill the launcher child if it's still
        // running. The launcher script's own `trap cleanup EXIT` is
        // the load-bearing tear-down (overlay qcow2, sockets,
        // backend pidfile) — sending SIGTERM lets that trap fire.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn one target's launcher and wait for the conduit-backend to
/// register its pid. Returns the addressing payload the orchestrator
/// uses to open control SHM.
///
/// Per-target paths live under `BIFROST_LAUNCH_DIR` (default `/tmp`)
/// so concurrent launches can't collide on a shared pidfile name.
pub fn spawn_target(target: &Target, project_root: &Path) -> Result<SpawnedLauncher> {
    let launch_dir = std::env::var("BIFROST_LAUNCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let launch_dir = PathBuf::from(launch_dir);
    let id = &target.id;
    let backend_pid_file = launch_dir.join(format!("bifrost-orch-{id}-backend.pid"));
    let launch_log = launch_dir.join(format!("bifrost-orch-{id}-launch.log"));
    let qmp_socket = launch_dir.join(format!("bifrost-orch-{id}-qmp.sock"));
    let conduit_sock = launch_dir.join(format!("bifrost-orch-{id}-conduit.sock"));
    let conduit_log = launch_dir.join(format!("bifrost-orch-{id}-conduit.log"));
    let data_shm_name = format!("/bifrost-orch-{id}-data");

    // Best-effort wipe of any stale per-target files left by a
    // previous run so a crashed launcher's old pid doesn't fool the
    // wait loop below.
    let _ = std::fs::remove_file(&backend_pid_file);
    let _ = std::fs::remove_file(&launch_log);
    let _ = std::fs::remove_file(&qmp_socket);
    let _ = std::fs::remove_file(&conduit_sock);

    let (script, args, kind) = match &target.launcher {
        LauncherSpec::Smolvm { script, args } => (script.clone(), args.clone(), "smolvm"),
        LauncherSpec::QemuFreebsd { script, args } => {
            (script.clone(), args.clone(), "qemu-freebsd")
        }
        LauncherSpec::Attach => {
            bail!(
                "target `{id}` declares launcher=attach; spawn_target should not have been called"
            )
        }
        LauncherSpec::MacosHostDtrace { .. } => {
            bail!(
                "target `{id}` declares launcher=macos-host-dtrace; \
                 spawn_target should not have been called \
                 (macos-host targets are dispatched via cli::macos_host)"
            )
        }
    };
    let resolved_script = if script.is_absolute() {
        script.clone()
    } else {
        project_root.join(&script)
    };
    if !resolved_script.exists() {
        bail!(
            "launcher script for target `{id}` not found at {}",
            resolved_script.display()
        );
    }

    let log_file = std::fs::File::create(&launch_log).map_err(|e| {
        anyhow!(
            "create launcher log file {} for target `{id}`: {e}",
            launch_log.display()
        )
    })?;
    let log_for_stderr = log_file.try_clone().map_err(|e| {
        anyhow!(
            "dup launcher log file {} for target `{id}`: {e}",
            launch_log.display()
        )
    })?;

    let mut cmd = Command::new(&resolved_script);
    cmd.args(&args)
        .env("CONDUIT_BACKEND_PID_FILE", &backend_pid_file)
        .env("CONDUIT_SOCK", &conduit_sock)
        .env("CONDUIT_LOG", &conduit_log)
        .env("CONDUIT_DATA_SHM_NAME", &data_shm_name)
        .env("QEMU_QMP_SOCK", &qmp_socket)
        .env(
            "QEMU_PID_FILE",
            launch_dir.join(format!("bifrost-orch-{id}-qemu.pid")),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_for_stderr));
    // Hand the launcher a hint for `BIFROST_ROOT`; helpful when the
    // script's own discovery walks above its own location.
    cmd.env("BIFROST_ROOT", project_root);
    // When bifrost runs under `sudo -n` (the common case for the
    // orchestrate path on macOS), sudo's default `secure_path` strips
    // Homebrew's bin directories out of PATH.  The launcher scripts
    // then can't find `qemu-img`, `bsdtar`, `xz`, etc. — tools that
    // live under /opt/homebrew/bin on Apple Silicon.  Re-add the
    // Homebrew prefixes ahead of whatever sudo left so the launcher
    // shell can resolve them; user-supplied PATH still takes
    // precedence when bifrost is invoked outside a sudo context.
    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let augmented_path = if inherited_path.is_empty() {
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
    } else {
        format!("/opt/homebrew/bin:/usr/local/bin:{inherited_path}")
    };
    cmd.env("PATH", augmented_path);

    eprintln!(
        "[orchestrate] launching target `{id}` ({kind}) via {} (log: {})",
        resolved_script.display(),
        launch_log.display(),
    );
    let child = cmd.spawn().map_err(|e| {
        anyhow!(
            "spawn launcher {} for target `{id}`: {e}",
            resolved_script.display()
        )
    })?;

    // Wait up to 5 minutes for the launcher to register the
    // conduit-backend pid.  Both smolvm-launch.sh and
    // qemu-launch-freebsd.sh write CONDUIT_BACKEND_PID_FILE after
    // the backend daemonizes successfully.  Anything longer than
    // that is a real failure (or a cold qcow2 download for the
    // FreeBSD path; users with a slow first-run should set
    // BIFROST_LAUNCH_TIMEOUT_SECS).
    let timeout_secs = std::env::var("BIFROST_LAUNCH_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    // FreeBSD launchers need a QMP-driven EFI loader preload
    // before the kernel boots (the dtrace + provider modules
    // aren't in `loader.conf` on the stock cloud image; the
    // preload sequence load+boots them by hand).  Kick off the
    // preload in a background thread so it can race with the
    // backend-pidfile wait — the conduit-backend pid only lands
    // after the guest comes up, which only happens after the
    // preload completes.
    let preload_thread = if matches!(target.launcher, LauncherSpec::QemuFreebsd { .. }) {
        let sock = qmp_socket.clone();
        let log = launch_log.clone();
        let id_for_log = id.clone();
        Some(std::thread::spawn(move || {
            match crate::cli::qmp::run_freebsd_preload(
                &sock,
                &log,
                Duration::from_secs(timeout_secs),
            ) {
                Ok(()) => eprintln!(
                    "[orchestrate] target `{id_for_log}` EFI preload complete"
                ),
                Err(e) => eprintln!(
                    "[orchestrate] target `{id_for_log}` EFI preload failed: {e} \
                     — the launcher may still succeed if loader.conf has the modules"
                ),
            }
        }))
    } else {
        None
    };

    let backend_pid = loop {
        if let Ok(s) = std::fs::read_to_string(&backend_pid_file) {
            if let Ok(pid) = s.trim().parse::<u32>() {
                break pid;
            }
        }
        if Instant::now() >= deadline {
            bail!(
                "target `{id}` launcher did not write {} within {timeout_secs}s — tail of log {}: {}",
                backend_pid_file.display(),
                launch_log.display(),
                tail_for_diagnostic(&launch_log, 20),
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    if let Some(handle) = preload_thread {
        // Best-effort join; the preload already logged success/failure.
        let _ = handle.join();
    }

    // FreeBSD-only: the qemu-launch-freebsd.sh script writes the
    // conduit-backend pidfile BEFORE QEMU boots the guest, so
    // "backend pid ready" is not the same as "guest kernel has
    // registered the bifrost driver and is servicing LOAD_PROG".
    // Push payloads at that point race the boot — the existing
    // 17-second session timeout (5s base + 2s duration_ms + 10s
    // overhead in dispatch_multi_target) is well under the
    // ~30-45s the FreeBSD QCOW2 takes to reach single-user mode.
    // Gate on the `login:` marker the launcher writes after the
    // guest hits its login prompt; same pattern as the existing
    // cross-kernel-fbsd-x2 demo's bash preamble.
    if matches!(target.launcher, LauncherSpec::QemuFreebsd { .. }) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !wait_for_log_marker(&launch_log, "login:", remaining) {
            bail!(
                "target `{id}` FreeBSD guest did not reach login: prompt within \
                 {timeout_secs}s — tail of log {}: {}",
                launch_log.display(),
                tail_for_diagnostic(&launch_log, 20),
            );
        }
        eprintln!("[orchestrate] target `{id}` FreeBSD guest reached login");
    }

    eprintln!(
        "[orchestrate] target `{id}` conduit-backend pid={backend_pid} ready",
    );

    Ok(SpawnedLauncher {
        target_id: id.clone(),
        child,
        backend_pid,
        backend_pid_file,
        launch_log,
        qmp_socket: if matches!(target.launcher, LauncherSpec::QemuFreebsd { .. }) {
            Some(qmp_socket)
        } else {
            None
        },
    })
}

/// Synthesize a [`ConduitEndpoint`] from the spawned launcher's
/// backend pid. The orchestrator uses this to override the plan's
/// placeholder `pid: 0` slot.
pub fn endpoint_for(spawned: &SpawnedLauncher) -> ConduitEndpoint {
    ConduitEndpoint::Pid(spawned.backend_pid)
}

/// Wait for `marker` to appear in `path`. Returns `true` if seen
/// within the timeout. Used to wait for "login:" or other launcher-
/// specific ready markers before the orchestrator pushes session
/// payloads through control SHM.
pub fn wait_for_log_marker(
    path: &Path,
    marker: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(body) = std::fs::read_to_string(path) {
            if body.contains(marker) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

fn tail_for_diagnostic(path: &Path, lines: usize) -> String {
    let Ok(body) = std::fs::read_to_string(path) else {
        return "<no log file>".to_string();
    };
    let all: Vec<&str> = body.lines().collect();
    let n = all.len();
    let start = n.saturating_sub(lines);
    all[start..].join("\n")
}
