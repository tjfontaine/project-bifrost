//! Demo smoke tests — the integration shim.
//!
//! Each test shells out to `examples/<demo>/run.sh` and asserts a
//! clean exit.  The harness inside run.sh enforces drops=0,
//! records-floor, and agg-rows-floor; this file is the bridge
//! that lets `cargo test` discover and run them.
//!
//! These tests are gated by the `BIFROST_VM_AVAILABLE=1`
//! environment variable.  Without it, every test is skipped with
//! a clear "set BIFROST_VM_AVAILABLE=1 to run" message — that
//! posture matches the existing `path_basename_compat` and
//! `wrapper_golden` tests, which are unconditional but cheap.
//! The demo smokes are *expensive* (each boots smolvm) so they
//! only fire on hosts that have a working hypervisor + libkrunfw.
//!
//! On CI: gate on the same env var.  See
//! `.github/workflows/demos.yml`.

use std::path::PathBuf;
use std::process::Command;

/// Resolve the project root from `CARGO_MANIFEST_DIR` (the
/// `host/bifrost/` directory).  Two levels up gets us to the
/// repository root where `examples/` lives.
fn project_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // host/bifrost → host
    p.pop(); // host → repo root
    p
}

/// True when the test environment opts into VM-bound smoke runs.
/// `BIFROST_VM_AVAILABLE=1` is the contract; anything else (incl.
/// unset) skips.
fn vm_available() -> bool {
    matches!(std::env::var("BIFROST_VM_AVAILABLE").as_deref(), Ok("1"))
}

/// Run one demo through its `run.sh`; assert exit 0.  Each demo
/// boots smolvm internally and runs a 16-second trace; the
/// harness inside run.sh enforces drops=0, records-floor, and
/// agg-rows-floor per `demo.toml`.
fn run_demo(name: &str) {
    if !vm_available() {
        eprintln!(
            "skipping {} — set BIFROST_VM_AVAILABLE=1 to run (needs smolvm + libkrunfw + sudo NOPASSWD on host/*/*)",
            name
        );
        return;
    }
    let root = project_root();
    let run_sh = root.join("examples").join(name).join("run.sh");
    assert!(
        run_sh.exists(),
        "missing run.sh for demo {}: expected at {}",
        name,
        run_sh.display()
    );
    let status = Command::new("bash")
        .arg(&run_sh)
        .current_dir(&root)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn run.sh for {}: {}", name, e));
    assert!(
        status.success(),
        "demo {} failed (exit {:?}); see harness output for [demo-harness] FAIL line",
        name,
        status.code()
    );
}

// One #[test] per demo so cargo can run them in parallel-ish (the
// harness's cleanup-trap.sh actually serializes via the shared
// /conduit-<pid> shmem, so --test-threads=1 is the safer CI invocation).
//
// Demos converted to the harness are listed here.  `redis-smoke-test`
// uses an older bespoke `run.sh` shape and isn't covered yet.

#[test]
fn smoke_redis_uprobe() {
    run_demo("redis-uprobe");
}

#[test]
fn smoke_failed_opens() {
    run_demo("failed-opens");
}

#[test]
fn smoke_postgres_usdt() {
    run_demo("postgres-usdt");
}

#[test]
fn smoke_intra_guest_http() {
    run_demo("intra-guest-http");
}

#[test]
fn smoke_scheduler_offcpu() {
    run_demo("scheduler-offcpu");
}

#[test]
fn smoke_sched_multi() {
    run_demo("sched-multi");
}

#[test]
fn smoke_probe_control() {
    run_demo("probe-control");
}

#[test]
fn smoke_compile_profile() {
    run_demo("compile-profile");
}

#[test]
fn smoke_cross_domain_http() {
    run_demo("cross-domain-http");
}

#[test]
fn smoke_postgres_slow_query() {
    run_demo("postgres-slow-query");
}

/// `redis-smoke-test/` uses an older bespoke `run.sh` shape that
/// boots smolvm + drives PINGs + counts records itself rather
/// than going through `examples/_common/run-demo.sh`.  It still
/// honors the exit-code contract (0 = pass, non-zero = fail), so
/// the demo_smoke shim treats it like any other harness demo
/// from the test harness's perspective — it just doesn't share
/// the `[demo-harness]` prefix in its output.
#[test]
fn smoke_redis_smoke_test() {
    run_demo("redis-smoke-test");
}
