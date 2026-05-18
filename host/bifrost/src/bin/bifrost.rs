// SPDX-License-Identifier: Apache-2.0
//! `bifrost` — DTrace-shaped runner for the cross-domain trace pipeline.
//!
//! Compile a D probe action, ship it through the bifrost virtio bridge
//! into the guest kernel, and stream the resulting records to stdout
//! correlated with macOS-side DTrace probes against the smolvm
//! libkrun process.
//!
//! Usage:
//!   bifrost -n '<d-program>' --target <kprobe-symbol>
//!   bifrost -s <d-file>      --target <kprobe-symbol>
//!   bifrost --emit-ebpf <out> -n '<d-program>' --target <symbol>
//!
//! Mirrors a subset of the `dtrace(1)` CLI:
//!   -n <script>         D program text
//!   -s <file>           D program file
//!   --target <sym>      kprobe symbol the guest probe attaches to
//!                       (required until the userspace bifrost: provider
//!                        is registered with libdtrace)
//!   --emit-ebpf <path>  just write the BFR7 wrapper, no run
//!
//! Requires: sudo for libdtrace; HVF entitlements on the smolvm-
//! vendored libkrun.dylib / libkrunfw.5.dylib (handled by
//! `host/runtime/stage-libkrun.sh` / `stage-libkrunfw.sh`); the
//! smolvm CLI built and a libkrun process to attach to. Default
//! paths assume the in-tree project layout.
//!
//! What it does, in order:
//!   1. Compile D → DOF → DIF → eBPF (this is dif_compile internally).
//!   2. Build the BFR7 wrapper bytes in memory.
//!   3. Push the wrapper through the target libkrun's control SHM
//!      cmd ring (`bifrost -p <pid>`).
//!   4. Attach the in-process libdtrace consumer and stream records
//!      to stdout until interrupted.

use anyhow::anyhow;
use bifrost::cli::args::parse_args;
use bifrost::cli::linux_compile::{LinuxCompileOpts, compile_linux_programs};
use bifrost::cli::profile::run_profile;
use bifrost::cli::runtime::{
    run_attach, run_attach_trace, run_data, run_freebsd_proof, run_list, run_ls,
};
use std::path::PathBuf;
use std::process::ExitCode;

// args/help/Args/ExtraProg/find_project_root/project_path/default_vmlinux
// moved to bifrost::cli::args.

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("bifrost only runs on macOS (links libdtrace).");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    match run() {
        Ok(c) => c,
        Err(e) => {
            // anyhow::Error rendering would print the chain via {:#}
            // here once run() returns anyhow::Result<ExitCode>; the
            // stringly-typed run() still in flight prints flat.
            // Keeping the prefix consistent so log scrapers don't
            // diff during the migration.
            eprintln!("bifrost: {}", e);
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "macos")]
fn run() -> anyhow::Result<ExitCode> {
    // Install the tracing subscriber before any CLI work so that
    // the diagnostic stderr stream (`[bifrost] <message>` lines)
    // routes through the global subscriber from the very first
    // event.  Idempotent + RUST_LOG-aware.
    bifrost::logging::init();

    // parse_args returns Result<_, ArgsError>; anyhow's blanket
    // From<E: std::error::Error> bridges via `?` (no .map_err
    // wrapper needed).
    let args = parse_args()?;

    // -l short-circuits everything else: just walk vmlinux's
    // symtab and print one probe spec per FUNC symbol matching
    // the optional pattern. No VM boot, no sudo.
    if args.list {
        return run_list(args.list_pattern.as_deref());
    }

    // `bifrost attach <pid>`: one-shot probe of the libkrun
    // control SHM endpoint. Just verify the endpoint's header
    // and print what's available — no trace loop, no wrapper
    // push. Real command pumping (LOAD_PROG, etc.) layers on
    // top of this.
    if let Some(pid) = args.attach_pid {
        return run_attach(pid, args.attach_raw_ebpf.as_deref());
    }

    // `bifrost freebsd-proof <pid>` — host-driven native FreeBSD DTrace session.
    if let Some(freebsd) = args.freebsd_dtrace.as_ref() {
        return run_freebsd_proof(freebsd);
    }

    // `bifrost profile -p <pid>` — profiling short-circuit.
    if let Some(pid) = args.profile_pid {
        return run_profile(pid, args.profile_max_samples.unwrap_or(16));
    }

    // `bifrost data <pid>` — direct data-SHM diagnostic.
    if let Some(data) = args.data_pid {
        return run_data(data.pid, data.records, data.watch_ms, data.interval_ms);
    }

    // `bifrost orchestrate <plan>` — multi-target entry.
    if let Some(orch) = args.orchestrate.as_ref() {
        return bifrost::cli::orchestrate::run_orchestrate(orch);
    }

    // `bifrost ls` — discovery short-circuit.
    if args.do_ls {
        return run_ls();
    }

    let script = args
        .script
        .ok_or_else(|| anyhow!("no D program (use -n or -s, or -l to list probes)"))?;

    // 0-3. Linux compile pipeline. Extracted from this run() body
    //      so the multi-target orchestrator can call it per Linux target;
    //      see host/bifrost/src/cli/linux_compile.rs for the full
    //      step list (stable provider rewrite, cross-domain agg
    //      discovery, xstack detection, libdtrace compile + DIF
    //      lowering, BFR7 wrapper write).
    let compile_opts = LinuxCompileOpts {
        target_override: args.target.clone(),
        emit_wrapper_to: args.emit_ebpf.as_deref().map(PathBuf::from),
        host_resolve_uprobe: args.host_resolve_uprobe,
        rootfs: args.rootfs.clone(),
        usdt_workspace_target: args.usdt_workspace_target,
        xstack_fold_enabled: args.xstack_fold.is_some(),
    };
    let compiled = compile_linux_programs(&script, &compile_opts)?;
    let programs = compiled.programs;
    let parsed_source = compiled.parsed_source;
    let btf_bytes_for_wrapper = compiled.btf_bytes;


    if args.emit_ebpf.is_some() {
        return Ok(ExitCode::SUCCESS);
    }

    // `bifrost -p <pid> -s script.d` runs an attach-mode trace
    // against an externally-spawned libkrun. We push the just-
    // built BFR7 wrapper through the target's control SHM cmd
    // ring, attach the in-process libdtrace consumer to the
    // target's pid, and run the dtrace_work loop. The target
    // keeps doing whatever it was doing; we observe.
    if let Some(target_pid) = args.trace_pid {
        let xstack_fold_path = args.xstack_fold.clone();
        let preserve = args.preserve;
        let trace_self_level = args.trace_self_level;
        let direct_data_render = args.direct_data_render;
        return run_attach_trace(
            target_pid,
            &programs,
            &parsed_source,
            xstack_fold_path,
            preserve,
            btf_bytes_for_wrapper.as_deref(),
            trace_self_level,
            direct_data_render,
        )
        .map(|_| ExitCode::SUCCESS);
    }

    // No mode selected. Spawn mode was retired alongside the legacy
    // host/libkrun + harness + bifrost_agent stack; the only
    // supported entry points are attach-mode against an externally-
    // running smolvm libkrun process and the read-only enumeration
    // helpers.
    Err(anyhow!(
        "no mode selected. bifrost requires one of:\n\
         \n  \
           bifrost -p <pid> -s probe.d   attach-mode trace against a\n  \
                                         running smolvm libkrun process\n  \
           bifrost attach <pid>          probe a libkrun control SHM\n  \
                                         endpoint (smoke test)\n  \
           bifrost ls                    list libkrun processes\n  \
                                         observable via /bifrost-<pid>\n  \
           bifrost -l [pattern]          enumerate kprobes in vmlinux\n\
         \n\
         Tip: launch the target via `smolvm machine run -d ... -- CMD`,\n\
         then pass its pid to `-p` from another shell."
    ))
}

// run_ls / run_attach / run_attach_trace / ctrlc_install_flag /
// run_list moved to bifrost::cli::runtime; run_profile moved to
// bifrost::cli::profile.

// XstackMode/XstackState/XstackPending and the marker parsers
// moved to bifrost::cli::xstack (along with dump_xstack_fold,
// extract_xstack_args, strip_xstack_to_gustack, etc.).
// CrossAggValue, XAGG_LAST_HASH, dump_xagg_state*, dump_quantize_state,
// bucket_label, collect_*, inject_guest_agg_stubs,
// rewrite_host_clauses_for_cross_aggs, split_top_level_commas,
// extract_agg_key_expr, try_parse_xagg_line, parse_quantize_marker,
// extract_first_agg_name, extract_nth_agg_name moved to
// bifrost::cli::xagg.
