// SPDX-License-Identifier: Apache-2.0
//! Linux eBPF compile pipeline — extracted from `bin/bifrost.rs::run()`
//! so it can be reused by the multi-target orchestrator.
//!
//! The CLI single-target path (`bifrost -p <pid> -s probe.d`) and the
//! orchestrator's `dispatch_multi_target` Linux branch both need to
//! turn a D source into a vector of (target, schema, maps, ebpf, …)
//! tuples ready to push through control SHM and stream back into
//! `run_attach_trace`.  Before this extraction the pipeline lived
//! inline in `bin/bifrost.rs::run()` as ~1k lines pulling directly
//! from `Args`; the orchestrator was therefore unable to compile
//! Linux programs for any N≥2 plan that included a Linux target.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

use crate::Dof;
use crate::cli::args::{ExtraProg, default_vmlinux};
use crate::cli::schema_pick::{
    is_aggregation_program, pick_schema, pick_schema_for_action, program_uses_globals,
    program_uses_tls,
};
use crate::cli::source_rewrite::{
    build_clause_program, materialize_field_relocs, rewrite_core_offsetof, rewrite_g_actions,
    rewrite_offsetof, rewrite_retval, rewrite_stable_providers,
};
use crate::cli::wrapper::{MapDecl, OwnedFieldReloc, write_wrapper};
use crate::cli::xagg::{
    collect_cross_domain_aggs, collect_guest_only_aggs_referenced_by_host, collect_libact_hints,
    collect_quantize_params, extract_first_agg_name, extract_nth_agg_name, inject_guest_agg_stubs,
    rewrite_host_clauses_for_cross_aggs,
};
use crate::cli::xstack::{XstackMode, extract_xstack_args, strip_xstack_to_gustack};
use crate::dtrace_ffi::DtraceHandle;
use crate::lower::{LoweringOpts, lower_with_opts};
use crate::parse;
use crate::schema::RecordSchema;

/// One lowered Linux probe ready to ship via control SHM. Matches
/// the tuple shape that `run_attach_trace` already accepts.
///
/// The trailing `Option<u64>` profile-timer
/// period_ns slot: when probe_type is `PROBE_TYPE_PROFILE_TIMER`,
/// this carries the perf_event sample period passed through to the
/// guest via the trailer.  Other probe types leave it `None`.
pub type LoweredProgram = (
    String,
    RecordSchema,
    Vec<MapDecl>,
    Vec<u8>,
    u8,
    Option<crate::elf_syms::UprobeTarget>,
    Vec<(u32, String)>,
    Vec<OwnedFieldReloc>,
    Option<u64>,
);

/// Knobs the CLI / orchestrator pass into the compile pipeline.
/// All fields are optional / boolean — the legacy `bifrost -p` path
/// fills them from clap-parsed `Args`; the orchestrator passes
/// per-target defaults for now.
#[derive(Default, Clone, Debug)]
pub struct LinuxCompileOpts {
    /// Override the kprobe symbol the wrapper attaches to. Ambiguous
    /// with multi-clause sources; we reject upfront.
    pub target_override: Option<String>,
    /// If set, write the BFR7 wrapper to this path; otherwise the
    /// pipeline picks `/tmp/bifrost-<pid>.ebpf`.
    pub emit_wrapper_to: Option<PathBuf>,
    /// `--host-resolve-uprobe` / BIFROST_HOST_RESOLVE_UPROBE.
    pub host_resolve_uprobe: bool,
    /// Staged guest rootfs for host-resolved uprobes.
    pub rootfs: Option<String>,
    /// `--usdt-workspace-target` / BIFROST_USDT_WORKSPACE_TARGET.
    pub usdt_workspace_target: bool,
    /// `--xstack-fold` was passed; implies xstack-active for any
    /// bifrost: clause's gustack() so the renderer can produce the
    /// fold output even when xstack() wasn't explicit in source.
    pub xstack_fold_enabled: bool,
}

/// Output of [`compile_linux_programs`]. The CLI single-target path
/// hands `programs` straight to `run_attach_trace`; the orchestrator
/// pushes the same vector through each target's control SHM in
/// `dispatch_multi_target`.
pub struct LinuxCompileOutput {
    pub programs: Vec<LoweredProgram>,
    /// The fully-rewritten parse tree.  Attach-mode needs it for the
    /// auto-injected host D (xstack dispatch, bifrost_event_received
    /// taps), and the orchestrator's renderer reads probe specs out
    /// of it to label records.
    pub parsed_source: parse::Parsed,
    /// Captured BTF bytes (for `run_attach_trace`'s self-trace
    /// plumbing). May be `None` if vmlinux wasn't found.
    pub btf_bytes: Option<Vec<u8>>,
    /// Where the BFR7 wrapper landed on disk. Same path the CLI used
    /// to log via `[bifrost] wrote …`.
    pub wrapper_path: PathBuf,
    /// True if the source's bifrost: clauses asked for xstack capture
    /// (or `xstack_fold_enabled` opt-in turned implicit gustack into
    /// xstack). Forwarded to `run_attach_trace` so it wires up the
    /// host-side xstack dispatch tap.
    pub xstack_enabled: bool,
    pub xstack_depth: Option<u32>,
    pub xstack_mode: XstackMode,
}

/// Drive the full Linux compile pipeline.  See module docs for the
/// step list.  Logs to stderr the same `[bifrost] …` lines the
/// pre-extraction inline path emitted so demos and CI greps continue
/// to work.
pub fn compile_linux_programs(
    d_source: &str,
    opts: &LinuxCompileOpts,
) -> Result<LinuxCompileOutput> {
    // 0. Stable provider catalog rewrite.
    let script = rewrite_stable_providers(d_source);

    // 1. Parse the unified D source and split clauses by provider.
    let mut parsed_source = parse::parse(&script).map_err(|e| anyhow!("{}", e))?;

    // Cross-domain aggregation discovery + per-side rewrites.
    let cross_aggs = collect_cross_domain_aggs(&parsed_source);
    if !cross_aggs.is_empty() {
        rewrite_host_clauses_for_cross_aggs(&mut parsed_source, &cross_aggs);
        eprintln!(
            "[bifrost] cross-domain aggregations active: {}",
            cross_aggs
                .iter()
                .map(|s| format!("@{}", s))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let stub_aggs = collect_guest_only_aggs_referenced_by_host(&parsed_source);
    if !stub_aggs.is_empty() {
        inject_guest_agg_stubs(&mut parsed_source, &stub_aggs);
        eprintln!(
            "[bifrost] stubbed guest-only aggs for libdtrace: {}",
            stub_aggs
                .iter()
                .map(|s| format!("@{}", s))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    collect_libact_hints(&parsed_source);
    collect_quantize_params(&parsed_source);

    // xstack detection + body rewriting.
    let mut xstack_enabled = false;
    let mut xstack_depth: Option<u32> = None;
    let mut xstack_mode = XstackMode::Forced;
    for c in &mut parsed_source.clauses {
        if !c.is_bifrost() {
            continue;
        }
        if let Some((mode, d)) = extract_xstack_args(&c.body) {
            xstack_enabled = true;
            xstack_depth = Some(xstack_depth.map_or(d, |old| old.max(d)));
            if mode == XstackMode::Sample {
                xstack_mode = XstackMode::Sample;
            }
            c.body = strip_xstack_to_gustack(&c.body);
            if let Some(open) = c.source.find('{') {
                c.source = format!("{}{{\n    {}\n}}", &c.source[..open], c.body.trim());
            }
        }
    }
    if opts.xstack_fold_enabled && !xstack_enabled {
        xstack_enabled = true;
        xstack_depth = Some(xstack_depth.unwrap_or(8));
    }
    if xstack_enabled {
        eprintln!(
            "[bifrost] xstack() detected — cross-domain host stack capture active (mode={:?}, ustack depth={}{})",
            xstack_mode,
            xstack_depth.unwrap_or(8),
            if opts.xstack_fold_enabled {
                ", fold output"
            } else {
                ""
            }
        );
    }

    // Linux backend now accepts two clause shapes:
    //   1. bifrost-routed clauses (fbt/tracepoint/uprobe/usdt) —
    //      lowered through the existing path.
    //   2. `profile:::tick-Nms` / `profile-Nsec` / `tick-Nhz` (Track
    //      B P0 #6) — lowered to a BPF_PROG_TYPE_PERF_EVENT program
    //      attached via `perf_event_create_kernel_counter` on the
    //      guest.  The clause has no bifrost spec, only a
    //      profile-timer spec; we treat it as the canonical bspec
    //      for lowering purposes below.
    let bifrost_clauses: Vec<&parse::Clause> = parsed_source
        .clauses
        .iter()
        .filter(|c| {
            c.specs
                .iter()
                .any(|s| s.is_bifrost() || s.is_profile_timer())
        })
        .collect();
    if bifrost_clauses.is_empty() {
        bail!(
            "no Linux-routable clause in source (need at least one fbt/tracepoint/uprobe/usdt or profile:::tick-N{{ns,us,ms,sec,hz}})"
        );
    }

    // Deprecation gate — refuse retired probe shapes upfront.
    for clause in &bifrost_clauses {
        for spec in &clause.specs {
            if spec.is_deprecated_kprobe() {
                bail!(
                    "probe `{}` uses the retired kprobe shape — rewrite as `fbt:guest:{}:{}` to attach via the BPF trampoline (FENTRY for :entry, FEXIT for :return).",
                    spec.render(),
                    spec.function,
                    spec.name,
                );
            }
            if spec.is_deprecated_uprobe() {
                let bin = spec.binary.as_deref().unwrap_or("?");
                bail!(
                    "probe `{}` uses the retired uprobe shape — rewrite as `uprobe:guest:{}:{}:{}`.",
                    spec.render(),
                    bin,
                    spec.function,
                    spec.name,
                );
            }
            if spec.is_deprecated_empty_domain() {
                let canonical_module = "guest";
                if let Some(bin) = &spec.binary {
                    bail!(
                        "probe `{}` is missing a domain in the module slot — rewrite as `{}:{}:{}:{}:{}`. Domain is one of `guest` (in-VM kernel/user) or `vmm` (libkrun host process).",
                        spec.render(),
                        spec.provider,
                        canonical_module,
                        bin,
                        spec.function,
                        spec.name,
                    );
                }
                bail!(
                    "probe `{}` is missing a domain in the module slot — rewrite as `{}:{}:{}:{}`. Domain is one of `guest` (in-VM target) or `vmm` (libkrun host process).",
                    spec.render(),
                    spec.provider,
                    canonical_module,
                    spec.function,
                    spec.name,
                );
            }
        }
    }
    if opts.target_override.is_some() && bifrost_clauses.len() > 1 {
        bail!("--target override is ambiguous with multi-clause sources");
    }

    // libdtrace handle + BTF.
    let mut hdl = DtraceHandle::open().map_err(anyhow::Error::msg)?;
    let mut btf_bytes_for_wrapper: Option<Vec<u8>> = None;
    let mut btf: Option<crate::btf::Btf> = {
        let path = default_vmlinux();
        match crate::btf::extract_btf_section(Path::new(&path)) {
            Ok(bytes) => match crate::btf::parse(&bytes) {
                Ok(p) => {
                    eprintln!("[bifrost] BTF loaded from {} ({} bytes)", path, bytes.len());
                    btf_bytes_for_wrapper = Some(bytes);
                    Some(p)
                }
                Err(e) => {
                    eprintln!("[bifrost] BTF parse failed: {} (continuing without)", e);
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "[bifrost] BTF load from {} failed: {} (continuing without)",
                    path, e
                );
                None
            }
        }
    };
    eprintln!(
        "[bifrost] BFR7 wrapper format — kfuncs resolved on the guest \
         against running kernel BTF (no compile-time btf_id baking)"
    );

    // Compile every clause; build the programs vector.
    let mut programs: Vec<LoweredProgram> = Vec::with_capacity(bifrost_clauses.len());
    let mut agg_base: u32 = 0;
    let mut next_agg_fd: i32 = crate::lower::AGG_MAP_FAKE_FD;
    let mut next_global_probe_id: u32 = 1;
    for (clause_idx, clause) in bifrost_clauses.iter().enumerate() {
        // Profile-timer clauses don't carry a "bifrost" spec; they
        // route through the profile-timer probe shape.  Resolve the
        // profile spec first, then fall back to the bifrost spec for
        // every other shape.
        let ptspec = clause.specs.iter().find(|s| s.is_profile_timer());
        let bspec = clause.specs.iter().find(|s| s.is_bifrost());
        let is_profile_timer = ptspec.is_some() && bspec.is_none();
        let profile_period_ns: Option<u64> = ptspec.and_then(|s| s.profile_timer_period_ns());
        if is_profile_timer && profile_period_ns.is_none() {
            bail!(
                "profile-timer probe `{}` has unrecognized period suffix — \
                 expected `tick-Nms` / `tick-Nsec` / `tick-Nusec` / `tick-Nns` / `tick-Nhz`",
                ptspec.unwrap().render(),
            );
        }
        let target_for_tracepoint = bspec.map(|s| s.is_tracepoint()).unwrap_or(false);
        let target = match opts.target_override.clone() {
            Some(t) => t,
            None => {
                if is_profile_timer {
                    // Use the probe name (e.g. "tick-100ms") as the
                    // 32-byte target_name; the kernel needs the
                    // human-readable label for diagnostics and the
                    // actual period is carried via the trailer.
                    ptspec.unwrap().name.clone()
                } else {
                    let s = bspec.ok_or_else(|| {
                        anyhow!("bifrost: clause has no bifrost-routed spec")
                    })?;
                    let raw = if target_for_tracepoint {
                        s.name.clone()
                    } else {
                        s.function.clone()
                    };
                    if raw.is_empty() {
                        if target_for_tracepoint {
                            bail!("bifrost: tracepoint spec missing event name");
                        } else {
                            bail!("bifrost: probe spec missing function field; pass --target");
                        }
                    }
                    raw
                }
            }
        };
        let is_user_probe = bspec.map(|s| s.is_guest_user()).unwrap_or(false);
        let is_usdt = bspec.map(|s| s.is_usdt()).unwrap_or(false);
        let is_fbt = bspec.map(|s| s.is_fbt()).unwrap_or(false);
        let is_tracepoint = bspec.map(|s| s.is_tracepoint()).unwrap_or(false);
        let name_kind = bspec.map(|s| s.name.as_str()).unwrap_or("entry");
        let host_resolve = is_user_probe
            && (opts.host_resolve_uprobe
                || std::env::var_os("BIFROST_HOST_RESOLVE_UPROBE").is_some());
        let probe_type: u8 = if is_profile_timer {
            // Wire-level PROBE_TYPE_PROFILE_TIMER.
            bifrost_wire::PROBE_TYPE_PROFILE_TIMER
        } else if is_tracepoint {
            8
        } else if is_fbt {
            match name_kind {
                "return" => 7,
                _ => 6,
            }
        } else if is_usdt {
            9
        } else if is_user_probe {
            match (host_resolve, name_kind) {
                (true, "return") => 3,
                (true, _) => 2,
                (false, "return") => 5,
                (false, _) => 4,
            }
        } else {
            bail!(
                "internal: clause `{}` doesn't match any canonical bifrost-routed shape (fbt/tracepoint/uprobe/usdt/profile-timer). The deprecation gate should have caught this earlier.",
                bspec.map(|s| s.render()).unwrap_or_else(|| "?".to_string()),
            );
        };

        let uprobe_target: Option<crate::elf_syms::UprobeTarget> = if is_usdt {
            let bspec = bspec.expect("is_usdt implies a bifrost spec");
            let basename = bspec
                .binary
                .as_deref()
                .ok_or_else(|| anyhow!("usdt probe missing binary slot (parser bug)"))?;
            let target = if opts.usdt_workspace_target
                || std::env::var_os("BIFROST_USDT_WORKSPACE_TARGET").is_some()
            {
                format!("/workspace/{basename}")
            } else {
                basename.to_string()
            };
            eprintln!(
                "[bifrost] usdt {}:{}:{} (guest-resolved .note.stapsdt)",
                target, bspec.function, bspec.name
            );
            Some(crate::elf_syms::UprobeTarget {
                basename: target,
                sdt_provider: bspec.function.clone(),
                symbol: bspec.name.clone(),
                ..Default::default()
            })
        } else if is_user_probe {
            let bspec = bspec.expect("guest_user implies a bifrost spec");
            let basename = bspec
                .binary
                .as_deref()
                .ok_or_else(|| anyhow!("guest_user probe missing binary slot (parser bug)"))?;
            if host_resolve {
                let rootfs_value = opts
                    .rootfs
                    .clone()
                    .or_else(|| std::env::var("BIFROST_ROOTFS").ok())
                    .unwrap_or_else(|| "/tmp/bifrost_rootfs".to_string());
                let rootfs = Path::new(&rootfs_value).to_path_buf();
                let resolved =
                    crate::elf_syms::resolve_uprobe_target(&rootfs, basename, &bspec.function)
                        .map_err(|e| {
                            anyhow!(
                                "bifrost: clause #{}: {} (use --rootfs or BIFROST_ROOTFS to override)",
                                clause_idx,
                                e
                            )
                        })?;
                eprintln!(
                    "[bifrost] host-resolved uprobe {}:{} -> {} +0x{:x}",
                    basename, bspec.function, resolved.guest_path, resolved.file_offset
                );
                Some(resolved)
            } else {
                eprintln!(
                    "[bifrost] kernel-resolved uprobe {}:{} (driver walks /proc + parses ELF)",
                    basename, bspec.function
                );
                Some(crate::elf_syms::UprobeTarget {
                    basename: basename.to_string(),
                    symbol: bspec.function.clone(),
                    ..Default::default()
                })
            }
        } else {
            None
        };

        let expanded_body =
            crate::translators::expand_translators(clause, &clause.body, btf.as_mut())
                .map_err(|e| anyhow!("{}", e))?;
        let clause_with_expansion = if expanded_body == clause.body {
            (*clause).clone()
        } else {
            let mut c = (*clause).clone();
            c.source = if let Some(open) = c.source.find('{') {
                format!("{}{{{}}}", &c.source[..open], expanded_body)
            } else {
                c.source.clone()
            };
            c.body = expanded_body;
            c
        };
        let clause = &clause_with_expansion;
        let clause_program = build_clause_program(clause);
        let after_retval = rewrite_retval(&clause_program, clause, btf.as_mut())?;
        let after_g_actions = rewrite_g_actions(&after_retval);
        let (after_core_offsetof, core_markers) =
            rewrite_core_offsetof(&after_g_actions, btf.as_mut());
        let bifrost_source = rewrite_offsetof(&after_core_offsetof, btf.as_mut());
        let dof = hdl
            .compile_to_dof(&bifrost_source)
            .map_err(anyhow::Error::msg)?;
        let parsed = Dof::parse(&dof).map_err(|e| anyhow!("{}", e))?;

        let is_agg = is_aggregation_program(&parsed);
        let schema = if is_agg {
            RecordSchema::default_trace()
        } else {
            pick_schema(&parsed)
        };
        let lowering_schema: Option<&RecordSchema> = if is_agg { None } else { Some(&schema) };
        let this_agg_base = agg_base;
        let probe_id = next_global_probe_id;
        next_global_probe_id += 1;
        let this_agg_fd = if is_agg {
            let fd = next_agg_fd;
            next_agg_fd += 1;
            fd
        } else {
            crate::lower::AGG_MAP_FAKE_FD
        };
        // Recovered n_keys per agg from the D source body, paired
        // with each agg's wire position.  Used below to compute the
        // FIRST agg's chain_start, which the existing dispatcher
        // implicitly assumed was 0 — wrong whenever the clause has
        // a leading standalone action like `trace(timestamp)` before
        // the first agg.  Without this fix the BPF map's key_size
        // and the runtime store-key code disagree on how many bytes
        // make up the key, and the resulting AGG_SNAPSHOT rows ship
        // 16 bytes of key for what should be an 8-byte single key —
        // breaking cross-target reducer fold across kernels.
        let agg_decls = crate::cli::agg_decl::discover_aggs(&clause.body);
        let mut first_agg_chain_start_opt: Option<usize> = None;
        let extra_progs: Vec<ExtraProg> = if let Some(ecb) = parsed.first_ecb() {
            let actions = parsed.actions_in_chain(ecb.actions);
            let is_printf = actions
                .first()
                .map(|a| a.kind == crate::lower::DTRACEACT_PRINTF)
                .unwrap_or(false);
            if is_printf {
                Vec::new()
            } else if is_agg {
                let agg_positions: Vec<usize> = actions
                    .iter()
                    .enumerate()
                    .filter_map(|(i, a)| {
                        if crate::lower::is_agg_action(a.kind) {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .collect();
                let mut out: Vec<ExtraProg> = Vec::new();
                // First-agg chain_start: derived from the parser's
                // n_keys for the first agg in source order.  Used by
                // agg_map_decl_for_chain_at below to pick the right
                // BPF map key_size when the clause has a leading
                // standalone DIFEXPR like `trace(timestamp);` before
                // the first agg.
                if let (Some(&first_agg_pos), Some(first_decl)) =
                    (agg_positions.first(), agg_decls.first())
                {
                    // libdtrace agg-chain shape:
                    //   [value_DIFEXPR, key0_DIFEXPR, ..,
                    //    key{N-1}_DIFEXPR, AGG]
                    // chain_start points at the leading
                    // value_DIFEXPR (always present, even for
                    // count() where it's a dummy zero), so:
                    //   chain_start = first_agg_pos - n_keys - 1
                    // Standalone actions before the chain live in
                    // [0 ... chain_start).
                    let cs = first_agg_pos.saturating_sub(first_decl.n_keys + 1);
                    first_agg_chain_start_opt = Some(cs);
                    // Emit ExtraProg::Action for
                    // every leading standalone DIFEXPR (e.g.
                    // `trace(timestamp);`) before the first agg's
                    // key-store sequence, so per-fire records reach
                    // the host's MergedRing instead of being
                    // silently dropped.  Each ExtraProg::Action
                    // becomes its own BPF program with its own
                    // probe_id; the kernel module attaches them as
                    // peers under separate slots, so there's no
                    // shared map/slot to collide on.
                    for i in 0..cs {
                        let act_kind = actions[i].kind;
                        if act_kind == crate::lower::DTRACEACT_LIBACT {
                            continue;
                        }
                        if !matches!(
                            act_kind,
                            crate::lower::DTRACEACT_DIFEXPR
                                | crate::lower::DTRACEACT_PRINTA
                        ) {
                            // Other action kinds (printf with args,
                            // ustack, etc.) need richer lowering
                            // than the peer-program path provides;
                            // skip rather than blow up.
                            continue;
                        }
                        out.push(ExtraProg::Action { action_idx: i });
                    }
                }
                for i in 1..agg_positions.len() {
                    let start = agg_positions[i - 1] + 1;
                    out.push(ExtraProg::AggChain { chain_start: start });
                }
                if let Some(&last_agg) = agg_positions.last() {
                    for i in (last_agg + 1)..actions.len() {
                        if actions[i].kind == crate::lower::DTRACEACT_LIBACT {
                            if actions[i].arg as u64 == crate::lower::DT_ACT_CLEAR {
                                out.push(ExtraProg::ClearAgg {
                                    fake_fd: this_agg_fd,
                                });
                            }
                            continue;
                        }
                        out.push(ExtraProg::Action { action_idx: i });
                    }
                }
                out
            } else {
                (1..actions.len())
                    .filter(|&i| actions[i].kind != crate::lower::DTRACEACT_LIBACT)
                    .map(|i| ExtraProg::Action { action_idx: i })
                    .collect()
            }
        } else {
            Vec::new()
        };

        let (mut ebpf, kfunc_relocs) = lower_with_opts(
            &parsed,
            lowering_schema,
            LoweringOpts {
                agg_base: this_agg_base,
                probe_id,
                agg_map_fake_fd: this_agg_fd,
                action_idx: 0,
                // Pass the first agg's true chain_start (if any) so
                // emit_agg_chain_at scopes its key-store loop to the
                // agg's actual key DIFEXPRs and skips any leading
                // standalone actions.
                agg_chain_start: first_agg_chain_start_opt,
                force_standalone_action: false,
            },
        )
        .map_err(|e| anyhow!("lowering '{}': {}", target, e))?;

        let materialized = materialize_field_relocs(&mut ebpf, &core_markers);
        let field_relocs_owned: Vec<OwnedFieldReloc> = materialized
            .into_iter()
            .map(|m| OwnedFieldReloc {
                insn_idx: m.insn_idx,
                access_kind: m.access_kind,
                byte_off_in_insn: m.byte_off_in_insn,
                struct_name: m.struct_name,
                field_name: m.field_name,
            })
            .collect();

        if let Err(e) = crate::verify::verify(&ebpf[..]) {
            bail!(
                "bifrost: pre-flight verification failed for clause #{} target='{}': {}",
                clause_idx,
                target,
                e
            );
        }
        if is_agg {
            agg_base += 1;
        }

        let mut maps: Vec<MapDecl> = Vec::new();
        if is_agg {
            if let Some(ecb) = parsed.first_ecb() {
                let actions = parsed.actions_in_chain(ecb.actions);
                let agg_idx = actions
                    .iter()
                    .position(|a| crate::lower::is_agg_action(a.kind));
                if let Some(pos) = agg_idx
                    && let Some((mt, ks, vs, me)) =
                        crate::lower::agg_map_decl_for_chain_at(
                            &actions,
                            first_agg_chain_start_opt.unwrap_or(0),
                            pos,
                        )
                {
                    let agg_name = extract_first_agg_name(&clause.body).unwrap_or_default();
                    let kind = crate::lower::agg_kind_str(actions[pos].kind).unwrap_or("unknown");
                    let encoded = format!("{}\0{}", kind, agg_name);
                    maps.push(MapDecl {
                        map_type: mt,
                        key_size: ks,
                        value_size: vs,
                        max_entries: me,
                        fake_fd: this_agg_fd,
                        name: encoded,
                    });
                }
            }
        } else if !schema.fields.is_empty() {
            maps.push(MapDecl {
                map_type: 27, // BPF_MAP_TYPE_RINGBUF
                key_size: 0,
                value_size: 0,
                max_entries: 256 * 1024,
                fake_fd: 100,
                name: String::new(),
            });
        }

        if program_uses_tls(&parsed) {
            maps.push(MapDecl {
                map_type: crate::lower::BPF_MAP_TYPE_HASH,
                key_size: crate::lower::TLS_MAP_KEY_SIZE,
                value_size: crate::lower::TLS_MAP_VALUE_SIZE,
                max_entries: crate::lower::TLS_MAP_MAX_ENTRIES,
                fake_fd: crate::lower::TLS_MAP_FAKE_FD,
                name: String::new(),
            });
        }

        if program_uses_globals(&parsed) {
            maps.push(MapDecl {
                map_type: crate::lower::BPF_MAP_TYPE_HASH,
                key_size: crate::lower::GLOBAL_MAP_KEY_SIZE,
                value_size: crate::lower::GLOBAL_MAP_VALUE_SIZE,
                max_entries: crate::lower::GLOBAL_MAP_MAX_ENTRIES,
                fake_fd: crate::lower::GLOBAL_MAP_FAKE_FD,
                name: String::new(),
            });
        }

        let kfunc_relocs_owned: Vec<(u32, String)> = kfunc_relocs
            .into_iter()
            .map(|(idx, name)| (idx, name.to_string()))
            .collect();
        programs.push((
            target.clone(),
            schema.clone(),
            maps.clone(),
            ebpf,
            probe_type,
            uprobe_target.clone(),
            kfunc_relocs_owned,
            field_relocs_owned,
            profile_period_ns,
        ));

        for extra in extra_progs.iter().copied() {
            let extra_probe_id = next_global_probe_id;
            next_global_probe_id += 1;
            let (extra_schema, extra_lowering_schema, extra_opts, extra_maps, label) = match extra {
                ExtraProg::Action { action_idx } => {
                    let s = pick_schema_for_action(&parsed, action_idx);
                    let opts = LoweringOpts {
                        agg_base: this_agg_base,
                        probe_id: extra_probe_id,
                        agg_map_fake_fd: this_agg_fd,
                        action_idx,
                        agg_chain_start: None,
                        // Even when the action sits
                        // BEFORE the first agg in source order,
                        // lower it as a standalone per-fire program
                        // (not as part of the agg-chain).
                        force_standalone_action: true,
                    };
                    (
                        s,
                        true,
                        opts,
                        maps.clone(),
                        format!("action #{}", action_idx),
                    )
                }
                ExtraProg::AggChain { chain_start } => {
                    let sub_fd = next_agg_fd;
                    next_agg_fd += 1;
                    let opts = LoweringOpts {
                        agg_base,
                        probe_id: extra_probe_id,
                        agg_map_fake_fd: sub_fd,
                        action_idx: chain_start,
                        agg_chain_start: Some(chain_start),
                        force_standalone_action: false,
                    };
                    let mut sub_maps: Vec<MapDecl> = Vec::new();
                    if let Some(ecb) = parsed.first_ecb() {
                        let actions = parsed.actions_in_chain(ecb.actions);
                        let agg_ordinal = actions[..chain_start]
                            .iter()
                            .filter(|a| crate::lower::is_agg_action(a.kind))
                            .count()
                            + 1;
                        let sub_agg_pos_rel = actions[chain_start..]
                            .iter()
                            .position(|a| crate::lower::is_agg_action(a.kind));
                        if let Some(rel) = sub_agg_pos_rel {
                            let slice = &actions[chain_start..=chain_start + rel];
                            let sub_pos_in_slice = rel;
                            if let Some((mt, ks, vs, me)) =
                                crate::lower::agg_map_decl_for_chain(slice, sub_pos_in_slice)
                            {
                                let agg_name = extract_nth_agg_name(&clause.body, agg_ordinal)
                                    .unwrap_or_default();
                                let kind = crate::lower::agg_kind_str(slice[sub_pos_in_slice].kind)
                                    .unwrap_or("unknown");
                                let encoded = format!("{}\0{}", kind, agg_name);
                                sub_maps.push(MapDecl {
                                    map_type: mt,
                                    key_size: ks,
                                    value_size: vs,
                                    max_entries: me,
                                    fake_fd: sub_fd,
                                    name: encoded,
                                });
                            }
                        }
                    }
                    if program_uses_tls(&parsed) {
                        sub_maps.push(MapDecl {
                            map_type: crate::lower::BPF_MAP_TYPE_HASH,
                            key_size: crate::lower::TLS_MAP_KEY_SIZE,
                            value_size: crate::lower::TLS_MAP_VALUE_SIZE,
                            max_entries: crate::lower::TLS_MAP_MAX_ENTRIES,
                            fake_fd: crate::lower::TLS_MAP_FAKE_FD,
                            name: String::new(),
                        });
                    }
                    if program_uses_globals(&parsed) {
                        sub_maps.push(MapDecl {
                            map_type: crate::lower::BPF_MAP_TYPE_HASH,
                            key_size: crate::lower::GLOBAL_MAP_KEY_SIZE,
                            value_size: crate::lower::GLOBAL_MAP_VALUE_SIZE,
                            max_entries: crate::lower::GLOBAL_MAP_MAX_ENTRIES,
                            fake_fd: crate::lower::GLOBAL_MAP_FAKE_FD,
                            name: String::new(),
                        });
                    }
                    (
                        RecordSchema::default_trace(),
                        false,
                        opts,
                        sub_maps,
                        format!("agg-chain @{}", chain_start),
                    )
                }
                ExtraProg::ClearAgg { fake_fd } => {
                    use crate::lower::{
                        KFUNC_CLEAR_AGG, bpf_exit, bpf_ld_map_fd, bpf_mov64_imm, emit_kfunc_call,
                    };
                    let mut body: Vec<u8> = Vec::new();
                    let mut relocs: Vec<(u32, &'static str)> = Vec::new();
                    body.extend_from_slice(&bpf_ld_map_fd(1, fake_fd));
                    emit_kfunc_call(&mut body, &mut relocs, KFUNC_CLEAR_AGG);
                    body.extend_from_slice(&bpf_mov64_imm(0, 0));
                    body.extend_from_slice(&bpf_exit());
                    let relocs_owned: Vec<(u32, String)> = relocs
                        .into_iter()
                        .map(|(i, n)| (i, n.to_string()))
                        .collect();
                    if let Err(e) = crate::verify::verify(&body[..]) {
                        bail!(
                            "bifrost: pre-flight verification failed for clause #{} target='{}' clear(@agg fd={}): {}",
                            clause_idx,
                            target,
                            fake_fd,
                            e
                        );
                    }
                    programs.push((
                        target.clone(),
                        RecordSchema::default_trace(),
                        maps.clone(),
                        body,
                        probe_type,
                        uprobe_target.clone(),
                        relocs_owned,
                        Vec::<OwnedFieldReloc>::new(),
                        profile_period_ns,
                    ));
                    continue;
                }
            };
            let lowering_schema_arg: Option<&RecordSchema> = if extra_lowering_schema {
                Some(&extra_schema)
            } else {
                None
            };
            let (mut extra_ebpf, extra_relocs) =
                lower_with_opts(&parsed, lowering_schema_arg, extra_opts)
                    .map_err(|e| anyhow!("lowering '{}' {}: {}", target, label, e))?;
            let extra_materialized = materialize_field_relocs(&mut extra_ebpf, &core_markers);
            let extra_field_relocs_owned: Vec<OwnedFieldReloc> = extra_materialized
                .into_iter()
                .map(|m| OwnedFieldReloc {
                    insn_idx: m.insn_idx,
                    access_kind: m.access_kind,
                    byte_off_in_insn: m.byte_off_in_insn,
                    struct_name: m.struct_name,
                    field_name: m.field_name,
                })
                .collect();
            if let Err(e) = crate::verify::verify(&extra_ebpf[..]) {
                bail!(
                    "bifrost: pre-flight verification failed for clause #{} target='{}' {}: {}",
                    clause_idx,
                    target,
                    label,
                    e
                );
            }
            let extra_relocs_owned: Vec<(u32, String)> = extra_relocs
                .into_iter()
                .map(|(idx, name)| (idx, name.to_string()))
                .collect();
            programs.push((
                target.clone(),
                extra_schema.clone(),
                extra_maps,
                extra_ebpf,
                probe_type,
                uprobe_target.clone(),
                extra_relocs_owned,
                extra_field_relocs_owned,
                profile_period_ns,
            ));
        }
    }

    // Write the BFR7 wrapper. Default path mirrors the legacy CLI's
    // /tmp/bifrost-<pid>.ebpf so existing log greps keep working.
    let wrapper_path = opts
        .emit_wrapper_to
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/bifrost-{}.ebpf", std::process::id())));
    write_wrapper(&wrapper_path, &programs)?;
    for (i, (target, schema, maps, ebpf, probe_type, uprobe, _, _, _)) in
        programs.iter().enumerate()
    {
        let pt = match *probe_type {
            0 | 2 | 4 => "entry",
            1 | 3 | 5 => "return",
            9 => "fire",
            _ => "entry",
        };
        let kind = match *probe_type {
            0 => "kprobe",
            1 => "kretprobe",
            2 => "uprobe",
            3 => "uretprobe",
            4 => "uprobe(by-sym)",
            5 => "uretprobe(by-sym)",
            6 => "fentry",
            7 => "fexit",
            8 => "tracepoint",
            9 => "usdt",
            _ => "?",
        };
        let target_pretty = match (*probe_type, uprobe) {
            (2 | 3, Some(u)) => format!("{} +0x{:x}", u.guest_path, u.file_offset),
            (4 | 5, Some(u)) => format!("{}:{} (kernel-resolved)", u.basename, u.symbol),
            (9, Some(u)) => format!(
                "{} usdt:{}:{} (kernel-resolved via .note.stapsdt)",
                u.basename, u.sdt_provider, u.symbol
            ),
            (_, _) => target.clone(),
        };
        if uprobe.is_some() {
            eprintln!(
                "[bifrost] prog #{}: {} insns, {} target={} ({}), schema={} fields ({}-byte records), {} map(s)",
                i,
                ebpf.len() / 8,
                kind,
                target_pretty,
                pt,
                schema.fields.len(),
                schema.record_size(),
                maps.len()
            );
            continue;
        }
        eprintln!(
            "[bifrost] prog #{}: {} insns, target='{}:{}', schema={} fields ({}-byte records), {} map(s)",
            i,
            ebpf.len() / 8,
            target,
            pt,
            schema.fields.len(),
            schema.record_size(),
            maps.len()
        );
    }
    eprintln!(
        "[bifrost] wrote {} ({} prog(s), {} bytes)",
        wrapper_path.display(),
        programs.len(),
        wrapper_path.metadata().map(|m| m.len()).unwrap_or(0)
    );
    let _ = btf_bytes_for_wrapper; // unused since BFR7 retirement of fingerprint

    Ok(LinuxCompileOutput {
        programs,
        parsed_source,
        btf_bytes: btf_bytes_for_wrapper,
        wrapper_path,
        xstack_enabled,
        xstack_depth,
        xstack_mode,
    })
}
