// CLI argument parsing for the `bifrost` binary.
//
// Migrated from a hand-rolled parse loop to clap derive (Oxide-
// style; per Rain @ rust-cli-recommendations.sunshowers.io: "use
// clap, do not write a parser by hand.").  The public surface
// (`Args`, `ExtraProg`, `parse_args`, `default_vmlinux`,
// `project_path`, `find_project_root`) is preserved bit-for-bit
// so callers in cli/runtime.rs and bin/bifrost.rs see no behavior
// change.  Internally the parsing is now `clap::Parser` derive.
//
// CLI shape (preserved):
//
//   bifrost -p <pid> -s <file> [opts]    attach-mode trace
//   bifrost -p <pid> <file>              positional file form
//                                        (also for shebang dispatch)
//   bifrost attach <pid>                 control-SHM smoke test
//   bifrost ls                           list observable libkrun pids
//   bifrost -l [pattern]                 enumerate kprobes
//   bifrost --emit-ebpf <out> -s <file>  wrapper-only
//
// Subcommand-vs-flag handling:
//   - `ls` and `attach` are clap subcommands.
//   - everything else (`-l`, `-n`, `-s`, `-p`, etc.) lives at the
//     top-level Cli struct and is interpreted in trace mode.
//   - positional FILE on the top-level is read as the D source
//     when no `-n`/`-s` was given; if `-l` is set, the positional
//     becomes the list-pattern instead (matches the original
//     parser's branchy behavior).

use clap::{Parser, Subcommand};
use std::env;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

/// Errors `parse_args` can return.  Oxide-style: typed enum at
/// the module boundary; `From<ArgsError> for String` bridges to
/// the still-stringly-typed legacy callers (none today).
#[derive(Debug, Error)]
pub enum ArgsError {
    #[error("read {path}: {source}")]
    ReadScript {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("unexpected positional argument: {0}")]
    UnexpectedPositional(String),

    #[error("{0}")]
    Invalid(String),
}

impl From<ArgsError> for String {
    fn from(err: ArgsError) -> String {
        err.to_string()
    }
}

/// Walk up from the bifrost binary's location looking for the
/// project-bifrost source tree, which is the natural default for
/// resolving every other path (smolvm dylib dir, libkrunfw bundle,
/// vmlinux, demo D scripts). Markers we accept:
///
///   - `BIFROST_ROOT` env var (explicit override, highest priority)
///   - directory containing `host/bifrost/Cargo.toml`
///   - `.gitmodules` next to a `host/` and `guest/` subtree
///
/// Returns `None` if the binary lives outside any recognizable
/// tree (e.g. when shipped via a package manager); callers should
/// then require the env var instead.
pub fn find_project_root() -> Option<PathBuf> {
    if let Ok(p) = env::var("BIFROST_ROOT") {
        return Some(PathBuf::from(p));
    }
    let exe = env::current_exe().ok()?;
    let mut dir = exe
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))?;
    loop {
        if dir.join("host/bifrost/Cargo.toml").is_file() {
            return Some(dir);
        }
        if dir.join(".gitmodules").is_file()
            && dir.join("host").is_dir()
            && dir.join("guest").is_dir()
        {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn project_path(rel: &str, env_override: &str, hint: &str) -> String {
    if let Ok(p) = env::var(env_override) {
        return p;
    }
    if let Some(root) = find_project_root() {
        return root.join(rel).to_string_lossy().into_owned();
    }
    eprintln!(
        "[bifrost] WARNING: project root not detected; {} is unset and there's no relative \
         fallback for {}. Set BIFROST_ROOT or {} to point at the right path.",
        env_override, hint, env_override
    );
    rel.to_string()
}

pub fn default_vmlinux() -> String {
    // BTF ids are kernel-build-specific. Without matching BTF the
    // emitted kfunc btf_ids won't resolve in the guest verifier and
    // bifrost_verify_prog returns -EINVAL with "kernel btf_id N is
    // not a function" in dmesg. Smolvm's libkrunfw is the canonical
    // kernel source.
    project_path(
        "third_party/smolvm/libkrunfw/linux-6.12.76/vmlinux",
        "BIFROST_VMLINUX",
        "the unstripped vmlinux ELF",
    )
}

/// One entry in the per-clause multi-action fan-out list.  Each
/// becomes its own eBPF program with its own kprobe slot.
#[derive(Clone, Copy)]
pub enum ExtraProg {
    /// Plain action (DIFEXPR / USTACK / STACK) at `action_idx`.
    Action { action_idx: usize },
    /// Additional agg sub-chain whose value DIFEXPR is at
    /// `chain_start`.  The AGG action is the first AGG-shaped action
    /// at index >= chain_start.
    AggChain { chain_start: usize },
    /// `clear(@agg)`.  Emits a tiny standalone program that
    /// loads the agg map's fake fd into `r1` and calls
    /// `bifrost_kfunc_clear_agg` (which walks the map's per-CPU
    /// slots and zeroes them).  The fake_fd is the same one used
    /// by the main agg-chain program in this clause.
    ClearAgg { fake_fd: i32 },
}

/// The final dispatch-shape consumed by `cli::runtime::*`.  Built
/// from the clap-parsed `Cli` below.  Field set is the same as
/// the pre-clap struct so call sites don't change.
pub struct Args {
    pub script: Option<String>,
    pub target: Option<String>,
    pub emit_ebpf: Option<String>,
    pub list: bool,
    pub list_pattern: Option<String>,
    pub xstack_fold: Option<String>,
    /// Minimum self-trace level to render to stderr.
    /// `None` = self-trace disabled; `Some(SELF_LEVEL_*)` enables
    /// rendering at that floor and above.  Parsed from the
    /// `--trace-self[=LEVEL]` flag.
    pub trace_self_level: Option<u8>,
    pub attach_pid: Option<u32>,
    pub attach_raw_ebpf: Option<String>,
    /// FreeBSD kernel-only native-DTrace session request.
    pub freebsd_dtrace: Option<FreebsdDtraceArgs>,
    pub trace_pid: Option<u32>,
    pub do_ls: bool,
    pub preserve: bool,
    pub host_resolve_uprobe: bool,
    pub rootfs: Option<String>,
    pub usdt_workspace_target: bool,
    /// Direct data-SHM attach path. The VMM-rendered compatibility
    /// path has been retired, so this is always true for trace
    /// attaches.
    pub direct_data_render: bool,
    /// Profiling: target pid for `bifrost profile -p $PID`.
    /// `Some(pid)` short-circuits the trace path and runs the
    /// profile-sample consumer (cli/profile::run_profile) instead.
    /// libkrun no longer generates samples; until guest-side
    /// profile records land, the CLI falls back to a local synthetic
    /// sample for the demo path.
    pub profile_pid: Option<u32>,
    pub profile_max_samples: Option<u32>,
    /// Conduit diagnostic: map the advertised data SHM
    /// region and print its current header/producer state.
    pub data_pid: Option<DataArgs>,
    /// Multi-target orchestrator.  Populated when the user
    /// invokes `bifrost orchestrate <plan>`; short-circuits the
    /// trace path.
    pub orchestrate: Option<OrchestrateArgs>,
}

pub struct OrchestrateArgs {
    pub plan_path: String,
    pub source_file: Option<String>,
    pub script_text: Option<String>,
    pub dry_run: bool,
}

pub struct DataArgs {
    pub pid: u32,
    pub records: usize,
    pub watch_ms: u64,
    pub interval_ms: u64,
}

pub struct FreebsdDtraceArgs {
    pub pid: u32,
    pub dof: Option<String>,
    pub source_file: Option<String>,
    pub script: Option<String>,
    pub expected: Option<String>,
    pub probe_id: u32,
    pub records: usize,
    pub no_render: bool,
}

#[derive(Parser, Debug)]
#[command(
    name = "bifrost",
    version,
    about = "DTrace-shaped runner for project-bifrost",
    long_about = "Compile a D probe action, ship it through the bifrost virtio bridge \
                  into the guest kernel, and stream the resulting records to stdout \
                  correlated with macOS-side DTrace probes against the smolvm libkrun \
                  process.\n\
                  \n\
                  A D source can mix host-side and guest-side clauses; bifrost \
                  dispatches `bifrost:` clauses through the DIF→eBPF lowering \
                  (pushed into the target via control SHM), and everything else \
                  (syscall:, pid$:, BEGIN, END) through the in-process libdtrace \
                  consumer attached to the same target pid.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,

    /// D program text (single source)
    #[arg(short = 'n', value_name = "script", conflicts_with_all = ["script_file", "positional"])]
    script_text: Option<String>,

    /// D program file
    #[arg(short = 's', value_name = "file", conflicts_with_all = ["script_text", "positional"])]
    script_file: Option<String>,

    /// Attach to an externally-running smolvm libkrun process and run the trace
    #[arg(short = 'p', long = "trace-pid", value_name = "pid")]
    trace_pid: Option<u32>,

    /// Keep queued LOAD_PROGs in the target on detach (default: reap the queue)
    #[arg(long)]
    preserve: bool,

    /// Resolve guest_user uprobes on the host against a staged rootfs.
    /// Default is kernel-resolved uprobes: the guest driver finds the
    /// running task and parses task->exe_file.
    #[arg(long = "host-resolve-uprobe")]
    host_resolve_uprobe: bool,

    /// Staged guest rootfs used with --host-resolve-uprobe.
    #[arg(long = "rootfs", value_name = "path")]
    rootfs: Option<String>,

    /// For USDT probes, target /workspace/<binary> in the guest.
    /// Useful for demos that copy a binary out of overlayfs onto
    /// smolvm's ext4 workspace so uprobe_register can patch it.
    #[arg(long = "usdt-workspace-target")]
    usdt_workspace_target: bool,

    /// Render per-fire guest records directly from data SHM instead of RECORD_PUSH.
    /// This is the only supported attach path; the flag remains as an explicit spelling for scripts.
    #[arg(long = "direct-data-render")]
    direct_data_render: bool,

    /// Retired compatibility path. libkrun no longer parses BFR7 wrappers or renders records.
    #[arg(long = "legacy-vmm-render", conflicts_with = "direct_data_render")]
    legacy_vmm_render: bool,

    /// List available kprobes (analog of `dtrace -l`).  No VM boot —
    /// walks vmlinux's symtab on disk.  Optional substring or *-glob
    /// pattern filters.
    #[arg(short = 'l')]
    list: bool,

    /// Override target kprobe symbol (default: extracted from
    /// `bifrost:_:<sym>:entry` probe spec)
    #[arg(long, value_name = "sym")]
    target: Option<String>,

    /// Write the BFR7 wrapper, don't push it
    #[arg(long = "emit-ebpf", value_name = "path")]
    emit_ebpf: Option<String>,

    /// Write FlameGraph-foldable cross-domain stacks on shutdown
    #[arg(long = "xstack-fold", value_name = "path")]
    xstack_fold: Option<String>,

    /// Render structured self-trace events from each layer to
    /// stderr, filtered by level (Bifrost-on-Bifrost diagnostics).
    /// Layer / subsystem / level surface in a
    /// `[layer/subsys/level] msg {key=val,…}` line.  Use
    /// `--trace-self` (no value) for INFO+, `--trace-self=debug`
    /// for everything down to debug, `--trace-self=warn` for
    /// warnings + errors only.  Off by default.
    #[arg(long = "trace-self", value_name = "level", default_missing_value = "info", num_args = 0..=1)]
    trace_self: Option<String>,

    /// First non-flag positional is a D script file path (also
    /// matches the form used by `#!/usr/bin/env bifrost`
    /// shebang dispatch in D scripts).  When `-l` is set the
    /// positional becomes the list-pattern instead.
    #[arg(value_name = "FILE_OR_PATTERN")]
    positional: Option<String>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// List libkrun processes observable via /bifrost-<pid>
    Ls,
    /// Probe a libkrun control SHM endpoint (smoke test)
    Attach {
        /// Target libkrun process pid
        pid: u32,
        /// Ferry a pre-built BFR7 wrapper instead of a dummy probe
        #[arg(long = "raw-ebpf", value_name = "path")]
        raw_ebpf: Option<String>,
    },
    /// Ask a FreeBSD guest conduit to run the host-supplied kernel DTrace proof
    FreebsdProof {
        /// Target conduit-backend or libkrun process pid
        pid: u32,
        /// Load this host-selected DOF blob instead of the built-in proof fixture
        #[arg(long = "dof", value_name = "path", conflicts_with_all = ["source_file", "script"])]
        dof: Option<String>,
        /// Compile this D source file to FreeBSD-compatible DOF on the host
        #[arg(short = 's', long = "source", value_name = "path", conflicts_with_all = ["dof", "script"])]
        source_file: Option<String>,
        /// Compile this inline D source to FreeBSD-compatible DOF on the host
        #[arg(short = 'n', long = "script", value_name = "script", conflicts_with_all = ["dof", "source_file"])]
        script: Option<String>,
        /// Optional expected trace() value, decimal or 0x-prefixed
        #[arg(long = "expected", value_name = "value")]
        expected: Option<String>,
        /// Probe id used by the native session's schema table
        #[arg(long = "probe-id", value_name = "id", default_value_t = 2)]
        probe_id: u32,
        /// Maximum matching native records to render from data SHM
        #[arg(long = "records", value_name = "N", default_value_t = 8)]
        records: usize,
        /// Only send the session and report the control response
        #[arg(long = "no-render")]
        no_render: bool,
    },
    /// Consume profile-N samples from a target.
    /// Performs OBSERVER_HELLO with FEATURE_PROFILE_N requested,
    /// then drains D4_KIND_PROFILE_SAMPLE records from the rsp ring
    /// and renders each as one line. If no transport sample arrives,
    /// emits one CLI-owned synthetic sample so the renderer/demo path
    /// remains available after removing VMM profile semantics.
    Profile {
        /// Target libkrun process pid
        pid: u32,
        /// Stop after this many samples (default 16)
        #[arg(long = "max-samples", value_name = "N")]
        max_samples: Option<u32>,
    },
    /// Map the advertised data SHM region and print its raw header
    Data {
        /// Target libkrun process pid
        pid: u32,
        /// Maximum raw record headers to print
        #[arg(long = "records", value_name = "N", default_value_t = 8)]
        records: usize,
        /// Keep sampling the data SHM for this many milliseconds
        #[arg(long = "watch-ms", value_name = "MS", default_value_t = 0)]
        watch_ms: u64,
        /// Poll interval for --watch-ms
        #[arg(long = "interval-ms", value_name = "MS", default_value_t = 100)]
        interval_ms: u64,
    },
    /// Multi-target session orchestrator.
    ///
    /// Parses a plan file (`plan.yaml`), resolves each D clause to a
    /// concrete target via the cross-kernel router, and reports the
    /// per-target routing. In dry-run mode it prints the routing and
    /// exits 0; without --dry-run it dispatches to the per-target
    /// backend session paths (today: N=1 only — N=2 transport plumbing
    /// follows).
    Orchestrate {
        /// Plan file (YAML; see host/bifrost/src/plan.rs for shape)
        #[arg(value_name = "plan.yaml")]
        plan: String,
        /// D source override — file path. Defaults to the plan's
        /// `script_file` or `script` field.
        #[arg(short = 's', long = "source", value_name = "path")]
        source_file: Option<String>,
        /// D source override — inline text. Defaults to the plan's
        /// `script` field.
        #[arg(short = 'n', long = "script", value_name = "script")]
        script_text: Option<String>,
        /// Parse + route only; print the routing plan and exit 0
        /// without touching any conduit. Useful for plan validation
        /// and CI gates.
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
}

pub fn parse_args() -> Result<Args, ArgsError> {
    let cli = Cli::parse();
    if cli.legacy_vmm_render {
        return Err(ArgsError::Invalid(
            "--legacy-vmm-render has been retired; the VMM now accepts opaque LOAD_PROG bytes and the CLI renders direct data SHM".into(),
        ));
    }

    // Resolve script: -n inline, -s file, or positional file (when
    // not in -l list mode).
    let mut script: Option<String> = cli.script_text;
    if let Some(path) = cli.script_file {
        let body = fs::read_to_string(&path).map_err(|source| ArgsError::ReadScript {
            path: path.clone(),
            source,
        })?;
        script = Some(body);
    }

    // Positional handling: in list mode it's the pattern; otherwise
    // it's an implicit -s.  This mirrors the original parser's
    // branchy behavior.
    let mut list_pattern: Option<String> = None;
    if let Some(arg) = cli.positional {
        if cli.list {
            list_pattern = Some(arg);
        } else if script.is_none() {
            let body = fs::read_to_string(&arg).map_err(|source| ArgsError::ReadScript {
                path: arg.clone(),
                source,
            })?;
            script = Some(body);
        } else {
            return Err(ArgsError::UnexpectedPositional(arg));
        }
    }

    // Subcommand → trace-mode flag mapping.  `bifrost ls` and
    // `bifrost attach <pid>` short-circuit the trace path; the
    // existing run() dispatcher reads do_ls / attach_pid /
    // attach_raw_ebpf to decide which branch to take.
    let (
        do_ls,
        attach_pid,
        attach_raw_ebpf,
        freebsd_dtrace,
        profile_pid,
        profile_max_samples,
        data_pid,
        orchestrate,
    ) = match cli.command {
        Some(CliCommand::Ls) => (true, None, None, None, None, None, None, None),
        Some(CliCommand::Attach { pid, raw_ebpf }) => {
            (false, Some(pid), raw_ebpf, None, None, None, None, None)
        }
        Some(CliCommand::FreebsdProof {
            pid,
            dof,
            source_file,
            script,
            expected,
            probe_id,
            records,
            no_render,
        }) => (
            false,
            None,
            None,
            Some(FreebsdDtraceArgs {
                pid,
                dof,
                source_file,
                script,
                expected,
                probe_id,
                records,
                no_render,
            }),
            None,
            None,
            None,
            None,
        ),
        Some(CliCommand::Profile { pid, max_samples }) => {
            (false, None, None, None, Some(pid), max_samples, None, None)
        }
        Some(CliCommand::Data {
            pid,
            records,
            watch_ms,
            interval_ms,
        }) => (
            false,
            None,
            None,
            None,
            None,
            None,
            Some(DataArgs {
                pid,
                records,
                watch_ms,
                interval_ms,
            }),
            None,
        ),
        Some(CliCommand::Orchestrate {
            plan,
            source_file,
            script_text,
            dry_run,
        }) => (
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(OrchestrateArgs {
                plan_path: plan,
                source_file,
                script_text,
                dry_run,
            }),
        ),
        None => (false, None, None, None, None, None, None, None),
    };

    let trace_self_level = cli.trace_self.as_deref().and_then(|s| match s {
        "trace" => Some(bifrost_wire::SELF_LEVEL_TRACE),
        "debug" => Some(bifrost_wire::SELF_LEVEL_DEBUG),
        "info" | "" => Some(bifrost_wire::SELF_LEVEL_INFO),
        "warn" => Some(bifrost_wire::SELF_LEVEL_WARN),
        "error" => Some(bifrost_wire::SELF_LEVEL_ERROR),
        // Unknown values default to INFO (matches `--trace-self`
        // bare).  An explicit level outside the closed enum is a
        // typo, not a feature; render at INFO and let the user
        // notice via stderr — never silently disable.
        _ => Some(bifrost_wire::SELF_LEVEL_INFO),
    });

    Ok(Args {
        script,
        target: cli.target,
        emit_ebpf: cli.emit_ebpf,
        list: cli.list,
        list_pattern,
        xstack_fold: cli.xstack_fold,
        trace_self_level,
        attach_pid,
        attach_raw_ebpf,
        freebsd_dtrace,
        trace_pid: cli.trace_pid,
        do_ls,
        preserve: cli.preserve,
        host_resolve_uprobe: cli.host_resolve_uprobe,
        rootfs: cli.rootfs,
        usdt_workspace_target: cli.usdt_workspace_target,
        direct_data_render: true,
        profile_pid,
        profile_max_samples,
        data_pid,
        orchestrate,
    })
}
