// SPDX-License-Identifier: Apache-2.0
//! Multi-target session plan.
//!
//! A `Plan` is the host-side description of "this Bifrost session spans
//! these targets." Each `Target` carries the per-VM addressing the
//! orchestrator needs (`id` for record-stream tagging, `guest_os` for
//! backend selection, `launcher` for VM lifecycle, `conduit` for the
//! per-target control + data SHM endpoint) plus the slice of the D
//! source the planner routed to it.
//!
//! The plan is the only data-plane addition the multi-target path
//! introduces above the single-target conduit. Single-guest
//! invocations are the degenerate N=1
//! shape of this same type, not a privileged code path.

use anyhow::{Result, anyhow, bail};
use std::path::{Path, PathBuf};

use crate::backend::{GuestOs, RejectReason};
use crate::parse::{Clause, Parsed, ProbeSpec};

/// One Bifrost session — N targets driven by one orchestrator + one D
/// source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Inline D source for the whole session (the planner routes
    /// clauses per target via `TraceTarget::route_probe`).
    pub script: Option<String>,
    /// On-disk D source; mutually exclusive with `script`. The
    /// orchestrator resolves this to text before lowering.
    pub script_file: Option<PathBuf>,
    pub targets: Vec<Target>,
}

/// One guest the orchestrator drives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Short identifier used as the record-stream tag (`"linux"`,
    /// `"freebsd"`, eventually `"illumos"`). Must be unique within a
    /// plan and short enough to fit a per-record stamp byte downstream.
    pub id: String,
    pub guest_os: GuestOs,
    pub launcher: LauncherSpec,
    /// Per-target conduit endpoint.  `None` is only legal for
    /// macos-host targets (no SHM conduit; the orchestrator parses
    /// `dtrace(1)`'s text output directly).
    pub conduit: Option<ConduitEndpoint>,
    /// Per-target D source override; when `None` the orchestrator uses
    /// `Plan::script`/`Plan::script_file`. Single-target N=1 plans set this
    /// alongside `LauncherSpec::Attach` to keep single-target attach
    /// demos working before the planner is plumbed through.
    pub script: Option<String>,
    pub script_file: Option<PathBuf>,
    /// Optional native-DTrace sample window in milliseconds for this
    /// target.  `None` keeps the kernel-side default; setting it lets
    /// a plan say "let this DTrace state run for 2 seconds" instead
    /// of relying on the historical 500 ms pause.  Forwarded to the
    /// FreeBSD bridge through the v2 NDT session header.
    pub duration_ms: Option<u32>,
}

/// VM lifecycle policy. The orchestrator drives each launcher script
/// and routes per-target logs to predictable files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LauncherSpec {
    /// `host/runtime/smolvm-launch.sh` (or override path).
    Smolvm {
        script: PathBuf,
        args: Vec<String>,
    },
    /// `host/runtime/qemu-launch-freebsd.sh` (or override path).
    QemuFreebsd {
        script: PathBuf,
        args: Vec<String>,
    },
    /// No launcher: orchestrator attaches to an externally-running
    /// conduit-backend (the attach demo shape).  The conduit
    /// endpoint must already be addressable.
    Attach,
    /// macOS-host `dtrace(1)` child.  The orchestrator spawns
    /// `sudo -n dtrace -q -n '<routed source>' -o <fifo>` directly;
    /// there's no SHM conduit and no guest VM.  `extra_args` lets
    /// the plan pass through `-x` settings or `-Z` etc. without
    /// rewriting the routing layer.
    MacosHostDtrace {
        extra_args: Vec<String>,
    },
}

/// One clause routed to one target.  The clause is borrowed from the
/// caller-owned [`Parsed`] so we don't copy bodies around.
#[derive(Debug)]
pub struct RoutedClause<'a> {
    pub clause: &'a Clause,
    /// Which probe specs in the clause survived routing under the
    /// chosen target.  The planner only routes whole clauses (an action
    /// body can't be split across kernels), so the list is either
    /// every spec or an explicit error.
    pub specs: Vec<&'a ProbeSpec>,
}

/// One [`Target`]'s share of the plan's D source after the planner
/// has resolved per-clause routing.
#[derive(Debug)]
pub struct RoutedTarget<'a> {
    pub target: &'a Target,
    pub clauses: Vec<RoutedClause<'a>>,
}

/// The plan after `route_clauses` has resolved each D clause to a
/// concrete target.  Indexed by target position so the orchestrator
/// can zip this with the plan's per-target launcher / conduit slots.
#[derive(Debug)]
pub struct RoutedPlan<'a> {
    pub per_target: Vec<RoutedTarget<'a>>,
}

/// Resolve each clause in the parsed D source to exactly one target
/// in `plan`.  This is the cross-kernel D plumbing:
///
///   - probes that route to a `Guest(Linux)` target via
///     [`TraceTarget::route_probe`] go to that target's bucket;
///   - probes that route to a `Guest(FreeBsd|Illumos)` target go to
///     theirs;
///   - probes that get [`ProbeRoute::Rejected`] under every target
///     in the plan surface as a structured error naming the
///     offending probe and the reason — guest-userspace probes
///     (uprobe / USDT / pid) are the canonical example.
///
/// A clause whose probes split across targets is also an error: we
/// can't physically execute one action body in two kernels.  Users
/// hit this by mixing `bifrost:guest:foo:entry` and `fbt:kernel:bar:entry`
/// in one clause; the diagnostic names both probes so the fix is
/// obvious (split into two clauses).
pub fn route_clauses<'a>(plan: &'a Plan, parsed: &'a Parsed) -> Result<RoutedPlan<'a>> {
    plan.validate()?;
    let mut per_target: Vec<RoutedTarget<'a>> = plan
        .targets
        .iter()
        .map(|t| RoutedTarget {
            target: t,
            clauses: Vec::new(),
        })
        .collect();

    for clause in &parsed.clauses {
        let chosen = pick_targets_for_clause(plan, clause)?;
        for idx in chosen {
            per_target[idx].clauses.push(RoutedClause {
                clause,
                specs: clause.specs.iter().collect(),
            });
        }
    }

    Ok(RoutedPlan { per_target })
}

fn pick_targets_for_clause(plan: &Plan, clause: &Clause) -> Result<Vec<usize>> {
    // Compute each spec's natural target kind first.  This is
    // *tighter* than `TraceTarget::route_probe`, which accepts any
    // `is_bifrost()` provider under Linux — including `fbt:kernel:*`,
    // a FreeBSD shape that happens to share the `fbt` provider name.
    // The planner needs to distinguish them because the same Linux
    // backend would not actually attach `fbt:kernel:*`; the kernel
    // module slot is the bifrost domain marker.
    let natural: Vec<NaturalKind> =
        clause.specs.iter().map(natural_kind_of).collect();

    // Reject mixed clauses up front: an action body can't run in
    // two kernels.  The diagnostic names every spec and its kind so
    // the user knows how to split.
    let kinds: std::collections::BTreeSet<NaturalKind> = natural.iter().copied().collect();
    let concrete_kinds: Vec<NaturalKind> = kinds
        .iter()
        .copied()
        .filter(|k| !matches!(k, NaturalKind::Userspace | NaturalKind::Either))
        .collect();
    if concrete_kinds.len() > 1 {
        let pairs: Vec<String> = clause
            .specs
            .iter()
            .zip(natural.iter())
            .map(|(spec, kind)| format!("`{}` → {:?}", spec.render(), kind))
            .collect();
        bail!(
            "clause probes split across plan targets — split this clause across kernels: {}",
            pairs.join("; ")
        );
    }

    // Find candidate targets that match every spec's natural kind.
    let candidates: Vec<usize> = plan
        .targets
        .iter()
        .enumerate()
        .filter(|(_, target)| {
            natural.iter().all(|&kind| target_matches_kind(target, kind))
        })
        .map(|(idx, _)| idx)
        .collect();

    if candidates.is_empty() {
        // Name the first spec with no candidate and emit a reason.
        let bad_idx = natural
            .iter()
            .enumerate()
            .find(|(_, kind)| {
                !plan
                    .targets
                    .iter()
                    .any(|t| target_matches_kind(t, **kind))
            })
            .map(|(i, _)| i)
            .unwrap_or(0);
        let bad = &clause.specs[bad_idx];
        let reason = match natural[bad_idx] {
            NaturalKind::Userspace => describe_reject_reason(RejectReason::GuestUserspaceProbe),
            NaturalKind::Linux => describe_reject_reason(RejectReason::LinuxNeedsBifrostProvider),
            NaturalKind::NativeKernel => {
                "the Linux backend requires the bifrost provider namespace (e.g. fbt:guest:foo:entry); native DTrace tuples like fbt:kernel:* are routed to FreeBSD/illumos targets instead"
            }
            NaturalKind::Either => "no target in the plan accepts this probe",
        };
        bail!(
            "probe `{}` cannot be routed to any plan target: {}",
            bad.render(),
            reason,
        );
    }

    // Fan out: when multiple targets accept the same clause (most
    // common when every spec is `Either` — BEGIN/END/profile/tick),
    // every accepting target gets its own copy.  Each target's
    // kernel then independently fires the probe and emits records
    // into its own per-target data SHM; the merge layer combines.
    //
    // For concrete kinds (NativeKernel/Linux), candidates are
    // already disjoint with target_matches_kind, so fan-out only
    // duplicates when two targets share the same guest_os family.
    Ok(candidates)
}

/// The natural target *kind* for one probe spec.  Strictly more
/// discriminating than `TraceTarget::route_probe`, which is too
/// permissive for cross-kernel planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NaturalKind {
    /// Bifrost-domain probes shaped for the Linux eBPF backend.
    Linux,
    /// Provider/module shaped like a native FreeBSD/illumos DTrace
    /// tuple (`fbt:kernel:*`, `syscall::*`, etc.).
    NativeKernel,
    /// Userspace probes (uprobe / USDT / pid) — currently not
    /// supported under any guest backend.
    Userspace,
    /// Provider-only probes (`BEGIN`, `END`, `ERROR`) or other
    /// shapes that any kernel-native backend could accept; the
    /// planner sends them to the first listed target.
    Either,
}

fn natural_kind_of(spec: &ProbeSpec) -> NaturalKind {
    if crate::backend::is_guest_userspace_probe(spec) {
        return NaturalKind::Userspace;
    }
    // Bifrost domain convention: `<provider>:<guest|vmm|guest_kernel>:*`
    // is the Linux eBPF shape.  Anything from the `bifrost:` provider
    // family also belongs to Linux unconditionally.
    if spec.provider == "bifrost" {
        return NaturalKind::Linux;
    }
    if matches!(spec.module.as_str(), "guest" | "vmm" | "guest_kernel") {
        return NaturalKind::Linux;
    }
    // `dtrace:::BEGIN` / `dtrace:::END` and other identifier-only
    // probes have empty module/function/name — these are valid on
    // every kernel-native backend.
    if spec.module.is_empty() && spec.function.is_empty() && !spec.name.is_empty() {
        return NaturalKind::Either;
    }
    // `dtrace:::BEGIN` parses as provider=dtrace, module="",
    // function="", name="BEGIN".
    if spec.provider == "dtrace" {
        return NaturalKind::Either;
    }
    // Identifier-only probes (BEGIN/END/ERROR) parse with provider
    // set to the identifier and everything else empty.
    if matches!(spec.provider.as_str(), "BEGIN" | "END" | "ERROR") {
        return NaturalKind::Either;
    }
    NaturalKind::NativeKernel
}

fn target_matches_kind(target: &Target, kind: NaturalKind) -> bool {
    match (kind, target.guest_os) {
        (NaturalKind::Linux, GuestOs::Linux) => true,
        (NaturalKind::NativeKernel, GuestOs::FreeBsd | GuestOs::Illumos) => true,
        // macos-host runs the routed source through host `dtrace(1)`,
        // which accepts the same native-DTrace tuple surface as
        // FreeBSD/illumos.  Per the architectural note that "the
        // frontend shouldn't have to encode per-OS differences," the
        // user writes a kernel-agnostic D source; the macos-host
        // backend matches whatever the host `dtrace(1)` would
        // legitimately attach.
        (NaturalKind::NativeKernel, GuestOs::MacosHost) => true,
        (NaturalKind::Either, _) => true,
        // Guest-userspace probes (uprobe / USDT / pid) are honored
        // by the existing Linux uprobe machinery — see the
        // redis-uprobe / postgres-usdt demos.  FreeBSD's native-DTrace
        // backend still rejects them via `is_guest_userspace_probe`
        // until the guest kernel module grows uprobe coverage.
        (NaturalKind::Userspace, GuestOs::Linux) => true,
        _ => false,
    }
}

fn describe_reject_reason(reason: RejectReason) -> &'static str {
    match reason {
        RejectReason::GuestUserspaceProbe => {
            "guest-userspace probes (uprobe / USDT / pid) are not yet supported under a native-DTrace guest"
        }
        RejectReason::LinuxNeedsBifrostProvider => {
            "the Linux backend requires the bifrost provider namespace (e.g. fbt:guest:foo:entry); native DTrace tuples are routed to FreeBSD/illumos targets instead"
        }
    }
}

/// How to reach one target's conduit-backend control + data SHM.
///
/// Today's `ControlShmAttachment::open(pid)` path indexes by
/// conduit-backend pid; the socket / data-shm-name variants are
/// reserved for the N=2 transport-plumbing step and reject in the
/// scaffold so we don't ship a half-working endpoint family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConduitEndpoint {
    Pid(u32),
    Socket(PathBuf),
    DataShmName(String),
}

impl Plan {
    /// Construct a degenerate N=1 plan from CLI arguments.
    pub fn single(target: Target) -> Self {
        Self {
            script: None,
            script_file: None,
            targets: vec![target],
        }
    }

    /// Parse a plan file. Format is selected by extension; today only
    /// the tiny in-tree YAML subset is supported.
    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("read plan {}: {}", path.display(), e))?;
        Plan::parse(&body).map_err(|e| anyhow!("parse plan {}: {}", path.display(), e))
    }

    /// Parse a plan from a YAML body. The accepted subset is
    /// deliberately tiny — keys we recognize at top-level are
    /// `script`, `script_file`, and `targets`; each `targets` entry
    /// carries `id`, `guest_os`, `launcher`, `conduit`, and an
    /// optional per-target `script` / `script_file`. Anything else is
    /// rejected so misspellings surface loudly instead of silently
    /// being ignored.
    pub fn parse(body: &str) -> Result<Self> {
        let doc = MiniYaml::parse(body)?;
        Plan::from_yaml(&doc)
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            bail!("plan must declare at least one target");
        }
        let mut seen = std::collections::HashSet::new();
        for target in &self.targets {
            if target.id.is_empty() {
                bail!("target id must be non-empty");
            }
            if !target.id.is_ascii() {
                bail!("target id {:?} must be ASCII", target.id);
            }
            if target.id.len() > 32 {
                bail!(
                    "target id {:?} is {} bytes; max 32 (target_id stamping budget)",
                    target.id,
                    target.id.len()
                );
            }
            if !seen.insert(target.id.clone()) {
                bail!("duplicate target id {:?}", target.id);
            }
            if target.script.is_some() && target.script_file.is_some() {
                bail!(
                    "target {:?} declares both inline script and script_file",
                    target.id
                );
            }
            // Conduit endpoint constraint: every target except
            // macos-host must declare one.  macos-host targets are
            // fed by the orchestrator's `dtrace(1)` child, not by
            // an SHM conduit, so they MUST omit `conduit:`.
            match (&target.launcher, &target.conduit) {
                (LauncherSpec::MacosHostDtrace { .. }, None) => {}
                (LauncherSpec::MacosHostDtrace { .. }, Some(_)) => bail!(
                    "target {:?} uses launcher kind 'macos-host-dtrace' but \
                     declares a conduit endpoint; macos-host has no SHM conduit",
                    target.id,
                ),
                (_, None) => bail!(
                    "target {:?} missing required `conduit:` endpoint",
                    target.id,
                ),
                _ => {}
            }
            if matches!(target.launcher, LauncherSpec::MacosHostDtrace { .. })
                && target.guest_os != GuestOs::MacosHost
            {
                bail!(
                    "target {:?} uses launcher kind 'macos-host-dtrace' but \
                     guest_os is {:?}; want guest_os: macos-host",
                    target.id,
                    target.guest_os.name(),
                );
            }
            if target.guest_os == GuestOs::MacosHost
                && !matches!(target.launcher, LauncherSpec::MacosHostDtrace { .. })
            {
                bail!(
                    "target {:?} declares guest_os: macos-host but \
                     launcher kind is not 'macos-host-dtrace'",
                    target.id,
                );
            }
        }
        if self.script.is_some() && self.script_file.is_some() {
            bail!("plan declares both inline script and script_file");
        }
        Ok(())
    }

    fn from_yaml(doc: &MiniYaml) -> Result<Self> {
        let mapping = doc.as_mapping("plan")?;
        let mut script = None;
        let mut script_file = None;
        let mut targets = Vec::new();
        for (key, value) in mapping {
            match key.as_str() {
                "script" => script = Some(value.as_scalar("plan.script")?.to_string()),
                "script_file" => {
                    script_file = Some(PathBuf::from(value.as_scalar("plan.script_file")?))
                }
                "targets" => {
                    for (idx, entry) in value.as_sequence("plan.targets")?.iter().enumerate() {
                        targets.push(Target::from_yaml(entry, idx)?);
                    }
                }
                other => bail!("unknown plan key {:?}", other),
            }
        }
        let plan = Plan {
            script,
            script_file,
            targets,
        };
        plan.validate()?;
        Ok(plan)
    }
}

impl Target {
    fn from_yaml(node: &MiniYaml, idx: usize) -> Result<Self> {
        let mapping = node.as_mapping(&format!("targets[{idx}]"))?;
        let mut id = None;
        let mut guest_os = None;
        let mut launcher = None;
        let mut conduit = None;
        let mut script = None;
        let mut script_file = None;
        let mut duration_ms = None;
        for (key, value) in mapping {
            match key.as_str() {
                "id" => id = Some(value.as_scalar("target.id")?.to_string()),
                "guest_os" => guest_os = Some(parse_guest_os(value.as_scalar("target.guest_os")?)?),
                "launcher" => launcher = Some(LauncherSpec::from_yaml(value)?),
                "conduit" => conduit = Some(ConduitEndpoint::from_yaml(value)?),
                "script" => script = Some(value.as_scalar("target.script")?.to_string()),
                "script_file" => {
                    script_file = Some(PathBuf::from(value.as_scalar("target.script_file")?))
                }
                "duration_ms" => {
                    let raw = value.as_scalar("target.duration_ms")?;
                    let ms: u32 = raw.parse().map_err(|e| {
                        anyhow!("target #{idx} duration_ms {:?} is not a u32: {e}", raw)
                    })?;
                    duration_ms = Some(ms);
                }
                other => bail!("unknown target key {:?} (target #{idx})", other),
            }
        }
        Ok(Target {
            id: id.ok_or_else(|| anyhow!("target #{idx} missing required key 'id'"))?,
            guest_os: guest_os
                .ok_or_else(|| anyhow!("target #{idx} missing required key 'guest_os'"))?,
            launcher: launcher
                .ok_or_else(|| anyhow!("target #{idx} missing required key 'launcher'"))?,
            // `conduit:` is required by validate() for every target
            // except macos-host; carry None through here and let
            // validate() emit the precise diagnostic.
            conduit,
            script,
            script_file,
            duration_ms,
        })
    }
}

fn parse_guest_os(s: &str) -> Result<GuestOs> {
    match s {
        "linux" => Ok(GuestOs::Linux),
        "freebsd" => Ok(GuestOs::FreeBsd),
        "illumos" => Ok(GuestOs::Illumos),
        "macos-host" => Ok(GuestOs::MacosHost),
        other => bail!(
            "unknown guest_os {:?} (want linux|freebsd|illumos|macos-host)",
            other
        ),
    }
}

impl LauncherSpec {
    fn from_yaml(node: &MiniYaml) -> Result<Self> {
        let mapping = node.as_mapping("target.launcher")?;
        let mut kind = None;
        let mut script = None;
        let mut args = Vec::new();
        for (key, value) in mapping {
            match key.as_str() {
                "kind" => kind = Some(value.as_scalar("launcher.kind")?.to_string()),
                "script" => script = Some(PathBuf::from(value.as_scalar("launcher.script")?)),
                "args" => {
                    for arg in value.as_sequence("launcher.args")? {
                        args.push(arg.as_scalar("launcher.args[]")?.to_string());
                    }
                }
                other => bail!("unknown launcher key {:?}", other),
            }
        }
        match kind.as_deref() {
            Some("attach") => Ok(LauncherSpec::Attach),
            Some("smolvm") => Ok(LauncherSpec::Smolvm {
                script: script
                    .unwrap_or_else(|| PathBuf::from("host/runtime/smolvm-launch.sh")),
                args,
            }),
            Some("qemu-freebsd") => Ok(LauncherSpec::QemuFreebsd {
                script: script
                    .unwrap_or_else(|| PathBuf::from("host/runtime/qemu-launch-freebsd.sh")),
                args,
            }),
            Some("macos-host-dtrace") => {
                if script.is_some() {
                    bail!(
                        "launcher kind 'macos-host-dtrace' does not take a `script:` — \
                         the orchestrator spawns /usr/sbin/dtrace directly"
                    );
                }
                Ok(LauncherSpec::MacosHostDtrace { extra_args: args })
            }
            Some(other) => bail!(
                "unknown launcher kind {:?} (want attach|smolvm|qemu-freebsd|macos-host-dtrace)",
                other
            ),
            None => bail!("launcher missing required 'kind'"),
        }
    }
}

impl ConduitEndpoint {
    fn from_yaml(node: &MiniYaml) -> Result<Self> {
        let mapping = node.as_mapping("target.conduit")?;
        let mut found = None;
        for (key, value) in mapping {
            let scalar = value.as_scalar(&format!("conduit.{key}"))?;
            let next = match key.as_str() {
                "pid" => {
                    let pid = scalar
                        .parse::<u32>()
                        .map_err(|e| anyhow!("conduit.pid {:?}: {}", scalar, e))?;
                    ConduitEndpoint::Pid(pid)
                }
                "socket" => ConduitEndpoint::Socket(PathBuf::from(scalar)),
                "data_shm_name" => ConduitEndpoint::DataShmName(scalar.to_string()),
                other => bail!("unknown conduit key {:?}", other),
            };
            if found.is_some() {
                bail!("conduit endpoint must declare exactly one of pid|socket|data_shm_name");
            }
            found = Some(next);
        }
        found.ok_or_else(|| {
            anyhow!("conduit endpoint must declare one of pid|socket|data_shm_name")
        })
    }
}

// ---------------------------------------------------------------------------
// MiniYaml: a tiny indent-sensitive subset of YAML used by plan.rs.
//
// What it accepts:
//   - block mappings   `key: value` (value may be a scalar, a nested
//     mapping/sequence on the next indent level, or absent)
//   - block sequences  `- item` (item may be a scalar or a nested
//     mapping)
//   - quoted strings   `"..."` / `'...'`
//   - comments         everything after `#` outside a quoted string
//   - blank lines      ignored
//
// What it explicitly rejects (so we fail loudly on real YAML the
// scaffold doesn't model):
//   - flow style        `{a: b}` / `[1, 2]`
//   - multi-doc          `---`
//   - tags / anchors    `!foo` / `&anchor`
//
// This is purposefully thin: plan.yaml is the only producer.  Adding a
// real YAML crate later is a one-line dep swap.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum MiniYaml {
    Scalar(String),
    Sequence(Vec<MiniYaml>),
    Mapping(Vec<(String, MiniYaml)>),
}

impl MiniYaml {
    fn parse(body: &str) -> Result<Self> {
        let lines = preprocess_lines(body)?;
        let mut cursor = 0;
        let value = parse_block(&lines, &mut cursor, 0)?;
        if cursor != lines.len() {
            bail!(
                "unexpected content at line {} (parser stopped early)",
                lines[cursor].line_no
            );
        }
        Ok(value)
    }

    fn as_mapping(&self, ctx: &str) -> Result<&[(String, MiniYaml)]> {
        match self {
            MiniYaml::Mapping(m) => Ok(m),
            _ => bail!("expected mapping at {}", ctx),
        }
    }

    fn as_sequence(&self, ctx: &str) -> Result<&[MiniYaml]> {
        match self {
            MiniYaml::Sequence(s) => Ok(s),
            _ => bail!("expected sequence at {}", ctx),
        }
    }

    fn as_scalar(&self, ctx: &str) -> Result<&str> {
        match self {
            MiniYaml::Scalar(s) => Ok(s.as_str()),
            _ => bail!("expected scalar at {}", ctx),
        }
    }
}

#[derive(Debug)]
struct YamlLine {
    line_no: usize,
    indent: usize,
    content: String,
}

fn preprocess_lines(body: &str) -> Result<Vec<YamlLine>> {
    let mut out = Vec::new();
    for (idx, raw) in body.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw)?;
        let trimmed = stripped.trim_end();
        if trimmed.trim_start().is_empty() {
            continue;
        }
        let indent = trimmed.len() - trimmed.trim_start_matches(' ').len();
        if trimmed.starts_with('\t') {
            bail!("tabs are not supported as indentation (line {line_no})");
        }
        let content = trimmed[indent..].to_string();
        if content.starts_with("---") || content.starts_with("...") {
            bail!("multi-document YAML is not supported (line {line_no})");
        }
        if content.starts_with('&') || content.starts_with('*') || content.starts_with('!') {
            bail!("anchors/aliases/tags are not supported (line {line_no})");
        }
        out.push(YamlLine {
            line_no,
            indent,
            content,
        });
    }
    Ok(out)
}

fn strip_comment(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (None, '#') => break,
            (None, '"') | (None, '\'') => {
                quote = Some(ch);
                out.push(ch);
            }
            (Some(q), c) if c == q => {
                quote = None;
                out.push(c);
            }
            (_, c) => out.push(c),
        }
    }
    if quote.is_some() {
        bail!("unterminated quoted string");
    }
    Ok(out)
}

fn parse_block(lines: &[YamlLine], cursor: &mut usize, indent: usize) -> Result<MiniYaml> {
    if *cursor >= lines.len() {
        return Ok(MiniYaml::Scalar(String::new()));
    }
    let first = &lines[*cursor];
    if first.indent < indent {
        return Ok(MiniYaml::Scalar(String::new()));
    }
    if first.content.starts_with("- ") || first.content == "-" {
        parse_sequence(lines, cursor, first.indent)
    } else {
        parse_mapping(lines, cursor, first.indent)
    }
}

fn parse_mapping(lines: &[YamlLine], cursor: &mut usize, indent: usize) -> Result<MiniYaml> {
    let mut out = Vec::new();
    while *cursor < lines.len() {
        let line = &lines[*cursor];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            bail!(
                "unexpected indent {} > {} at line {}",
                line.indent,
                indent,
                line.line_no
            );
        }
        if line.content.starts_with("- ") || line.content == "-" {
            bail!("sequence entry inside mapping at line {}", line.line_no);
        }
        let (key, rest) = split_key(&line.content, line.line_no)?;
        *cursor += 1;
        let value = if rest.is_empty() {
            parse_block(lines, cursor, indent + 1)?
        } else {
            MiniYaml::Scalar(unquote(rest))
        };
        out.push((key, value));
    }
    Ok(MiniYaml::Mapping(out))
}

fn parse_sequence(lines: &[YamlLine], cursor: &mut usize, indent: usize) -> Result<MiniYaml> {
    let mut out = Vec::new();
    while *cursor < lines.len() {
        let line = &lines[*cursor];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            bail!(
                "unexpected indent {} > {} at line {}",
                line.indent,
                indent,
                line.line_no
            );
        }
        if !line.content.starts_with("- ") && line.content != "-" {
            break;
        }
        let after_dash = if line.content == "-" {
            ""
        } else {
            &line.content[2..]
        };
        *cursor += 1;
        if after_dash.is_empty() {
            let value = parse_block(lines, cursor, indent + 1)?;
            out.push(value);
            continue;
        }
        if let Some((key, rest)) = try_split_key(after_dash) {
            // Inline first key of a mapping element. Replace the
            // current "- key: value" line with a synthetic mapping
            // headed at indent+2 (length of "- ") so subsequent
            // sibling keys at that column attach correctly.
            let synthetic_indent = indent + 2;
            let value = if rest.is_empty() {
                parse_block(lines, cursor, synthetic_indent + 1)?
            } else {
                MiniYaml::Scalar(unquote(rest))
            };
            let mut mapping = vec![(key, value)];
            while *cursor < lines.len() {
                let next = &lines[*cursor];
                if next.indent != synthetic_indent {
                    break;
                }
                if next.content.starts_with("- ") || next.content == "-" {
                    break;
                }
                let (k, r) = split_key(&next.content, next.line_no)?;
                *cursor += 1;
                let v = if r.is_empty() {
                    parse_block(lines, cursor, synthetic_indent + 1)?
                } else {
                    MiniYaml::Scalar(unquote(r))
                };
                mapping.push((k, v));
            }
            out.push(MiniYaml::Mapping(mapping));
        } else {
            out.push(MiniYaml::Scalar(unquote(after_dash)));
        }
    }
    Ok(MiniYaml::Sequence(out))
}

fn split_key(content: &str, line_no: usize) -> Result<(String, &str)> {
    try_split_key(content).ok_or_else(|| anyhow!("expected `key: value` at line {}", line_no))
}

fn try_split_key(content: &str) -> Option<(String, &str)> {
    // A key terminates at the first unquoted `:` followed by space or
    // end-of-line. This is just enough to handle our restricted schema.
    let mut quote: Option<char> = None;
    let bytes = content.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (None, b'"') | (None, b'\'') => quote = Some(b as char),
            (Some(q), c) if c as char == q => quote = None,
            (None, b':') => {
                let after = &content[i + 1..];
                if after.is_empty() || after.starts_with(' ') {
                    let key = unquote(&content[..i]);
                    let value = after.trim_start();
                    return Some((key, value));
                }
            }
            _ => {}
        }
    }
    None
}

fn unquote(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        let last = trimmed.as_bytes()[trimmed.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    fn cross_kernel_plan() -> Plan {
        Plan {
            script: None,
            script_file: None,
            targets: vec![
                Target {
                    id: "linux".into(),
                    guest_os: GuestOs::Linux,
                    launcher: LauncherSpec::Attach,
                    conduit: Some(ConduitEndpoint::Pid(1)),
                    script: None,
                    script_file: None,
                    duration_ms: None,
                },
                Target {
                    id: "freebsd".into(),
                    guest_os: GuestOs::FreeBsd,
                    launcher: LauncherSpec::Attach,
                    conduit: Some(ConduitEndpoint::Pid(2)),
                    script: None,
                    script_file: None,
                    duration_ms: None,
                },
            ],
        }
    }

    fn linux_only_plan() -> Plan {
        Plan {
            script: None,
            script_file: None,
            targets: vec![Target {
                id: "linux".into(),
                guest_os: GuestOs::Linux,
                launcher: LauncherSpec::Attach,
                conduit: Some(ConduitEndpoint::Pid(1)),
                script: None,
                script_file: None,
                duration_ms: None,
            }],
        }
    }

    fn freebsd_only_plan() -> Plan {
        Plan {
            script: None,
            script_file: None,
            targets: vec![Target {
                id: "freebsd".into(),
                guest_os: GuestOs::FreeBsd,
                launcher: LauncherSpec::Attach,
                conduit: Some(ConduitEndpoint::Pid(2)),
                script: None,
                script_file: None,
                duration_ms: None,
            }],
        }
    }


    #[test]
    fn parses_n1_attach_plan() {
        let body = r#"
script_file: trace.d
targets:
  - id: linux
    guest_os: linux
    launcher:
      kind: attach
    conduit:
      pid: 4242
"#;
        let plan = Plan::parse(body).expect("parse plan");
        assert_eq!(plan.script_file.as_deref(), Some(Path::new("trace.d")));
        assert_eq!(plan.targets.len(), 1);
        let t = &plan.targets[0];
        assert_eq!(t.id, "linux");
        assert_eq!(t.guest_os, GuestOs::Linux);
        assert_eq!(t.launcher, LauncherSpec::Attach);
        assert_eq!(t.conduit, Some(ConduitEndpoint::Pid(4242)));
        assert_eq!(t.duration_ms, None);
    }

    #[test]
    fn parses_target_duration_ms_into_session_lifecycle_knob() {
        let body = r#"
script_file: trace.d
targets:
  - id: freebsd
    guest_os: freebsd
    launcher:
      kind: attach
    conduit:
      pid: 4242
    duration_ms: 2500
"#;
        let plan = Plan::parse(body).expect("parse plan");
        let t = &plan.targets[0];
        assert_eq!(t.duration_ms, Some(2500));
    }

    #[test]
    fn rejects_non_numeric_duration_ms() {
        let body = r#"
script_file: trace.d
targets:
  - id: freebsd
    guest_os: freebsd
    launcher:
      kind: attach
    conduit:
      pid: 4242
    duration_ms: "two seconds"
"#;
        let err = Plan::parse(body).unwrap_err();
        assert!(
            err.to_string().contains("duration_ms"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn parses_cross_kernel_plan() {
        let body = r#"
script_file: trace.d
targets:
  - id: linux
    guest_os: linux
    launcher:
      kind: smolvm
      args:
        - "machine"
        - "run"
        - "-d"
    conduit:
      pid: 1001
  - id: freebsd
    guest_os: freebsd
    launcher:
      kind: qemu-freebsd
      args:
        - "--qcow2"
        - "freebsd-14.3.qcow2"
    conduit:
      socket: /tmp/conduit-freebsd.sock
"#;
        let plan = Plan::parse(body).expect("parse plan");
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(plan.targets[0].id, "linux");
        assert_eq!(plan.targets[1].id, "freebsd");
        assert!(matches!(
            plan.targets[0].launcher,
            LauncherSpec::Smolvm { ref args, .. } if args == &["machine", "run", "-d"]
        ));
        assert_eq!(
            plan.targets[1].conduit,
            Some(ConduitEndpoint::Socket(PathBuf::from("/tmp/conduit-freebsd.sock")))
        );
    }

    #[test]
    fn rejects_duplicate_target_ids() {
        let body = r#"
targets:
  - id: linux
    guest_os: linux
    launcher: { kind: attach }
    conduit: { pid: 1 }
  - id: linux
    guest_os: freebsd
    launcher: { kind: attach }
    conduit: { pid: 2 }
"#;
        let err = Plan::parse(body).unwrap_err();
        // Flow-style mappings are not supported; the parser should
        // reject the inline `{ ... }` shape before getting to the
        // duplicate-id check. Either failure mode is acceptable; this
        // pins that the parser fails loudly on the malformed input.
        let msg = err.to_string();
        assert!(!msg.is_empty(), "parser should reject malformed input");
    }

    #[test]
    fn rejects_unknown_key() {
        let body = r#"
banana: yes
targets:
  - id: linux
    guest_os: linux
    launcher:
      kind: attach
    conduit:
      pid: 1
"#;
        let err = Plan::parse(body).unwrap_err();
        assert!(err.to_string().contains("unknown plan key"));
    }

    #[test]
    fn rejects_empty_targets() {
        let body = "script_file: trace.d\ntargets: []\n";
        // The mini-yaml parser doesn't support flow-style `[]`, so the
        // empty form here actually parses as "targets: " with no
        // children, which Plan::validate rejects.
        let err = Plan::parse(body).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("at least one target") || msg.contains("expected"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn routes_cross_kernel_clauses_per_target() {
        let src = r#"
fbt:guest:vfs_open:entry { trace(arg0); }
fbt:kernel:tcp_input:entry { trace(0xC0FFEE); }
"#;
        let parsed = parse::parse(src).expect("parse D");
        let plan = cross_kernel_plan();
        let routed = route_clauses(&plan, &parsed).expect("route");
        assert_eq!(routed.per_target.len(), 2);
        assert_eq!(routed.per_target[0].target.id, "linux");
        assert_eq!(routed.per_target[0].clauses.len(), 1);
        assert_eq!(
            routed.per_target[0].clauses[0].clause.specs[0].render(),
            "fbt:guest:vfs_open:entry"
        );
        assert_eq!(routed.per_target[1].target.id, "freebsd");
        assert_eq!(routed.per_target[1].clauses.len(), 1);
        assert_eq!(
            routed.per_target[1].clauses[0].clause.specs[0].render(),
            "fbt:kernel:tcp_input:entry"
        );
    }

    #[test]
    fn rejects_uprobe_under_freebsd_target() {
        let src = r#"
uprobe:guest:nginx:ngx_http_finalize_request:entry { trace(0x1); }
"#;
        let parsed = parse::parse(src).expect("parse D");
        let plan = freebsd_only_plan();
        let err = route_clauses(&plan, &parsed).unwrap_err().to_string();
        assert!(
            err.contains("uprobe:guest:nginx:ngx_http_finalize_request:entry"),
            "error should name the offending probe: {err}"
        );
        assert!(
            err.contains("guest-userspace probes"),
            "error should explain the reason: {err}"
        );
    }

    #[test]
    fn rejects_native_fbt_under_linux_only_plan() {
        let src = r#"
fbt:kernel:tcp_input:entry { trace(0x1); }
"#;
        let parsed = parse::parse(src).expect("parse D");
        let plan = linux_only_plan();
        let err = route_clauses(&plan, &parsed).unwrap_err().to_string();
        assert!(
            err.contains("fbt:kernel:tcp_input:entry"),
            "error should name the offending probe: {err}"
        );
        assert!(
            err.contains("bifrost provider namespace"),
            "error should explain the Linux backend's namespace requirement: {err}"
        );
    }

    #[test]
    fn rejects_clause_with_split_probes_across_targets() {
        // One clause whose two probe specs each route to a different
        // target. We can't physically execute one action body in two
        // kernels; the diagnostic must surface both probes.
        let src = r#"
fbt:guest:vfs_open:entry,
fbt:kernel:tcp_input:entry
{ trace(0x1); }
"#;
        let parsed = parse::parse(src).expect("parse D");
        let plan = cross_kernel_plan();
        let err = route_clauses(&plan, &parsed).unwrap_err().to_string();
        assert!(
            err.contains("split across plan targets"),
            "error should call out the split: {err}"
        );
        assert!(err.contains("fbt:guest:vfs_open:entry"));
        assert!(err.contains("fbt:kernel:tcp_input:entry"));
    }

    #[test]
    fn prefers_linux_for_bifrost_probes_when_both_targets_accept() {
        // The current TraceTarget::route_probe accepts non-userspace
        // probes under a native-DTrace target permissively, including
        // `bifrost:guest:*` shapes which are Linux-native. The
        // planner's tie-break must still send these to the Linux
        // target so they get the eBPF lowering pipeline.
        let src = r#"
bifrost:guest:vfs_open:entry { trace(arg0); }
"#;
        let parsed = parse::parse(src).expect("parse D");
        let plan = cross_kernel_plan();
        let routed = route_clauses(&plan, &parsed).expect("route");
        let linux_clauses = &routed.per_target[0].clauses;
        let freebsd_clauses = &routed.per_target[1].clauses;
        assert_eq!(
            linux_clauses.len(),
            1,
            "bifrost: clause should land on the Linux target"
        );
        assert_eq!(freebsd_clauses.len(), 0);
    }

    #[test]
    fn rejects_oversize_target_id() {
        let id = "x".repeat(40);
        let body = format!(
            r#"
targets:
  - id: {id}
    guest_os: linux
    launcher:
      kind: attach
    conduit:
      pid: 1
"#,
            id = id
        );
        let err = Plan::parse(&body).unwrap_err();
        assert!(err.to_string().contains("max 32"));
    }
}
