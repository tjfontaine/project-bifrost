// SPDX-License-Identifier: Apache-2.0
//! Guest backend selection and probe-routing model.
//!
//! Bifrost's first Linux implementation made the eBPF path look like
//! the universal guest shape: parse D, lower DIF to eBPF, wrap it in
//! BFR7, and let the Linux guest driver attach BPF programs.  That is
//! only the Linux compatibility backend.  Native DTrace guests such as
//! FreeBSD and illumos keep their provider tuples intact and execute
//! through kernel DTrace facilities exposed by the guest kernel.
//!
//! This module is deliberately small: it is the policy boundary the
//! CLI/session planner uses before choosing a concrete compiler.  The
//! transport below it remains the generic virtio conduit; the Linux
//! lowering and native-DTrace load formats live behind the selected
//! backend.

use crate::parse::ProbeSpec;
use crate::schema::RecordSchema;
use anyhow::{Result, anyhow, bail};

/// Operating system running inside the traced guest — or, for
/// [`GuestOs::MacosHost`], the macOS host itself acting as a peer
/// orchestrate target.  The name `guest_os` predates the host-as-peer
/// addition (cross-kernel orchestration); we keep the field
/// name and just extend the enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestOs {
    /// Current shipping backend: DTrace/DIF lowered to eBPF and
    /// attached through the patched Linux guest driver.
    Linux,
    /// First native-DTrace target.  The acceptance path is
    /// kernel-only: no guest userspace agent and no in-guest
    /// `dtrace(1)` process.
    FreeBsd,
    /// Follow-on native-DTrace target.  It should share the same
    /// kernel-only backend contract as FreeBSD.
    Illumos,
    /// macOS host itself, traced via a child `dtrace(1)` process
    /// rather than a guest VM.  Records flow into the orchestrator
    /// through a text-mode pipe, not the SHM conduit; clauses route
    /// here when they're shaped with module="host".
    MacosHost,
}

impl GuestOs {
    pub fn backend_kind(self) -> BackendKind {
        match self {
            GuestOs::Linux => BackendKind::LinuxEbpf,
            GuestOs::FreeBsd | GuestOs::Illumos => BackendKind::NativeKernelDtrace,
            GuestOs::MacosHost => BackendKind::MacosHostDtrace,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            GuestOs::Linux => "linux",
            GuestOs::FreeBsd => "freebsd",
            GuestOs::Illumos => "illumos",
            GuestOs::MacosHost => "macos-host",
        }
    }
}

/// Compiler/runtime family behind a guest OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    /// Linux-only compatibility backend: host lowers DIF to eBPF and
    /// the guest driver verifies/JITs/attaches the program.
    LinuxEbpf,
    /// Native DTrace backend: the guest kernel consumes a
    /// kernel-loadable DTrace session description and produces
    /// normalized Bifrost records.
    NativeKernelDtrace,
    /// macOS host backend: orchestrator spawns `dtrace(1)` as a
    /// child and parses its text-mode output stream — there's no
    /// kernel-loadable payload, no SHM conduit, and no guest VM.
    MacosHostDtrace,
}

/// Backend-owned payload family that rides the opaque conduit control
/// channel after the session planner has selected a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFormat {
    /// Existing Linux payload family.  BFR7 is a host-local wrapper;
    /// direct_load.rs derives one or more Linux LOAD_PROG byte
    /// payloads from it.
    LinuxBfr7LoadProg,
    /// Native DTrace payload for a guest-kernel consumer.  FreeBSD is
    /// first; illumos should share the same high-level contract while
    /// keeping provider and argument differences backend-local.
    NativeKernelDtraceSession,
}

impl BackendKind {
    pub fn load_format(self) -> LoadFormat {
        match self {
            BackendKind::LinuxEbpf => LoadFormat::LinuxBfr7LoadProg,
            BackendKind::NativeKernelDtrace => LoadFormat::NativeKernelDtraceSession,
            // The macOS host backend has no on-wire payload — the
            // orchestrator spawns `dtrace(1)` with the routed source
            // directly.  Reusing `NativeKernelDtraceSession` keeps
            // the [`LoadFormat`] discriminant tight; callers that
            // actually need a payload (LOAD_PROG path) check the
            // backend kind first.
            BackendKind::MacosHostDtrace => LoadFormat::NativeKernelDtraceSession,
        }
    }
}

/// One opaque control payload ready to send through the conduit.
///
/// The `kind` is a conduit transport discriminator; `body` belongs to
/// the selected guest backend.  Callers must not infer Linux BFR7 or
/// native-DTrace DOF semantics from this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestControlPayload {
    pub kind: u32,
    pub body: Vec<u8>,
}

impl GuestControlPayload {
    pub fn new(kind: u32, body: Vec<u8>) -> Self {
        Self { kind, body }
    }
}

/// Host-side schema metadata for records a backend expects the guest
/// to publish after a session starts.
///
/// The conduit only ferries bytes.  Backends attach the schema table
/// here so renderers can decode records without learning Linux BFR7 or
/// native-DTrace DOF internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestRecordSchema {
    pub probe_id: u32,
    pub label: String,
    pub schema: RecordSchema,
}

impl GuestRecordSchema {
    pub fn new(probe_id: u32, label: impl Into<String>, schema: RecordSchema) -> Self {
        Self {
            probe_id,
            label: label.into(),
            schema,
        }
    }
}

/// Backend-produced session payloads for one guest trace activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestBackendSession {
    pub os: GuestOs,
    pub backend_kind: BackendKind,
    pub load_format: LoadFormat,
    pub payloads: Vec<GuestControlPayload>,
    pub statuses: Vec<u8>,
    pub record_schemas: Vec<GuestRecordSchema>,
}

impl GuestBackendSession {
    pub fn new(os: GuestOs, payloads: Vec<GuestControlPayload>, statuses: Vec<u8>) -> Self {
        let backend_kind = os.backend_kind();
        Self {
            os,
            backend_kind,
            load_format: backend_kind.load_format(),
            payloads,
            statuses,
            record_schemas: Vec::new(),
        }
    }

    pub fn with_record_schemas(mut self, record_schemas: Vec<GuestRecordSchema>) -> Self {
        self.record_schemas = record_schemas;
        self
    }

    pub fn single_payload(&self) -> Result<&GuestControlPayload> {
        match self.payloads.as_slice() {
            [payload] => Ok(payload),
            _ => bail!(
                "{} backend produced {} control payloads, expected one",
                self.os.name(),
                self.payloads.len()
            ),
        }
    }
}

/// A concrete guest backend converts a high-level trace/session request
/// into opaque conduit payloads.
pub trait GuestBackend<Request> {
    fn guest_os(&self) -> GuestOs;
    fn build_session(&self, request: Request) -> Result<GuestBackendSession>;
}

pub const FREEBSD_DTRACE_PROOF_VALUE: u64 = 0x4653_4244_5452_4143;

pub const NATIVE_DTRACE_SESSION_MAGIC: u32 = 0x3154_444e; // "NDT1"
/// Wire-format version.  v2 added the 8-byte `duration_ms` + reserved
/// tail at offset 32, replacing the kernel's hard-coded 500 ms sample
/// window with a host-supplied lifecycle knob (fidelity fix).
pub const NATIVE_DTRACE_SESSION_VERSION: u16 = 2;
pub const NATIVE_DTRACE_OP_RUN_DOF: u16 = 1;
pub const NATIVE_DTRACE_GUEST_OS_FREEBSD: u16 = 1;
pub const NATIVE_DTRACE_GUEST_OS_ILLUMOS: u16 = 2;
pub const NATIVE_DTRACE_FLAG_EXPECT_VALUE: u16 = 1;
pub const NATIVE_DTRACE_HEADER_LEN: usize = 40;
pub const NATIVE_DTRACE_DEFAULT_PROBE_ID: u32 = 2;
pub const NATIVE_DTRACE_DEFAULT_LABEL: &str = "freebsd:kernel:dtrace:trace";
pub const NATIVE_DTRACE_MAX_TRACE_RECORDS: usize = 64;
/// Default sample window when callers leave `duration_ms` at zero.
/// Mirrors `BIFROST_CONDUIT_NATIVE_DTRACE_DEFAULT_DURATION_MS`.
pub const NATIVE_DTRACE_DEFAULT_DURATION_MS: u32 = 500;
/// Maximum sample window the kernel-side wrapper will honor.
pub const NATIVE_DTRACE_MAX_DURATION_MS: u32 = 30_000;

/// Native-DTrace request v2: load one host-supplied DOF blob in the
/// guest kernel, run it for `duration_ms` (defaulted via
/// `NATIVE_DTRACE_DEFAULT_DURATION_MS` when left at zero), and
/// publish every supported `trace(u64)` record + per-session
/// AGG_SNAPSHOT through a host-declared schema slot.
#[derive(Clone, Copy, Debug)]
pub struct NativeDtraceSessionRequest<'a> {
    pub dof: &'a [u8],
    pub expected_value: Option<u64>,
    pub probe_id: u32,
    pub label: &'a str,
    /// Sample window in milliseconds; `0` selects the kernel default
    /// (500 ms).  Clamped guest-side at `NATIVE_DTRACE_MAX_DURATION_MS`.
    pub duration_ms: u32,
}

impl<'a> NativeDtraceSessionRequest<'a> {
    pub fn run_dof(dof: &'a [u8], expected_value: u64) -> Self {
        Self {
            dof,
            expected_value: Some(expected_value),
            probe_id: NATIVE_DTRACE_DEFAULT_PROBE_ID,
            label: NATIVE_DTRACE_DEFAULT_LABEL,
            duration_ms: 0,
        }
    }

    pub fn run_dof_session(
        dof: &'a [u8],
        probe_id: u32,
        expected_value: Option<u64>,
        label: &'a str,
    ) -> Self {
        Self {
            dof,
            expected_value,
            probe_id,
            label,
            duration_ms: 0,
        }
    }

    pub fn with_duration_ms(mut self, duration_ms: u32) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NativeDtraceBackend {
    os: GuestOs,
}

impl NativeDtraceBackend {
    pub fn for_guest(os: GuestOs) -> Result<Self> {
        match os {
            GuestOs::FreeBsd | GuestOs::Illumos => Ok(Self { os }),
            GuestOs::Linux => bail!("linux uses the eBPF backend, not native DTrace"),
            GuestOs::MacosHost => {
                bail!("macos-host uses the dtrace(1) child path, not the kernel-loadable native DTrace session")
            }
        }
    }

    pub fn freebsd() -> Self {
        Self {
            os: GuestOs::FreeBsd,
        }
    }

    pub fn illumos() -> Self {
        Self {
            os: GuestOs::Illumos,
        }
    }

    fn native_os_id(self) -> u16 {
        match self.os {
            GuestOs::FreeBsd => NATIVE_DTRACE_GUEST_OS_FREEBSD,
            GuestOs::Illumos => NATIVE_DTRACE_GUEST_OS_ILLUMOS,
            GuestOs::Linux | GuestOs::MacosHost => {
                unreachable!("constructor rejects Linux and MacosHost")
            }
        }
    }
}

impl GuestBackend<NativeDtraceSessionRequest<'_>> for NativeDtraceBackend {
    fn guest_os(&self) -> GuestOs {
        self.os
    }

    fn build_session(
        &self,
        request: NativeDtraceSessionRequest<'_>,
    ) -> Result<GuestBackendSession> {
        if request.dof.is_empty() {
            bail!("native DTrace session requires a non-empty DOF payload");
        }
        let dof_len: u32 = request
            .dof
            .len()
            .try_into()
            .map_err(|_| anyhow!("native DTrace DOF payload exceeds u32 length"))?;

        if request.probe_id == 0 {
            bail!("native DTrace session requires a non-zero probe id");
        }

        let flags = if request.expected_value.is_some() {
            NATIVE_DTRACE_FLAG_EXPECT_VALUE
        } else {
            0
        };
        let mut body = Vec::with_capacity(NATIVE_DTRACE_HEADER_LEN + request.dof.len());
        body.extend_from_slice(&NATIVE_DTRACE_SESSION_MAGIC.to_le_bytes());
        body.extend_from_slice(&NATIVE_DTRACE_SESSION_VERSION.to_le_bytes());
        body.extend_from_slice(&NATIVE_DTRACE_OP_RUN_DOF.to_le_bytes());
        body.extend_from_slice(&self.native_os_id().to_le_bytes());
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&(NATIVE_DTRACE_HEADER_LEN as u32).to_le_bytes());
        body.extend_from_slice(&dof_len.to_le_bytes());
        body.extend_from_slice(&request.probe_id.to_le_bytes());
        body.extend_from_slice(&request.expected_value.unwrap_or(0).to_le_bytes());
        // v2 tail: u32 duration_ms (0 = guest default), u32 reserved.
        body.extend_from_slice(&request.duration_ms.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(request.dof);

        let trace_records = native_trace_record_count(request.dof)?;
        if request.probe_id > u32::MAX - (trace_records as u32 - 1) {
            bail!("native DTrace session probe id range overflows u32");
        }
        let mut record_schemas = Vec::with_capacity(trace_records);
        for i in 0..trace_records {
            record_schemas.push(GuestRecordSchema::new(
                request.probe_id + i as u32,
                request.label,
                RecordSchema::default_trace(),
            ));
        }

        Ok(GuestBackendSession::new(
            self.os,
            vec![GuestControlPayload::new(
                crate::control_shmem::KIND_LOAD_PROG,
                body,
            )],
            vec![bifrost_wire::RSP_LOADPROG_STATUS_OK],
        )
        .with_record_schemas(record_schemas))
    }
}

fn native_trace_record_count(dof_bytes: &[u8]) -> Result<usize> {
    let Ok(dof) = crate::Dof::parse(dof_bytes) else {
        return Ok(1);
    };
    let ecbs = dof.all_ecbs();
    if ecbs.is_empty() {
        return Ok(1);
    }

    // Provider preflight: the FreeBSD kernel wrapper accepts the
    // probe families listed in `is_supported_native_probe`
    // (`dtrace:::BEGIN`, `fbt:<module>:<function>:{entry,return}`,
    // `syscall::<function>:{entry,return}`, and
    // `profile::{tick,profile}-N{ms,sec,usec,...}`). Surface the
    // offending tuple host-side so users see the limitation
    // immediately rather than hitting `status=-2 detail=native DOF
    // matched zero probes` from the guest.
    //
    // Walk every ECB: libdtrace emits one ECB per probe-clause (and
    // one per probe spec inside a clause that names several), so a
    // multi-clause D script lands here with several entries that all
    // need to attach.
    for ecb in &ecbs {
        for probe in &dof.probe_descs(ecb.probes) {
            if !is_supported_native_probe(probe) {
                bail!(
                    "native FreeBSD DTrace session targets unsupported probe `{}`; \
                     the kernel module accepts `dtrace:::BEGIN`, \
                     `fbt:<module>:<function>:{{entry|return}}`, \
                     `syscall::<function>:{{entry|return}}`, and \
                     `profile::{{tick|profile}}-N`. Other providers must be added \
                     in guest/freebsd-bifrost/ before they will attach.",
                    probe.render(),
                );
            }
        }
    }

    // The FreeBSD kernel wrapper today honors two action families:
    //   - DTRACEACT_DIFEXPR              — `trace(<scalar>)`, drained
    //                                       as per-fire records via
    //                                       `dtrace_bifrost_drain_records`.
    //   - DTRACEAGG_* (kind & 0xff00 == 0x0700) — aggregations like
    //                                       `count()` / `sum()` /
    //                                       `quantize()`, surfaced by
    //                                       `dtrace_bifrost_drain_aggs`
    //                                       and published as an
    //                                       AGG_SNAPSHOT record.
    // Anything else — `exit()`, `printf()` with non-DIFEXPR shapes,
    // string `trace()` — still gets rejected here so the CLI names
    // the offending action up front.
    // `printa()` is a rendering action: libdtrace traditionally
    // formats it inside the consumer using the aggregation snapshot.
    // Bifrost's host renderer reads AGG_SNAPSHOT records and emits
    // the same output, so we don't need to consume the kernel's
    // printa-tagged record bytes — `drain_records` already skips
    // any non-DIFEXPR action.  Allowing the action through preflight
    // means a D source authored against Linux (where libdtrace
    // accepts `END { printa(...) }`) runs unchanged on FreeBSD.
    let mut trace_count = 0usize;
    let mut agg_count = 0usize;
    let mut printa_count = 0usize;
    for ecb in &ecbs {
        let actions = dof.actions_in_chain(ecb.actions);
        if let Some(bad) = actions.iter().find(|a| {
            a.kind != crate::lower::DTRACEACT_DIFEXPR
                && a.kind != crate::lower::DTRACEACT_PRINTA
                && !crate::lower::is_agg_action(a.kind)
        }) {
            bail!(
                "native FreeBSD DTrace session contains unsupported action kind {} ({}); \
                 only chains of scalar `trace()`, DTRACEAGG_* aggregations, and `printa()` \
                 are accepted by the current kernel module. Drop the offending action and re-run.",
                bad.kind,
                describe_dtrace_action(bad.kind),
            );
        }
        trace_count += actions
            .iter()
            .filter(|a| a.kind == crate::lower::DTRACEACT_DIFEXPR)
            .count();
        agg_count += actions
            .iter()
            .filter(|a| crate::lower::is_agg_action(a.kind))
            .count();
        printa_count += actions
            .iter()
            .filter(|a| a.kind == crate::lower::DTRACEACT_PRINTA)
            .count();
    }
    if trace_count == 0 && agg_count == 0 && printa_count == 0 {
        bail!("native DTrace session has no supported trace() or aggregation actions");
    }
    if trace_count > NATIVE_DTRACE_MAX_TRACE_RECORDS {
        bail!(
            "native DTrace session has {} trace() actions, max supported is {}",
            trace_count,
            NATIVE_DTRACE_MAX_TRACE_RECORDS
        );
    }
    // Schema array sizes against trace() actions; the
    // AGG_SNAPSHOT path routes by probe id and carries its own
    // per-row kind/size discriminators (see `cli::agg_decl` for the
    // host-side identity/shape contract derived from the D source,
    // and `cli::orchestrate::ingest_agg_snapshot` for the value
    // decoders that handle scalar, stddev, and full quantize/
    // lquantize bucket arrays).
    Ok(trace_count.max(1))
}

/// Is this probe descriptor in the set the FreeBSD kernel wrapper
/// can attach today?  Provider coverage expands as `guest/freebsd-bifrost/`
/// preloads more provider modules: the cross-kernel demos rely
/// on `fbt:kernel:*`, `syscall::*`, and `profile:::tick-*sec`, which
/// register through the corresponding .ko modules (fbt, systrace,
/// profile) when they're staged on the module disk and preloaded at
/// the EFI loader.  Anything outside this set still gets the
/// host-side rejection so users see the limitation up front instead
/// of `status=-2 detail=native DOF matched zero probes` from the
/// guest.
fn is_supported_native_probe(probe: &crate::ProbeDescTuple) -> bool {
    // `dtrace:::BEGIN` and `dtrace:::END` are part of every D program.
    // BEGIN fires inside `dtrace_state_go`; END fires inside
    // `dtrace_state_stop`, both before the kernel-side bridge drains
    // records and aggs.  Authors should not have to know which guest
    // they are targeting just to know whether END is allowed.
    //
    // Provider slot is empty when the source uses the bare form
    // (`END { ... }`) — libdtrace canonicalizes those to
    // `dtrace:::END` at match time but the DOF probedesc keeps the
    // unqualified form.
    if (probe.provider == "dtrace" || probe.provider.is_empty())
        && matches!(probe.name.as_str(), "BEGIN" | "END")
    {
        return true;
    }
    // fbt:<module>:<function>:<entry|return>.  The wrapper allows
    // any module slot because module names are case-by-case (some
    // probes live in "kernel", others in driver modules).
    if probe.provider == "fbt"
        && matches!(probe.name.as_str(), "entry" | "return")
        && !probe.function.is_empty()
    {
        return true;
    }
    // syscall::<func>:<entry|return> (FreeBSD systrace).  Module
    // slot is empty for syscall probes by convention.
    if probe.provider == "syscall"
        && matches!(probe.name.as_str(), "entry" | "return")
        && !probe.function.is_empty()
    {
        return true;
    }
    // profile::tick-Nsec / profile::profile-Nsec.
    if probe.provider == "profile"
        && (probe.name.starts_with("tick-") || probe.name.starts_with("profile-"))
    {
        return true;
    }
    false
}

fn describe_dtrace_action(kind: u32) -> &'static str {
    use crate::lower::*;
    match kind {
        DTRACEACT_DIFEXPR => "trace()",
        DTRACEACT_EXIT => "exit()",
        DTRACEACT_PRINTF => "printf()",
        DTRACEACT_PRINTA => "printa()",
        DTRACEACT_TRACEMEM => "tracemem()",
        DTRACEACT_TRACEMEM_DYNSIZE => "tracemem(dynsize)",
        DTRACEACT_USTACK => "ustack()",
        DTRACEACT_STACK => "stack()",
        DTRACEACT_SPECULATE => "speculate()",
        DTRACEACT_COMMIT => "commit()",
        DTRACEACT_DISCARD => "discard()",
        DTRACEACT_LIBACT => "libdtrace-internal action",
        _ => "unknown action",
    }
}

/// Top-level target for a D clause after the session planner has
/// resolved any CLI option or future source-level target annotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceTarget {
    /// macOS host libdtrace path.
    Host,
    /// Guest kernel path for the selected OS.
    Guest(GuestOs),
}

/// Concrete route for one probe spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeRoute {
    HostLibdtrace,
    LinuxEbpf,
    NativeKernelDtrace(GuestOs),
    Rejected(RejectReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The selected guest backend is kernel-only, but the probe
    /// targets guest userspace (`uprobe`, `usdt`, `pid`, or a
    /// Bifrost 5-tuple carrying a binary slot).
    GuestUserspaceProbe,
    /// The Linux backend still requires the existing Bifrost-shaped
    /// provider namespace (`fbt:guest`, `tracepoint:guest`, etc.).
    LinuxNeedsBifrostProvider,
}

impl TraceTarget {
    pub fn route_probe(self, spec: &ProbeSpec) -> ProbeRoute {
        match self {
            TraceTarget::Host => ProbeRoute::HostLibdtrace,
            TraceTarget::Guest(GuestOs::Linux) => {
                // profile:::tick-Nms / tick-Nsec etc.
                // also route to the Linux backend (lowered as a
                // BPF_PROG_TYPE_PERF_EVENT program; attached via
                // perf_event_create_kernel_counter on the guest).
                if spec.is_bifrost() || spec.is_profile_timer() {
                    ProbeRoute::LinuxEbpf
                } else {
                    ProbeRoute::Rejected(RejectReason::LinuxNeedsBifrostProvider)
                }
            }
            TraceTarget::Guest(os @ (GuestOs::FreeBsd | GuestOs::Illumos)) => {
                if is_guest_userspace_probe(spec) {
                    ProbeRoute::Rejected(RejectReason::GuestUserspaceProbe)
                } else {
                    ProbeRoute::NativeKernelDtrace(os)
                }
            }
            TraceTarget::Guest(GuestOs::MacosHost) => {
                // macos-host runs the routed clauses through the
                // host's own `dtrace(1)` binary — same acceptance
                // surface as the native-DTrace backend.
                if is_guest_userspace_probe(spec) {
                    ProbeRoute::Rejected(RejectReason::GuestUserspaceProbe)
                } else {
                    ProbeRoute::HostLibdtrace
                }
            }
        }
    }
}

/// FreeBSD/illumos v0 is intentionally kernel-only.  A probe with a
/// binary slot is unambiguously a userspace probe in Bifrost's parser;
/// the classic DTrace `pid` provider and the Bifrost-specific uprobe
/// and USDT provider shapes are userspace as well.
pub fn is_guest_userspace_probe(spec: &ProbeSpec) -> bool {
    spec.binary.is_some()
        || spec.provider == "uprobe"
        || spec.provider == "usdt"
        || spec.provider == "pid"
        || spec.provider.starts_with("pid$")
        || (spec.provider == "bifrost" && spec.module == "guest_user")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(s: &str) -> ProbeSpec {
        ProbeSpec::parse(s).unwrap_or_else(|| panic!("failed to parse probe spec: {s}"))
    }

    #[test]
    fn linux_guest_keeps_existing_ebpf_route() {
        assert_eq!(
            TraceTarget::Guest(GuestOs::Linux).route_probe(&spec("fbt:guest:vfs_open:entry")),
            ProbeRoute::LinuxEbpf
        );
        assert_eq!(
            TraceTarget::Guest(GuestOs::Linux)
                .route_probe(&spec("tracepoint:guest:raw_syscalls:sys_enter")),
            ProbeRoute::LinuxEbpf
        );
    }

    #[test]
    fn guest_os_selects_load_format() {
        assert_eq!(
            GuestOs::Linux.backend_kind().load_format(),
            LoadFormat::LinuxBfr7LoadProg
        );
        assert_eq!(
            GuestOs::FreeBsd.backend_kind().load_format(),
            LoadFormat::NativeKernelDtraceSession
        );
        assert_eq!(
            GuestOs::Illumos.backend_kind().load_format(),
            LoadFormat::NativeKernelDtraceSession
        );
    }

    #[test]
    fn native_dtrace_backend_encodes_host_supplied_dof_session() {
        let dof = b"\x7fDOF-test";
        let backend = NativeDtraceBackend::freebsd();
        let session = backend
            .build_session(NativeDtraceSessionRequest::run_dof(
                dof,
                FREEBSD_DTRACE_PROOF_VALUE,
            ))
            .expect("build native DTrace session");

        assert_eq!(session.os, GuestOs::FreeBsd);
        assert_eq!(session.backend_kind, BackendKind::NativeKernelDtrace);
        assert_eq!(session.load_format, LoadFormat::NativeKernelDtraceSession);
        assert_eq!(session.statuses, vec![bifrost_wire::RSP_LOADPROG_STATUS_OK]);
        let payload = session.single_payload().expect("one payload");
        assert_eq!(payload.kind, crate::control_shmem::KIND_LOAD_PROG);
        assert_eq!(
            u32::from_le_bytes(payload.body[0..4].try_into().unwrap()),
            NATIVE_DTRACE_SESSION_MAGIC
        );
        assert_eq!(
            u16::from_le_bytes(payload.body[4..6].try_into().unwrap()),
            NATIVE_DTRACE_SESSION_VERSION
        );
        assert_eq!(
            u16::from_le_bytes(payload.body[6..8].try_into().unwrap()),
            NATIVE_DTRACE_OP_RUN_DOF
        );
        assert_eq!(
            u16::from_le_bytes(payload.body[8..10].try_into().unwrap()),
            NATIVE_DTRACE_GUEST_OS_FREEBSD
        );
        assert_eq!(
            u16::from_le_bytes(payload.body[10..12].try_into().unwrap()),
            NATIVE_DTRACE_FLAG_EXPECT_VALUE
        );
        assert_eq!(
            u32::from_le_bytes(payload.body[12..16].try_into().unwrap()),
            NATIVE_DTRACE_HEADER_LEN as u32
        );
        assert_eq!(
            u32::from_le_bytes(payload.body[16..20].try_into().unwrap()),
            dof.len() as u32
        );
        assert_eq!(
            u32::from_le_bytes(payload.body[20..24].try_into().unwrap()),
            NATIVE_DTRACE_DEFAULT_PROBE_ID
        );
        assert_eq!(
            u64::from_le_bytes(payload.body[24..32].try_into().unwrap()),
            FREEBSD_DTRACE_PROOF_VALUE
        );
        assert_eq!(&payload.body[NATIVE_DTRACE_HEADER_LEN..], dof);
        assert_eq!(session.record_schemas.len(), 1);
        assert_eq!(
            session.record_schemas[0].probe_id,
            NATIVE_DTRACE_DEFAULT_PROBE_ID
        );
        assert_eq!(
            session.record_schemas[0].schema,
            RecordSchema::default_trace()
        );
    }

    #[test]
    fn native_dtrace_backend_rejects_linux_and_empty_dof() {
        assert!(NativeDtraceBackend::for_guest(GuestOs::Linux).is_err());
        let err = NativeDtraceBackend::freebsd()
            .build_session(NativeDtraceSessionRequest::run_dof(
                b"",
                FREEBSD_DTRACE_PROOF_VALUE,
            ))
            .unwrap_err();
        assert!(
            err.to_string().contains("non-empty DOF"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn linux_guest_rejects_native_tuple_without_rewrite() {
        assert_eq!(
            TraceTarget::Guest(GuestOs::Linux).route_probe(&spec("syscall::open:entry")),
            ProbeRoute::Rejected(RejectReason::LinuxNeedsBifrostProvider)
        );
    }

    #[test]
    fn freebsd_guest_preserves_native_kernel_dtrace_tuple() {
        assert_eq!(
            TraceTarget::Guest(GuestOs::FreeBsd).route_probe(&spec("syscall::open:entry")),
            ProbeRoute::NativeKernelDtrace(GuestOs::FreeBsd)
        );
        assert_eq!(
            TraceTarget::Guest(GuestOs::FreeBsd).route_probe(&spec("fbt:kernel:vfs_open:entry")),
            ProbeRoute::NativeKernelDtrace(GuestOs::FreeBsd)
        );
    }

    #[test]
    fn illumos_uses_same_native_kernel_dtrace_contract() {
        assert_eq!(
            TraceTarget::Guest(GuestOs::Illumos).route_probe(&spec("fbt:genunix:open:entry")),
            ProbeRoute::NativeKernelDtrace(GuestOs::Illumos)
        );
    }

    #[test]
    fn native_guest_rejects_userspace_probe_shapes() {
        for raw in [
            "uprobe:guest:redis-server:processCommand:entry",
            "usdt:guest:postgres:postgresql:query__start",
            "pid$target::malloc:entry",
            "bifrost:guest_user:redis-server:processCommand:entry",
        ] {
            assert_eq!(
                TraceTarget::Guest(GuestOs::FreeBsd).route_probe(&spec(raw)),
                ProbeRoute::Rejected(RejectReason::GuestUserspaceProbe),
                "{raw}"
            );
        }
    }

    #[test]
    fn host_target_stays_host_libdtrace() {
        assert_eq!(
            TraceTarget::Host.route_probe(&spec("syscall::open:entry")),
            ProbeRoute::HostLibdtrace
        );
    }

    #[test]
    fn v2_session_header_has_40_byte_size_and_default_duration_zero() {
        // Wire-format pin: v2 header lays out
        //   off 0   u32 magic
        //   off 4   u16 version
        //   off 6   u16 op
        //   off 8   u16 os
        //   off 10  u16 flags
        //   off 12  u32 header_len
        //   off 16  u32 dof_len
        //   off 20  u32 probe_id
        //   off 24  u64 expected
        //   off 32  u32 duration_ms
        //   off 36  u32 reserved
        // for a total of 40 bytes, followed by DOF.
        assert_eq!(NATIVE_DTRACE_HEADER_LEN, 40);
        assert_eq!(NATIVE_DTRACE_SESSION_VERSION, 2);

        let dof = b"\x7fDOF-payload";
        let session = NativeDtraceBackend::freebsd()
            .build_session(NativeDtraceSessionRequest::run_dof(dof, 0xdeadbeef))
            .expect("build session");
        let body = &session.single_payload().unwrap().body;

        assert_eq!(body.len(), NATIVE_DTRACE_HEADER_LEN + dof.len());
        assert_eq!(
            u32::from_le_bytes(body[12..16].try_into().unwrap()),
            NATIVE_DTRACE_HEADER_LEN as u32
        );
        // Default duration_ms is zero — kernel substitutes its own
        // default (500 ms).
        assert_eq!(
            u32::from_le_bytes(body[32..36].try_into().unwrap()),
            0,
        );
        assert_eq!(
            u32::from_le_bytes(body[36..40].try_into().unwrap()),
            0,
            "reserved tail must be zero on emit"
        );
        assert_eq!(&body[NATIVE_DTRACE_HEADER_LEN..], dof);
    }

    #[test]
    fn with_duration_ms_round_trips_into_session_header() {
        let dof = b"\x7fDOF-x";
        let req = NativeDtraceSessionRequest::run_dof_session(
            dof,
            NATIVE_DTRACE_DEFAULT_PROBE_ID,
            None,
            NATIVE_DTRACE_DEFAULT_LABEL,
        )
        .with_duration_ms(1234);
        let session = NativeDtraceBackend::freebsd()
            .build_session(req)
            .expect("build session");
        let body = &session.single_payload().unwrap().body;
        assert_eq!(
            u32::from_le_bytes(body[32..36].try_into().unwrap()),
            1234
        );
        // Without the expect-value flag, expected slot is zero.
        assert_eq!(
            u16::from_le_bytes(body[10..12].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn is_supported_native_probe_matches_the_kernel_attach_set() {
        // Lock the host-side preflight allow-list against the
        // `dtrace:::BEGIN`, fbt, syscall, and profile probe
        // families the FreeBSD bridge actually attaches.  Adds
        // regression coverage so a future scope-widening accident
        // in the kernel doesn't drift out of sync with this
        // gate without notice.
        let yes = |raw: &str| {
            let spec = crate::parse::ProbeSpec::parse(raw).expect(raw);
            let tuple = crate::ProbeDescTuple {
                provider: spec.provider.clone(),
                module: spec.module.clone(),
                function: spec.function.clone(),
                name: spec.name.clone(),
                id: 0,
            };
            assert!(
                is_supported_native_probe(&tuple),
                "{raw} should be accepted"
            );
        };
        let no = |raw: &str| {
            let spec = crate::parse::ProbeSpec::parse(raw).expect(raw);
            let tuple = crate::ProbeDescTuple {
                provider: spec.provider.clone(),
                module: spec.module.clone(),
                function: spec.function.clone(),
                name: spec.name.clone(),
                id: 0,
            };
            assert!(
                !is_supported_native_probe(&tuple),
                "{raw} should be rejected"
            );
        };

        yes("dtrace:::BEGIN");
        // dtrace:::END is auto-fired by dtrace_state_stop in the
        // FreeBSD kernel and must be acceptable to the host
        // preflight so cross-guest D programs that print agg
        // snapshots in END run unchanged.
        yes("dtrace:::END");
        // The bare forms — libdtrace leaves the provider slot
        // empty in the DOF probedesc but resolves them to dtrace:::
        // at match time.  Authors should be able to write `END { ... }`
        // without spelling out the provider just to satisfy preflight.
        yes(":::BEGIN");
        yes(":::END");
        yes("fbt:kernel:vfs_open:entry");
        yes("fbt:kernel:tcp_input:return");
        yes("syscall::open:entry");
        yes("syscall::write:return");
        yes("profile:::tick-1sec");
        yes("profile:::profile-100hz");

        // Rejected: unknown providers, profile without dash suffix.
        no("usdt:guest:redis-server:redis:cmd");
        no("profile:::tick");
        no("fbt:kernel::entry"); // empty function slot
    }
}
