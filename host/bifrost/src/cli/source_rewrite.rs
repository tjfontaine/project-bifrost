// Source-level rewrites applied to the user's D program before
// libdtrace consumes it.  Each rewrite is a pure text→text transform
// that takes a clause body / source string and returns a modified
// version, or in the case of `rewrite_retval`, a `Result` that
// surfaces a typed error if the source uses `retval` in a clause
// shape that can't support it.
//
// The rewrites compose left-to-right in the order the bifrost CLI
// applies them: gstack/gustack → OFFSETOF → retval → libdtrace.

#![cfg(target_os = "macos")]

use crate::parse;
use thiserror::Error;

/// Errors `rewrite_retval` can return.  Oxide-style: typed enum at
/// the module boundary; `From<RewriteError> for String` bridges to
/// the still-stringly-typed callers (parse_args).
#[derive(Debug, Error)]
pub enum RewriteError {
    #[error("internal: clause has no probe specs")]
    ClauseHasNoSpecs,

    #[error(
        "`retval` is only valid in fbt:<domain>:<funcname>:return clauses; clause `{spec_render}` uses provider `{provider}` / name `{name}`"
    )]
    RetvalInNonFbtReturn {
        spec_render: String,
        provider: String,
        name: String,
    },

    #[error(
        "`retval` requires vmlinux BTF to resolve the target function's arity; BTF was not loaded"
    )]
    RetvalRequiresBtf,

    #[error(
        "`retval` in `{spec_render}`: function `{function}` not found in vmlinux BTF, cannot determine arity"
    )]
    FunctionNotInBtf {
        spec_render: String,
        function: String,
    },

    #[error(
        "`retval` in `{spec_render}`: function `{function}` has arity {arity} which exceeds the arg0..arg9 DIF range; access the return value via `args[{arity}]` directly once typed-arg lowering lands"
    )]
    ArityExceedsArgRange {
        spec_render: String,
        function: String,
        arity: usize,
    },
}

impl From<RewriteError> for String {
    fn from(err: RewriteError) -> String {
        err.to_string()
    }
}

/// Build a self-contained D program from a single clause. libdtrace
/// happily compiles `provider:m:f:n /pred/ { body }` as a one-clause
/// program with DTRACE_C_ZDEFS, even when the provider doesn't exist
/// (which is the case for `bifrost:`).
pub fn build_clause_program(c: &parse::Clause) -> String {
    // libdtrace's probe-description grammar is hard-pinned at 4
    // tuples; the canonical `uprobe:<domain>:<binary>:<sym>:<name>`
    // (and the retired `bifrost:guest_user:<binary>:<sym>:<name>`)
    // 5-tuple shapes would parse as "Overspecified".  Render them
    // as 4-tuples for libdtrace's consumption — the binary slot is
    // preserved on the original ProbeSpec and used by the BFR7
    // wrapper builder.
    let specs = c
        .specs
        .iter()
        .map(|s| {
            if s.is_guest_user() || s.is_usdt() {
                format!("{}:{}:{}:{}", s.provider, s.module, s.function, s.name)
            } else {
                s.render()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = String::new();
    s.push_str(&specs);
    if let Some(p) = &c.predicate {
        s.push_str(" /");
        s.push_str(p);
        s.push('/');
    }
    s.push_str(" {");
    s.push_str(&c.body);
    s.push('}');
    s
}

/// Rewrite `retval` token references in a clause body+predicate to
/// `arg<arity>`, the slot a BPF_TRACE_FEXIT trampoline writes the
/// function's return value into.  Only meaningful for fexit clauses
/// (`fbt:<domain>:<funcname>:return`) — for any other clause shape,
/// `retval` is left unchanged so it surfaces as a libdtrace
/// "Unknown variable name" error (which is the right diagnostic).
///
/// Returns either the rewritten source or an `Err` if a clause uses
/// `retval` against a target whose arity isn't resolvable from the
/// loaded vmlinux BTF.  For arity > 9 (the existing arg0..arg9 DIF
/// builtin range), returns an error pointing at the limitation.
pub fn rewrite_retval(
    source: &str,
    clause: &parse::Clause,
    btf: Option<&mut crate::btf::Btf>,
) -> Result<String, RewriteError> {
    if !contains_word(source, "retval") {
        return Ok(source.to_string());
    }
    // retval only meaningful in fexit clauses.  Detect via the
    // first spec — multi-spec clauses with mixed entry/return are
    // legal D but `retval` in a mixed clause has ambiguous meaning,
    // so we require a single :return spec on a fbt provider.
    let spec = clause.specs.first().ok_or(RewriteError::ClauseHasNoSpecs)?;
    if !(spec.is_fbt() && spec.name == "return") {
        return Err(RewriteError::RetvalInNonFbtReturn {
            spec_render: spec.render(),
            provider: spec.provider.clone(),
            name: spec.name.clone(),
        });
    }
    let btf = btf.ok_or(RewriteError::RetvalRequiresBtf)?;
    let arity = btf
        .func_arity(&spec.function)
        .ok_or_else(|| RewriteError::FunctionNotInBtf {
            spec_render: spec.render(),
            function: spec.function.clone(),
        })?;
    if arity > 9 {
        return Err(RewriteError::ArityExceedsArgRange {
            spec_render: spec.render(),
            function: spec.function.clone(),
            arity: arity as usize,
        });
    }
    let replacement = format!("arg{}", arity);
    Ok(replace_word_token(source, "retval", &replacement))
}

/// Token-level substitution.  Replace standalone occurrences of
/// `needle` (not part of a longer identifier) with `replacement`.
pub fn replace_word_token(haystack: &str, needle: &str, replacement: &str) -> String {
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < bytes.len() {
        let prev_ok = i == 0 || !is_ident_char(bytes[i - 1]);
        let after = i + needle_bytes.len();
        let next_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
        if prev_ok && next_ok && bytes[i..].starts_with(needle_bytes) {
            out.push_str(replacement);
            i = after;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

pub fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    for i in 0..bytes.len() {
        let prev_ok = i == 0 || !is_ident_char(bytes[i - 1]);
        let after = i + needle_bytes.len();
        let next_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
        if prev_ok && next_ok && bytes[i..].starts_with(needle_bytes) {
            return true;
        }
    }
    false
}

pub fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Stable provider catalog.  D scripts that reference
/// `proc:::exec`, `sched:::switch`, `io:::start`, `syscall:::entry`,
/// etc., get rewritten to the underlying canonical bifrost-routed
/// probe spec (`tracepoint:guest:<category>:<event>` or
/// `tracepoint:guest:raw_syscalls:sys_enter`) before the parser
/// sees them.
///
/// Why a stable provider catalog: today's clauses hardcode the raw
/// tracepoint name (`tracepoint:guest:sched:sched_switch:entry`).
/// When the upstream kernel renames or restructures a tracepoint —
/// `block_rq_issue` ↔ `block_rq_insert`, `sched_wakeup` body shape
/// changes, etc. — every D script that referenced it breaks.
/// DTrace's whole bet was that stable providers (proc, sched, io,
/// syscall, vminfo, sysinfo, …) survive kernel internals churn:
/// the *contract* is the provider name; the implementation is free
/// to evolve underneath.
///
/// This commit ships the *mapping table*; the underlying tracepoint
/// path is unchanged.  When a future kernel renames a tracepoint we
/// touch one entry here, and every script that referenced the
/// stable name keeps working.
const STABLE_PROVIDERS: &[(&str, &str)] = &[
    // ────────────────────────────────────────────────────────────
    // proc:::*  process lifecycle
    // ────────────────────────────────────────────────────────────
    ("proc:::exec", "tracepoint:guest:sched:sched_process_exec"),
    ("proc:::exit", "tracepoint:guest:sched:sched_process_exit"),
    ("proc:::fork", "tracepoint:guest:sched:sched_process_fork"),
    ("proc:::lwp-start", "tracepoint:guest:task:task_newtask"),
    // ────────────────────────────────────────────────────────────
    // sched:::*  scheduler events
    // ────────────────────────────────────────────────────────────
    ("sched:::switch", "tracepoint:guest:sched:sched_switch"),
    // sched:::on-cpu / off-cpu — DTrace classically has two distinct
    // probes that fire on opposite sides of a context switch.  Linux
    // emits one `sched_switch` event carrying both `prev_*` and
    // `next_*` args; we map both stable names to that single event
    // and rely on the user predicating with `pid == next_pid` (on-cpu)
    // or `pid == prev_pid` (off-cpu).  A future extension
    // could synthesize a body-rewrite that auto-binds the right side.
    ("sched:::on-cpu", "tracepoint:guest:sched:sched_switch"),
    ("sched:::off-cpu", "tracepoint:guest:sched:sched_switch"),
    ("sched:::wakeup", "tracepoint:guest:sched:sched_wakeup"),
    (
        "sched:::wakeup-new",
        "tracepoint:guest:sched:sched_wakeup_new",
    ),
    (
        "sched:::migrate-task",
        "tracepoint:guest:sched:sched_migrate_task",
    ),
    // ────────────────────────────────────────────────────────────
    // io:::*  block I/O lifecycle
    // ────────────────────────────────────────────────────────────
    ("io:::start", "tracepoint:guest:block:block_rq_issue"),
    ("io:::done", "tracepoint:guest:block:block_rq_complete"),
    ("io:::insert", "tracepoint:guest:block:block_rq_insert"),
    // ────────────────────────────────────────────────────────────
    // syscall:::*  generic syscall entry/return.  For per-syscall
    // probes (e.g. `syscall::execve:entry`), use the existing
    // `tracepoint:guest:syscalls:sys_enter_<name>` form directly —
    // the per-syscall map is too long to enumerate here and the
    // canonical raw_syscalls events cover the all-syscalls case.
    // ────────────────────────────────────────────────────────────
    ("syscall:::entry", "tracepoint:guest:raw_syscalls:sys_enter"),
    ("syscall:::return", "tracepoint:guest:raw_syscalls:sys_exit"),
    // ────────────────────────────────────────────────────────────
    // tcp:::*  TCP send/receive lifecycle.  DTrace classically
    // models these as stable per-connection events with translators
    // that expose `args[0]->ip_saddr` etc.  Linux's `tcp:tcp_*`
    // tracepoints carry similar args.  This catalog maps the
    // canonical names; until a translator layer lands, scripts
    // still access tracepoint args via the raw arg0..N indexes.
    // ────────────────────────────────────────────────────────────
    ("tcp:::send", "tracepoint:guest:tcp:tcp_send_reset"),
    ("tcp:::receive", "tracepoint:guest:tcp:tcp_receive_reset"),
    ("tcp:::probe", "tracepoint:guest:tcp:tcp_probe"),
    (
        "tcp:::retransmit",
        "tracepoint:guest:tcp:tcp_retransmit_skb",
    ),
    ("tcp:::destroy", "tracepoint:guest:tcp:tcp_destroy_sock"),
    // ────────────────────────────────────────────────────────────
    // signal:::*  signal lifecycle
    // ────────────────────────────────────────────────────────────
    ("signal:::send", "tracepoint:guest:signal:signal_generate"),
    ("signal:::handle", "tracepoint:guest:signal:signal_deliver"),
];

/// Apply the stable-provider mappings to a D source.  Pure
/// text→text; preserves all non-matching content verbatim.  The
/// rewrite is word-boundary aware (via `replace_word_token`) so
/// unrelated tokens that happen to share a prefix (`procX:::exec`,
/// `proc:::exec_extra`) don't accidentally match.
///
/// Two passes:
///   1. Static table (`STABLE_PROVIDERS`) — fixed (needle, replacement)
///      pairs for the all-syscalls / process-lifecycle / scheduler /
///      io shapes.
///   2. Per-syscall dynamic rewrite — `syscall::<name>:entry|return`
///      maps to `tracepoint:guest:syscalls:sys_enter_<name>` /
///      `sys_exit_<name>`.  The static table can't enumerate every
///      syscall, so this pass walks the source for the pattern.
pub fn rewrite_stable_providers(input: &str) -> String {
    let mut out = input.to_string();
    for (needle, replacement) in STABLE_PROVIDERS {
        if contains_word(&out, needle) {
            out = replace_word_token(&out, needle, replacement);
        }
    }
    rewrite_per_syscall(&out)
}

// Typed-translator expansion happens via the parser-aware pass in
// `crate::translators::expand_translators`, called per bifrost-
// routed clause body after `parse::parse` has split the source.
// Splitting first then rewriting:
//
//   - keeps `printf("args[0]->prev->comm")` literal mentions
//     intact (a pure `String::replace` on the unsplit source would
//     rewrite those too).
//   - only rewrites in `bifrost:` / `tracepoint:` / `fbt:`
//     clauses; host-routed clauses keep the real DTrace translator
//     semantics.
//   - admits BTF-driven chains (`args[0]->prev->se.sum_exec_runtime`)
//     because the rewriter sees structured clause context, not just
//     raw bytes — see `host/bifrost/src/translators.rs`.

/// Per-syscall dynamic rewrite.  Walk the source looking for
/// `syscall::<name>:entry` and `syscall::<name>:return` shapes
/// (where `<name>` is a valid identifier — alphanumeric or
/// underscore) and translate each occurrence to the matching
/// `tracepoint:guest:syscalls:sys_(enter|exit)_<name>` form.
///
/// Word-boundary aware on both ends so we don't accidentally
/// rewrite tokens that contain `syscall::` as a substring of a
/// larger identifier.
fn rewrite_per_syscall(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let prefix = b"syscall::";
    while i < bytes.len() {
        if bytes[i..].starts_with(prefix) {
            let prev_ok = i == 0 || !is_ident_char(bytes[i - 1]);
            if prev_ok {
                // Extract <name> after the `syscall::` prefix.
                let name_start = i + prefix.len();
                let mut name_end = name_start;
                while name_end < bytes.len() && is_ident_char(bytes[name_end]) {
                    name_end += 1;
                }
                if name_end > name_start {
                    // Look for `:entry` or `:return` immediately after
                    // the name.
                    let suffix_pos = name_end;
                    let entry_marker: &[u8] = b":entry";
                    let return_marker: &[u8] = b":return";
                    let (variant, suffix_len) = if bytes[suffix_pos..].starts_with(entry_marker) {
                        ("enter", entry_marker.len())
                    } else if bytes[suffix_pos..].starts_with(return_marker) {
                        ("exit", return_marker.len())
                    } else {
                        out.push(bytes[i] as char);
                        i += 1;
                        continue;
                    };
                    let after = suffix_pos + suffix_len;
                    let next_ok = after >= bytes.len() || !is_ident_char(bytes[after]);
                    if next_ok {
                        let name = std::str::from_utf8(&bytes[name_start..name_end])
                            .unwrap_or("__bad_utf8");
                        out.push_str("tracepoint:guest:syscalls:sys_");
                        out.push_str(variant);
                        out.push('_');
                        out.push_str(name);
                        i = after;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Replace bifrost's `gstack(...)`/`gustack(...)` helpers with the
/// underlying DTrace action names `stack(...)`/`ustack(...)`. Word-
/// boundary aware so identifiers containing `gstack` as a substring
/// (e.g. an arbitrarily-named variable) aren't accidentally rewritten.
pub fn rewrite_g_actions(input: &str) -> String {
    fn replace_word(haystack: &str, needle: &str, replacement: &str) -> String {
        let mut out = String::with_capacity(haystack.len());
        let bytes = haystack.as_bytes();
        let n_bytes = needle.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if i + n_bytes.len() <= bytes.len()
                && &bytes[i..i + n_bytes.len()] == n_bytes
                && (i == 0 || !is_ident_byte(bytes[i - 1]))
                && (i + n_bytes.len() == bytes.len() || !is_ident_byte(bytes[i + n_bytes.len()]))
            {
                out.push_str(replacement);
                i += n_bytes.len();
            } else {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
        out
    }
    fn is_ident_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    let s = replace_word(input, "gstack", "stack");
    replace_word(&s, "gustack", "ustack")
}

/// One CORE_OFFSETOF site recorded by `rewrite_core_offsetof`.
///
/// Each site is rewritten in source text to a unique sentinel u64
/// literal that survives libdtrace's inttab canonicalization without
/// colliding with plausibly-real script constants (high 32 bits are
/// pinned to the magic `0xC0FECAFE`).  After the eBPF stream is
/// lowered, `materialize_field_relocs` walks the bytecode for
/// `bpf_ld_imm64` instructions whose imm matches a sentinel: each
/// gets its imm rewritten to the host-resolved `fallback_offset` (so
/// the program runs even when the libkrun BTF patcher is absent or
/// fails) AND a `MaterializedFieldReloc` is emitted pointing at that
/// instruction's `imm` byte position so the guest's CO-RE-aware
/// patcher can re-resolve against the running kernel's BTF.
#[derive(Debug, Clone)]
pub struct CoreOffsetofMarker {
    /// Unique-per-CLI-invocation sentinel.  High 32 bits are the
    /// magic `0xC0FECAFE` so accidental matches against legitimate
    /// program constants are vanishingly unlikely.  Low 32 bits = seq.
    pub sentinel: u64,
    pub struct_name: String,
    pub field_name: String,
    /// Host-resolved offset (from the dev box's vmlinux BTF) used as
    /// a fallback when the patcher is absent.  Stored as u32 because
    /// every realistic struct field offset fits in u32 — the wire
    /// format reserves only 4 bytes per patch site.
    pub fallback_offset: u32,
}

/// High 32 bits of every CORE_OFFSETOF sentinel.  Pinned at this
/// value so the post-process eBPF scanner can cheaply triage
/// candidate `bpf_ld_imm64` instructions before consulting the
/// marker list.  Real D-source integer constants this large are
/// vanishingly rare.
///
/// Bit 63 is intentionally clear: libdtrace's integer-constant
/// parser only accepts values that fit in a built-in integral
/// type, and the largest is int64.  A HI prefix with bit 31 set
/// (e.g. `0xC0FECAFE`) builds a literal that overflows int64
/// before the lower seq bits are even ORed in — `0xC0FECAFE...`
/// then surfaces as `cannot be represented in any built-in
/// integral type` from the libdtrace compiler.  `0x7C0FECAFE` is
/// equally improbable as a real script constant and stays inside
/// int64.
pub const CORE_OFFSETOF_SENTINEL_HI: u32 = 0x7C0F_CAFE;

fn core_offsetof_sentinel(seq: u32) -> u64 {
    ((CORE_OFFSETOF_SENTINEL_HI as u64) << 32) | (seq as u64)
}

/// Quick triage: does `imm64` look like one of our sentinels?  The
/// caller still has to confirm against the marker list to recover
/// the `(struct, field)` pair, but this avoids walking the marker
/// list for every imm64 in the program.
pub fn is_core_offsetof_sentinel(imm64: u64) -> bool {
    ((imm64 >> 32) as u32) == CORE_OFFSETOF_SENTINEL_HI
}

/// Resolve `CORE_OFFSETOF(struct_name, field)` patterns in D source
/// against the host-side BTF (the dev box's `vmlinux`), replacing
/// each with a *unique sentinel u64 literal* and returning a parallel
/// list of `CoreOffsetofMarker` records that pin
/// `(sentinel, struct, field, host-resolved-offset)`.
///
/// Distinct from the older `rewrite_offsetof`: this rewrite is
/// CO-RE aware.  The sentinel survives libdtrace compilation as a
/// normal integer constant; after eBPF lowering, the post-process
/// step `materialize_field_relocs` scans the bytecode for
/// `bpf_ld_imm64` instructions whose imm matches a sentinel,
/// patches each in place to the fallback offset, and emits a
/// wrapper-level field reloc the libkrun-side patcher uses to
/// re-resolve against the *guest's* running-kernel BTF.  Net
/// effect: programs are kernel-version durable — the guest patcher
/// updates `task_struct.comm`'s offset to whatever the running
/// kernel's BTF says, regardless of what the dev box's BTF said
/// at compile time.
///
/// If BTF isn't loaded, returns the source unchanged with an empty
/// marker list — the existing libdtrace compile error path surfaces
/// the missing-BTF diagnostic.  Any `CORE_OFFSETOF(...)` whose
/// (struct, field) pair fails BTF lookup also leaves the source
/// untouched at that site (and stderr diagnostic), matching the
/// `rewrite_offsetof` posture.
///
/// MUST run *before* `rewrite_offsetof` so the latter's `OFFSETOF`
/// substring search doesn't swallow the `CORE_OFFSETOF` macro
/// spelling (token-boundary check guards against most cases, but
/// running CORE-first is the simpler invariant).
pub fn rewrite_core_offsetof(
    input: &str,
    btf: Option<&mut crate::btf::Btf>,
) -> (String, Vec<CoreOffsetofMarker>) {
    let Some(btf) = btf else {
        return (input.to_string(), Vec::new());
    };
    let mut out = String::with_capacity(input.len());
    let mut markers: Vec<CoreOffsetofMarker> = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    let needle = b"CORE_OFFSETOF";
    while i < bytes.len() {
        let starts = i + needle.len() <= bytes.len()
            && &bytes[i..i + needle.len()] == needle
            && (i == 0 || (!bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_'));
        if !starts {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let mut j = i + needle.len();
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'(' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        j += 1;
        let (struct_name, after_name) = scan_ident(bytes, j);
        let mut k = after_name;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b',' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        let (field_name, after_field) = scan_ident(bytes, k);
        let mut m = after_field;
        while m < bytes.len() && bytes[m].is_ascii_whitespace() {
            m += 1;
        }
        if m >= bytes.len() || bytes[m] != b')' || struct_name.is_empty() || field_name.is_empty() {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        m += 1;
        match btf.field_offset(struct_name, field_name) {
            Ok((off, _size)) => {
                use std::fmt::Write;
                let seq = markers.len() as u32;
                let sentinel = core_offsetof_sentinel(seq);
                let _ = write!(out, "{}", sentinel);
                markers.push(CoreOffsetofMarker {
                    sentinel,
                    struct_name: struct_name.to_string(),
                    field_name: field_name.to_string(),
                    fallback_offset: off,
                });
                i = m;
            }
            Err(e) => {
                eprintln!(
                    "[bifrost] CORE_OFFSETOF({}, {}) failed: {}; leaving source as-is",
                    struct_name, field_name, e
                );
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    (out, markers)
}

/// One field-reloc record materialized from a `CoreOffsetofMarker`
/// after the lowering pass.  Owning string fields so the post-process
/// can run after the lowering's borrows have ended.  Mirrors the
/// shape of `bifrost::cli::wrapper::OwnedFieldReloc`; the cli-layer
/// holds the canonical owning shape, but this module re-exports
/// its own to keep the source-rewrite layer free of cross-layer
/// coupling for unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedFieldReloc {
    /// Byte offset into the program's eBPF stream.
    pub insn_idx: u32,
    pub access_kind: u8,
    pub byte_off_in_insn: u8,
    pub struct_name: String,
    pub field_name: String,
}

/// Walk a lowered eBPF stream looking for `bpf_ld_imm64`
/// instructions whose 64-bit immediate matches a
/// `CoreOffsetofMarker` sentinel.  For each hit, *patch the
/// immediate in place* with the marker's `fallback_offset` (so the
/// program is verifier-correct even when no BTF patcher is
/// present) and emit a `MaterializedFieldReloc` pointing at that
/// instruction's `imm` byte position so the libkrun-side patcher
/// can re-resolve against running-kernel BTF.
///
/// `bpf_ld_imm64` is the two-slot wide-immediate eBPF form:
///   slot 0:  [code=0x18 | dst=rd, src=0 | off=0 | imm32=lo]
///   slot 1:  [code=0x00 | dst=0,  src=0 | off=0 | imm32=hi]
/// We detect it by checking slot 0's opcode (0x18) AND slot 1's
/// opcode (0x00) AND slot 0's `src` nibble = 0 (so a
/// `bpf_ld_map_fd` — same opcode but `src=BPF_PSEUDO_MAP_FD=1` —
/// never matches).
///
/// All offsets reported are byte offsets, so the libkrun patcher
/// applies `insns[insn_idx + byte_off..+4] = resolved` directly.
pub fn materialize_field_relocs(
    ebpf: &mut [u8],
    markers: &[CoreOffsetofMarker],
) -> Vec<MaterializedFieldReloc> {
    let mut out: Vec<MaterializedFieldReloc> = Vec::new();
    if markers.is_empty() || ebpf.len() < 16 {
        return out;
    }
    let mut i = 0usize;
    while i + 16 <= ebpf.len() {
        let lo_code = ebpf[i];
        let lo_src_dst = ebpf[i + 1];
        let hi_code = ebpf[i + 8];
        let hi_src_dst = ebpf[i + 9];
        // Discriminate plain bpf_ld_imm64 from bpf_ld_map_fd / kfunc
        // by requiring slot 0 src==0 (high nibble of byte 1) and
        // slot 1's bytes match the canonical hi-half encoding
        // (code=0x00, src=0, dst=0).  See bpf_ld_imm64() in
        // host/bifrost/src/lower/emit.rs.
        if lo_code == 0x18 && (lo_src_dst & 0xF0) == 0 && hi_code == 0x00 && hi_src_dst == 0 {
            let lo_imm = u32::from_le_bytes(ebpf[i + 4..i + 8].try_into().unwrap());
            let hi_imm = u32::from_le_bytes(ebpf[i + 12..i + 16].try_into().unwrap());
            let imm64 = ((hi_imm as u64) << 32) | (lo_imm as u64);
            if is_core_offsetof_sentinel(imm64)
                && let Some(m) = markers.iter().find(|m| m.sentinel == imm64)
            {
                ebpf[i + 4..i + 8].copy_from_slice(&m.fallback_offset.to_le_bytes());
                ebpf[i + 12..i + 16].copy_from_slice(&0u32.to_le_bytes());
                out.push(MaterializedFieldReloc {
                    insn_idx: i as u32,
                    access_kind: bifrost_wire::FIELD_RELOC_OFFSET,
                    byte_off_in_insn: 4,
                    struct_name: m.struct_name.clone(),
                    field_name: m.field_name.clone(),
                });
            }
            i += 16;
            continue;
        }
        i += 8;
    }
    out
}

/// Resolve `OFFSETOF(struct_name, field)` patterns in D source against
/// the guest kernel's BTF, replacing each with the literal byte offset.
/// libdtrace doesn't know about Linux kernel struct layouts; this is
/// the cheapest CO-RE-style: bake offsets in at host-side compile time
/// using `vmlinux`'s `.BTF` section.
///
/// Lookup is greedy on `struct_name` and `field`. Only top-level fields
/// are supported; for nested derefs the user writes `OFFSETOF(...)`
/// per hop. `BTFOFFSETOF` is also accepted as a synonym for grep-ability.
///
/// If BTF can't be loaded (e.g. vmlinux not on disk yet, or no .BTF
/// section), the preprocessor leaves the source alone — the resulting
/// libdtrace compile error points the user at the missing file.
///
/// Distinct from `rewrite_core_offsetof`: this OFFSETOF rewrite bakes
/// the resolved offset in as a *static* literal — the guest patcher
/// has nothing to do, and the program is locked to whatever
/// `task_struct.comm` was on the dev box.  CO-RE durability is
/// opt-in via `CORE_OFFSETOF`.
pub fn rewrite_offsetof(input: &str, btf: Option<&mut crate::btf::Btf>) -> String {
    let Some(btf) = btf else {
        return input.to_string();
    };
    // Pattern: OFFSETOF(<struct>, <field>) — whitespace allowed around
    // the comma. Both names are bare identifiers (no quotes), matching
    // C's offsetof() spelling.
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let needle = b"OFFSETOF";
    while i < bytes.len() {
        let starts = i + needle.len() <= bytes.len()
            && &bytes[i..i + needle.len()] == needle
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_');
        if !starts {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        // Skip past the keyword and optional whitespace.
        let mut j = i + needle.len();
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'(' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        j += 1;
        let (struct_name, after_name) = scan_ident(bytes, j);
        let mut k = after_name;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b',' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        let (field_name, after_field) = scan_ident(bytes, k);
        let mut m = after_field;
        while m < bytes.len() && bytes[m].is_ascii_whitespace() {
            m += 1;
        }
        if m >= bytes.len() || bytes[m] != b')' || struct_name.is_empty() || field_name.is_empty() {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        m += 1;
        match btf.field_offset(struct_name, field_name) {
            Ok((off, _size)) => {
                use std::fmt::Write;
                let _ = write!(out, "{}", off);
                i = m;
            }
            Err(e) => {
                eprintln!(
                    "[bifrost] OFFSETOF({}, {}) failed: {}; leaving source as-is",
                    struct_name, field_name, e
                );
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    out
}

/// Scan an identifier (alpha/digit/underscore, must start with non-digit)
/// from `bytes[at..]`. Returns (name_str, position_after).
pub fn scan_ident(bytes: &[u8], at: usize) -> (&str, usize) {
    let mut end = at;
    if end < bytes.len() && (bytes[end].is_ascii_alphabetic() || bytes[end] == b'_') {
        end += 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
    }
    let s = std::str::from_utf8(&bytes[at..end]).unwrap_or("");
    (s, end)
}

#[cfg(test)]
#[path = "source_rewrite_tests.rs"]
mod tests;
