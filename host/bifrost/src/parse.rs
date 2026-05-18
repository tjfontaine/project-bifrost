// SPDX-License-Identifier: Apache-2.0
//! Minimal D source parser — just enough to split a single source
//! file into clauses by provider, so the bifrost runner can dispatch
//! `bifrost:*` clauses to our DIF→eBPF lowering and everything else
//! (syscall:, pid$:, BEGIN, END, etc.) to native macOS dtrace.
//!
//! This is NOT a full D parser. It strips line/block comments, then
//! walks the source recognizing top-level clauses of the form:
//!
//!   probe-spec [, probe-spec ...]  [predicate]  { body }
//!
//! where:
//!   - probe-spec is `provider:module:function:name`. The provider
//!     and individual fields may contain wildcards (`*`/`?`); names
//!     can also include `$target` literally.
//!   - predicate is a `/expression/` — we don't parse the expression,
//!     just find the matching closing `/` (taking care to skip over
//!     `/` inside strings).
//!   - body is `{ ... }` with brace matching that respects strings
//!     and chars.
//!
//! Anything we don't recognize is preserved verbatim so it can be
//! emitted to the host-side script (e.g. `#pragma D option quiet`).

#![allow(dead_code)]

#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub provider: String,
    pub module: String,
    pub function: String,
    pub name: String,
    /// For `bifrost:guest_user:<binary>:<sym>:entry|return` probes:
    /// the binary slot. The 5-tuple is parsed by extending the
    /// 4-tuple shape only when `module == "guest_user"`. None for
    /// every other probe form (kernel, host, USDT, …).
    ///
    /// The binary is a basename (e.g. `nginx`, `redis-server`) — the
    /// CLI resolves it against the staged guest rootfs to get the
    /// absolute path. Slashes in the binary slot would clash with
    /// the clause walker's `/predicate/` recognition.
    pub binary: Option<String>,
}

impl ProbeSpec {
    pub fn parse(s: &str) -> Option<Self> {
        // Special-case identifier-only probes (BEGIN, END, ERROR).
        let trimmed = s.trim();
        if !trimmed.contains(':') && !trimmed.is_empty() {
            return Some(ProbeSpec {
                provider: trimmed.to_string(),
                module: String::new(),
                function: String::new(),
                name: String::new(),
                binary: None,
            });
        }
        // 5-tuple shapes carry a binary slot.  Three are recognized:
        //   - `uprobe:<domain>:<binary>:<sym>:<name>` — canonical
        //     userspace probe form (domain ∈ {guest, vmm}).
        //   - `usdt:<domain>:<binary>:<provider>:<probe>` — userspace
        //     SDT probe (domain ∈ {guest}). 4th slot is the SDT
        //     provider name (e.g. `postgresql`); 5th is the probe
        //     name (e.g. `query__start`). Unlike uprobe there is no
        //     entry/return distinction — USDT sites are single fire
        //     points marked by NOPs.
        //   - `bifrost:guest_user:<binary>:<sym>:<name>` — retired
        //     uprobe shape; still parses (so callers can produce a
        //     migration diagnostic) but is_deprecated_uprobe() flags
        //     it for rejection.
        let peek: Vec<&str> = trimmed.splitn(3, ':').collect();
        let is_5tuple = peek.len() == 3
            && ((peek[0] == "uprobe" && (peek[1] == "guest" || peek[1] == "vmm"))
                || (peek[0] == "usdt" && peek[1] == "guest")
                || (peek[0] == "bifrost" && peek[1] == "guest_user"));
        if is_5tuple {
            let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
            if parts.len() != 5 {
                return None;
            }
            return Some(ProbeSpec {
                provider: parts[0].to_string(),
                module: parts[1].to_string(),
                function: parts[3].to_string(),
                name: parts[4].to_string(),
                binary: Some(parts[2].to_string()),
            });
        }
        let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
        if parts.len() != 4 {
            return None;
        }
        Some(ProbeSpec {
            provider: parts[0].to_string(),
            module: parts[1].to_string(),
            function: parts[2].to_string(),
            name: parts[3].to_string(),
            binary: None,
        })
    }

    /// True if this probe routes through bifrost's eBPF lowering
    /// rather than native macOS dtrace.  Three canonical shapes plus
    /// two retired forms (kept for migration diagnostics):
    ///
    ///   - `fbt:<domain>:<funcname>:<entry|return>`           ← canonical fbt
    ///   - `tracepoint:<domain>:<category>:<event>`           ← canonical tracepoint
    ///   - `uprobe:<domain>:<binary>:<funcname>:<entry|return>` ← canonical uprobe
    ///   - `fbt::<funcname>:<entry|return>`                   ← retired (empty domain)
    ///   - `bifrost:guest_user:<binary>:<sym>:<entry|return>` ← retired uprobe
    ///   - `bifrost::<funcname>:<entry|return>`               ← retired kprobe
    ///   - `bifrost:guest_kernel:<funcname>:<entry|return>`   ← retired kprobe
    ///
    /// Domain in the canonical shapes is `guest` or `vmm`.  Empty
    /// modules (`fbt::funcname:entry`) are flagged by
    /// `is_deprecated_empty_domain` for upfront rejection.
    pub fn is_bifrost(&self) -> bool {
        matches!(
            self.provider.as_str(),
            "bifrost" | "fbt" | "tracepoint" | "uprobe" | "usdt"
        )
    }

    /// True for the canonical uprobe shape
    /// `uprobe:<domain>:<binary>:<funcname>:<entry|return>`.  Drives
    /// uprobe registration on the guest side.
    pub fn is_uprobe(&self) -> bool {
        self.provider == "uprobe"
            && (self.module == "guest" || self.module == "vmm")
            && self.binary.is_some()
    }

    /// True for the canonical USDT shape
    /// `usdt:guest:<binary>:<provider>:<probe>`.  4th slot is the SDT
    /// provider name from `.note.stapsdt` (e.g. `postgresql`); 5th
    /// is the probe name (e.g. `query__start`).  No entry/return —
    /// USDT sites are single-shot NOPs.  The CLI walks the binary's
    /// `.note.stapsdt` section to expand a single USDT clause into
    /// one uprobe registration per call site (a probe name often has
    /// a single site, but inlined macros can have several).
    pub fn is_usdt(&self) -> bool {
        self.provider == "usdt" && self.module == "guest" && self.binary.is_some()
    }

    /// True for any probe carrying a binary slot — covers both the
    /// canonical `uprobe:<domain>:...` form and the retired
    /// `bifrost:guest_user:...` form.  The CLI uses this to decide
    /// whether to walk the uprobe-target resolution path; the
    /// `is_deprecated_uprobe` predicate gates rejection of the old
    /// shape before that point.
    pub fn is_guest_user(&self) -> bool {
        self.binary.is_some()
            && (self.is_uprobe() || (self.provider == "bifrost" && self.module == "guest_user"))
    }

    /// True for the canonical fbt shape
    /// `fbt:<domain>:<funcname>:<entry|return>`.  Drives FENTRY/FEXIT
    /// trampoline attach on the guest side.
    pub fn is_fbt(&self) -> bool {
        self.provider == "fbt" && (self.module == "guest" || self.module == "vmm")
    }

    /// True for the canonical tracepoint shape
    /// `tracepoint:<domain>:<category>:<event>`.  Drives raw
    /// tracepoint attach on the guest side.
    pub fn is_tracepoint(&self) -> bool {
        self.provider == "tracepoint" && (self.module == "guest" || self.module == "vmm")
    }

    /// True for `profile:::tick-Nms` / `profile:::tick-Nsec` /
    /// `profile:::tick-Nusec` (and the analogous `profile-` forms).
    /// Routes to a BPF_PROG_TYPE_PERF_EVENT program attached via
    /// `perf_event_create_kernel_counter` with a CPU-clock sample
    /// period on the Linux guest, and to FreeBSD/macOS native dtrace
    /// directly.
    pub fn is_profile_timer(&self) -> bool {
        self.provider == "profile"
            && self.module.is_empty()
            && self.function.is_empty()
            && (self.name.starts_with("tick-") || self.name.starts_with("profile-"))
    }

    /// Decode the period suffix on a `profile:::tick-Nms` /
    /// `tick-Nsec` / `tick-Nusec` / `tick-Nns` probe into a u64
    /// nanosecond period.  Returns `None` for unrecognized shapes;
    /// callers should reject those before lowering.
    pub fn profile_timer_period_ns(&self) -> Option<u64> {
        if !self.is_profile_timer() {
            return None;
        }
        let rest = self
            .name
            .strip_prefix("tick-")
            .or_else(|| self.name.strip_prefix("profile-"))?;
        let (num_str, unit) = rest
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| (&rest[..i], &rest[i..]))
            .unwrap_or((rest, "hz"));
        let n: u64 = num_str.parse().ok()?;
        if n == 0 {
            return None;
        }
        let ns = match unit {
            "ns" => n,
            "us" | "usec" => n.checked_mul(1_000)?,
            "ms" | "msec" => n.checked_mul(1_000_000)?,
            "s" | "sec" => n.checked_mul(1_000_000_000)?,
            // `tick-N` without a unit means N Hz (1 sec / N).
            "hz" | "" => 1_000_000_000u64.checked_div(n)?,
            _ => return None,
        };
        Some(ns)
    }

    /// True for the retired bare `bifrost::funcname:entry|return`
    /// (kprobe) and `bifrost:guest_kernel:funcname:entry|return`
    /// shapes.  Callers should reject these with a "rewrite as
    /// `fbt:guest:funcname:...`" diagnostic.
    pub fn is_deprecated_kprobe(&self) -> bool {
        self.provider == "bifrost" && self.module != "guest_user" && self.binary.is_none()
    }

    /// True for the retired `bifrost:guest_user:bin:sym:name` uprobe
    /// shape.  Callers should reject with "rewrite as
    /// `uprobe:guest:bin:sym:name`".
    pub fn is_deprecated_uprobe(&self) -> bool {
        self.provider == "bifrost" && self.module == "guest_user" && self.binary.is_some()
    }

    /// True for the retired empty-domain `fbt::funcname:entry|return`
    /// shape (canonicalized today as `fbt:guest:funcname:...`).
    pub fn is_deprecated_empty_domain(&self) -> bool {
        matches!(self.provider.as_str(), "fbt" | "tracepoint" | "uprobe") && self.module.is_empty()
    }

    pub fn render(&self) -> String {
        if self.module.is_empty() && self.function.is_empty() && self.name.is_empty() {
            self.provider.clone()
        } else if let Some(bin) = &self.binary {
            format!(
                "{}:{}:{}:{}:{}",
                self.provider, self.module, bin, self.function, self.name
            )
        } else {
            format!(
                "{}:{}:{}:{}",
                self.provider, self.module, self.function, self.name
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct Clause {
    pub specs: Vec<ProbeSpec>,
    pub predicate: Option<String>,
    /// Action body without the surrounding braces.
    pub body: String,
    /// Original source span — for diagnostics.
    pub source: String,
}

impl Clause {
    pub fn is_bifrost(&self) -> bool {
        self.specs.iter().any(|s| s.is_bifrost())
    }
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "D parse error: {}", self.0)
    }
}

/// Strip line (`// ...`) and block (`/* ... */`) comments, replacing
/// them with single spaces so byte offsets don't surprise downstream
/// users (we don't actually use offsets, but it's a defensive habit).
fn strip_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    let mut in_char = false;
    while i < bytes.len() {
        let b = bytes[i];
        if !in_str && !in_char && b == b'/' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'/' => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'*' => {
                    i += 2;
                    while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                        i += 1;
                    }
                    if i + 1 < bytes.len() {
                        i += 2;
                    }
                    out.push(' ');
                    continue;
                }
                _ => {}
            }
        }
        if b == b'\\' && (in_str || in_char) && i + 1 < bytes.len() {
            out.push(b as char);
            out.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if b == b'"' && !in_char {
            in_str = !in_str;
        } else if b == b'\'' && !in_str {
            in_char = !in_char;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// Parse the source into clauses. Anything outside clauses (pragmas,
/// declarations, whitespace) is collected separately and returned
/// alongside so the caller can rebuild the host-side script verbatim.
pub fn parse(input: &str) -> Result<Parsed, ParseError> {
    let src = strip_comments(input);
    let bytes = src.as_bytes();
    let mut clauses: Vec<Clause> = Vec::new();
    let mut preamble = String::new();
    let mut i = 0;

    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            preamble.push(bytes[i] as char);
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Pragmas and other top-level non-clause text — copy through
        // until newline or until we hit something that looks like a
        // clause start.
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                preamble.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }

        // Try to recognize a clause: one or more comma-separated probe
        // specs, optional predicate, action body.
        let clause_start = i;
        let mut specs_str = String::new();
        // Collect chars up to '/', '{', or end-of-token after the
        // probe-spec list. We accept any byte except '/' '{' as part
        // of the spec list (probe specs allow wildcards `*?`, `$`).
        while i < bytes.len() && bytes[i] != b'/' && bytes[i] != b'{' {
            specs_str.push(bytes[i] as char);
            i += 1;
        }
        let specs_str = specs_str.trim().to_string();
        if specs_str.is_empty() {
            // Nothing recognizable — push the byte to preamble and continue.
            if i < bytes.len() {
                preamble.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        let specs: Vec<ProbeSpec> = specs_str.split(',').filter_map(ProbeSpec::parse).collect();
        if specs.is_empty() {
            // Wasn't a valid probe-spec — emit to preamble.
            preamble.push_str(&specs_str);
            continue;
        }

        // Optional predicate.
        let mut predicate: Option<String> = None;
        if i < bytes.len() && bytes[i] == b'/' {
            i += 1;
            let pred_start = i;
            // Find matching '/', skipping over strings.
            let mut in_s = false;
            let mut in_c = false;
            while i < bytes.len() {
                let b = bytes[i];
                if !in_c && b == b'"' {
                    in_s = !in_s;
                } else if !in_s && b == b'\'' {
                    in_c = !in_c;
                } else if !in_s && !in_c && b == b'/' {
                    break;
                }
                if b == b'\\' && (in_s || in_c) && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                i += 1;
            }
            if i >= bytes.len() {
                return Err(ParseError(format!(
                    "unterminated predicate at byte {}",
                    pred_start
                )));
            }
            predicate = Some(src[pred_start..i].to_string());
            i += 1;
        }

        // Skip whitespace before body.
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'{' {
            return Err(ParseError(format!(
                "expected '{{' to begin action body for clause {}",
                specs
                    .iter()
                    .map(|s| s.render())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let body_start = i + 1;
        i += 1;
        let mut depth = 1;
        let mut in_s = false;
        let mut in_c = false;
        while i < bytes.len() && depth > 0 {
            let b = bytes[i];
            if b == b'\\' && (in_s || in_c) && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if !in_c && b == b'"' {
                in_s = !in_s;
            } else if !in_s && b == b'\'' {
                in_c = !in_c;
            } else if !in_s && !in_c {
                if b == b'{' {
                    depth += 1;
                } else if b == b'}' {
                    depth -= 1;
                }
            }
            i += 1;
        }
        if depth != 0 {
            return Err(ParseError(format!(
                "unterminated action body in clause {}",
                specs
                    .iter()
                    .map(|s| s.render())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let body_end = i - 1;
        let body = src[body_start..body_end].to_string();
        let source = src[clause_start..i].to_string();
        clauses.push(Clause {
            specs,
            predicate,
            body,
            source,
        });
    }

    Ok(Parsed { preamble, clauses })
}

#[derive(Debug)]
pub struct Parsed {
    /// Pragmas and other non-clause text in source order.
    pub preamble: String,
    pub clauses: Vec<Clause>,
}

impl Parsed {
    /// Render the subset of clauses whose probe-specs target the host
    /// (i.e. anything that isn't `bifrost:`) as a complete D script
    /// suitable for native dtrace. Includes any preamble.
    pub fn host_script(&self) -> String {
        let mut s = self.preamble.clone();
        for c in &self.clauses {
            if !c.is_bifrost() {
                s.push_str(&c.source);
                s.push('\n');
            }
        }
        s
    }

    /// Iterate the bifrost-targeted clauses.
    pub fn bifrost_clauses(&self) -> impl Iterator<Item = &Clause> {
        self.clauses.iter().filter(|c| c.is_bifrost())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_native_clause() {
        let p = parse("syscall::openat:entry { trace(arg0); }").unwrap();
        assert_eq!(p.clauses.len(), 1);
        assert_eq!(p.clauses[0].specs[0].provider, "syscall");
        assert_eq!(p.clauses[0].specs[0].function, "openat");
        assert!(!p.clauses[0].is_bifrost());
    }

    #[test]
    fn parses_bifrost_clause() {
        let p = parse("bifrost:guest_kernel:tcp_v4_connect:entry { gstack(); }").unwrap();
        assert!(p.clauses[0].is_bifrost());
        assert_eq!(p.clauses[0].specs[0].function, "tcp_v4_connect");
    }

    #[test]
    fn parses_clause_with_predicate() {
        let p = parse("bifrost:guest_kernel:foo:entry /pid > 1/ { gstack(); }").unwrap();
        assert!(p.clauses[0].predicate.is_some());
    }

    #[test]
    fn splits_mixed_source() {
        let src = r#"
            BEGIN { printf("start"); }
            syscall::openat:entry { printf("host"); }
            bifrost:guest_kernel:do_sys_openat2:entry { gstack(); }
        "#;
        let p = parse(src).unwrap();
        assert_eq!(p.clauses.len(), 3);
        let bifrost: Vec<_> = p.bifrost_clauses().collect();
        assert_eq!(bifrost.len(), 1);
        let host = p.host_script();
        assert!(host.contains("BEGIN"));
        assert!(host.contains("syscall::openat:entry"));
        assert!(!host.contains("bifrost:guest_kernel"));
    }

    #[test]
    fn parses_guest_user_probe_5_tuple() {
        let p = parse("bifrost:guest_user:nginx:ngx_http_handler:entry { gustack(); }").unwrap();
        let spec = &p.clauses[0].specs[0];
        assert!(spec.is_bifrost());
        assert!(spec.is_guest_user());
        assert_eq!(spec.module, "guest_user");
        assert_eq!(spec.binary.as_deref(), Some("nginx"));
        assert_eq!(spec.function, "ngx_http_handler");
        assert_eq!(spec.name, "entry");
    }

    #[test]
    fn guest_user_probe_basename_only() {
        // Binary slot is a basename; the CLI resolves to the absolute
        // path against the staged rootfs. Slashes would collide with
        // the clause walker's predicate recognition, so reject them
        // at spec-parse time and let the CLI emit a clear error.
        let p =
            parse("bifrost:guest_user:redis-server:processCommand:return { trace(0); }").unwrap();
        let spec = &p.clauses[0].specs[0];
        assert!(spec.is_guest_user());
        assert_eq!(spec.binary.as_deref(), Some("redis-server"));
        assert_eq!(spec.function, "processCommand");
        assert_eq!(spec.name, "return");
    }

    #[test]
    fn render_round_trip_guest_user() {
        let s = "bifrost:guest_user:redis-server:processCommand:entry";
        let spec = ProbeSpec::parse(s).unwrap();
        assert_eq!(spec.render(), s);
    }

    #[test]
    fn render_round_trip_guest_kernel() {
        let s = "bifrost:guest_kernel:do_sys_openat2:entry";
        let spec = ProbeSpec::parse(s).unwrap();
        assert_eq!(spec.render(), s);
    }

    #[test]
    fn guest_kernel_is_not_guest_user() {
        let spec = ProbeSpec::parse("bifrost:guest_kernel:foo:entry").unwrap();
        assert!(!spec.is_guest_user());
        assert!(spec.binary.is_none());
    }

    // ── Canonical shapes ────────────────────────────────────────────

    #[test]
    fn fbt_guest_canonical() {
        let spec = ProbeSpec::parse("fbt:guest:do_sys_openat2:entry").unwrap();
        assert_eq!(spec.provider, "fbt");
        assert_eq!(spec.module, "guest");
        assert_eq!(spec.function, "do_sys_openat2");
        assert_eq!(spec.name, "entry");
        assert!(spec.is_bifrost());
        assert!(spec.is_fbt());
        assert!(!spec.is_uprobe());
        assert!(!spec.is_tracepoint());
        assert!(!spec.is_deprecated_kprobe());
        assert!(!spec.is_deprecated_empty_domain());
    }

    #[test]
    fn fbt_guest_return_canonical() {
        let spec = ProbeSpec::parse("fbt:guest:vfs_open:return").unwrap();
        assert!(spec.is_fbt());
        assert_eq!(spec.name, "return");
    }

    #[test]
    fn tracepoint_guest_canonical() {
        let spec = ProbeSpec::parse("tracepoint:guest:sched:sched_switch").unwrap();
        assert_eq!(spec.provider, "tracepoint");
        assert_eq!(spec.module, "guest");
        assert_eq!(spec.function, "sched");
        assert_eq!(spec.name, "sched_switch");
        assert!(spec.is_bifrost());
        assert!(spec.is_tracepoint());
        assert!(!spec.is_fbt());
    }

    #[test]
    fn uprobe_guest_canonical() {
        let spec = ProbeSpec::parse("uprobe:guest:redis-server:processCommand:entry").unwrap();
        assert_eq!(spec.provider, "uprobe");
        assert_eq!(spec.module, "guest");
        assert_eq!(spec.function, "processCommand");
        assert_eq!(spec.name, "entry");
        assert_eq!(spec.binary.as_deref(), Some("redis-server"));
        assert!(spec.is_bifrost());
        assert!(spec.is_uprobe());
        assert!(
            spec.is_guest_user(),
            "is_guest_user covers the canonical uprobe form"
        );
        assert!(!spec.is_fbt());
        assert!(!spec.is_deprecated_uprobe());
    }

    #[test]
    fn usdt_guest_canonical() {
        let spec = ProbeSpec::parse("usdt:guest:postgres:postgresql:query__start").unwrap();
        assert_eq!(spec.provider, "usdt");
        assert_eq!(spec.module, "guest");
        assert_eq!(spec.function, "postgresql");
        assert_eq!(spec.name, "query__start");
        assert_eq!(spec.binary.as_deref(), Some("postgres"));
        assert!(spec.is_bifrost());
        assert!(spec.is_usdt());
        assert!(
            !spec.is_uprobe(),
            "is_uprobe is false for USDT specs (different resolution path)"
        );
        assert!(
            !spec.is_guest_user(),
            "is_guest_user routes to symbol-based resolution; USDT uses .note.stapsdt instead"
        );
    }

    #[test]
    fn usdt_double_underscore_probe_name_round_trips() {
        // SystemTap SDT probe names commonly use `__` separators
        // (`query__start`, `transaction__commit`).  The 5-tuple parser
        // splits on `:` only — the underscore form must round-trip
        // cleanly through render().
        let raw = "usdt:guest:postgres:postgresql:lwlock__wait__start";
        let spec = ProbeSpec::parse(raw).unwrap();
        assert_eq!(spec.name, "lwlock__wait__start");
        assert_eq!(spec.render(), raw);
    }

    // ── Retired shapes (must produce migration diagnostics) ─────────

    #[test]
    fn empty_domain_fbt_is_deprecated() {
        let spec = ProbeSpec::parse("fbt::do_sys_openat2:entry").unwrap();
        assert!(spec.is_deprecated_empty_domain());
        assert!(
            !spec.is_fbt(),
            "empty-domain fbt does not satisfy the canonical predicate"
        );
    }

    #[test]
    fn empty_domain_tracepoint_is_deprecated() {
        let spec = ProbeSpec::parse("tracepoint::sched:sched_switch").unwrap();
        assert!(spec.is_deprecated_empty_domain());
        assert!(!spec.is_tracepoint());
    }

    #[test]
    fn bare_bifrost_kprobe_is_deprecated() {
        let spec = ProbeSpec::parse("bifrost::do_sys_openat2:entry").unwrap();
        assert!(spec.is_deprecated_kprobe());
        assert!(!spec.is_fbt());
    }

    #[test]
    fn guest_kernel_bifrost_is_deprecated() {
        let spec = ProbeSpec::parse("bifrost:guest_kernel:foo:entry").unwrap();
        assert!(spec.is_deprecated_kprobe());
    }

    #[test]
    fn guest_user_bifrost_is_deprecated_uprobe() {
        let spec =
            ProbeSpec::parse("bifrost:guest_user:redis-server:processCommand:entry").unwrap();
        assert!(
            spec.is_guest_user(),
            "is_guest_user still covers the retired form"
        );
        assert!(
            spec.is_deprecated_uprobe(),
            "the retired bifrost:guest_user shape needs to be rewritten to uprobe:guest:"
        );
        assert!(
            !spec.is_uprobe(),
            "is_uprobe matches only the canonical uprobe:domain shape"
        );
        assert!(!spec.is_deprecated_kprobe());
    }

    #[test]
    fn handles_comments() {
        let src = r#"
            // line comment
            /* block
               comment */
            bifrost:a:b:c { gstack(); }
        "#;
        let p = parse(src).unwrap();
        assert_eq!(p.clauses.len(), 1);
    }
}
