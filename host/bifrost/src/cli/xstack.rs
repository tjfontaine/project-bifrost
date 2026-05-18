// Cross-domain stack stitching state and parsers.
//
// `xstack(...)` is bifrost's primitive for pairing a guest-side
// fire (kprobe/uprobe/fbt/tracepoint) with a host-side ustack
// captured the same instant via libdtrace's
// `pid$target:Hypervisor:hv_vcpu_run:return` sample.  The CLI emits
// markers from both sides into the dtrace stdout stream; this
// module owns the marker parsers and the `XstackState` that
// matches them up across pthread tids.
//
// `XstackMode` controls capture timing (Forced = synchronous vCPU
// exit per fire; Sample = async profile sampling at ~997 Hz).

#![cfg(target_os = "macos")]

/// Stack-capture mode. SAMPLE mode swaps the per-event forced
/// vCPU exit for periodic profile-997hz samples on the vCPU
/// threads. Non-perturbing alternative — accepts fuzzier
/// wallclock pairing in exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XstackMode {
    /// Synchronous forced-exit (default). Every guest fire
    /// triggers a vcpu_request_exit; libdtrace's
    /// pid$target:Hypervisor:hv_vcpu_run:return clause captures
    /// the host stack at exactly that instant.
    Forced,
    /// Async profile sampler. profile-997hz fires on the vCPU
    /// threads continuously; correlator pairs guest events
    /// with the most recent sample on the originating tid
    /// within a tolerance window (±1ms by default).
    Sample,
}

/// Parse the optional `xstack(...)` arg list. Returns
/// `(mode, depth)` for the deepest arg list found in `body` (or
/// None if no xstack call). Supported syntaxes:
///   xstack()                 → (Forced, 8)
///   xstack(N)                → (Forced, N)
///   xstack(SAMPLE)           → (Sample, 8)
///   xstack(SAMPLE, N)        → (Sample, N)
///   xstack(N, SAMPLE)        → (Sample, N)
pub fn extract_xstack_args(body: &str) -> Option<(XstackMode, u32)> {
    let bytes = body.as_bytes();
    let needle = b"xstack(";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let prev_ok = i == 0 || {
                let p = bytes[i - 1];
                !(p.is_ascii_alphanumeric() || p == b'_')
            };
            if !prev_ok {
                i += 1;
                continue;
            }
            let arg_start = i + needle.len();
            let mut j = arg_start;
            let mut paren_depth = 1;
            while j < bytes.len() && paren_depth > 0 {
                match bytes[j] {
                    b'(' => paren_depth += 1,
                    b')' => {
                        paren_depth -= 1;
                        if paren_depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if j >= bytes.len() {
                return None;
            }
            let inside = body[arg_start..j].trim();
            if inside.is_empty() {
                return Some((XstackMode::Forced, 8));
            }
            let mut mode = XstackMode::Forced;
            let mut depth: Option<u32> = None;
            for tok in inside.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
                if tok.eq_ignore_ascii_case("SAMPLE") || tok.eq_ignore_ascii_case("ASYNC") {
                    mode = XstackMode::Sample;
                } else if let Ok(n) = tok.parse::<u32>() {
                    depth = Some(n);
                }
            }
            return Some((mode, depth.unwrap_or(8)));
        }
        i += 1;
    }
    None
}

/// Backwards-compatible wrapper: returns just the depth.
pub fn extract_xstack_depth(body: &str) -> Option<u32> {
    extract_xstack_args(body).map(|(_, d)| d)
}

/// Replace every `xstack(...)` with `gustack()` so the DIF
/// lowering compiles (it doesn't know xstack as a primitive).
pub fn strip_xstack_to_gustack(body: &str) -> String {
    let bytes = body.as_bytes();
    let needle = b"xstack(";
    let mut out = String::new();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let prev_ok = i == 0 || {
                let p = bytes[i - 1];
                !(p.is_ascii_alphanumeric() || p == b'_')
            };
            if prev_ok {
                let mut j = i + needle.len();
                let mut depth = 1;
                while j < bytes.len() && depth > 0 {
                    match bytes[j] {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if j < bytes.len() {
                    out.push_str("gustack()");
                    i = j + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Cross-domain interleaved stack state. The bifrost CLI
/// listens for `##xstack-pending##|seq|label|gpid|tid` markers on
/// dtrace stdout and pairs them, **per host pthread tid**, with
/// `##xstack-host##|tid` / `##xstack-end##|tid` blocks. Per-tid
/// queues guarantee FIFO correctness even when concurrent
/// dispatches across vCPUs interleave on the dtrace stream.
#[derive(Default)]
pub struct XstackState {
    /// Pending guest fires waiting for their host stack capture,
    /// keyed by the host pthread tid that will run the
    /// hv_vcpu_run:return clause (i.e. the vCPU thread that
    /// libkrun forced out of guest mode for this fire).
    pub pending: std::collections::HashMap<u64, std::collections::VecDeque<XstackPending>>,
    /// Currently-open host-stack block: `(active_tid, frames_so_far)`.
    /// dtrace's stdout is single-stream so only one block can be
    /// open at any moment — the marker tid tags it for matching
    /// against the per-tid pending queue at close time.
    pub in_block: Option<(u64, Vec<String>)>,
    /// Optional folded-stack accumulator for --xstack-fold.
    /// Key is the joined frames (one stack per record);
    /// value is the count seen for that exact stack.
    pub fold: Option<std::collections::HashMap<String, u64>>,
    /// Output path for fold-mode dump on shutdown.
    pub fold_out: Option<String>,
}

#[derive(Debug, Clone)]
pub struct XstackPending {
    pub seq: u64,
    pub label: String,
    pub gpid: String,
    /// Host pthread tid the vCPU thread is running on. Carried
    /// through to the unified block header for correlation with
    /// `dtrace -ln 'pid$target:Hypervisor:hv_vcpu_run:*'` output
    /// when more than one vCPU is in flight.
    pub tid: u64,
}

/// Strip a `##...|tid` trailing tid field; returns (rest_before_pipe, tid).
/// Falls back to `tid=0` if the line predates the cross-domain stitch format (no tail and not parseable).
///
/// `rest` is the substring AFTER `##xstack-host##` / `##xstack-end##`,
/// already trimmed of the leading `|`. Two shapes are accepted:
///   - bare tid: `"7891622"` → `("", 7891622)`
///   - tid with extra trailing context: `"...|7891622"` → (prefix, 7891622)
pub fn split_xstack_tid(rest: &str) -> (&str, u64) {
    let trimmed = rest.trim();
    if let Ok(t) = trimmed.parse::<u64>() {
        return ("", t);
    }
    if let Some(p) = trimmed.rfind('|')
        && let Ok(t) = trimmed[p + 1..].trim().parse::<u64>()
    {
        return (&trimmed[..p], t);
    }
    (trimmed, 0)
}

/// Try to parse a cross-domain stitch marker line. Returns true if consumed
/// (so the line should not pass through to stdout). Updates the
/// shared state and emits the unified guest+host block when a
/// host capture completes.
pub fn try_parse_xstack_line(
    line: &str,
    state: &std::sync::Arc<std::sync::Mutex<XstackState>>,
) -> bool {
    if let Some(idx) = line.find("##xstack-pending##|") {
        let rest = &line[idx + "##xstack-pending##|".len()..];
        let mut parts = rest.splitn(4, '|');
        let seq: u64 = parts
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let label = parts.next().unwrap_or("").trim().to_string();
        let gpid = parts.next().unwrap_or("").trim().to_string();
        let tid: u64 = parts
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if std::env::var_os("BIFROST_XSTACK_DEBUG").is_some() {
            eprintln!(
                "[xstack-debug] pending seq={} tid={} label={}",
                seq, tid, label
            );
        }
        if let Ok(mut g) = state.lock() {
            g.pending.entry(tid).or_default().push_back(XstackPending {
                seq,
                label,
                gpid,
                tid,
            });
        }
        return true;
    }
    if let Some(idx) = line.find("##xstack-host##") {
        let rest = &line[idx + "##xstack-host##".len()..];
        let (_, tid) = split_xstack_tid(rest.trim_start_matches('|'));
        if let Ok(mut g) = state.lock() {
            g.in_block = Some((tid, Vec::new()));
        }
        return true;
    }
    if let Some(idx) = line.find("##xstack-end##") {
        let rest = &line[idx + "##xstack-end##".len()..];
        let (_, tid) = split_xstack_tid(rest.trim_start_matches('|'));
        if std::env::var_os("BIFROST_XSTACK_DEBUG").is_some() {
            eprintln!("[xstack-debug] end tid={} raw={:?}", tid, rest);
        }
        let (frames, pending, fold_present) = match state.lock() {
            Ok(mut g) => {
                if std::env::var_os("BIFROST_XSTACK_DEBUG").is_some() {
                    let avail: Vec<u64> = g.pending.keys().copied().collect();
                    eprintln!("[xstack-debug] end queues_for_tids={:?}", avail);
                }
                let frames = g.in_block.take().map(|(_t, v)| v);
                let pending = g.pending.get_mut(&tid).and_then(|q| q.pop_front());
                let fold_present = g.fold.is_some();
                (frames, pending, fold_present)
            }
            Err(_) => return true,
        };
        if let Some(frames) = frames {
            if fold_present {
                if let Ok(mut g) = state.lock() {
                    let mp = g.fold.as_mut();
                    emit_unified_xstack_block(pending, &frames, mp);
                }
            } else {
                emit_unified_xstack_block(pending, &frames, None);
            }
        }
        return true;
    }
    if let Ok(mut g) = state.lock()
        && let Some((_tid, buf)) = g.in_block.as_mut()
    {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("CPU") && !trimmed.contains("FUNCTION") {
            buf.push(trimmed.to_string());
        }
        return true;
    }
    false
}

/// Render one unified xstack block. In normal mode, prints the
/// pending marker + divider + frames as a human-readable block.
/// In fold mode, increments the count for the joined frame string
/// in the shared accumulator and skips the visible block.
pub fn emit_unified_xstack_block(
    pending: Option<XstackPending>,
    frames: &[String],
    fold: Option<&mut std::collections::HashMap<String, u64>>,
) {
    if let Some(map) = fold {
        // FlameGraph format: leaf-to-root ordering, semicolon-
        // separated, count at end. dtrace's ustack() prints leaf
        // first; the guest probe label is the "deepest known
        // ancestor" so we put it last.
        let mut joined: Vec<String> = frames
            .iter()
            .filter_map(|f| {
                let frame = clean_frame_for_fold(f);
                if frame.is_empty() { None } else { Some(frame) }
            })
            .collect();
        if let Some(p) = pending {
            joined.push(p.label.replace(';', "_"));
        }
        if !joined.is_empty() {
            let key = joined.join(";");
            *map.entry(key).or_insert(0) += 1;
        }
        return;
    }
    println!();
    println!("  ┄┄┄ host stack (vCPU thread, hv_vcpu_run:return) ┄┄┄");
    if let Some(p) = pending {
        println!(
            "    seq={}  for guest fire: {}  gpid={}  vcpu_tid={}",
            p.seq, p.label, p.gpid, p.tid,
        );
    }
    for f in frames {
        println!("    {}", f);
    }
    println!("  ┄┄┄ end ┄┄┄");
}

/// Strip the dtrace ustack() output adornments and produce a
/// FlameGraph-style frame string. `module``function`+`offset` →
/// `module!function`. Empty raw addresses get filtered out.
pub fn clean_frame_for_fold(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_offset = trimmed.rsplit_once('+').map(|(s, _)| s).unwrap_or(trimmed);
    let normalized = without_offset.replace('`', "!");
    if normalized.starts_with("0x") {
        return format!("[unknown:{}]", normalized);
    }
    normalized
}

/// Dump the accumulated foldable stacks to the user-provided
/// path. Called once at script shutdown when --xstack-fold is set.
pub fn dump_xstack_fold(state: &std::sync::Arc<std::sync::Mutex<XstackState>>) {
    use std::io::Write;
    let (path, map) = match state.lock() {
        Ok(g) => (g.fold_out.clone(), g.fold.clone()),
        Err(_) => return,
    };
    let (path, map) = match (path, map) {
        (Some(p), Some(m)) => (p, m),
        _ => return,
    };
    if map.is_empty() {
        eprintln!(
            "[bifrost] --xstack-fold: no captures collected; not writing {}",
            path
        );
        return;
    }
    let mut sorted: Vec<(String, u64)> = map.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    match std::fs::File::create(&path) {
        Ok(mut f) => {
            for (k, v) in &sorted {
                let _ = writeln!(f, "{} {}", k, v);
            }
            eprintln!(
                "[bifrost] --xstack-fold: wrote {} unique stacks to {}",
                sorted.len(),
                path
            );
        }
        Err(e) => {
            eprintln!("[bifrost] --xstack-fold: open {}: {}", path, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_xstack_args_default() {
        assert_eq!(
            extract_xstack_args("xstack()"),
            Some((XstackMode::Forced, 8))
        );
    }

    #[test]
    fn extract_xstack_args_depth() {
        assert_eq!(
            extract_xstack_args("xstack(16)"),
            Some((XstackMode::Forced, 16))
        );
    }

    #[test]
    fn extract_xstack_args_sample_mode() {
        assert_eq!(
            extract_xstack_args("xstack(SAMPLE)"),
            Some((XstackMode::Sample, 8))
        );
        assert_eq!(
            extract_xstack_args("xstack(SAMPLE, 32)"),
            Some((XstackMode::Sample, 32))
        );
        assert_eq!(
            extract_xstack_args("xstack(32, SAMPLE)"),
            Some((XstackMode::Sample, 32))
        );
    }

    #[test]
    fn extract_xstack_args_word_boundary() {
        // identifiers that contain "xstack" as substring must not match
        assert_eq!(extract_xstack_args("bifrost_xstack(1)"), None);
    }

    #[test]
    fn split_xstack_tid_bare() {
        assert_eq!(split_xstack_tid("123456"), ("", 123456));
    }

    #[test]
    fn split_xstack_tid_with_prefix() {
        assert_eq!(split_xstack_tid("foo|789"), ("foo", 789));
    }

    #[test]
    fn split_xstack_tid_unparseable() {
        assert_eq!(split_xstack_tid("xx"), ("xx", 0));
    }

    #[test]
    fn strip_xstack_to_gustack_replaces() {
        assert_eq!(strip_xstack_to_gustack("xstack(8)"), "gustack()");
        assert_eq!(strip_xstack_to_gustack("xstack(SAMPLE)"), "gustack()");
    }

    #[test]
    fn clean_frame_strips_offset() {
        assert_eq!(
            clean_frame_for_fold("Hypervisor`Hv::run()+0x40"),
            "Hypervisor!Hv::run()"
        );
    }

    #[test]
    fn clean_frame_preserves_unknown_addr() {
        assert_eq!(clean_frame_for_fold("0x1234"), "[unknown:0x1234]");
    }
}
