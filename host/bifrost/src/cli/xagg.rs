// Cross-domain aggregation rendering and source rewriting.
//
// "xagg" = `@<name>` aggregations that span both host and guest
// clauses.  The CLI rewrites host clauses to emit
// `##xagg-host##|...` markers per fire and parses both host and
// guest markers from the dtrace stream into a shared map; at
// shutdown the map renders as a `dtrace -a`-style table.
//
// Quantize buckets ride a separate global because they're stored
// per-(name, bucket_id) and merge with absolute counts from
// AGG_SNAPSHOT.
//
// Source-rewriting helpers:
//   - collect_cross_domain_aggs / collect_guest_only_aggs_referenced_by_host
//   - inject_guest_agg_stubs (BEGIN-stub injection so libdtrace
//     compiles printa() against guest-only aggs)
//   - rewrite_host_clauses_for_cross_aggs (tags host fires with
//     ##xagg-host##| markers)
// Stream-parsing helpers:
//   - try_parse_xagg_line
//   - parse_quantize_marker
// Render helpers:
//   - dump_xagg_state / dump_xagg_state_force / dump_quantize_state

#![cfg(target_os = "macos")]

use crate::parse;

/// Process-wide hash of the last-dumped xagg table.  Used by
/// `dump_xagg_state` to suppress identical re-prints under
/// long-running traces where AGG_PUSH lands every ~1 s but the
/// underlying counts only change every few seconds.  Without
/// this gate, a 25 s trace with a quiet aggregation produces
/// dozens of identical 60-row tables in stderr.
static XAGG_LAST_HASH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Render-time hints applied to a named aggregation at dump
/// time.  Populated by `collect_libact_hints` walking the source
/// for `normalize(@x, N)` / `trunc(@x[, N])` / `denormalize(@x)`
/// in bifrost-clause bodies, then consumed by
/// `dump_xagg_state_inner` and `dump_quantize_state` so the
/// rendered values are divided / capped accordingly.
///
/// `divisor == 0` ⇒ no normalize; `trunc == None` ⇒ no row cap.
/// Both can co-exist on the same agg name.
#[derive(Default, Clone, Copy)]
pub struct AggRenderHint {
    pub divisor: u64,
    pub trunc: Option<u32>,
}

fn agg_render_hints() -> &'static std::sync::Mutex<std::collections::HashMap<String, AggRenderHint>>
{
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static S: OnceLock<Mutex<HashMap<String, AggRenderHint>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// set the divisor for `normalize(@<name>, divisor)`.
/// Zero clears it (matches `denormalize(@<name>)`).
pub fn register_normalize(name: &str, divisor: u64) {
    if let Ok(mut g) = agg_render_hints().lock() {
        g.entry(name.to_string()).or_default().divisor = divisor;
    }
}

/// set the top-N row cap for `trunc(@<name>, N)`.  `None`
/// matches `trunc(@<name>)` and clears the cap.
pub fn register_trunc(name: &str, trunc: Option<u32>) {
    if let Ok(mut g) = agg_render_hints().lock() {
        g.entry(name.to_string()).or_default().trunc = trunc;
    }
}

/// lookup helper used by the renderer.
pub fn render_hint_for(name: &str) -> AggRenderHint {
    agg_render_hints()
        .lock()
        .ok()
        .and_then(|g| g.get(name).copied())
        .unwrap_or_default()
}

/// `lquantize(value, base, upper, step)` parameters,
/// stashed per agg name at compile time.  The lowerer encodes
/// them into BPF (so the guest produces bucket-indexed counts);
/// the host renderer reads them back at dump time to format
/// each bucket label as `base + i*step .. base + (i+1)*step`.
#[derive(Default, Clone, Copy)]
pub struct LquantizeParams {
    pub base: i64,
    pub step: u64,
    pub levels: u32,
}

/// `llquantize(value, factor, low_mag, high_mag,
/// steps_per_mag)` parameters.  Same per-agg-name storage as
/// `LquantizeParams`; renderer formats bucket labels as
/// `factor^(low_mag + i / steps_per_mag) * (...)`.
#[derive(Default, Clone, Copy)]
pub struct LlquantizeParams {
    pub factor: u16,
    pub low_mag: u8,
    pub high_mag: u8,
    pub steps_per_mag: u16,
}

fn lquantize_params_store()
-> &'static std::sync::Mutex<std::collections::HashMap<String, LquantizeParams>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static S: OnceLock<Mutex<HashMap<String, LquantizeParams>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn llquantize_params_store()
-> &'static std::sync::Mutex<std::collections::HashMap<String, LlquantizeParams>> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static S: OnceLock<Mutex<HashMap<String, LlquantizeParams>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_lquantize(name: &str, p: LquantizeParams) {
    if let Ok(mut g) = lquantize_params_store().lock() {
        g.insert(name.to_string(), p);
    }
}

pub fn register_llquantize(name: &str, p: LlquantizeParams) {
    if let Ok(mut g) = llquantize_params_store().lock() {
        g.insert(name.to_string(), p);
    }
}

pub fn lquantize_params_for(name: &str) -> Option<LquantizeParams> {
    lquantize_params_store()
        .lock()
        .ok()
        .and_then(|g| g.get(name).copied())
}

pub fn llquantize_params_for(name: &str) -> Option<LlquantizeParams> {
    llquantize_params_store()
        .lock()
        .ok()
        .and_then(|g| g.get(name).copied())
}

/// Scan every clause body for `lquantize(...)` /
/// `llquantize(...)` calls and stash the parameters per
/// `@<name>` on the global params store.  Called alongside
/// `collect_libact_hints` at compile time.
pub fn collect_quantize_params(parsed: &parse::Parsed) {
    for clause in &parsed.clauses {
        // Match `@<name>[<key>] = lquantize(value, base, upper, step);`
        // and capture the agg name via the existing
        // `extract_first_agg_name` helper applied per fragment.
        // Simpler: regex-style scan for `lquantize(` and
        // `llquantize(`, then walk back to find the assigned
        // `@<name>`.
        let body = &clause.body;
        for (start, _) in scan_call_positions(body, "lquantize") {
            if !is_lquantize_at(body, start) {
                continue;
            }
            let args = parse_call_args_at(body, start, "lquantize");
            let name = name_for_assignment_ending_at(body, start);
            if let (Some(name), Some(args)) = (name, args)
                && args.len() >= 4
            {
                // args[0] = value (skip — runtime DIFO)
                // args[1] = base
                // args[2] = upper
                // args[3] = step
                let base: i64 = args[1].trim().parse().unwrap_or(0);
                let upper: i64 = args[2].trim().parse().unwrap_or(0);
                let step: u64 = args[3].trim().parse().unwrap_or(0);
                if step == 0 || upper <= base {
                    continue;
                }
                let levels = ((upper - base) as u64 / step) as u32;
                register_lquantize(&name, LquantizeParams { base, step, levels });
            }
        }
        for (start, _) in scan_call_positions(body, "llquantize") {
            let args = parse_call_args_at(body, start, "llquantize");
            let name = name_for_assignment_ending_at(body, start);
            if let (Some(name), Some(args)) = (name, args)
                && args.len() >= 5
            {
                // args[0] = value (skip)
                // args[1] = factor
                // args[2] = low_mag
                // args[3] = high_mag
                // args[4] = steps_per_mag
                let factor: u16 = args[1].trim().parse().unwrap_or(0);
                let low_mag: u8 = args[2].trim().parse().unwrap_or(0);
                let high_mag: u8 = args[3].trim().parse().unwrap_or(0);
                let steps_per_mag: u16 = args[4].trim().parse().unwrap_or(0);
                if factor < 2 || steps_per_mag == 0 || low_mag > high_mag {
                    continue;
                }
                register_llquantize(
                    &name,
                    LlquantizeParams {
                        factor,
                        low_mag,
                        high_mag,
                        steps_per_mag,
                    },
                );
            }
        }
    }
}

fn is_lquantize_at(body: &str, start: usize) -> bool {
    // Word-boundary check: the token immediately before `start`
    // must not be `l` (would make `llquantize`).
    let bytes = body.as_bytes();
    if start == 0 {
        return true;
    }
    !matches!(bytes[start - 1], b'l' | b'L')
}

fn scan_call_positions(body: &str, call: &str) -> Vec<(usize, usize)> {
    let bytes = body.as_bytes();
    let call_bytes = call.as_bytes();
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i + call_bytes.len() <= bytes.len() {
        let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
        if prev_ok && &bytes[i..i + call_bytes.len()] == call_bytes {
            let after = i + call_bytes.len();
            let mut j = after;
            while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                out.push((i, j));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn parse_call_args_at(body: &str, start: usize, call: &str) -> Option<Vec<String>> {
    let bytes = body.as_bytes();
    let after = start + call.len();
    let mut j = after;
    while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] != b'(' {
        return None;
    }
    let mut depth = 1;
    let mut k = j + 1;
    let mut arg_start = k;
    let mut args: Vec<String> = Vec::new();
    while k < bytes.len() && depth > 0 {
        let b = bytes[k];
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                args.push(String::from_utf8_lossy(&bytes[arg_start..k]).to_string());
                return Some(args);
            }
        } else if b == b',' && depth == 1 {
            args.push(String::from_utf8_lossy(&bytes[arg_start..k]).to_string());
            arg_start = k + 1;
        }
        k += 1;
    }
    None
}

/// Walk backwards from `end` looking for the `@<name>` that
/// the assignment binds against.  E.g. for
/// `@lat[execname] = lquantize(arg0, 0, 1000, 100);`,
/// `end` points at the `l` of `lquantize`, and we walk back
/// past `=`, optional `[...]`, to find `lat`.
fn name_for_assignment_ending_at(body: &str, end: usize) -> Option<String> {
    let bytes = body.as_bytes();
    if end == 0 {
        return None;
    }
    // Walk back past whitespace and `=`.
    let mut i = end;
    while i > 0 && (bytes[i - 1] as char).is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 || bytes[i - 1] != b'=' {
        return None;
    }
    i -= 1;
    while i > 0 && (bytes[i - 1] as char).is_ascii_whitespace() {
        i -= 1;
    }
    // Optional `[<key>]`.
    if i > 0 && bytes[i - 1] == b']' {
        let mut depth = 1;
        i -= 1;
        while i > 0 && depth > 0 {
            i -= 1;
            if bytes[i] == b']' {
                depth += 1;
            } else if bytes[i] == b'[' {
                depth -= 1;
            }
        }
        while i > 0 && (bytes[i - 1] as char).is_ascii_whitespace() {
            i -= 1;
        }
    }
    // Now i should point just past the agg name; the byte at
    // i-1 should be an ident byte and the name extends back
    // to the `@`.
    if i == 0 {
        return None;
    }
    let name_end = i;
    while i > 0 && is_ident_byte(bytes[i - 1]) {
        i -= 1;
    }
    if i == 0 || bytes[i - 1] != b'@' {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[i..name_end]).to_string())
}

/// scan every clause body (host + guest) for libdtrace
/// lib-action calls (`normalize` / `denormalize` / `trunc`) and
/// register them as render-time hints on the agg's name.
/// Scanning host clauses too lets users put hints in a natural
/// `END { normalize(@x, 1000); trunc(@x, 5); }` block — the agg
/// is guest-side (libdtrace never sees its values, only the
/// injected stub), so without this we'd silently drop the
/// hints applied via the host-side END clause.
pub fn collect_libact_hints(parsed: &parse::Parsed) {
    for clause in &parsed.clauses {
        for (name, divisor) in scan_normalize_calls(&clause.body) {
            register_normalize(&name, divisor);
        }
        for name in scan_denormalize_calls(&clause.body) {
            register_normalize(&name, 0);
        }
        for (name, n) in scan_trunc_calls(&clause.body) {
            register_trunc(&name, n);
        }
    }
}

/// match `normalize(@<name>, <int>)`.  Returns
/// `(name, divisor)` pairs in source order.
fn scan_normalize_calls(body: &str) -> Vec<(String, u64)> {
    scan_two_arg("normalize", body, |a, b| {
        let name = strip_agg_prefix(a)?;
        let div: u64 = b.parse().ok()?;
        Some((name, div))
    })
}

/// match `denormalize(@<name>)`.  Returns names.
fn scan_denormalize_calls(body: &str) -> Vec<String> {
    scan_one_arg("denormalize", body)
        .into_iter()
        .filter_map(|s| strip_agg_prefix(&s))
        .collect()
}

/// match `trunc(@<name>)` (clear cap) and
/// `trunc(@<name>, N)` (top-N cap).
fn scan_trunc_calls(body: &str) -> Vec<(String, Option<u32>)> {
    let mut out: Vec<(String, Option<u32>)> = Vec::new();
    for args in scan_call_args("trunc", body) {
        let trimmed: Vec<&str> = args.iter().map(|s| s.trim()).collect();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(name) = strip_agg_prefix(trimmed[0]) {
            let n = trimmed.get(1).and_then(|s| s.parse::<u32>().ok());
            out.push((name, n));
        }
    }
    out
}

fn strip_agg_prefix(s: &str) -> Option<String> {
    let t = s.trim();
    t.strip_prefix('@').map(|n| n.trim().to_string())
}

fn scan_one_arg(call: &str, body: &str) -> Vec<String> {
    scan_call_args(call, body)
        .into_iter()
        .filter_map(|args| args.into_iter().next())
        .map(|s| s.trim().to_string())
        .collect()
}

fn scan_two_arg<T, F: Fn(&str, &str) -> Option<T>>(call: &str, body: &str, f: F) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for args in scan_call_args(call, body) {
        if args.len() < 2 {
            continue;
        }
        if let Some(v) = f(args[0].trim(), args[1].trim()) {
            out.push(v);
        }
    }
    out
}

/// Walk `body` looking for `<call>(...)` and return the
/// comma-separated argument list for each match.  Handles
/// nested parentheses and ignores `<call>` substrings inside
/// strings / longer identifiers (e.g. `denormalize` mustn't
/// match `normalize`).  Lightweight regex-equivalent.
fn scan_call_args(call: &str, body: &str) -> Vec<Vec<String>> {
    let bytes = body.as_bytes();
    let call_bytes = call.as_bytes();
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut i = 0;
    while i + call_bytes.len() < bytes.len() {
        // Match `<call>` at word-boundary.
        let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
        if prev_ok && bytes[i..i + call_bytes.len()] == *call_bytes {
            let after = i + call_bytes.len();
            // Skip whitespace, expect '('.
            let mut j = after;
            while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                // Match: collect comma-separated args until matching ')'.
                let mut depth = 1;
                let mut k = j + 1;
                let mut start = k;
                let mut args: Vec<String> = Vec::new();
                while k < bytes.len() && depth > 0 {
                    let b = bytes[k];
                    if b == b'(' {
                        depth += 1;
                    } else if b == b')' {
                        depth -= 1;
                        if depth == 0 {
                            args.push(String::from_utf8_lossy(&bytes[start..k]).to_string());
                            break;
                        }
                    } else if b == b',' && depth == 1 {
                        args.push(String::from_utf8_lossy(&bytes[start..k]).to_string());
                        start = k + 1;
                    }
                    k += 1;
                }
                out.push(args);
                i = k + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Per-(name, key) running totals for a cross-domain aggregation,
/// split by the side that contributed each tick. Lets us print a
/// merged table where the user sees one row per key, with separate
/// columns for the host count and the guest count plus a sum.
#[derive(Default, Clone, Copy)]
pub struct CrossAggValue {
    pub host: u64,
    pub guest: u64,
}

/// Render the accumulated cross-domain aggregations as a
/// `dtrace -a`-style table on stderr. Pulls from the xagg_state
/// HashMap that `try_parse_xagg_line` populates in real time as
/// `##xagg-guest##|...` and `##xagg-host##|...` markers stream
/// through dispatch_line. Called once at shutdown so the user
/// sees the totals even though individual marker lines were
/// consumed (not re-printed) by the dispatch_line filter.
///
/// The `host` and `guest` columns separate side contributions so
/// cross-domain aggs are legible — for guest-only @counts the host
/// column is always 0; the sum collapses to a normal scalar.
///
/// Skips the print entirely if the (name, key, host, guest) tuple
/// set hashes to the same value as the previous call — keeps long
/// traces' stderr legible.  Pass `force=true` from the shutdown
/// path so the final dump always lands.
pub fn dump_xagg_state(
    state: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), CrossAggValue>>,
    >,
) {
    dump_xagg_state_inner(state, false)
}

pub fn dump_xagg_state_force(
    state: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), CrossAggValue>>,
    >,
) {
    dump_xagg_state_inner(state, true)
}

fn dump_xagg_state_inner(
    state: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), CrossAggValue>>,
    >,
    force: bool,
) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let map = match state.lock() {
        Ok(g) => g.clone(),
        Err(_) => return,
    };
    let q_empty = quantize_state()
        .lock()
        .map(|g| g.is_empty())
        .unwrap_or(true);
    if map.is_empty() && q_empty {
        return;
    }
    let mut by_name: std::collections::BTreeMap<String, Vec<(String, CrossAggValue)>> =
        std::collections::BTreeMap::new();
    for ((name, key), v) in map {
        by_name.entry(name).or_default().push((key, v));
    }
    if !force {
        let mut hasher = DefaultHasher::new();
        for (name, rows) in &by_name {
            name.hash(&mut hasher);
            let mut sorted = rows.clone();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (k, v) in &sorted {
                k.hash(&mut hasher);
                v.host.hash(&mut hasher);
                v.guest.hash(&mut hasher);
            }
        }
        if let Ok(qg) = quantize_state().lock() {
            let mut entries: Vec<(&(String, u32), &u64)> = qg.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for ((n, b), c) in entries {
                n.hash(&mut hasher);
                b.hash(&mut hasher);
                c.hash(&mut hasher);
            }
        }
        let cur = hasher.finish();
        let prev = XAGG_LAST_HASH.swap(cur, std::sync::atomic::Ordering::Relaxed);
        if prev == cur {
            return;
        }
    }
    eprintln!();
    for (name, mut rows) in by_name {
        rows.sort_by(|a, b| (b.1.host + b.1.guest).cmp(&(a.1.host + a.1.guest)));
        // Apply per-agg render-time hints.  Normalize
        // divides each row's total by the registered divisor;
        // trunc caps the row count at the registered N.
        let hint = render_hint_for(&name);
        let div = if hint.divisor == 0 { 1 } else { hint.divisor };
        if let Some(cap) = hint.trunc {
            rows.truncate(cap as usize);
        }
        let any_host = rows.iter().any(|(_, v)| v.host != 0);
        let any_guest = rows.iter().any(|(_, v)| v.guest != 0);
        eprintln!(
            "  @{}{}{}",
            name,
            if hint.divisor != 0 {
                format!(" (normalize={})", hint.divisor)
            } else {
                String::new()
            },
            if hint.trunc.is_some() {
                format!(" (trunc={})", hint.trunc.unwrap())
            } else {
                String::new()
            }
        );
        if any_host && any_guest {
            eprintln!(
                "{:>32} {:>12} {:>12} {:>12}",
                "key", "host", "guest", "total"
            );
            for (k, v) in rows {
                eprintln!(
                    "{:>32} {:>12} {:>12} {:>12}",
                    k,
                    v.host / div,
                    v.guest / div,
                    (v.host + v.guest) / div
                );
            }
        } else {
            eprintln!("{:>32} {:>12}", "key", "value");
            for (k, v) in rows {
                eprintln!("{:>32} {:>12}", k, (v.host + v.guest) / div);
            }
        }
    }
    dump_quantize_state();
}

/// Render every guest-side quantize aggregation as an ASCII
/// power-of-two histogram, matching libdtrace's standard format
/// (`value` / `------------- Distribution -------------` / `count`).
/// One block per agg name.  Buckets are power-of-two indices —
/// bucket K covers `[2^(K-1), 2^K)` ns (with bucket 0 = "0 ns" and
/// bucket 1 = "[1, 2) ns").
pub fn dump_quantize_state() {
    let map = match quantize_state().lock() {
        Ok(g) => g.clone(),
        Err(_) => return,
    };
    if map.is_empty() {
        return;
    }
    let mut by_name: std::collections::BTreeMap<String, Vec<(u32, u64)>> =
        std::collections::BTreeMap::new();
    for ((name, bucket), count) in map {
        if count == 0 {
            continue;
        }
        by_name.entry(name).or_default().push((bucket, count));
    }
    for (name, mut buckets) in by_name {
        buckets.sort_by_key(|(b, _)| *b);
        if buckets.is_empty() {
            continue;
        }
        let max = buckets.iter().map(|(_, c)| *c).max().unwrap_or(1);
        // Route to the right histogram shape based on which
        // parameter store (if any) holds this agg name.  lquantize
        // / llquantize land here too because they share the
        // PERCPU_ARRAY-of-bucket-counts map shape with quantize;
        // the only difference is the bucket-id → user-value
        // labeling.
        let lp = lquantize_params_for(&name);
        let llp = llquantize_params_for(&name);
        let header = if lp.is_some() {
            "lquantize"
        } else if llp.is_some() {
            "llquantize"
        } else {
            "quantize"
        };
        eprintln!();
        eprintln!("  @{} ({})", name, header);
        eprintln!(
            "{:>20} {:<41} {:>10}",
            "value", "------------- Distribution -------------", "count"
        );
        let lo = buckets
            .first()
            .map(|(b, _)| *b)
            .unwrap_or(0)
            .saturating_sub(1);
        let hi = buckets.last().map(|(b, _)| *b).unwrap_or(0) + 1;
        let by_bucket: std::collections::HashMap<u32, u64> = buckets.into_iter().collect();
        for b in lo..=hi {
            let count = by_bucket.get(&b).copied().unwrap_or(0);
            let bar_width = if max == 0 {
                0
            } else {
                (count * 40 / max) as usize
            };
            let bar: String = "@".repeat(bar_width);
            let label = if let Some(p) = lp {
                lquantize_bucket_label(p, b)
            } else if let Some(p) = llp {
                llquantize_bucket_label(p, b)
            } else {
                bucket_label(b)
            };
            eprintln!("{:>20} |{:<40} {:>10}", label, bar, count);
        }
    }
}

/// Bucket label for `lquantize`.  Bucket 0 = underflow
/// (`< base`), buckets 1..=levels = in-range
/// `[base + (i-1)*step, base + i*step)`, bucket levels+1 = overflow.
fn lquantize_bucket_label(p: LquantizeParams, bucket: u32) -> String {
    if bucket == 0 {
        return format!("< {}", p.base);
    }
    if bucket > p.levels {
        return format!(">= {}", p.base + (p.levels as i64) * (p.step as i64));
    }
    let lo = p.base + ((bucket as i64) - 1) * (p.step as i64);
    format!("{}", lo)
}

/// Bucket label for `llquantize`.  Bucket 0 = underflow
/// (`< factor^low_mag`), buckets 1..=N = in-range subdivisions
/// per magnitude band, last bucket = overflow.
fn llquantize_bucket_label(p: LlquantizeParams, bucket: u32) -> String {
    let n_in_range = ((p.high_mag - p.low_mag) as u32 + 1) * (p.steps_per_mag as u32);
    if bucket == 0 {
        return format!("< {}^{}", p.factor, p.low_mag);
    }
    if bucket > n_in_range {
        return format!(">= {}^{}", p.factor, p.high_mag + 1);
    }
    let i = bucket - 1;
    let mag = (i / (p.steps_per_mag as u32)) + (p.low_mag as u32);
    let sub = i % (p.steps_per_mag as u32);
    // factor^mag (lo of band) + sub * (factor^(mag+1) - factor^mag) / steps_per_mag
    let mut lo: u128 = 1;
    for _ in 0..mag {
        lo = lo.saturating_mul(p.factor as u128);
    }
    let band_lo = lo;
    let band_hi = lo.saturating_mul(p.factor as u128);
    let band = band_hi.saturating_sub(band_lo);
    let sub_step = band / (p.steps_per_mag as u128);
    let v = band_lo + (sub as u128) * sub_step;
    format!("{}", v)
}

pub fn bucket_label(bucket: u32) -> String {
    if bucket == 0 {
        return "0".into();
    }
    if bucket >= 64 {
        return format!("2^{}", bucket - 1);
    }
    let lo = 1u64 << (bucket - 1);
    lo.to_string()
}

/// Walk the parsed source and return the set of `@<name>`s that
/// are declared/written in a guest (bifrost:) clause but only
/// REFERENCED (e.g. via `printa()`) in a host clause.  Without a
/// host-side declaration libdtrace's parser rejects the script
/// with `Unknown variable name`, so each such name needs a stub
/// clause that declares the agg without populating it.
pub fn collect_guest_only_aggs_referenced_by_host(
    parsed: &parse::Parsed,
) -> std::collections::BTreeSet<String> {
    let mut guest_decl: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut host_decl: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut host_ref: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in &parsed.clauses {
        if c.is_bifrost() {
            guest_decl.extend(collect_clause_agg_names(&c.body));
        } else {
            let masked = mask_printa_calls(&c.body);
            host_decl.extend(collect_clause_agg_names(&masked));
            host_ref.extend(collect_printa_agg_names(&c.body));
            // Host END / BEGIN clauses commonly carry
            // `normalize(@x, N) / denormalize(@x) / trunc(@x[, N])`
            // / `clear(@x)` lib-action calls against a guest-side
            // agg.  libdtrace would otherwise refuse to compile
            // the script with `Unknown variable name @x`, so each
            // such reference needs a host-side stub injected.
            for (n, _) in scan_normalize_calls(&c.body) {
                host_ref.insert(n);
            }
            for n in scan_denormalize_calls(&c.body) {
                host_ref.insert(n);
            }
            for (n, _) in scan_trunc_calls(&c.body) {
                host_ref.insert(n);
            }
            for args in scan_call_args("clear", &c.body) {
                if let Some(first) = args.first()
                    && let Some(n) = strip_agg_prefix(first)
                {
                    host_ref.insert(n);
                }
            }
        }
    }
    host_ref
        .into_iter()
        .filter(|n| guest_decl.contains(n) && !host_decl.contains(n))
        .collect()
}

/// Find every `@<name>` referenced as the second argument of a
/// `printa(...)` call in `body`.  Approximate but good enough for
/// the patterns demos use: scan for `printa(` and pull out
/// `@<ident>` tokens until the matching `)`.
pub fn collect_printa_agg_names(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let needle = b"printa(";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut depth = 1;
            let mut j = i + needle.len();
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let inner = if j > 0 && j <= bytes.len() {
                &body[i + needle.len()..j - 1]
            } else {
                ""
            };
            for n in collect_clause_agg_names(inner) {
                out.push(n);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Prepend a `dtrace:::BEGIN / 0 / { @<name>[<dummy_key>] = count(); }`
/// stub clause to the parsed source for each agg in `stubs`.  The
/// `/0/` predicate ensures the body never runs at trace start, so
/// the agg stays empty in libdtrace's state — but the declaration
/// causes libdtrace to allocate the symbol AND infer its key type
/// from the dummy expression, so subsequent `printa(@<name>, ...)`
/// calls in END clauses compile cleanly with the right format
/// signature.
pub fn inject_guest_agg_stubs(
    parsed: &mut parse::Parsed,
    stubs: &std::collections::BTreeSet<String>,
) {
    let mut key_for: std::collections::HashMap<&String, String> = std::collections::HashMap::new();
    for name in stubs {
        let mut sig: Option<String> = None;
        for c in &parsed.clauses {
            if !c.is_bifrost() {
                continue;
            }
            if let Some(expr) = extract_agg_key_expr(&c.body, name) {
                let dummies: Vec<String> = split_top_level_commas(&expr)
                    .into_iter()
                    .map(|comp| {
                        let trimmed = comp.trim();
                        if trimmed == "execname"
                            || trimmed == "probefunc"
                            || trimmed == "probename"
                            || trimmed == "probeprov"
                            || trimmed == "probemod"
                        {
                            "\"\"".into()
                        } else {
                            "0".into()
                        }
                    })
                    .collect();
                sig = Some(dummies.join(", "));
                break;
            }
        }
        key_for.insert(name, sig.unwrap_or_else(|| "0".into()));
    }

    for name in stubs {
        let dummy_key = key_for.get(name).cloned().unwrap_or_else(|| "0".into());
        let body = format!("@{}[{}] = count();", name, dummy_key);
        let source = format!("dtrace:::BEGIN / 0 / {{ {} }}", body);
        let stub = parse::Clause {
            source,
            body,
            specs: vec![parse::ProbeSpec {
                provider: "dtrace".into(),
                module: String::new(),
                function: String::new(),
                name: "BEGIN".into(),
                binary: None,
            }],
            predicate: Some("0".into()),
        };
        parsed.clauses.insert(0, stub);
    }
}

/// Walk the parsed source and return the set of `@<name>`s that
/// appear in BOTH a host clause AND a guest (bifrost:) clause.
/// These are the aggregations that should be merged into a single
/// cross-domain table at script termination.
pub fn collect_cross_domain_aggs(parsed: &parse::Parsed) -> std::collections::BTreeSet<String> {
    let mut host: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut guest: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in &parsed.clauses {
        if c.is_bifrost() {
            guest.extend(collect_clause_agg_names(&c.body));
        } else {
            let masked = mask_printa_calls(&c.body);
            host.extend(collect_clause_agg_names(&masked));
        }
    }
    host.intersection(&guest).cloned().collect()
}

/// Replace each `printa(...)` call in `body` with a same-length
/// run of spaces.  Used by collect_cross_domain_aggs so a host
/// END clause that only formats a guest agg via printa() does
/// not falsely register the agg as cross-domain.
pub fn mask_printa_calls(body: &str) -> String {
    let bytes = body.as_bytes();
    let needle = b"printa(";
    let mut out = body.to_string();
    let buf = unsafe { out.as_bytes_mut() };
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut depth = 1;
            let mut j = i + needle.len();
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            for k in i..j.min(buf.len()) {
                buf[k] = b' ';
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// All `@<name>` references in a clause body, skipping anything
/// inside a `"..."` string literal (so `printf("@count is ...")`
/// doesn't false-positive). We catch `@foo`, `@foo[…]`, and
/// `@foo = …`. Anonymous `@ =` is intentionally excluded.
pub fn collect_clause_agg_names(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if b == b'@' {
            let j = i + 1;
            if j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
                let mut k = j;
                while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                    k += 1;
                }
                out.push(String::from_utf8_lossy(&bytes[j..k]).into_owned());
                i = k;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Append a tagged `printf` action to every host clause whose body
/// references a cross-domain aggregation, so the bifrost CLI's
/// pump() threads can observe per-fire host increments and feed a
/// shared HashMap. The original `@<name>` aggregation is preserved
/// alongside the printf so libdtrace's normal `printa()` flow still
/// works for users who want their own END action.
pub fn rewrite_host_clauses_for_cross_aggs(
    parsed: &mut parse::Parsed,
    shared: &std::collections::BTreeSet<String>,
) {
    if shared.is_empty() {
        return;
    }
    for c in &mut parsed.clauses {
        if c.is_bifrost() {
            continue;
        }
        let names: Vec<_> = collect_clause_agg_names(&c.body)
            .into_iter()
            .filter(|n| shared.contains(n))
            .collect();
        if names.is_empty() {
            continue;
        }
        let mut tail = String::new();
        for name in &names {
            let key_expr = extract_agg_key_expr(&c.body, name).unwrap_or_else(|| "0".to_string());
            let components = split_top_level_commas(&key_expr);
            let mut fmt_parts: Vec<String> = Vec::with_capacity(components.len());
            let mut arg_parts: Vec<String> = Vec::with_capacity(components.len());
            for comp in &components {
                let trimmed = comp.trim();
                if trimmed == "execname" || trimmed == "probefunc" || trimmed == "probename" {
                    fmt_parts.push("\\\"%s\\\"".into());
                    arg_parts.push(trimmed.into());
                } else {
                    fmt_parts.push("%lld".into());
                    arg_parts.push(format!("(long long)({})", trimmed));
                }
            }
            let fmt = fmt_parts.join(",");
            let args = arg_parts.join(", ");
            tail.push_str(&format!(
                "\n    printf(\"##xagg-host##|{}|{}|+1\\n\", {});",
                name, fmt, args
            ));
        }
        c.body.push_str(&tail);
        if let Some(open) = c.source.find('{')
            && let Some(close) = c.source.rfind('}')
        {
            c.source = format!("{}{{\n    {}\n}}", &c.source[..open], c.body.trim());
            let _ = close;
        }
    }
}

/// Split a multi-key expression on top-level commas.  Respects
/// `[]` and `()` nesting so subscript / function-call commas stay
/// glued to their owner component.  e.g. `execname, pid` →
/// `["execname", "pid"]`; `f(a,b), pid` → `["f(a,b)", "pid"]`.
pub fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut depth_brk: i32 = 0;
    let mut depth_par: i32 = 0;
    let mut start = 0usize;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'[' => depth_brk += 1,
            b']' => depth_brk -= 1,
            b'(' => depth_par += 1,
            b')' => depth_par -= 1,
            b',' if depth_brk == 0 && depth_par == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= s.len() {
        out.push(s[start..].to_string());
    }
    out
}

/// Return the key expression for the first `@<name>[<expr>]` in
/// `body`, or None for anonymous `@<name> =`.
pub fn extract_agg_key_expr(body: &str, name: &str) -> Option<String> {
    let needle = format!("@{}", name);
    let bytes = body.as_bytes();
    let nb = needle.as_bytes();
    let mut i = 0;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let next = bytes.get(i + nb.len()).copied().unwrap_or(0);
            if next.is_ascii_alphanumeric() || next == b'_' {
                i += 1;
                continue;
            }
            let mut j = i + nb.len();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'[' {
                let start = j + 1;
                let mut depth = 1;
                let mut k = start;
                while k < bytes.len() {
                    match bytes[k] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(
                                    String::from_utf8_lossy(&bytes[start..k]).trim().to_string(),
                                );
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
            }
            return None;
        }
        i += 1;
    }
    None
}

/// Parse a `##xagg-host##|<name>|<key>|+<delta>`,
/// `##xagg-guest##|<name>|<key>|<value>`, or
/// `##xagg-guest-quantize##|<name>|<bucket>|<count>` line and update
/// the cross-domain agg state. Host lines record per-fire increments;
/// guest count/sum/min/max/avg lines record cumulative absolute
/// values from the AGG_SNAPSHOT stream (we store the absolute as the
/// running guest total).  Quantize lines carry per-bucket counts
/// indexed by the agg name; they render as a separate ASCII
/// histogram in `dump_xagg_state`.
pub fn try_parse_xagg_line(
    line: &str,
    state: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), CrossAggValue>>,
    >,
) -> bool {
    if let Some(rest) = strip_marker(line, "##xagg-guest-quantize##|") {
        return parse_quantize_marker(rest);
    }
    let body = if let Some(rest) = strip_marker(line, "##xagg-host##|") {
        rest
    } else if let Some(rest) = strip_marker(line, "##xagg-guest##|") {
        rest
    } else {
        return false;
    };
    let is_host = line.contains("##xagg-host##");
    let mut parts = body.splitn(3, '|');
    let name = match parts.next() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return false,
    };
    let key = match parts.next() {
        Some(k) => k.trim().to_string(),
        _ => return false,
    };
    let value_field = match parts.next() {
        Some(v) => v.trim(),
        _ => return false,
    };
    let value: u64 = if let Some(rest) = value_field.strip_prefix('+') {
        rest.parse().unwrap_or(0)
    } else {
        value_field.parse().unwrap_or(0)
    };
    if let Ok(mut g) = state.lock() {
        let entry = g.entry((name, key)).or_default();
        if is_host {
            entry.host = entry.host.wrapping_add(value);
        } else {
            entry.guest = value;
        }
    }
    true
}

/// Match a marker prefix at line start OR mid-string (libdtrace's
/// printf can interleave with other output, so the marker may not be
/// at column 0).  Returns the body after the prefix on success.
pub fn strip_marker<'a>(line: &'a str, tag: &str) -> Option<&'a str> {
    if let Some(rest) = line.strip_prefix(tag) {
        return Some(rest);
    }
    if let Some(idx) = line.find(tag) {
        return Some(&line[idx + tag.len()..]);
    }
    None
}

/// Per-(name, bucket_id) running total for guest-side quantize
/// aggs.  Buckets are power-of-two indices: bucket 0 = [0, 1) ns,
/// bucket 12 = [4096, 8192) ns, etc.  Stored as a global state map
/// keyed by (agg_name, bucket_id).  Rendered as an ASCII histogram
/// at dump time alongside the scalar xagg table.
static QUANTIZE_STATE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<(String, u32), u64>>,
> = std::sync::OnceLock::new();

pub fn quantize_state() -> &'static std::sync::Mutex<std::collections::HashMap<(String, u32), u64>>
{
    QUANTIZE_STATE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub fn parse_quantize_marker(body: &str) -> bool {
    let mut parts = body.splitn(3, '|');
    let name = match parts.next() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return false,
    };
    let bucket: u32 = match parts.next().and_then(|s| s.trim().parse().ok()) {
        Some(b) => b,
        None => return false,
    };
    let count: u64 = match parts.next().and_then(|s| s.trim().parse().ok()) {
        Some(c) => c,
        None => return false,
    };
    if let Ok(mut g) = quantize_state().lock() {
        g.insert((name, bucket), count);
    }
    true
}

pub fn extract_first_agg_name(body: &str) -> Option<String> {
    extract_nth_agg_name(body, 1)
}

/// Extract the `n`-th agg name (1-indexed) from a clause body.
/// Used by the multi-agg fan-out so each agg sub-chain gets the
/// matching `@<name>` for its map decl encoding.  libdtrace's DOF
/// doesn't carry @-names, so we fall back to source-level scanning.
pub fn extract_nth_agg_name(body: &str, n: usize) -> Option<String> {
    if n == 0 {
        return None;
    }
    let bytes = body.as_bytes();
    let mut i = 0;
    let mut seen = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let j = i + 1;
            if j >= bytes.len() || !(bytes[j].is_ascii_alphabetic() || bytes[j] == b'_') {
                i += 1;
                continue;
            }
            let mut k = j;
            while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                k += 1;
            }
            seen += 1;
            if seen == n {
                return Some(String::from_utf8_lossy(&bytes[j..k]).into_owned());
            }
            i = k;
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_clause_agg_names_basic() {
        assert_eq!(
            collect_clause_agg_names("@foo[pid] = count();"),
            vec!["foo"]
        );
    }

    #[test]
    fn collect_clause_agg_names_multiple() {
        let body = "@a = count(); @bar[pid] = sum(x); @baz[execname, pid] = count();";
        let names = collect_clause_agg_names(body);
        assert_eq!(names, vec!["a", "bar", "baz"]);
    }

    #[test]
    fn collect_clause_agg_names_skips_strings() {
        // `@count` inside a string literal must not register.
        let body = r#"printf("@count is high"); @real = count();"#;
        assert_eq!(collect_clause_agg_names(body), vec!["real"]);
    }

    #[test]
    fn split_top_level_commas_respects_brackets() {
        assert_eq!(split_top_level_commas("a, b, c"), vec!["a", " b", " c"]);
        assert_eq!(split_top_level_commas("f(a,b), c"), vec!["f(a,b)", " c"]);
        assert_eq!(split_top_level_commas("x[a,b], y"), vec!["x[a,b]", " y"]);
    }

    #[test]
    fn extract_agg_key_expr_finds_expr() {
        let body = "@foo[execname, pid] = count();";
        assert_eq!(
            extract_agg_key_expr(body, "foo"),
            Some("execname, pid".into())
        );
    }

    #[test]
    fn extract_agg_key_expr_anonymous_returns_none() {
        let body = "@foo = count();";
        assert_eq!(extract_agg_key_expr(body, "foo"), None);
    }

    #[test]
    fn extract_agg_key_expr_word_boundary() {
        // `@foobar` must not match `foo`.
        let body = "@foobar[pid] = count();";
        assert_eq!(extract_agg_key_expr(body, "foo"), None);
    }

    #[test]
    fn bucket_label_zero() {
        assert_eq!(bucket_label(0), "0");
    }

    #[test]
    fn bucket_label_powers_of_two() {
        assert_eq!(bucket_label(1), "1");
        assert_eq!(bucket_label(11), "1024");
        assert_eq!(bucket_label(13), "4096");
    }

    #[test]
    fn bucket_label_overflow_safe() {
        // bucket >= 64 must not panic on shift overflow.
        assert_eq!(bucket_label(64), "2^63");
    }

    #[test]
    fn strip_marker_at_start() {
        assert_eq!(
            strip_marker("##xagg-host##|a|b", "##xagg-host##|"),
            Some("a|b")
        );
    }

    #[test]
    fn strip_marker_mid_string() {
        assert_eq!(
            strip_marker("CPU 1: ##xagg-host##|a|b", "##xagg-host##|"),
            Some("a|b"),
        );
    }

    #[test]
    fn strip_marker_absent() {
        assert!(strip_marker("nothing", "##xagg-host##|").is_none());
    }

    #[test]
    fn extract_first_agg_name_basic() {
        assert_eq!(
            extract_first_agg_name("@foo = count();"),
            Some("foo".into())
        );
    }

    #[test]
    fn extract_nth_agg_name_indexed() {
        let body = "@a = count(); @b = count(); @c = count();";
        assert_eq!(extract_nth_agg_name(body, 1), Some("a".into()));
        assert_eq!(extract_nth_agg_name(body, 2), Some("b".into()));
        assert_eq!(extract_nth_agg_name(body, 3), Some("c".into()));
        assert_eq!(extract_nth_agg_name(body, 4), None);
    }
}
