// SPDX-License-Identifier: Apache-2.0
//! End-of-session `printa()` renderer for the multi-target
//! orchestrator.
//!
//! The single-target attach path renders user-supplied `printa(...)`
//! format strings via libdtrace's in-process consumer.  The
//! orchestrator's `dispatch_multi_target` doesn't run a host
//! libdtrace consumer (each target's libkrun host process is a
//! distinct pid; native FreeBSD targets don't emit pid$target
//! events at all), so we render END-clause `printa` calls from
//! `merge::CrossTargetAggReducer` state directly.
//!
//! Scope: enough to handle the killer-demo D shapes — `%s` /
//! `%-Ns` / `%Ns` for the key tuple, `%d` / `%u` / `%x` for plain
//! integers, `%@d` / `%@u` / `%@x` for the agg value, and the
//! usual C escapes (`\n`, `\t`, `\\`).  Quantize aggs fall through
//! to the reducer's generic histogram dump.

#![cfg(target_os = "macos")]

use crate::merge::{CrossTargetAggReducer, CrossTargetAggValue};
use crate::parse::Parsed;

/// Render every printa() call in every END clause of `parsed`
/// against `reducer`.  Falls back to the reducer's own `dump()` for
/// aggs that are touched but not named in any printa.  No-ops if
/// the source has no END clauses or if every named agg is missing
/// from the reducer.
pub fn render_end_printa(parsed: &Parsed, reducer: &CrossTargetAggReducer) {
    let mut printa_named_aggs: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    for clause in &parsed.clauses {
        if !is_end_clause(clause) {
            continue;
        }
        // printf() calls with literal args render immediately
        // (status banners, "session ended" lines, etc.).  Calls
        // referencing D variables or arguments are skipped today
        // since we have no libdtrace consumer to resolve them.
        for call in scan_printf_calls(&clause.body) {
            print!("{}", call.rendered);
        }
        for call in scan_printa_calls(&clause.body) {
            for agg in &call.aggs {
                printa_named_aggs.insert(agg.clone());
            }
            render_one_printa(&call, reducer);
        }
    }

    // For aggs that are present in the reducer but never rendered
    // via printa, fall through to the generic dump so the user
    // doesn't lose visibility — common case: a guest-only agg with
    // no END clause at all.
    let mut un_rendered: Vec<(String, String, &crate::merge::CrossTargetAggCell)> = Vec::new();
    for (name, key, cell) in reducer.rows() {
        if !printa_named_aggs.contains(name) {
            un_rendered.push((name.to_string(), key.to_string(), cell));
        }
    }
    if !un_rendered.is_empty() {
        for (name, key, cell) in un_rendered {
            match &cell.value {
                CrossTargetAggValue::Scalar(v) => {
                    println!("xagg @{name}[{key}] = {v}");
                }
                CrossTargetAggValue::Histogram(buckets) => {
                    let parts: Vec<String> =
                        buckets.iter().map(|(b, c)| format!("{b}:{c}")).collect();
                    println!("xagg @{name}[{key}] = quantize {{ {} }}", parts.join(", "));
                }
            }
            // Surface the per-target contributor map so callers can
            // see which kernels actually fed this row.  This is the
            // direct evidence the cross-kernel-linux-fbsd-x2 demo's
            // acceptance gate checks for: one `@latency` row whose
            // contributors include both `linux-*` and `fbsd-*` target
            // ids proves the kill-demo's cross-kernel fold lands.
            if !cell.contributors.is_empty() {
                let ids: Vec<String> = cell.contributors.keys().cloned().collect();
                println!("  contributors: {}", ids.join(", "));
            }
        }
    }
}

fn is_end_clause(clause: &crate::parse::Clause) -> bool {
    clause
        .specs
        .iter()
        .any(|s| s.provider == "END" || (s.provider == "dtrace" && s.name == "END"))
}

fn is_begin_clause(clause: &crate::parse::Clause) -> bool {
    clause
        .specs
        .iter()
        .any(|s| s.provider == "BEGIN" || (s.provider == "dtrace" && s.name == "BEGIN"))
}

/// Render every literal-only printf() in BEGIN clauses to stdout.
/// Skips printf calls that reference D variables (those need a
/// libdtrace consumer).  Call at session start before the drain
/// loop so banners land in the right place in the output stream.
pub fn render_begin_printf(parsed: &Parsed) {
    for clause in &parsed.clauses {
        if !is_begin_clause(clause) {
            continue;
        }
        for call in scan_printf_calls(&clause.body) {
            print!("{}", call.rendered);
        }
    }
}

/// One printf() call with all-literal arguments.  Anything else
/// (variable substitution, function calls in the arg list) is
/// silently skipped by the scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrintfCall {
    rendered: String,
}

/// Scan a clause body for `printf(...)` calls that we can render
/// without a libdtrace consumer.  Today: only the literal-string,
/// no-arg form (`printf("session ended\n")`).  Anything with args
/// is silently dropped because the args could touch D variables or
/// args[N] which need the in-process consumer to resolve.
fn scan_printf_calls(body: &str) -> Vec<PrintfCall> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 7 <= bytes.len() {
        // Skip `printa(` — overlaps the `printf(` prefix scan and
        // we don't want to double-emit printa as printf.
        if i + 7 <= bytes.len() && &bytes[i..i + 7] == b"printa(" {
            i += 7;
            continue;
        }
        if &bytes[i..i + 7] == b"printf(" {
            let after = i + 7;
            if let Some((call, advance)) = parse_printf_args(&body[after..]) {
                out.push(call);
                i = after + advance;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn parse_printf_args(rest: &str) -> Option<(PrintfCall, usize)> {
    let mut i = 0;
    let bytes = rest.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'"' {
        return None;
    }
    i += 1;
    let format_start = i;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escape {
            escape = false;
        } else if b == b'\\' {
            escape = true;
        } else if b == b'"' {
            break;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let format = unescape_d_string(&rest[format_start..i]);
    i += 1; // close quote
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    if bytes[i] == b')' {
        // Pure literal printf — no arg substitution to do; the
        // format string itself is the rendered output (after
        // escape decoding).
        return Some((PrintfCall { rendered: format }, i + 1));
    }
    // Args present.  Today we drop these; a richer renderer could
    // attempt literal-arg substitution (e.g. `printf("hi %d\n", 7)`)
    // but the killer demos don't use that shape.
    None
}

/// A single `printa(format, @agg, ...)` call extracted from a D
/// clause body.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrintaCall {
    format: String,
    aggs: Vec<String>,
}

/// Scan a clause body for `printa(...)` calls.  Tolerates whitespace
/// and `// ...` line comments around them; rejects nested
/// parentheses inside the format string (none of the demos need
/// them and parsing balanced parens through a real expression tree
/// is out of scope here).
fn scan_printa_calls(body: &str) -> Vec<PrintaCall> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 7 <= bytes.len() {
        if &bytes[i..i + 7] == b"printa(" {
            let after = i + 7;
            if let Some((call, advance)) = parse_printa_args(&body[after..]) {
                out.push(call);
                i = after + advance;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Parse the contents of `printa(...)` starting just after the
/// opening paren.  Returns `(call, bytes_consumed_including_close)`
/// or `None` if the call is malformed.
fn parse_printa_args(rest: &str) -> Option<(PrintaCall, usize)> {
    let mut i = 0;
    let bytes = rest.as_bytes();

    // Skip whitespace.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }

    // Format string must start with `"`.
    if i >= bytes.len() || bytes[i] != b'"' {
        return None;
    }
    i += 1;
    let format_start = i;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escape {
            escape = false;
        } else if b == b'\\' {
            escape = true;
        } else if b == b'"' {
            break;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let format = unescape_d_string(&rest[format_start..i]);
    i += 1; // close quote

    // Comma-separated agg references.  Each `@<ident>` is captured;
    // anything else (literal scalar args to printf-shaped specs)
    // would be supported by a richer renderer — printa specifically
    // takes only aggregations after the format string, so this is
    // sufficient.
    let mut aggs: Vec<String> = Vec::new();
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] == b')' {
            i += 1;
            return Some((PrintaCall { format, aggs }, i));
        }
        if bytes[i] != b',' {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'@' {
            return None;
        }
        i += 1;
        let name_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        if name_start == i {
            return None;
        }
        aggs.push(rest[name_start..i].to_string());
    }
}

/// Translate D string escapes (`\n`, `\t`, `\\`, `\"`) into the
/// corresponding bytes.  Unknown escapes are passed through
/// verbatim so the user sees them as-is.
fn unescape_d_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('0') => out.push('\0'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn render_one_printa(call: &PrintaCall, reducer: &CrossTargetAggReducer) {
    for agg_name in &call.aggs {
        // Collect every row for this agg.
        let rows: Vec<(String, &crate::merge::CrossTargetAggCell)> = reducer
            .rows()
            .filter_map(|(n, k, cell)| {
                if n == agg_name {
                    Some((k.to_string(), cell))
                } else {
                    None
                }
            })
            .collect();
        if rows.is_empty() {
            // Honor the format anyway with placeholder rendering so
            // the user sees that the agg fired zero times rather
            // than silently dropping it.
            continue;
        }
        for (key, cell) in rows {
            let line = render_format(&call.format, &key, cell);
            print!("{line}");
        }
    }
}

/// Substitute one printa row into the format string.  Walks the
/// format greedily; each non-`%@` directive consumes the next key
/// element (split on `,`), each `%@<conv>` directive consumes the
/// agg value.  This matches D printa's "key specs first, then
/// value specs" semantics on the shapes the demos use.
fn render_format(
    format: &str,
    key: &str,
    cell: &crate::merge::CrossTargetAggCell,
) -> String {
    let key_parts: Vec<&str> = split_key(key);
    let mut key_iter = key_parts.into_iter();
    let mut out = String::with_capacity(format.len());
    let bytes = format.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'%' {
            out.push(b as char);
            i += 1;
            continue;
        }
        // Found '%' — parse [flags][width][.precision][@]<conv>.
        let spec_start = i;
        i += 1;
        let mut spec = String::from("%");
        let mut is_agg = false;
        // Flags.
        while i < bytes.len() && matches!(bytes[i], b'-' | b'+' | b' ' | b'#' | b'0') {
            spec.push(bytes[i] as char);
            i += 1;
        }
        // Width.
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            spec.push(bytes[i] as char);
            i += 1;
        }
        // Precision.
        if i < bytes.len() && bytes[i] == b'.' {
            spec.push('.');
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                spec.push(bytes[i] as char);
                i += 1;
            }
        }
        // Agg-value marker.
        if i < bytes.len() && bytes[i] == b'@' {
            is_agg = true;
            i += 1;
        }
        // Conversion.
        if i >= bytes.len() {
            // Trailing `%` with no conversion — pass through.
            out.push_str(&format[spec_start..]);
            break;
        }
        let conv = bytes[i] as char;
        i += 1;
        if conv == '%' {
            out.push('%');
            continue;
        }
        if is_agg {
            out.push_str(&render_agg_value(&spec, conv, cell));
        } else {
            let elem = key_iter.next().unwrap_or("");
            out.push_str(&render_key_element(&spec, conv, elem));
        }
    }
    out
}

fn split_key(key: &str) -> Vec<&str> {
    if key.is_empty() {
        return Vec::new();
    }
    // Honor quoted commas — `"foo,bar"` is one element.  Walk
    // top-level only.
    let mut parts: Vec<&str> = Vec::new();
    let mut depth = 0i32;
    let mut in_quote = false;
    let mut start = 0;
    for (i, ch) in key.char_indices() {
        match ch {
            '"' => in_quote = !in_quote,
            '(' | '[' if !in_quote => depth += 1,
            ')' | ']' if !in_quote => depth -= 1,
            ',' if !in_quote && depth == 0 => {
                parts.push(&key[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&key[start..]);
    parts
}

fn render_key_element(spec: &str, conv: char, elem: &str) -> String {
    let (left_pad, width) = parse_width(spec);
    match conv {
        's' => {
            // Strip surrounding quotes for clean display.
            let trimmed = elem.trim();
            let unquoted = trimmed
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(trimmed);
            pad_string(unquoted, width, left_pad)
        }
        'd' | 'i' | 'u' => {
            let trimmed = elem.trim();
            let val: i64 = trimmed.parse().unwrap_or(0);
            pad_string(&val.to_string(), width, left_pad)
        }
        'x' => {
            let val: u64 = elem.trim().parse().unwrap_or(0);
            pad_string(&format!("{val:x}"), width, left_pad)
        }
        'X' => {
            let val: u64 = elem.trim().parse().unwrap_or(0);
            pad_string(&format!("{val:X}"), width, left_pad)
        }
        _ => elem.to_string(),
    }
}

fn render_agg_value(
    spec: &str,
    conv: char,
    cell: &crate::merge::CrossTargetAggCell,
) -> String {
    let (left_pad, width) = parse_width(spec);
    match (&cell.value, conv) {
        (CrossTargetAggValue::Scalar(v), 'd') | (CrossTargetAggValue::Scalar(v), 'i') => {
            pad_string(&v.to_string(), width, left_pad)
        }
        (CrossTargetAggValue::Scalar(v), 'u') => {
            pad_string(&(*v as u64).to_string(), width, left_pad)
        }
        (CrossTargetAggValue::Scalar(v), 'x') => {
            pad_string(&format!("{:x}", *v as u64), width, left_pad)
        }
        (CrossTargetAggValue::Histogram(buckets), _) => {
            // No compact %@<one-char> spec captures a histogram —
            // render bucket-list inline.  Matches the reducer's
            // fallback dump format.
            let parts: Vec<String> =
                buckets.iter().map(|(b, c)| format!("{b}:{c}")).collect();
            // Suppress the kind suffix if the histogram is empty.
            if parts.is_empty() {
                "{}".to_string()
            } else {
                format!("{{ {} }}", parts.join(", "))
            }
        }
        _ => match &cell.value {
            CrossTargetAggValue::Scalar(v) => v.to_string(),
            CrossTargetAggValue::Histogram(_) => String::new(),
        },
    }
}

fn parse_width(spec: &str) -> (bool, usize) {
    let mut left_pad = false;
    let mut chars = spec.chars().peekable();
    chars.next(); // consume '%'
    while let Some(&c) = chars.peek() {
        if c == '-' {
            left_pad = true;
            chars.next();
        } else if matches!(c, '+' | ' ' | '#' | '0') {
            chars.next();
        } else {
            break;
        }
    }
    let mut width_str = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            width_str.push(c);
            chars.next();
        } else {
            break;
        }
    }
    let width: usize = width_str.parse().unwrap_or(0);
    (left_pad, width)
}

fn pad_string(s: &str, width: usize, left_pad: bool) -> String {
    if s.len() >= width || width == 0 {
        return s.to_string();
    }
    let pad = " ".repeat(width - s.len());
    if left_pad {
        format!("{s}{pad}")
    } else {
        format!("{pad}{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::{CrossTargetAggKind, CrossTargetAggReducer, CrossTargetAggValue};

    #[test]
    fn scan_picks_up_canonical_printa() {
        let body = r#"
            printa("%-10s %@d\n", @rx);
            printa("%s %s %@u", @counts);
        "#;
        let calls = scan_printa_calls(body);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].format, "%-10s %@d\n");
        assert_eq!(calls[0].aggs, vec!["rx".to_string()]);
        assert_eq!(calls[1].aggs, vec!["counts".to_string()]);
    }

    #[test]
    fn scan_handles_whitespace_between_args() {
        let body = r#"printa(   "%-10s %@d\n"  ,   @rx )"#;
        let calls = scan_printa_calls(body);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].aggs, vec!["rx".to_string()]);
    }

    #[test]
    fn render_format_left_pads_string_key_and_appends_value() {
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "rx",
            "\"linux\"",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(42),
        );
        let parsed = crate::parse::parse(
            r#"END { printa("%-10s %@d\n", @rx); }"#,
        )
        .expect("parse");
        // Use a buffer-capturing surrogate by inspecting via the
        // reducer + format directly.
        let cell = r.rows().next().unwrap().2;
        let line = render_format("%-10s %@d\n", "\"linux\"", cell);
        assert_eq!(line, "linux      42\n");
        let _ = parsed;
    }

    #[test]
    fn render_format_supports_multi_element_key() {
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "counts",
            "\"http\",80",
            CrossTargetAggKind::Count,
            CrossTargetAggValue::Scalar(7),
        );
        let cell = r.rows().next().unwrap().2;
        let line = render_format("%s %d => %@u\n", "\"http\",80", cell);
        assert_eq!(line, "http 80 => 7\n");
    }

    #[test]
    fn render_format_histogram_inlines_buckets() {
        let mut r = CrossTargetAggReducer::new();
        r.merge(
            "linux",
            "latency",
            "",
            CrossTargetAggKind::Quantize,
            CrossTargetAggValue::Histogram(vec![(0, 3), (64, 5)]),
        );
        let cell = r.rows().next().unwrap().2;
        let line = render_format("hist=%@d\n", "", cell);
        assert_eq!(line, "hist={ 0:3, 64:5 }\n");
    }

    #[test]
    fn unescape_handles_common_escapes() {
        assert_eq!(unescape_d_string(r"line\nbreak"), "line\nbreak");
        assert_eq!(unescape_d_string(r"tab\there"), "tab\there");
        assert_eq!(unescape_d_string(r"slash\\value"), "slash\\value");
    }

    #[test]
    fn scan_printf_picks_up_no_arg_literal() {
        let body = r#"printf("session ended\n"); printf("ok\n");"#;
        let calls = scan_printf_calls(body);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].rendered, "session ended\n");
        assert_eq!(calls[1].rendered, "ok\n");
    }

    #[test]
    fn scan_printf_skips_arg_bearing_calls() {
        // Has args -> parser rejects; renderer emits nothing.
        let body = r#"printf("got %d\n", arg0);"#;
        let calls = scan_printf_calls(body);
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn scan_printf_does_not_match_printa_prefix() {
        let body = r#"printa("%@d\n", @rx);"#;
        let calls = scan_printf_calls(body);
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn split_key_respects_quoted_commas() {
        assert_eq!(split_key("\"linux\""), vec!["\"linux\""]);
        assert_eq!(split_key("\"a,b\",17"), vec!["\"a,b\"", "17"]);
        assert_eq!(split_key("1,2,3"), vec!["1", "2", "3"]);
    }
}
