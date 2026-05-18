// SPDX-License-Identifier: Apache-2.0
//! Structured scanner that recovers the (aggid, kind, name) contract
//! for FreeBSD aggregations from D source.
//!
//! libdtrace assigns aggregation ids 1..N in the order the parser
//! first sees each `@<ident>` *declaration* (an `@x = …` or `@x[…] = …`
//! lhs).  References inside other actions (`printa(format, @x)`) do
//! not advance the counter.  The FreeBSD kernel-side bridge stamps
//! the libdtrace-assigned aggid into the wire-level `fd` slot of every
//! `AGG_SNAPSHOT` row, so the host needs the same name and the same
//! `kind` discriminator (which selects the value decoder — scalar vs.
//! histogram-bucket) to make sense of those rows.
//!
//! Earlier iterations of the orchestrator used a naïve byte scan that
//! was fooled by `@<ident>` tokens hiding inside C-style comments or
//! string literals.  This module replaces that with a small D-lexer
//! that strips comments and string contents before walking the
//! source, so `/* old @rx = count(); */` or `printf("%s\n", "@rx")`
//! can never contribute spurious aggregations.

use std::collections::HashMap;

/// One aggregation discovered in a per-target D source.  Ordered by
/// first appearance — `aggid` is `position+1` (libdtrace's 1-based
/// numbering).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggDecl {
    pub aggid: i32,
    pub name: String,
    pub kind: AggKind,
    /// Count of key tuple components, parsed from `@name[k0, k1, ...]
    /// = AGG(...)` in the D source.  `@name = AGG(...)` (no brackets)
    /// is 0; `@name[k] = AGG(...)` is 1; etc.  Used by the Linux
    /// lowering path (`linux_compile`) to derive the right
    /// chain_start when an agg sits behind one or more standalone
    /// per-fire actions (e.g. a leading `trace(timestamp)`).
    pub n_keys: usize,
}

/// Aggregation flavors libdtrace can compile, in the form the
/// FreeBSD bridge's AGG_SNAPSHOT decoder understands.  `Unknown` is
/// reserved for kinds we don't yet handle in the decoder; the
/// orchestrator skips rows whose kind is `Unknown` rather than
/// guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggKind {
    Count,
    Sum,
    Min,
    Max,
    Avg,
    Stddev,
    Quantize,
    Lquantize,
    Llquantize,
}

impl AggKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AggKind::Count => "count",
            AggKind::Sum => "sum",
            AggKind::Min => "min",
            AggKind::Max => "max",
            AggKind::Avg => "avg",
            AggKind::Stddev => "stddev",
            AggKind::Quantize => "quantize",
            AggKind::Lquantize => "lquantize",
            AggKind::Llquantize => "llquantize",
        }
    }

    fn from_call_name(name: &str) -> Option<Self> {
        Some(match name {
            "count" => Self::Count,
            "sum" => Self::Sum,
            "min" => Self::Min,
            "max" => Self::Max,
            "avg" => Self::Avg,
            "stddev" => Self::Stddev,
            "quantize" => Self::Quantize,
            "lquantize" => Self::Lquantize,
            "llquantize" => Self::Llquantize,
            _ => return None,
        })
    }
}

/// Strip C-style line and block comments and replace every string
/// literal's *content* with spaces (preserving the surrounding
/// quotes and lengths).  Returns the cleaned source — same byte
/// length as input — so byte positions still align with the
/// caller's source if needed.
pub fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // C++-style line comment.
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // C-style block comment.
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                // Preserve newlines so line counts stay aligned for
                // any later diagnostic that uses cleaned source.
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            // Skip the closing `*/` (if present).  Unterminated block
            // comments swallow the rest of the source, which matches
            // what libdtrace would do anyway.
            if i + 1 < bytes.len() {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            } else {
                while i < bytes.len() {
                    out.push(b' ');
                    i += 1;
                }
            }
            continue;
        }
        // String literal: copy the opening quote, blank the contents,
        // copy the closing quote.  Handle `\"` escapes.
        if bytes[i] == b'"' {
            out.push(b'"');
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i < bytes.len() {
                out.push(b'"');
                i += 1;
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    // SAFETY: we only ever wrote ASCII bytes (spaces, newlines,
    // existing source bytes) — all UTF-8 boundaries preserved.
    String::from_utf8(out).expect("cleaned source is valid UTF-8 by construction")
}

/// Scan `src` for `@<ident> [...optional key tuple...] = <agg_call>(`
/// declarations and return them in first-appearance order.  References
/// without an `=` (e.g. `printa(@x)`) are ignored.  Re-assignments to
/// an already-discovered name are also ignored — each name claims
/// exactly one aggid, set at its first declaration.
pub fn discover_aggs(src: &str) -> Vec<AggDecl> {
    let cleaned = strip_comments_and_strings(src);
    let bytes = cleaned.as_bytes();
    let mut out: Vec<AggDecl> = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'@' {
            i += 1;
            continue;
        }
        let name_start = i + 1;
        let mut j = name_start;
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
            j += 1;
        }
        if j == name_start {
            i += 1;
            continue;
        }
        let name = &cleaned[name_start..j];

        let mut k = j;
        skip_whitespace(bytes, &mut k);

        // Optional key tuple `[...]`; depth-tracked so nested
        // brackets inside the tuple don't confuse us.
        // Also count top-level commas inside the tuple so callers
        // can derive the agg's key arity (n_keys = commas + 1 when
        // the tuple is non-empty; 0 when no brackets).
        let mut n_keys: usize = 0;
        if k < bytes.len() && bytes[k] == b'[' {
            let mut depth = 1;
            n_keys = 1;
            k += 1;
            while k < bytes.len() && depth > 0 {
                match bytes[k] {
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    b',' if depth == 1 => n_keys += 1,
                    _ => {}
                }
                k += 1;
            }
            skip_whitespace(bytes, &mut k);
        }

        if k >= bytes.len() || bytes[k] != b'=' {
            i = j;
            continue;
        }
        k += 1;
        skip_whitespace(bytes, &mut k);

        // Read the next identifier and check whether it's an agg
        // call (`count`, `sum`, ...).  We REQUIRE an open-paren
        // immediately after the identifier so a stray
        // `@x = @y;` re-bind doesn't get misclassified.
        let call_start = k;
        while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
            k += 1;
        }
        if k == call_start {
            i = j;
            continue;
        }
        let call_name = &cleaned[call_start..k];
        skip_whitespace(bytes, &mut k);
        if k >= bytes.len() || bytes[k] != b'(' {
            i = j;
            continue;
        }
        let Some(kind) = AggKind::from_call_name(call_name) else {
            i = j;
            continue;
        };

        if out.iter().any(|d| d.name == name) {
            i = j;
            continue;
        }
        out.push(AggDecl {
            aggid: (out.len() as i32) + 1,
            name: name.to_string(),
            kind,
            n_keys,
        });
        i = k;
    }
    out
}

fn skip_whitespace(bytes: &[u8], i: &mut usize) {
    while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

/// Convenience: render `discover_aggs(src)` as the
/// `HashMap<aggid, (kind_str, name)>` shape the cross-target reducer
/// path consumes today.  Once that consumer accepts `AggKind` directly
/// this shim can go away.
pub fn agg_id_map(decls: &[AggDecl]) -> HashMap<i32, (String, String)> {
    decls
        .iter()
        .map(|d| (d.aggid, (d.kind.as_str().to_string(), d.name.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_count_declaration_picks_up_name_and_kind() {
        let src = r#"tick-1sec { @rx[probename] = count(); }"#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "rx");
        assert_eq!(decls[0].kind, AggKind::Count);
        assert_eq!(decls[0].aggid, 1);
    }

    #[test]
    fn multiple_aggs_get_sequential_aggids_in_first_seen_order() {
        let src = r#"
            BEGIN { @a = count(); @b[arg0] = sum(arg1); }
            tick-1sec { @c = quantize(arg2); }
        "#;
        let decls = discover_aggs(src);
        let by_name: Vec<_> = decls.iter().map(|d| (d.name.as_str(), d.aggid, d.kind)).collect();
        assert_eq!(
            by_name,
            vec![
                ("a", 1, AggKind::Count),
                ("b", 2, AggKind::Sum),
                ("c", 3, AggKind::Quantize),
            ]
        );
    }

    #[test]
    fn re_assignment_does_not_create_a_second_aggid() {
        // The same agg can be assigned across multiple clauses;
        // libdtrace numbers it only on first sight.
        let src = r#"
            BEGIN { @rx = count(); }
            tick-1sec { @rx = count(); }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].aggid, 1);
    }

    #[test]
    fn printa_reference_does_not_create_an_agg() {
        let src = r#"
            BEGIN { @rx = count(); }
            END { printa("%s %@d\n", @rx); }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "rx");
    }

    #[test]
    fn agg_in_block_comment_is_ignored() {
        let src = r#"
            /* historical: @stale = count(); */
            BEGIN { @real = count(); }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "real");
        assert_eq!(decls[0].aggid, 1);
    }

    #[test]
    fn agg_in_line_comment_is_ignored() {
        let src = r#"
            // disabled: @stale = count();
            BEGIN { @real = sum(arg0); }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "real");
        assert_eq!(decls[0].kind, AggKind::Sum);
    }

    #[test]
    fn agg_in_string_literal_is_ignored() {
        let src = r#"
            BEGIN { printf("never an agg: @fake = count();\n"); @real = count(); }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "real");
    }

    #[test]
    fn nested_keys_with_brackets_dont_confuse_the_scanner() {
        let src = r#"BEGIN { @h[arg0, arg1[0]] = quantize(arg2); }"#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "h");
        assert_eq!(decls[0].kind, AggKind::Quantize);
    }

    #[test]
    fn lquantize_and_llquantize_are_distinguished() {
        let src = r#"
            BEGIN {
                @a = quantize(arg0);
                @b = lquantize(arg0, 0, 100, 10);
                @c = llquantize(arg0, 10, 0, 6, 20);
            }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls[0].kind, AggKind::Quantize);
        assert_eq!(decls[1].kind, AggKind::Lquantize);
        assert_eq!(decls[2].kind, AggKind::Llquantize);
    }

    #[test]
    fn unknown_call_after_assign_skips_the_declaration() {
        // `@x = arg0;` is a scalar agg re-bind in D; we don't
        // model that as a named agg, so the scanner skips it.
        let src = r#"BEGIN { @maybe = arg0; }"#;
        let decls = discover_aggs(src);
        assert!(decls.is_empty(), "got {:?}", decls);
    }

    #[test]
    fn block_comment_is_terminated_by_close_marker_not_first_slash() {
        // Earlier scanners would close on `/` alone; this exercise
        // proves we wait for `*/`.
        let src = r#"
            /* a / b * c — still in the comment */
            BEGIN { @good = count(); }
        "#;
        let decls = discover_aggs(src);
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "good");
    }

    #[test]
    fn agg_id_map_round_trips_to_kind_string() {
        let decls = vec![
            AggDecl { aggid: 1, name: "a".into(), kind: AggKind::Count, n_keys: 0 },
            AggDecl { aggid: 2, name: "h".into(), kind: AggKind::Quantize, n_keys: 2 },
        ];
        let m = agg_id_map(&decls);
        assert_eq!(m.get(&1).unwrap().0, "count");
        assert_eq!(m.get(&1).unwrap().1, "a");
        assert_eq!(m.get(&2).unwrap().0, "quantize");
    }
}
