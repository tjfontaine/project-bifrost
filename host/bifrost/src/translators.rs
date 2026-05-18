// SPDX-License-Identifier: Apache-2.0
// Typed-translator expansion: lower `args[N]->field->subfield` chains
// into DIF the compiler can already digest, without resorting to
// string-level rewrites of the source.
//
// ## Conceptual model
//
// DTrace exposes structured arguments (`args[0]->prev->comm` and
// friends) that DIF has no native syntax for.  Two paths coexist:
//
//   1. A small *canonical* table for the chains DTrace traditionally
//      exposes for `sched_switch` and `proc:::exec`.  Each canonical
//      chain maps directly onto an `argN` builtin, so the rewrite is
//      a pure substitution that yields byte-identical DIF.
//
//   2. A *BTF-driven* path for arbitrary chains.  The host vmlinux
//      BTF resolves each step to a struct-offset addition; the
//      chain rewrites textually to
//        `*(unsigned T *)(argN + CORE_OFFSETOF(S1,F1)
//                              + CORE_OFFSETOF(S2,F2) + ...)`
//      where the `CORE_OFFSETOF` sentinels carry the host fallback
//      offsets.  `materialize_field_relocs` emits one wrapper-level
//      field reloc per step, so the libkrun-side patcher re-resolves
//      every offset against the *guest* kernel's BTF on load.  That
//      keeps a Linux-built program portable across kernel versions
//      with non-identical struct layouts.
//
// ## Invariants this module maintains
//
//   - Expansion runs *after* the source has been split into clauses
//     by `parse::parse` (which pre-strips comments), so the walker
//     only has to dodge string and char literals — never `/* ... */`
//     or `//`.
//   - `MAX_CHAIN_DEPTH` (= 4) bounds the unroll length so the
//     emitted DIF stays well inside the BPF verifier's
//     instruction-count budget.  Deeper chains return a typed
//     error rather than producing a program the verifier will
//     reject later.
//   - `MAX_CHAINS_PER_CLAUSE` (= 8) caps the per-clause chain count
//     for the same reason; one program lowered from a clause body
//     must fit a single verifier pass.
//   - BTF chains chase *kernel* pointers only.  Intermediate fields
//     marked as user-VA are rejected at host resolution rather than
//     producing a guest program that faults on first probe firing.
//   - Terminal fields are scalar (1 / 2 / 4 / 8-byte integers and
//     pointers).  String-typed terminals fall back to the canonical
//     path, which preserves DTrace's existing `comm`-as-string
//     rendering shape.
//
// ## Interactions
//
//   - `parse::Clause` supplies the (provider, function, name) tuple
//     used by `tp_root_for` to choose the right per-tracepoint root
//     descriptor.
//   - `btf::Btf` does the offset / type resolution for the BTF
//     path; the resulting `CORE_OFFSETOF` sentinels are consumed
//     downstream by `materialize_field_relocs` (in `core_reloc`).
//   - The TP_ROOTS table encodes the TP_PROTO arg index for each
//     supported tracepoint, because raw-tracepoint programs receive
//     the kernel struct pointer at the TP_PROTO position (not at the
//     synthetic `args[0]` the DTrace surface presents).

#![cfg(target_os = "macos")]

use crate::btf::Btf;
use crate::parse::{Clause, ParseError};
use thiserror::Error;

/// BTF chain-depth ceiling — `args[N]->a->b->c->d`.  Each step is
/// a CORE_OFFSETOF expansion that the libkrun-side patcher will
/// re-resolve; the BPF verifier rejects unbounded loops, so we keep
/// the unroll bound static and small.
pub const MAX_CHAIN_DEPTH: usize = 4;

/// BTF chains-per-clause ceiling.  Same reasoning as
/// `llquantize`'s 8-magnitude cap — keep the program well within
/// the verifier's instruction-count budget.
pub const MAX_CHAINS_PER_CLAUSE: usize = 8;

/// Why a BTF chain walk failed to resolve.  Sub-enum of
/// [`TranslatorError::Unresolved`] so callers can match on the
/// specific failure mode instead of regexing the rendered string.
#[derive(Debug, Error)]
pub enum ResolveFailure {
    #[error("vmlinux BTF not loaded; BTF chain resolution unavailable")]
    BtfNotLoaded,

    #[error("no BTF root descriptor for `args[{idx}]->{sub_arg}` on this probe spec")]
    NoTracepointRoot { idx: u32, sub_arg: String },

    #[error("BTF lookup failed: {0}")]
    Btf(#[from] crate::btf::BtfError),

    #[error(
        "intermediate field `{field}` is not a struct; \
         only embedded structs may appear before the terminal field"
    )]
    IntermediateNotStruct { field: String },
}

/// Errors specific to typed-translator expansion.  Bridged to the
/// shared `parse::ParseError` shape at the function boundary so
/// existing CLI plumbing surfaces them through the same channel as
/// other parse-time diagnostics.
#[derive(Debug, Error)]
pub enum TranslatorError {
    #[error(
        "typed translator `{chain}` does not resolve: {source} \
         (canonical set: `args[0]->{{prev,next}}->{{comm,pid}}` \
         and `args[0]->pr_pid`)"
    )]
    Unresolved {
        chain: String,
        source: ResolveFailure,
    },

    #[error(
        "typed translator `{chain}` chain depth {depth} exceeds the \
         chain-depth cap of {MAX_CHAIN_DEPTH}"
    )]
    ChainTooDeep { chain: String, depth: usize },

    #[error(
        "clause has {count} typed-translator chains; cap is \
         {MAX_CHAINS_PER_CLAUSE} per clause to keep the program within \
         the verifier insn budget"
    )]
    TooManyChains { count: usize },

    #[error("`args[{idx}]` exceeds the arg0..arg9 builtin range")]
    ArgIndexOutOfRange { idx: u32 },

    #[error(
        "typed translator `{chain}` would chase user-VA pointer `{field}` — \
         rejected at host-side BTF resolution (BTF chain-walk caps)"
    )]
    UserPointerChase { chain: String, field: String },

    #[error(
        "typed translator `{chain}` terminal field `{terminal}` has \
         {size}-byte size; only scalar terminals of 1/2/4/8 \
         bytes are supported"
    )]
    UnsupportedTerminal {
        chain: String,
        terminal: String,
        size: u32,
    },
}

impl From<TranslatorError> for ParseError {
    fn from(e: TranslatorError) -> ParseError {
        ParseError(e.to_string())
    }
}

/// One occurrence of `args[idx]->p0->p1.p2...` found in a clause body.
/// Spans `body[start..end]`; `path` is the parsed identifier chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedArg {
    pub idx: u32,
    pub path: Vec<String>,
    /// Byte range within the body the chain occupies.  Used by the
    /// single-pass splicer to avoid re-walking the body.
    pub start: usize,
    pub end: usize,
}

impl TypedArg {
    pub fn raw<'a>(&self, body: &'a str) -> &'a str {
        &body[self.start..self.end]
    }
}

/// One hop in a BTF chain — `(struct_name, field_name)`.
/// Named struct beats `(String, String)` so call sites read as
/// `hop.struct_name` / `hop.field_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfHop {
    pub struct_name: String,
    pub field_name: String,
    /// Byte size of the field, as reported by BTF.  Recorded during
    /// the walk so we don't have to re-query for the terminal size.
    pub size: u32,
}

/// A canonical translator chain — maps to one of the
/// `arg0..arg9` DIF builtins.  Module/function/name selectors are
/// intentionally absent: the textual rewrite this replaced did not
/// gate on probe spec, so the canonical path preserves that posture
/// for byte-identical DIF.
struct Canonical {
    /// First element is the sub-arg name (`prev` / `next` / `pr_pid`
    /// — the "translator field"); remaining elements are the path
    /// components after that.
    path: &'static [&'static str],
    /// args[idx] selector on the source side.
    src_arg: u32,
    /// `argN` builtin the chain rewrites to.
    dst_arg: u32,
}

const CANONICAL: &[Canonical] = &[
    // sched_switch tracepoint context (tracepoint format, not raw
    // TP_PROTO — bifrost reads via the trace_event_raw_sched_switch
    // shape).
    Canonical {
        path: &["prev", "comm"],
        src_arg: 0,
        dst_arg: 0,
    },
    Canonical {
        path: &["prev", "pid"],
        src_arg: 0,
        dst_arg: 1,
    },
    Canonical {
        path: &["next", "comm"],
        src_arg: 0,
        dst_arg: 4,
    },
    Canonical {
        path: &["next", "pid"],
        src_arg: 0,
        dst_arg: 5,
    },
    // proc:::exec — psinfo_t::pr_pid lowers to the matching
    // sched_process_exec arg.
    Canonical {
        path: &["pr_pid"],
        src_arg: 0,
        dst_arg: 1,
    },
];

/// Returns `Some(dst_arg)` if `(idx, path)` matches a canonical
/// chain in the canonical table.
fn match_canonical(arg: &TypedArg) -> Option<u32> {
    CANONICAL.iter().find_map(|c| {
        (c.src_arg == arg.idx
            && c.path.len() == arg.path.len()
            && c.path
                .iter()
                .zip(arg.path.iter())
                .all(|(a, b)| *a == b.as_str()))
        .then_some(c.dst_arg)
    })
}

/// BTF per-tracepoint root descriptor.  Maps the synthetic
/// `args[0]->prev` / `args[0]->next` sub-arg names onto:
///   - the *real* tracepoint context arg index that holds the
///     pointer to the underlying kernel struct, and
///   - the BTF struct name that pointer dereferences to.
///
/// For raw-tracepoint clauses bifrost lowers as
/// BPF_PROG_TYPE_RAW_TRACEPOINT, so the arg indices match the
/// TP_PROTO of each tracepoint.  `sched_switch`'s TP_PROTO is
/// `(bool preempt, struct task_struct *prev, struct task_struct *next,
/// unsigned int prev_state)` — `prev` is at arg index 1.
#[derive(Debug, Clone, Copy)]
struct TpRoot {
    sub_arg: &'static str,
    real_arg: u32,
    btf_struct: &'static str,
}

/// Per-tracepoint root tables.  BTF resolution only kicks in
/// when (provider, function, name) matches one of these entries AND
/// the chain's first path element matches one of the listed
/// `sub_arg`s.
struct TpRootSet {
    provider: &'static str,
    function: &'static str,
    name: &'static str,
    roots: &'static [TpRoot],
}

const TP_ROOTS: &[TpRootSet] = &[
    TpRootSet {
        provider: "tracepoint",
        function: "sched",
        name: "sched_switch",
        roots: &[
            TpRoot {
                sub_arg: "prev",
                real_arg: 1,
                btf_struct: "task_struct",
            },
            TpRoot {
                sub_arg: "next",
                real_arg: 2,
                btf_struct: "task_struct",
            },
        ],
    },
    TpRootSet {
        provider: "tracepoint",
        function: "sched",
        name: "sched_wakeup",
        roots: &[
            // sched_wakeup's TP_PROTO is (struct task_struct *p) — arg 0
            // is the wakee task pointer.
            TpRoot {
                sub_arg: "p",
                real_arg: 0,
                btf_struct: "task_struct",
            },
            TpRoot {
                sub_arg: "task",
                real_arg: 0,
                btf_struct: "task_struct",
            },
        ],
    },
    TpRootSet {
        provider: "tracepoint",
        function: "sched",
        name: "sched_wakeup_new",
        roots: &[
            TpRoot {
                sub_arg: "p",
                real_arg: 0,
                btf_struct: "task_struct",
            },
            TpRoot {
                sub_arg: "task",
                real_arg: 0,
                btf_struct: "task_struct",
            },
        ],
    },
];

fn tp_root_for(clause: &Clause, idx: u32, sub_arg: &str) -> Option<TpRoot> {
    if idx != 0 {
        return None;
    }
    clause
        .specs
        .iter()
        .filter(|s| s.is_tracepoint())
        .find_map(|spec| {
            TP_ROOTS
                .iter()
                .find(|set| {
                    set.provider == spec.provider
                        && set.function == spec.function
                        && set.name == spec.name
                })
                .and_then(|set| set.roots.iter().find(|r| r.sub_arg == sub_arg).copied())
        })
}

/// Body-walker state for the unified scan-and-splice pass.  Tracks
/// in-string / in-char / backslash-escape so a single state machine
/// drives both `find_typed_args` (legacy spelling, public for unit
/// tests) and `expand_translators` (the splicer).
struct BodyWalk<'a> {
    bytes: &'a [u8],
    cursor: usize,
    in_str: bool,
    in_char: bool,
}

impl<'a> BodyWalk<'a> {
    fn new(body: &'a str) -> Self {
        Self {
            bytes: body.as_bytes(),
            cursor: 0,
            in_str: false,
            in_char: false,
        }
    }

    /// Step the walker over a single position, handling escapes and
    /// string/char-literal entry/exit.  Returns `true` if the cursor
    /// is now outside any quoted span and pointing at code we should
    /// inspect for translator chains; `false` otherwise.  Always
    /// advances the cursor by at least one byte (or by two for a
    /// backslash escape).
    fn step_into_code(&mut self) -> bool {
        let b = self.bytes[self.cursor];
        if b == b'\\' && (self.in_str || self.in_char) && self.cursor + 1 < self.bytes.len() {
            self.cursor += 2;
            return false;
        }
        if b == b'"' && !self.in_char {
            self.in_str = !self.in_str;
            self.cursor += 1;
            return false;
        }
        if b == b'\'' && !self.in_str {
            self.in_char = !self.in_char;
            self.cursor += 1;
            return false;
        }
        if self.in_str || self.in_char {
            self.cursor += 1;
            return false;
        }
        true
    }

    /// Try to recognise a typed-translator chain starting at the
    /// cursor.  Returns the parsed `TypedArg` and leaves the cursor
    /// pointing past the chain.  Returns `None` and leaves the cursor
    /// unchanged if the cursor isn't on `args[`.
    fn try_chain(&mut self) -> Option<TypedArg> {
        let start = self.cursor;
        let b = self.bytes;
        if !b[start..].starts_with(b"args[") {
            return None;
        }
        // Identifier-prefix guard: `xargs[0]` must not match.
        if start > 0 && is_ident_byte(b[start - 1]) {
            return None;
        }
        let mut j = start + b"args[".len();
        let idx_start = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == idx_start || j >= b.len() || b[j] != b']' {
            return None;
        }
        let idx: u32 = std::str::from_utf8(&b[idx_start..j])
            .ok()
            .and_then(|s| s.parse().ok())?;
        j += 1; // past ']'
        // Need at least one `->ident` to count as a typed chain.
        if !b[j..].starts_with(b"->") {
            return None;
        }
        let mut path: Vec<String> = Vec::new();
        loop {
            if b[j..].starts_with(b"->") {
                j += 2;
            } else if !path.is_empty() && j < b.len() && b[j] == b'.' {
                j += 1;
            } else {
                break;
            }
            let id_start = j;
            while j < b.len() && is_ident_byte(b[j]) {
                j += 1;
            }
            if j == id_start {
                return None; // malformed — caller falls through
            }
            // SAFETY: only identifier bytes consumed.
            path.push(std::str::from_utf8(&b[id_start..j]).unwrap().to_string());
        }
        if path.is_empty() {
            return None;
        }
        let arg = TypedArg {
            idx,
            path,
            start,
            end: j,
        };
        self.cursor = j;
        Some(arg)
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Scan `body` for `args[N]->ident(->ident|.ident)*` occurrences
/// outside of string literals.  Public so unit tests can pin the
/// scanner shape; the splice path uses the same walker internally.
pub fn find_typed_args(body: &str) -> Vec<TypedArg> {
    let mut walk = BodyWalk::new(body);
    let mut out = Vec::new();
    while walk.cursor < walk.bytes.len() {
        if !walk.step_into_code() {
            continue;
        }
        if let Some(chain) = walk.try_chain() {
            out.push(chain);
        } else {
            walk.cursor += 1;
        }
    }
    out
}

/// Canonical + BTF-chain clause expansion.  Returns a rewritten body
/// suitable for libdtrace.  Any unresolved chain produces a typed
/// `ParseError` rather than silently passing through.
///
/// `btf` is `None` either because the host hasn't loaded vmlinux BTF
/// or the caller intentionally restricts to canonical semantics.
pub fn expand_translators(
    clause: &Clause,
    body: &str,
    btf: Option<&mut Btf>,
) -> Result<String, ParseError> {
    // Single-pass scan: walk the body once, resolving each chain as
    // we hit it and splicing the replacement directly into `out`.
    // One state machine, one source of truth for string-literal
    // handling (avoids the drift hazard of a separate find pass and
    // splice pass that each have to recognise quotes the same way).
    let mut walk = BodyWalk::new(body);
    let mut out = String::with_capacity(body.len());
    let mut chain_count = 0usize;
    let mut btf = btf;
    while walk.cursor < walk.bytes.len() {
        if !walk.step_into_code() {
            // Step into a literal / escape — copy the consumed bytes
            // through.  `step_into_code` advanced the cursor; we have
            // to emit the byte(s) we just walked past.
            let resumed = walk.cursor;
            // The walker advances either 1 (quote toggle / in-literal
            // byte) or 2 (backslash escape).  Either way, copy from
            // the previous cursor position forward.
            let prev = resumed.saturating_sub(2).max(resumed.saturating_sub(1));
            // Defensive: prev should be < resumed since step_into_code
            // never advances by zero.
            for &b in &walk.bytes[prev..resumed] {
                out.push(b as char);
            }
            continue;
        }
        let chain_start = walk.cursor;
        match walk.try_chain() {
            Some(chain) => {
                chain_count += 1;
                if chain_count > MAX_CHAINS_PER_CLAUSE {
                    return Err(TranslatorError::TooManyChains { count: chain_count }.into());
                }
                let replacement = resolve_chain(clause, &chain, body, btf.as_deref_mut())?;
                out.push_str(&replacement);
            }
            None => {
                out.push(walk.bytes[chain_start] as char);
                walk.cursor = chain_start + 1;
            }
        }
    }
    Ok(out)
}

/// Resolve a single typed-arg occurrence into the source text it
/// rewrites to.  Pure: no shared state mutated beyond the BTF
/// reference threaded in.
fn resolve_chain(
    clause: &Clause,
    chain: &TypedArg,
    body: &str,
    btf: Option<&mut Btf>,
) -> Result<String, TranslatorError> {
    if chain.idx > 9 {
        return Err(TranslatorError::ArgIndexOutOfRange { idx: chain.idx });
    }
    if chain.path.len() > MAX_CHAIN_DEPTH {
        return Err(TranslatorError::ChainTooDeep {
            chain: chain.raw(body).to_string(),
            depth: chain.path.len(),
        });
    }
    if let Some(dst) = match_canonical(chain) {
        return Ok(format!("arg{}", dst));
    }
    // BTF chain walk.
    let raw = chain.raw(body).to_string();
    let Some(btf) = btf else {
        return Err(TranslatorError::Unresolved {
            chain: raw,
            source: ResolveFailure::BtfNotLoaded,
        });
    };
    let Some(root) = tp_root_for(clause, chain.idx, &chain.path[0]) else {
        return Err(TranslatorError::Unresolved {
            chain: raw,
            source: ResolveFailure::NoTracepointRoot {
                idx: chain.idx,
                sub_arg: chain.path[0].clone(),
            },
        });
    };
    // Walk the path through BTF, accumulating one hop per field.
    let mut hops: Vec<BtfHop> = Vec::with_capacity(chain.path.len());
    let mut current_struct = root.btf_struct.to_string();
    let chain_tail = &chain.path[1..];
    for (i, field) in chain_tail.iter().enumerate() {
        let (_off, size) =
            btf.field_offset(&current_struct, field)
                .map_err(|e| TranslatorError::Unresolved {
                    chain: raw.clone(),
                    source: ResolveFailure::Btf(e),
                })?;
        hops.push(BtfHop {
            struct_name: current_struct.clone(),
            field_name: field.clone(),
            size,
        });
        let is_terminal = i + 1 == chain_tail.len();
        if is_terminal {
            break;
        }
        // Mid-chain: must descend through an embedded struct.
        match btf.member_descend(&current_struct, field) {
            Some(MemberKind::EmbeddedStruct(name)) => current_struct = name,
            Some(MemberKind::Pointer(_)) => {
                return Err(TranslatorError::UserPointerChase {
                    chain: raw,
                    field: field.clone(),
                });
            }
            Some(MemberKind::Scalar) | None => {
                return Err(TranslatorError::Unresolved {
                    chain: raw,
                    source: ResolveFailure::IntermediateNotStruct {
                        field: field.clone(),
                    },
                });
            }
        }
    }
    let terminal = hops
        .last()
        .expect("chain_tail non-empty (try_chain enforces at least one `->ident`)");
    let deref_type = match terminal.size {
        1 => "unsigned char",
        2 => "unsigned short",
        4 => "unsigned int",
        8 => "unsigned long",
        other => {
            return Err(TranslatorError::UnsupportedTerminal {
                chain: raw,
                terminal: terminal.field_name.clone(),
                size: other,
            });
        }
    };
    // Build the rewritten expression:
    //   *(unsigned long *)((unsigned long)arg<root> + CORE_OFFSETOF(S1, F1)
    //                                              + CORE_OFFSETOF(S2, F2) ...)
    //
    // The CORE_OFFSETOF round-trip is intentional: each hop becomes a
    // standalone sentinel in the source, and the existing
    // `rewrite_core_offsetof` pass already knows how to record each
    // hop as its own wrapper-level field reloc.  Inlining the
    // sentinels here would short-circuit that machinery and force a
    // parallel reloc-emission path; the text round-trip keeps the
    // BTF chain walk a strict subset of the user-writable surface.
    use std::fmt::Write as _;
    let mut expr = String::with_capacity(64 + hops.len() * 48);
    write!(
        expr,
        "(*({} *)((unsigned long)arg{}",
        deref_type, root.real_arg
    )
    .unwrap();
    for hop in &hops {
        write!(
            expr,
            " + CORE_OFFSETOF({}, {})",
            hop.struct_name, hop.field_name
        )
        .unwrap();
    }
    expr.push_str("))");
    Ok(expr)
}

/// BTF chain-walk helper: classify a struct member as embedded-struct /
/// pointer / scalar, for the chain-walking descent in
/// `expand_translators`.  Returned `EmbeddedStruct(name)` carries
/// the BTF struct name so the next hop can index its members.
#[derive(Debug, Clone)]
pub enum MemberKind {
    EmbeddedStruct(String),
    Pointer(String),
    Scalar,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    #[test]
    fn find_typed_args_basic() {
        let chains = find_typed_args("@c[args[0]->prev->comm] = count();");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].idx, 0);
        assert_eq!(chains[0].path, vec!["prev", "comm"]);
        assert_eq!(
            &"@c[args[0]->prev->comm] = count();"[chains[0].start..chains[0].end],
            "args[0]->prev->comm"
        );
    }

    #[test]
    fn find_typed_args_skips_string_literal() {
        let chains = find_typed_args(r#"printf("args[0]->prev->comm");"#);
        assert!(chains.is_empty(), "literal string mention is not a chain");
    }

    #[test]
    fn find_typed_args_dotted_path() {
        let chains = find_typed_args("trace(args[0]->prev->se.sum_exec_runtime);");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].path, vec!["prev", "se", "sum_exec_runtime"]);
    }

    #[test]
    fn find_typed_args_ignores_identifier_prefix() {
        // A token that contains `args[` as a substring of a longer
        // identifier prefix must not match (`xargs[0]` is not a chain).
        let chains = find_typed_args("xargs[0]->prev->comm");
        assert!(chains.is_empty());
    }

    fn first_clause(src: &str) -> parse::Clause {
        parse::parse(src)
            .unwrap()
            .clauses
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn canonical_chain_lowers_to_arg_token() {
        let clause = first_clause(
            "tracepoint:guest:sched:sched_switch { @c[args[0]->prev->comm] = count(); }",
        );
        let rewritten = expand_translators(&clause, &clause.body, None).unwrap();
        assert!(rewritten.contains("arg0"));
        assert!(!rewritten.contains("args[0]->prev->comm"));
    }

    #[test]
    fn string_literal_chain_preserved() {
        let clause = first_clause(
            r#"tracepoint:guest:sched:sched_switch { printf("args[0]->prev->comm"); }"#,
        );
        let rewritten = expand_translators(&clause, &clause.body, None).unwrap();
        assert!(
            rewritten.contains("args[0]->prev->comm"),
            "string-literal chain must be preserved verbatim, got: {}",
            rewritten
        );
        assert!(
            !rewritten.contains("arg0"),
            "the only `args[0]->prev->comm` is in a string literal; no `arg0` should leak"
        );
    }

    #[test]
    fn unknown_chain_without_btf_errors() {
        let clause = first_clause(
            "tracepoint:guest:sched:sched_switch { trace(args[0]->prev->se.sum_exec_runtime); }",
        );
        let err = expand_translators(&clause, &clause.body, None).unwrap_err();
        // Typed match: the underlying ResolveFailure should be
        // BtfNotLoaded, surfaced through the parse-error bridge.
        assert!(
            err.to_string().contains("BTF not loaded"),
            "expected BtfNotLoaded error, got: {}",
            err
        );
    }

    #[test]
    fn args_index_out_of_range_errors() {
        let clause =
            first_clause("tracepoint:guest:sched:sched_switch { trace(args[10]->prev->comm); }");
        let err = expand_translators(&clause, &clause.body, None).unwrap_err();
        assert!(err.to_string().contains("exceeds the arg0..arg9"));
    }

    #[test]
    fn too_many_chains_errors() {
        let mut body = String::from("trace(0); ");
        for _ in 0..(MAX_CHAINS_PER_CLAUSE + 1) {
            body.push_str("trace(args[0]->prev->pid); ");
        }
        let src = format!("tracepoint:guest:sched:sched_switch {{ {} }}", body);
        let clause = first_clause(&src);
        let err = expand_translators(&clause, &clause.body, None).unwrap_err();
        assert!(err.to_string().contains("cap"));
    }

    #[test]
    fn btf_chain_lowers_to_core_offsetof_expr() {
        let path = crate::cli::args::default_vmlinux();
        let Ok(bytes) = crate::btf::extract_btf_section(std::path::Path::new(&path)) else {
            eprintln!("[test] skipping: no vmlinux at {}", path);
            return;
        };
        let mut btf = crate::btf::parse(&bytes).expect("btf parses");
        let clause = first_clause(
            "tracepoint:guest:sched:sched_switch \
             { @rs = sum(args[0]->prev->se.sum_exec_runtime); }",
        );
        let rewritten = expand_translators(&clause, &clause.body, Some(&mut btf)).unwrap();
        assert!(
            rewritten.contains("CORE_OFFSETOF(task_struct, se)"),
            "BTF chain must emit a CORE_OFFSETOF hop for task_struct.se, got: {}",
            rewritten,
        );
        assert!(
            rewritten.contains("CORE_OFFSETOF(sched_entity, sum_exec_runtime)"),
            "BTF chain must emit a CORE_OFFSETOF hop for sched_entity.sum_exec_runtime, \
             got: {}",
            rewritten,
        );
        assert!(
            rewritten.contains("(unsigned long *)"),
            "BTF chain must emit an 8-byte scalar deref, got: {}",
            rewritten,
        );
        assert!(
            rewritten.contains("arg1"),
            "BTF sched_switch `prev` chain must root at arg1, got: {}",
            rewritten,
        );
    }

    #[test]
    fn btf_chain_too_deep_errors() {
        let path = crate::cli::args::default_vmlinux();
        let Ok(bytes) = crate::btf::extract_btf_section(std::path::Path::new(&path)) else {
            return;
        };
        let mut btf = crate::btf::parse(&bytes).expect("btf parses");
        let depth5 = "args[0]->prev->a->b->c->d->e";
        let src = format!(
            "tracepoint:guest:sched:sched_switch {{ trace({}); }}",
            depth5
        );
        let clause = first_clause(&src);
        let err = expand_translators(&clause, &clause.body, Some(&mut btf)).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the chain-depth cap"),
            "depth-cap rejection expected, got: {}",
            err,
        );
    }

    #[test]
    fn unknown_chain_typed_match() {
        // Pin the typed shape of the unresolved error so callers can
        // pattern-match instead of regexing the rendered string.
        let clause = first_clause(
            "tracepoint:guest:sched:sched_switch { trace(args[0]->prev->se.sum_exec_runtime); }",
        );
        let err: TranslatorError = (|| -> Result<String, TranslatorError> {
            let chains = find_typed_args(&clause.body);
            assert_eq!(chains.len(), 1);
            resolve_chain(&clause, &chains[0], &clause.body, None)
        })()
        .unwrap_err();
        match err {
            TranslatorError::Unresolved {
                source: ResolveFailure::BtfNotLoaded,
                ..
            } => {}
            other => panic!("expected Unresolved/BtfNotLoaded, got: {:?}", other),
        }
    }

    #[test]
    fn comment_stripped_chain_does_not_reach_expansion() {
        // The parser strips comments before clause splitting; the
        // body received by expand_translators is comment-free, so a
        // commented-out chain never appears in the input.
        let p = parse::parse(
            r#"tracepoint:guest:sched:sched_switch {
                /* args[0]->prev->comm */
                @c = count();
            }"#,
        )
        .unwrap();
        let body = &p.clauses[0].body;
        assert!(
            !body.contains("args[0]->prev->comm"),
            "comments must be pre-stripped before expansion, got: {}",
            body
        );
        let rewritten = expand_translators(&p.clauses[0], body, None).unwrap();
        assert!(!rewritten.contains("args[0]->prev->comm"));
    }
}
