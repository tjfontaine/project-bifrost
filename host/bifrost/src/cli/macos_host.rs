// SPDX-License-Identifier: Apache-2.0
//! macOS-host orchestrate backend — spawn `dtrace(1)` as a child and
//! parse its text-mode output into the same `(per-fire record,
//! cross-target agg update)` shape the SHM-conduit backends produce.
//!
//! This is the third-kernel arm of `bifrost orchestrate`: instead of
//! loading a kernel-loadable session through an SHM conduit, the
//! orchestrator runs `sudo -n /usr/sbin/dtrace -q -n '<routed source>'`
//! and reads its stdout.  A small synthetic suffix appended to the
//! per-target source emits per-scalar-agg END rows in a marker-prefixed
//! line format so the reader thread can decode them without parsing
//! dtrace's default histogram-formatter.
//!
//! Per-fire `trace(value)` lines come out of `dtrace -q` as just the
//! raw value (decimal, one per line, often with leading whitespace).
//! We promote each to a [`crate::merge::TaggedRecord`] under the
//! macos-host target id and stamp it with the host wall-clock at
//! ingest, exactly like the SHM-conduit drain does for guest
//! records — so cross-target ordering in [`crate::merge::MergedRing`]
//! treats macos-host as a peer source.

#![cfg(target_os = "macos")]

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread::JoinHandle;

use anyhow::{Result, anyhow, bail};

use crate::merge::CrossTargetAggKind;
use crate::plan::RoutedTarget;

/// Decoded line from the dtrace child's stdout.
#[derive(Clone, Debug)]
pub enum MacosHostEvent {
    /// One `trace(value)` fire on the host.  The orchestrator wraps
    /// `value` in the same bifrost record sub-header layout
    /// `print_merged_record` decodes from guest payloads.
    PerFire { value: u64 },
    /// One scalar agg row at session END.  Synthesized by the
    /// `printa("\x01bf-mhx\x01<name>\x01%@d\n", @<name>)` clauses we
    /// append to the per-target source.
    AggUpdate {
        kind: CrossTargetAggKind,
        name: String,
        key: String,
        value: i64,
    },
}

/// One macos-host dtrace child + reader thread.
pub struct MacosHostSession {
    target_id: String,
    child: Option<Child>,
    reader: Option<JoinHandle<()>>,
    rx: Receiver<MacosHostEvent>,
    stderr_log_path: std::path::PathBuf,
}

impl MacosHostSession {
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Non-blocking drain of every event the reader thread has
    /// produced since the last call.
    pub fn drain_events(&self) -> Vec<MacosHostEvent> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(ev) => out.push(ev),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        out
    }

    /// SIGTERM the dtrace child (which makes dtrace dump its final
    /// agg tables through stdout), then join the reader thread so
    /// the channel drains.  Idempotent.
    pub fn terminate_and_join(&mut self) {
        if let Some(mut child) = self.child.take() {
            // dtrace handles SIGTERM by flushing aggs and exiting
            // cleanly.  SIGKILL would skip the agg dump.
            let pid = child.id();
            unsafe {
                // safe: pid came from Command::spawn
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            let _ = child.wait();
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }

    pub fn stderr_log_path(&self) -> &std::path::Path {
        &self.stderr_log_path
    }
}

impl Drop for MacosHostSession {
    fn drop(&mut self) {
        self.terminate_and_join();
    }
}

/// Concatenate every routed clause's source for `rt` into the per-
/// target D source the macos-host dtrace child will compile.
fn assemble_routed_source(rt: &RoutedTarget<'_>) -> Result<String> {
    let mut source = String::new();
    source.push_str("#pragma D option quiet\n");
    source.push_str("#pragma D option destructive\n");
    for rc in &rt.clauses {
        // Rebuild each clause from its specs + body so we can append
        // `printf("\n");` to every fire's body — `dtrace -q`'s
        // `trace(value)` writes raw bytes with no separator between
        // fires, which would collapse N trace() calls into one giant
        // digit run in our stdout tokenizer.  Adding a per-fire
        // newline keeps each PerFire its own line without forcing
        // the user to switch from `trace()` to `printf()`.
        let probes: Vec<String> = rc
            .specs
            .iter()
            .map(|s| s.render())
            .collect();
        source.push_str(&probes.join(",\n"));
        source.push('\n');
        if let Some(pred) = &rc.clause.predicate {
            source.push('/');
            source.push_str(pred);
            source.push('/');
            source.push('\n');
        }
        source.push_str("{\n");
        source.push_str(&rc.clause.body);
        // Ensure body ends with a `;` before our suffix.  Trim
        // trailing whitespace; add `;` only if not already present.
        let trimmed = rc.clause.body.trim_end();
        if !trimmed.ends_with(';') && !trimmed.is_empty() {
            source.push(';');
        }
        source.push_str("\n  printf(\"\\n\");\n}\n");
    }
    if source.trim().is_empty() {
        bail!("target `{}` has no clauses to run on macos-host", rt.target.id);
    }
    // Synthesize an END clause that dumps each declared scalar agg
    // through a marker-prefixed printa() so the reader thread can
    // decode rows without parsing dtrace's default histogram
    // formatter.  Quantize/lquantize aggs are deferred — the reducer
    // happily folds scalar contributors into a histogram cell from
    // another target.
    use crate::cli::agg_decl::discover_aggs;
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    let mut end_body = String::new();
    for rc in &rt.clauses {
        for d in discover_aggs(&rc.clause.body) {
            if !seen.insert(d.name.clone()) {
                continue;
            }
            let kind_name = d.kind.as_str();
            let scalar_kind =
                matches!(kind_name, "count" | "sum" | "min" | "max" | "avg");
            if scalar_kind {
                // Marker-prefixed line shape, parsed in
                // `decode_line`:
                //   \x01bf-mhx\x01<kind>\x01<name>\x01<key>\x01<value>\n
                // %s is the agg key tuple, %@d is the agg's reduced
                // value (count for count(), sum for sum(), etc.).
                end_body.push_str(&format!(
                    "    printa(\"\\1bf-mhx\\1{kind}\\1{name}\\1%s\\1%@d\\n\", @{name});\n",
                    kind = kind_name,
                    name = d.name,
                ));
            }
            // ALWAYS truncate the agg at END so dtrace's exit-time
            // default formatter doesn't dump a noisy histogram
            // table into our merged stream.  For scalar aggs we've
            // already emitted the marker line above; for
            // quantize/lquantize/llquantize we leave the cross-
            // target merge to FreeBSD / Linux contributors (their
            // AGG_SNAPSHOT path ships the full bucket array).
            end_body.push_str(&format!("    trunc(@{name});\n", name = d.name));
        }
    }
    if !end_body.is_empty() {
        source.push_str("dtrace:::END\n{\n");
        source.push_str(&end_body);
        source.push_str("}\n");
    }
    Ok(source)
}

/// Spawn one macos-host dtrace session for the routed target.
pub fn spawn_macos_host_session(
    rt: &RoutedTarget<'_>,
    extra_args: &[String],
) -> Result<MacosHostSession> {
    let routed_source = assemble_routed_source(rt)?;

    let log_dir = std::env::var("BIFROST_LAUNCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let stderr_log_path =
        std::path::PathBuf::from(&log_dir).join(format!("bifrost-orch-{}-dtrace.log", rt.target.id));
    let _ = std::fs::remove_file(&stderr_log_path);
    let stderr_file = std::fs::File::create(&stderr_log_path)
        .map_err(|e| anyhow!("create dtrace stderr log {}: {e}", stderr_log_path.display()))?;

    // `sudo -n` because /usr/sbin/dtrace on macOS requires root.
    // The orchestrator itself typically runs under sudo already for
    // the SHM-conduit path; the inner sudo is a no-op then, and if
    // the operator runs the orchestrator unprivileged it lets the
    // sudoers configuration carry the dtrace permission narrowly.
    let mut cmd = Command::new("sudo");
    cmd.arg("-n");
    cmd.arg("/usr/sbin/dtrace");
    cmd.arg("-q");
    cmd.arg("-n");
    cmd.arg(&routed_source);
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::from(stderr_file));

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn dtrace for target `{}`: {e}", rt.target.id))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("dtrace stdout pipe missing for target `{}`", rt.target.id))?;

    let (tx, rx) = channel::<MacosHostEvent>();
    let reader = std::thread::Builder::new()
        .name(format!("bifrost-macos-host-{}", rt.target.id))
        .spawn(move || {
            run_reader_loop(stdout, tx);
        })
        .map_err(|e| anyhow!("spawn dtrace reader thread: {e}"))?;

    Ok(MacosHostSession {
        target_id: rt.target.id.clone(),
        child: Some(child),
        reader: Some(reader),
        rx,
        stderr_log_path,
    })
}

/// Reader loop: streaming tokenizer over the dtrace child's stdout.
///
/// `dtrace -q` does not insert any separator between `trace()` fires
/// — every invocation writes just the value bytes back-to-back.  The
/// parser therefore reads bytes directly and recognizes two shapes
/// without relying on newlines:
///
///   - `\x01bf-mhx\x01<kind>\x01<name>\x01<key>\x01<value>\n` — the
///     marker-prefixed printa row our synthetic END clause emits.
///     The terminating `\n` is what bounds the marker; nothing else
///     uses that byte in our output.
///   - Otherwise: runs of ASCII digits (optionally with a leading
///     `-`) are decoded as per-fire `trace(value)` integers.  Any
///     other byte terminates the current digit run.
fn run_reader_loop<R: Read>(mut stdout: R, tx: Sender<MacosHostEvent>) {
    let mut buf = [0u8; 4096];
    // Accumulator for the in-flight integer token.  Reset whenever
    // a non-digit byte ends the run.
    let mut digit_acc: Vec<u8> = Vec::with_capacity(32);
    // Accumulator for the in-flight marker line (started by 0x01,
    // ended by 0x0A).
    let mut marker_acc: Vec<u8> = Vec::with_capacity(256);
    let mut in_marker = false;

    loop {
        let n = match stdout.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        for &b in &buf[..n] {
            if in_marker {
                if b == b'\n' {
                    // Finalize marker.
                    if let Some(ev) = decode_marker_line(&marker_acc) {
                        if tx.send(ev).is_err() {
                            return;
                        }
                    }
                    marker_acc.clear();
                    in_marker = false;
                } else {
                    marker_acc.push(b);
                }
                continue;
            }
            if b == 0x01 {
                // Flush any pending digit token before entering
                // marker mode.
                flush_digit(&mut digit_acc, &tx);
                in_marker = true;
                continue;
            }
            let is_digit = b.is_ascii_digit();
            let is_minus_start = b == b'-' && digit_acc.is_empty();
            if is_digit || is_minus_start {
                digit_acc.push(b);
            } else {
                // Whitespace or any other byte ends the current
                // digit run.  Push and reset.
                flush_digit(&mut digit_acc, &tx);
            }
        }
    }
    // EOF — flush any straggling state.
    flush_digit(&mut digit_acc, &tx);
    if in_marker && !marker_acc.is_empty() {
        if let Some(ev) = decode_marker_line(&marker_acc) {
            let _ = tx.send(ev);
        }
    }
}

fn flush_digit(digit_acc: &mut Vec<u8>, tx: &Sender<MacosHostEvent>) {
    if digit_acc.is_empty() {
        return;
    }
    // A bare `-` (operator typed `trace(-)`) is not a value.  Drop.
    if digit_acc.as_slice() == b"-" {
        digit_acc.clear();
        return;
    }
    if let Ok(s) = std::str::from_utf8(digit_acc) {
        if let Ok(v) = s.parse::<i64>() {
            let _ = tx.send(MacosHostEvent::PerFire { value: v as u64 });
        } else if let Ok(v) = s.parse::<u64>() {
            let _ = tx.send(MacosHostEvent::PerFire { value: v });
        }
    }
    digit_acc.clear();
}

/// Decode the bytes of one marker-bounded printa row (the leading
/// `\x01` is already consumed; the trailing `\n` not yet appended).
fn decode_marker_line(bytes: &[u8]) -> Option<MacosHostEvent> {
    let line = std::str::from_utf8(bytes).ok()?;
    // Format: "bf-mhx\x01<kind>\x01<name>\x01<key>\x01<value>"
    let mut parts = line.split('\u{0001}');
    let tag = parts.next()?;
    if tag != "bf-mhx" {
        return None;
    }
    let kind_str = parts.next()?;
    let name = parts.next()?;
    let key = parts.next()?;
    let value_str = parts.next()?;
    let value: i64 = value_str.trim().parse().ok()?;
    let kind = match kind_str {
        "count" => CrossTargetAggKind::Count,
        "sum" => CrossTargetAggKind::Sum,
        "min" => CrossTargetAggKind::Min,
        "max" => CrossTargetAggKind::Max,
        _ => return None,
    };
    // dtrace renders an empty key tuple as a single space.  Match
    // the host-side render_agg_key convention: empty string for the
    // no-keys case, quoted-string otherwise.
    let key = if key.trim().is_empty() {
        String::new()
    } else {
        format!("\"{}\"", key.trim())
    };
    Some(MacosHostEvent::AggUpdate {
        kind,
        name: name.to_string(),
        key,
        value,
    })
}

/// Synthesize a payload that decodes through `print_merged_record`
/// exactly like a guest-emitted `trace(value)` record.  The
/// orchestrator's renderer reads a 24-byte sub-header followed by a
/// little-endian u64 trace value, so we lay both out here.
pub fn synth_trace_payload(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    // vmid (u32) — 0 for macos-host (no VM id).
    out.extend_from_slice(&0u32.to_le_bytes());
    // probe_id (u32) — synthetic id for macos-host trace().
    out.extend_from_slice(&1u32.to_le_bytes());
    // gns (u64) — the renderer prints this; current_host_ns is
    // already stamped by the merger, so leave this zero.
    out.extend_from_slice(&0u64.to_le_bytes());
    // word3 reserved.
    out.extend_from_slice(&0u64.to_le_bytes());
    // trace value (u64 LE).
    out.extend_from_slice(&value.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(input: &[u8]) -> Vec<MacosHostEvent> {
        let (tx, rx) = channel::<MacosHostEvent>();
        run_reader_loop(input, tx);
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn tokenizer_splits_concatenated_trace_values_on_whitespace() {
        // The literal output `dtrace -q -n 'profile { trace(x); }'`
        // generates: every fire's value is appended directly to
        // stdout with no separator.  Whitespace (when present) ends
        // a token; the agg-marker line ends the stream.
        let events = drive(b"  12345  6789\n42 17");
        let values: Vec<u64> = events
            .iter()
            .filter_map(|e| {
                if let MacosHostEvent::PerFire { value } = e {
                    Some(*value)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(values, vec![12345, 6789, 42, 17]);
    }

    #[test]
    fn tokenizer_decodes_marker_line_with_kind_name_key_value() {
        let input = b"\x01bf-mhx\x01count\x01triplet\x01all\x0117\n";
        let events = drive(input);
        assert_eq!(events.len(), 1);
        match &events[0] {
            MacosHostEvent::AggUpdate {
                kind,
                name,
                key,
                value,
            } => {
                assert_eq!(*kind, CrossTargetAggKind::Count);
                assert_eq!(name, "triplet");
                assert_eq!(key, "\"all\"");
                assert_eq!(*value, 17);
            }
            other => panic!("expected AggUpdate, got {other:?}"),
        }
    }

    #[test]
    fn tokenizer_handles_concatenated_trace_followed_by_marker() {
        // The real wire shape: trace() fires concatenated, then the
        // END clause emits one marker-bounded printa row.  Both
        // shapes must decode from the same byte stream — the
        // marker's leading \x01 ends any pending digit token.
        let input =
            b"100200300\x01bf-mhx\x01count\x01triplet\x01all\x015\n";
        let events = drive(input);
        // The concatenated digits 100200300 parse as one giant
        // integer because there's no separator between fires —
        // that's a faithful decode of what dtrace emits.  Real
        // user demos use printf("%d\n", x) when they want
        // per-fire separation, or rely on the agg row for the
        // aggregate.
        let per_fire: Vec<&MacosHostEvent> = events
            .iter()
            .filter(|e| matches!(e, MacosHostEvent::PerFire { .. }))
            .collect();
        let agg: Vec<&MacosHostEvent> = events
            .iter()
            .filter(|e| matches!(e, MacosHostEvent::AggUpdate { .. }))
            .collect();
        assert_eq!(per_fire.len(), 1, "got events: {events:?}");
        assert_eq!(agg.len(), 1, "got events: {events:?}");
        if let MacosHostEvent::PerFire { value } = per_fire[0] {
            assert_eq!(*value, 100200300);
        }
    }

    #[test]
    fn tokenizer_drops_unknown_marker_tag() {
        // A marker that doesn't start with "bf-mhx" is some other
        // printa() the user added — skip rather than misdecode.
        let input = b"\x01custom\x01stuff\x015\n";
        let events = drive(input);
        assert!(events.is_empty(), "got events: {events:?}");
    }

    #[test]
    fn synth_trace_payload_lays_out_24_byte_subheader_plus_u64() {
        let p = synth_trace_payload(0xdead_beef);
        assert_eq!(p.len(), 32);
        let v = u64::from_le_bytes(p[24..32].try_into().unwrap());
        assert_eq!(v, 0xdead_beef);
    }
}
