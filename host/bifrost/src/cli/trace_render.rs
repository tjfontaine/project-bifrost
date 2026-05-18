// Direct data-SHM and self-trace rendering helpers for attach-mode.

#![cfg(target_os = "macos")]

use crate::cli::direct_symbols::DirectSymbolState;
use crate::cli::wrapper::MapDecl;
use crate::cli::xagg::{CrossAggValue, try_parse_xagg_line};
use crate::schema::{FieldKind, RecordSchema};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

pub(crate) fn render_direct_schema_record(
    schema: &RecordSchema,
    bytes: &[u8],
    symbols: &mut DirectSymbolState,
) -> String {
    let mut out = String::new();
    let mut off = 0usize;
    let mut gpid = None;
    for field in &schema.fields {
        if !out.is_empty() {
            out.push(' ');
        }
        let size = field.kind.record_size();
        let slice = bytes.get(off..off + size);
        match (slice, &field.kind) {
            (Some(s), FieldKind::U8) => {
                out.push_str(&format!("{}={}", field.name, s[0]));
            }
            (Some(s), FieldKind::U16) => {
                out.push_str(&format!(
                    "{}={}",
                    field.name,
                    u16::from_le_bytes([s[0], s[1]])
                ));
            }
            (Some(s), FieldKind::U32) => {
                out.push_str(&format!(
                    "{}={}",
                    field.name,
                    u32::from_le_bytes([s[0], s[1], s[2], s[3]])
                ));
            }
            (Some(s), FieldKind::U64) => {
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                let v = u64::from_le_bytes(a);
                if field.name == "gpid" {
                    gpid = Some(v);
                    out.push_str(&format!("{}={}", field.name, (v >> 32) as u32));
                } else {
                    out.push_str(&format!("{}=0x{:x}", field.name, v));
                }
            }
            (Some(s), FieldKind::I64) => {
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                out.push_str(&format!("{}={}", field.name, i64::from_le_bytes(a)));
            }
            (Some(s), FieldKind::String { .. }) => {
                let nul = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                out.push_str(&format!(
                    "{}={}",
                    field.name,
                    String::from_utf8_lossy(&s[..nul])
                ));
            }
            (Some(s), FieldKind::Bytes { .. }) => {
                // libdtrace-style hex/ASCII dump for raw byte
                // blobs (tracemem output). Multi-line:
                //
                //   <name>=
                //     0000: 7f 45 4c 46 02 01 01 00 ... |.ELF........|
                //     0010: 02 00 b7 00 01 00 00 00 ... |............|
                out.push_str(&field.name);
                out.push('=');
                out.push_str(&render_bytes_dump(s));
            }
            (Some(s), FieldKind::KernelStack { max_depth })
            | (Some(s), FieldKind::UserStack { max_depth }) => {
                let mut frames = Vec::new();
                let is_user_stack = matches!(field.kind, FieldKind::UserStack { .. });
                for chunk in s.chunks_exact(8).take(*max_depth as usize) {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(chunk);
                    let pc = u64::from_le_bytes(a);
                    if pc == 0 {
                        break;
                    }
                    let frame = if is_user_stack {
                        gpid.map(|gpid| symbols.render_user_pc(gpid, pc))
                            .unwrap_or_else(|| format!("0x{:x}", pc))
                    } else {
                        symbols.render_kernel_pc(pc)
                    };
                    frames.push(frame);
                }
                out.push_str(&format!("{}=[{}]", field.name, frames.join(",")));
            }
            (Some(s), FieldKind::GuestPtr { .. }) => {
                out.push_str(&format!(
                    "{}=0x{:08x}",
                    field.name,
                    u32::from_le_bytes([s[0], s[1], s[2], s[3]])
                ));
            }
            (None, _) => {
                out.push_str(&format!("{}=<truncated>", field.name));
            }
        }
        off += size;
    }
    out
}

pub(crate) fn direct_agg_names(
    programs: &[(
        String,
        RecordSchema,
        Vec<MapDecl>,
        Vec<u8>,
        u8,
        Option<crate::elf_syms::UprobeTarget>,
        Vec<(u32, String)>,
        Vec<crate::cli::wrapper::OwnedFieldReloc>,
        Option<u64>,
    )],
) -> HashMap<i32, (String, String)> {
    let mut out = HashMap::new();
    for (_, _, maps, _, _, _, _, _, _) in programs {
        for map in maps {
            if map.name.is_empty() {
                continue;
            }
            let split = map.name.find('\0').unwrap_or(map.name.len());
            let kind = map.name[..split].to_string();
            let name = if split + 1 < map.name.len() {
                map.name[split + 1..].to_string()
            } else {
                String::new()
            };
            out.insert(map.fake_fd, (kind, name));
        }
    }
    out
}

fn direct_agg_key(kb: &[u8]) -> String {
    kb.chunks(8)
        .map(|c| {
            let mut buf = [0u8; 8];
            buf[..c.len()].copy_from_slice(c);
            let trimmed: &[u8] = {
                let mut end = buf.len();
                while end > 0 && buf[end - 1] == 0 {
                    end -= 1;
                }
                &buf[..end]
            };
            let looks_ascii =
                !trimmed.is_empty() && trimmed.iter().all(|&b| (0x20..=0x7e).contains(&b));
            if looks_ascii {
                format!("\"{}\"", String::from_utf8_lossy(trimmed))
            } else {
                u64::from_le_bytes(buf).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn ingest_direct_agg_snapshot(
    payload: &[u8],
    agg_names: &HashMap<i32, (String, String)>,
    agg_last: &mut HashMap<(i32, u64), u64>,
    xagg_state: &Arc<std::sync::Mutex<HashMap<(String, String), CrossAggValue>>>,
) -> bool {
    if payload.len() < 28 {
        return false;
    }
    let n = u32::from_le_bytes(payload[24..28].try_into().unwrap()) as usize;
    let mut groups: BTreeMap<i32, Vec<(Vec<u8>, Vec<u8>)>> = BTreeMap::new();
    let mut changed_fds: HashSet<i32> = HashSet::new();
    const MAX_KEY_BYTES: usize = 32;
    const MAX_VAL_BYTES: usize = 32;
    let mut p = 28usize;
    let mut parsed = 0usize;
    // Per-row entries carry a u32 v_size after the key so STDDEV
    // rows can ship 24-byte (n, sum, sum_sq) triples alongside the
    // 8-byte sum / min / max / avg shapes.
    //   i32 fd
    //   u32 k_size
    //   u8;k_size key
    //   u32 v_size
    //   u8;v_size value
    while parsed < n {
        if payload.len() < p + 8 {
            break;
        }
        let fd = i32::from_le_bytes(payload[p..p + 4].try_into().unwrap());
        let k_size = u32::from_le_bytes(payload[p + 4..p + 8].try_into().unwrap()) as usize;
        if k_size > MAX_KEY_BYTES {
            break;
        }
        let v_size_off = p + 8 + k_size;
        if payload.len() < v_size_off + 4 {
            break;
        }
        let v_size =
            u32::from_le_bytes(payload[v_size_off..v_size_off + 4].try_into().unwrap()) as usize;
        if v_size == 0 || v_size > MAX_VAL_BYTES {
            break;
        }
        let entry_bytes = 4 + 4 + k_size + 4 + v_size;
        if payload.len() < p + entry_bytes {
            break;
        }
        let k_bytes = payload[p + 8..p + 8 + k_size].to_vec();
        let v_bytes = payload[v_size_off + 4..v_size_off + 4 + v_size].to_vec();
        // dedup key: xor-fold both the key and the value's first
        // u64 (covers STDDEV's `n` slot; changes-on-update for
        // any shape because at least one of the triple changes
        // whenever the BPF prog fires).
        let dedup_k: u64 = k_bytes
            .chunks(8)
            .map(|c| {
                let mut buf = [0u8; 8];
                buf[..c.len()].copy_from_slice(c);
                u64::from_le_bytes(buf)
            })
            .fold(0u64, |a, b| a ^ b);
        let v_head = {
            let mut buf = [0u8; 8];
            let take = v_bytes.len().min(8);
            buf[..take].copy_from_slice(&v_bytes[..take]);
            u64::from_le_bytes(buf)
        };
        let prev = *agg_last.get(&(fd, dedup_k)).unwrap_or(&0);
        if v_head != prev {
            changed_fds.insert(fd);
            agg_last.insert((fd, dedup_k), v_head);
        }
        groups.entry(fd).or_default().push((k_bytes, v_bytes));
        p += entry_bytes;
        parsed += 1;
    }

    let mut changed = false;
    for (fd, mut rows) in groups {
        if !changed_fds.contains(&fd) {
            continue;
        }
        let (kind, name) = agg_names.get(&fd).cloned().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        // Filter empty rows: for 8-byte values an all-zero value
        // is "no data"; for STDDEV's 24-byte triple the leading
        // u64 (n) being zero means the same.
        rows.retain(|(_, v)| !v.iter().all(|&b| b == 0));
        for (kb, v) in &rows {
            // lquantize / llquantize share the quantize
            // map shape and renderer entry point; route them
            // through the quantize tag so they land in
            // `quantize_state`.  `dump_quantize_state` picks the
            // right bucket-label formatter via
            // `lquantize_params_for` / `llquantize_params_for`.
            let tag = if kind == "quantize" || kind == "lquantize" || kind == "llquantize" {
                "##xagg-guest-quantize##"
            } else if kind == "stddev" {
                "##xagg-guest-stddev##"
            } else {
                "##xagg-guest##"
            };
            // Render the value field per agg shape.  STDDEV's
            // 24-byte triple decodes to a single rendered u64
            // (the computed stddev) so the existing xagg
            // pipeline can keep treating values as scalar; the
            // ##xagg-guest-stddev## tag lets the xagg renderer
            // label the line appropriately if it wants to.
            let v_rendered: u64 = if kind == "stddev" && v.len() >= 24 {
                let n = u64::from_le_bytes(v[0..8].try_into().unwrap());
                let sum = u64::from_le_bytes(v[8..16].try_into().unwrap());
                let sum_sq = u64::from_le_bytes(v[16..24].try_into().unwrap());
                stddev_from_triple(n, sum, sum_sq)
            } else {
                let mut buf = [0u8; 8];
                let take = v.len().min(8);
                buf[..take].copy_from_slice(&v[..take]);
                u64::from_le_bytes(buf)
            };
            let marker = format!("{}|{}|{}|{}", tag, name, direct_agg_key(kb), v_rendered);
            changed |= try_parse_xagg_line(&marker, xagg_state);
        }
    }
    changed
}

/// Render a byte slice as a libdtrace-style hex/ASCII dump.
/// Sixteen bytes per row, two-space groups of four; left column
/// is the byte offset, right column the printable-ASCII gutter.
/// Newline prefix so a record-line reads as `<name>=<dump>`.
fn render_bytes_dump(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for (row_idx, row) in bytes.chunks(16).enumerate() {
        out.push('\n');
        out.push_str(&format!("  {:04x}:", row_idx * 16));
        for (i, b) in row.iter().enumerate() {
            if i == 8 {
                out.push(' ');
            }
            out.push_str(&format!(" {:02x}", b));
        }
        // Pad if the final row is shorter than 16 bytes so the
        // ASCII gutter lines up.
        for i in row.len()..16 {
            if i == 8 {
                out.push(' ');
            }
            out.push_str("   ");
        }
        out.push_str("  |");
        for b in row {
            out.push(if (0x20..=0x7e).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        out.push('|');
    }
    out
}

/// Compute the integer-rounded population stddev from a
/// (n, sum, sum_of_squares) triple. Returns 0 when n < 2 (one
/// sample has no variance) — matches DTrace's display behavior
/// for single-sample stddev aggregations.
fn stddev_from_triple(n: u64, sum: u64, sum_sq: u64) -> u64 {
    if n < 2 {
        return 0;
    }
    // Variance = (n * sum_sq - sum²) / (n * (n - 1))
    // Use f64 to avoid intermediate overflow on the multiply;
    // single-precision is plenty for the int rounding we apply.
    let n_f = n as f64;
    let sum_f = sum as f64;
    let sum_sq_f = sum_sq as f64;
    let variance = (n_f * sum_sq_f - sum_f * sum_f) / (n_f * (n_f - 1.0));
    if variance < 0.0 {
        return 0;
    }
    variance.sqrt().round() as u64
}

/// Render one self-trace payload (`[u32 layer_probe_id LE]
/// [encode_event body]`) to stderr if `event.level >= floor`.
/// Module-level so both the rsp-ring decoder (libkrun-emitted
/// events) and the CLI's own state-transition emit closure
/// (`cli_self_trace` inside run_attach_trace) call into a single
/// renderer — same `[layer/subsys/level] msg {key=val,…}` format
/// across all three layers.
pub(crate) fn render_self_trace_payload_to_stderr(payload: &[u8], floor: u8) {
    if payload.len() < 4 {
        return;
    }
    let layer_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let layer_label = match layer_id {
        bifrost_wire::SELF_TRACE_DRIVER_PROBE_ID => "driver",
        bifrost_wire::SELF_TRACE_LIBKRUN_PROBE_ID => "libkrun",
        bifrost_wire::SELF_TRACE_CLI_PROBE_ID => "cli",
        _ => "unknown",
    };
    let body = &payload[4..];
    let event = match bifrost_wire::codec::decode_event(body) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "bifrost: malformed self-trace event from layer {}: {:?}",
                layer_label, e
            );
            return;
        }
    };
    if event.level < floor {
        return;
    }
    let level_label = bifrost_wire::codec::self_level_label(event.level);
    let subsys_label = bifrost_wire::codec::self_subsystem_label(event.subsystem);
    let msg = std::str::from_utf8(event.msg).unwrap_or("<non-utf8>");
    let mut line = format!("[{}/{}/{}] {}", layer_label, subsys_label, level_label, msg);
    let mut first = true;
    for f in event.fields() {
        let f = match f {
            Ok(v) => v,
            Err(_) => break,
        };
        if first {
            line.push_str(" {");
            first = false;
        } else {
            line.push_str(", ");
        }
        let key = std::str::from_utf8(f.key).unwrap_or("?");
        line.push_str(key);
        line.push('=');
        match f.value {
            bifrost_wire::codec::SelfFieldValue::U64(v) => line.push_str(&v.to_string()),
            bifrost_wire::codec::SelfFieldValue::I64(v) => line.push_str(&v.to_string()),
            bifrost_wire::codec::SelfFieldValue::Bool(v) => {
                line.push_str(if v { "true" } else { "false" });
            }
            bifrost_wire::codec::SelfFieldValue::Bytes(b) => {
                if let Ok(s) = std::str::from_utf8(b) {
                    line.push('"');
                    line.push_str(s);
                    line.push('"');
                } else {
                    line.push_str(&format!("{:?}", b));
                }
            }
        }
    }
    if !first {
        line.push('}');
    }
    eprintln!("{}", line);
}
