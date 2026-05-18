// BFR7 wrapper construction.
//
// The host CLI compiles each clause of the user's D source into an
// eBPF program, then packs the programs into the BFR7 wire format
// described below. Attach-mode decodes this format locally in the
// CLI, repacks it into guest-ready opaque LOAD_PROG payloads, and
// sends those through libkrun. The VMM no longer parses BFR7.
//
// Two callers in the binary use this module:
//   - attach-mode: build_wrapper_bytes(...) -> direct_load.rs ->
//     opaque LOAD_PROG payloads through the libkrun control SHM cmd ring
//   - --emit-ebpf: write_wrapper(...) → write to disk for offline
//     inspection

use crate::schema::RecordSchema;
use bifrost_wire::codec::{
    FieldRelocInput, MapSpec, ProgramSpec, TrailerSpec, WireError, WrapperBuilder,
};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

/// Errors `build_wrapper_bytes` and `write_wrapper` can return.
/// Oxide-style: typed enum at the module boundary, hosted in the
/// library; the binary entry point composes via `anyhow::Context`.
#[derive(Debug, Error)]
pub enum WrapperError {
    #[error("schema encode: {0}")]
    SchemaEncode(String),

    #[error("internal: {variant} uprobe requires UprobeTarget")]
    MissingUprobeTarget {
        /// "host-resolved" or "kernel-resolved" — names the
        /// trailer-shape branch in the BFR7 wrapper.
        variant: &'static str,
    },

    #[error("uprobe binary path too long ({len} bytes, max 256): {path}")]
    UprobePathTooLong { len: usize, path: String },

    #[error("uprobe basename length {0} out of range (1..=64)")]
    UprobeBasenameOutOfRange(usize),

    #[error("uprobe symbol length {0} out of range (1..=256)")]
    UprobeSymbolOutOfRange(usize),

    #[error("kfunc name length {len} out of range (1..=255): {name:?}")]
    KfuncNameOutOfRange { len: usize, name: String },

    #[error("write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Codec layer surfaced an error during encode (typically a
    /// length-cap violation that local validation didn't catch
    /// first).  Carried so the diagnostic message preserves the
    /// codec's `WireError` variant.
    #[error("wire codec: {0:?}")]
    Codec(WireError),
}

impl From<WireError> for WrapperError {
    fn from(e: WireError) -> Self {
        // Translate WireError variants into the wrapper-level
        // typed errors where they have a one-to-one mapping;
        // anything else falls through to Codec(..) so the diagnostic
        // surface stays specific.
        match e {
            WireError::PathTooLong { len } => WrapperError::UprobePathTooLong {
                len: len as usize,
                path: String::new(),
            },
            WireError::BasenameOutOfRange { len } => {
                WrapperError::UprobeBasenameOutOfRange(len as usize)
            }
            WireError::SymbolOutOfRange { len } | WireError::ProbeOutOfRange { len } => {
                WrapperError::UprobeSymbolOutOfRange(len as usize)
            }
            WireError::ProviderOutOfRange { len } => {
                WrapperError::UprobeBasenameOutOfRange(len as usize)
            }
            WireError::KfuncNameOutOfRange { len } => WrapperError::KfuncNameOutOfRange {
                len,
                name: String::new(),
            },
            other => WrapperError::Codec(other),
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, WrapperError>;

// Compose into the project's still-prevalent `Result<T, String>`
// dialect.  Callers that haven't yet migrated to thiserror/anyhow
// can still propagate WrapperError through `?` without losing the
// rendered message.  This impl is the bridge during the gradual
// migration; once all callers move to anyhow::Result it can be
// removed.
impl From<WrapperError> for String {
    fn from(err: WrapperError) -> String {
        err.to_string()
    }
}

/// One eBPF map declaration carried in a BFR7 wrapper. The 20
/// numeric bytes mirror the MapDef wire layout the guest module
/// understands; the trailing `name` is host-side metadata (libkrun
/// strips it before building the LOAD_PROG payload). For agg maps
/// `name` is the source-level `@<name>` (e.g. `by_pid`); for
/// ringbuf maps and anonymous aggs it's empty.
#[derive(Debug, Clone)]
pub struct MapDecl {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub fake_fd: i32,
    pub name: String,
}

/// Owning per-program BTF field-reloc record.  Mirrors the
/// `bifrost_wire::codec::FieldRelocInput` borrowed shape but holds
/// the `struct_name` / `field_name` strings inline so a Vec of
/// these can be stashed alongside the lowered eBPF until wrapper
/// assembly time without lifetime gymnastics.
///
/// `insn_idx` is a *byte offset* into the program's eBPF stream
/// (not a slot index — libkrun's patcher does
/// `insns[insn_idx + byte_off..+4] = resolved`).  `byte_off_in_insn`
/// is the byte position within the targeted 8-byte instruction
/// where the patched u32 lands; for `bpf_ld_imm64`'s low slot the
/// `imm` field starts at byte 4.
#[derive(Debug, Clone)]
pub struct OwnedFieldReloc {
    pub insn_idx: u32,
    pub access_kind: u8,
    pub byte_off_in_insn: u8,
    pub struct_name: String,
    pub field_name: String,
}

/// Wrapper format BFR7: kfunc references are emitted symbolically
/// as a per-program reloc table (insn index → kfunc name); the
/// guest worker resolves each name against the running kernel's
/// vmlinux BTF at LOAD_PROG time and patches `insn[idx].imm` with
/// the locally-resolved BTF id. This eliminates the BTF-staleness
/// bug class that BFR6's compile-time fingerprint check was
/// defending against (the host CLI no longer needs to read
/// vmlinux BTF for kfunc resolution at all).
///
/// Each program carries a 4-byte `flags` field right after the
/// 32-byte target_name. Low byte = probe_type:
///   0 = kprobe entry         (retired by patch 0040)
///   1 = kretprobe return     (retired by patch 0040)
///   2 = uprobe entry         (host-resolved: path + offset)
///   3 = uretprobe return     (host-resolved)
///   4 = uprobe entry         (kernel-resolved: basename + symbol)
///   5 = uretprobe return     (kernel-resolved)
///
/// Uprobe trailers depend on probe_type:
///   2/3:  [u32 path_len][u8;path_len path][u64 file_offset]
///   4/5:  [u32 bn_len][u8;bn_len basename][u32 sym_len][u8;sym_len symbol]
///   9   : [u32 bn_len][u8;bn_len basename]
///         [u32 prov_len][u8;prov_len sdt_provider]
///         [u32 probe_len][u8;probe_len sdt_probe]
///         (USDT — kernel-resolved.  Driver grabs task->exe_file,
///         walks `.note.stapsdt`, finds (sdt_provider, sdt_probe),
///         and registers a uprobe at the recorded pc + ref_ctr_offset.
///         No host-side rootfs mirror needed.)
/// Kprobe wrappers (0/1) emit no trailer.
///
///   [u32]    magic = b"BFR7"
///   [u32]    num_progs (LE)
///   for each program:
///     [u8;32]  target_name (NUL-padded symbol — kprobe sym OR
///                          uprobe function name within the binary)
///     [u32]    flags (LE; low byte=probe_type, rest reserved)
///     <uprobe trailer per table above, if applicable>
///     [u32]    schema_len (LE)
///     [u8;schema_len]  encoded RecordSchema
///     [u32]    num_maps (LE)
///     for each map:
///       [u32 type][u32 key_size][u32 value_size]
///       [u32 max_entries][i32 fake_fd][u8;32 name]   (52 bytes)
///     [u32]    num_insns (LE)
///     [u8; 8*num_insns]  raw eBPF instructions
///     [u32]    num_kfunc_relocs (LE)
///     for each reloc:
///       [u32 insn_idx][u8 name_len][u8;name_len name]
///
/// Build the BFR7 wrapper bytes in memory. Used by attach-mode as a
/// CLI-local intermediate for opaque LOAD_PROG payload construction and
/// by `--emit-ebpf` for offline inspection.
///
/// Per-program tuple shape (8 fields):
///   `(target_name, schema, maps, ebpf_bytes, probe_type,
///     uprobe_target, kfunc_relocs, field_relocs)`
///
/// `field_relocs` is the BTF field-reloc table the guest LOAD_PROG
/// patcher walks — populated by the CLI's CO-RE-aware
/// `CORE_OFFSETOF(...)` lowering path
/// (`source_rewrite::materialize_field_relocs`).  Empty vec ⇒ no
/// `PROGRAM_FLAG_FIELD_RELOCS_PRESENT` bit on the program header,
/// preserving wire shape for programs that don't need patching.
pub fn build_wrapper_bytes(
    programs: &[(
        String,
        RecordSchema,
        Vec<MapDecl>,
        Vec<u8>,
        u8,
        Option<crate::elf_syms::UprobeTarget>,
        Vec<(u32, String)>,
        Vec<OwnedFieldReloc>,
        Option<u64>,
    )],
) -> Result<Vec<u8>> {
    // Encode each program's schema once into an owned buffer; the
    // codec borrows from these.  Collected up front to keep
    // borrow-region lifetimes simple.
    let mut schema_bufs: Vec<Vec<u8>> = Vec::with_capacity(programs.len());
    for (_, schema, _, _, _, _, _, _, _) in programs {
        let mut buf = Vec::new();
        schema
            .encode(&mut buf)
            .map_err(|e| WrapperError::SchemaEncode(e.to_string()))?;
        schema_bufs.push(buf);
    }

    // Build the per-program codec inputs.  The codec validates
    // length caps; we layer typed `MissingUprobeTarget` errors here
    // because that's wrapper-policy (the caller forgot to attach
    // the resolved target), not a wire-format failure.
    let mut wrapped: Vec<u8> = Vec::new();
    let mut builder = WrapperBuilder::new(&mut wrapped, programs.len() as u32)?;
    for (
        i,
        (target, _, maps, ebpf, probe_type, uprobe, kfunc_relocs, field_relocs, profile_period_ns),
    ) in programs.iter().enumerate()
    {
        let trailer = match *probe_type {
            2 | 3 => {
                let u = uprobe.as_ref().ok_or(WrapperError::MissingUprobeTarget {
                    variant: "host-resolved",
                })?;
                TrailerSpec::Path {
                    path: &u.guest_path,
                    file_offset: u.file_offset,
                }
            }
            4 | 5 => {
                let u = uprobe.as_ref().ok_or(WrapperError::MissingUprobeTarget {
                    variant: "kernel-resolved",
                })?;
                TrailerSpec::Symbol {
                    basename: &u.basename,
                    symbol: &u.symbol,
                }
            }
            9 => {
                let u = uprobe
                    .as_ref()
                    .ok_or(WrapperError::MissingUprobeTarget { variant: "USDT" })?;
                TrailerSpec::Usdt {
                    basename: &u.basename,
                    provider: &u.sdt_provider,
                    probe: &u.symbol,
                }
            }
            10 => TrailerSpec::ProfileTimer {
                period_ns: profile_period_ns.unwrap_or_else(|| {
                    // Linker contract: the lowering path must have
                    // attached period_ns when probe_type=10.  A 0
                    // here means a programmer-side bug; surface
                    // loudly via a synthetic 1s tick.
                    1_000_000_000
                }),
            },
            _ => TrailerSpec::None,
        };

        let map_specs: Vec<MapSpec<'_>> = maps
            .iter()
            .map(|m| MapSpec {
                map_type: m.map_type,
                key_size: m.key_size,
                value_size: m.value_size,
                max_entries: m.max_entries,
                fake_fd: m.fake_fd,
                name: &m.name,
            })
            .collect();

        let kfunc_specs: Vec<(u32, &str)> = kfunc_relocs
            .iter()
            .map(|(idx, name)| (*idx, name.as_str()))
            .collect();

        // Field relocations — borrowed FieldRelocInput records.
        // Sourced from the CLI's CO-RE lowering (CORE_OFFSETOF).
        // Empty vec ⇒ wrapper-level wire shape unchanged.  Non-empty
        // ⇒ codec sets PROGRAM_FLAG_FIELD_RELOCS_PRESENT and appends
        // the standalone-encoded field-reloc section after kfunc_relocs.
        let field_reloc_specs: Vec<FieldRelocInput<'_>> = field_relocs
            .iter()
            .map(|r| FieldRelocInput {
                insn_idx: r.insn_idx,
                access_kind: r.access_kind,
                byte_off_in_insn: r.byte_off_in_insn,
                struct_name: r.struct_name.as_str(),
                field_name: r.field_name.as_str(),
            })
            .collect();

        builder.push_program(&ProgramSpec {
            target_name: target,
            probe_type: *probe_type,
            trailer,
            schema_bytes: &schema_bufs[i],
            maps: &map_specs,
            insns: ebpf,
            kfunc_relocs: &kfunc_specs,
            field_relocs: &field_reloc_specs,
        })?;
    }
    drop(builder);
    Ok(wrapped)
}

pub fn write_wrapper(
    path: &PathBuf,
    programs: &[(
        String,
        RecordSchema,
        Vec<MapDecl>,
        Vec<u8>,
        u8,
        Option<crate::elf_syms::UprobeTarget>,
        Vec<(u32, String)>,
        Vec<OwnedFieldReloc>,
        Option<u64>,
    )],
) -> Result<()> {
    let wrapped = build_wrapper_bytes(programs)?;
    fs::write(path, &wrapped).map_err(|source| WrapperError::WriteFile {
        path: path.clone(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_wrapper_has_magic_and_zero_count() {
        let w = build_wrapper_bytes(&[]).unwrap();
        assert_eq!(&w[..4], b"BFR7");
        assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn kprobe_wrapper_round_trips_target_name() {
        let target = "do_sys_openat2".to_string();
        let schema = RecordSchema::default();
        let progs = vec![(
            target.clone(),
            schema,
            Vec::<MapDecl>::new(),
            Vec::<u8>::new(),
            0u8, // kprobe entry
            None,
            Vec::<(u32, String)>::new(),
            Vec::<OwnedFieldReloc>::new(),
            None,
        )];
        let w = build_wrapper_bytes(&progs).unwrap();
        // Target name at offset 8 (after magic + num_progs), 32-byte field.
        let name_field = &w[8..40];
        let nul = name_field.iter().position(|&b| b == 0).unwrap_or(32);
        assert_eq!(&name_field[..nul], target.as_bytes());
    }

    #[test]
    fn rejects_oversize_kfunc_name() {
        let schema = RecordSchema::default();
        let big_name = "x".repeat(300);
        let progs = vec![(
            "t".to_string(),
            schema,
            Vec::<MapDecl>::new(),
            Vec::<u8>::new(),
            0u8,
            None,
            vec![(0u32, big_name)],
            Vec::<OwnedFieldReloc>::new(),
            None,
        )];
        let err = build_wrapper_bytes(&progs).unwrap_err();
        match err {
            WrapperError::KfuncNameOutOfRange { len, .. } => assert_eq!(len, 300),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn field_relocs_set_present_flag_and_round_trip() {
        // End-to-end: a non-empty field-reloc list flips
        // PROGRAM_FLAG_FIELD_RELOCS_PRESENT in the program header
        // and appends the standalone-encoded section after the
        // kfunc-relocs table.  Decoding via the wire codec yields
        // back the same (struct, field, kind, byte_off) tuple.
        use bifrost_wire::codec::{decode_bfr7, decode_field_relocs};
        use bifrost_wire::{FIELD_RELOC_OFFSET, PROGRAM_FLAG_FIELD_RELOCS_PRESENT};

        let target = "do_sys_openat2".to_string();
        let schema = RecordSchema::default();
        // 16 bytes of dummy eBPF (one bpf_ld_imm64 — two 8-byte
        // slots).  Reloc points at byte 0 of the program body,
        // byte_off=4 (the `imm` field of slot 0).  Patcher writes
        // the resolved offset into bytes 4..8 at LOAD_PROG time.
        let ebpf: Vec<u8> = vec![0u8; 16];
        let relocs = vec![OwnedFieldReloc {
            insn_idx: 0,
            access_kind: FIELD_RELOC_OFFSET,
            byte_off_in_insn: 4,
            struct_name: "task_struct".into(),
            field_name: "comm".into(),
        }];
        let progs = vec![(
            target.clone(),
            schema,
            Vec::<MapDecl>::new(),
            ebpf,
            0u8,
            None,
            Vec::<(u32, String)>::new(),
            relocs,
            None,
        )];
        let w = build_wrapper_bytes(&progs).unwrap();

        // Walk via decode_bfr7 to validate the flag bit + decoded
        // field_relocs section round-trip.  The 32-byte
        // target_name is followed by the 4-byte flags field; the
        // FIELD_RELOCS bit must be set.
        let mut iter = decode_bfr7(&w).expect("decode_bfr7");
        let prog = iter.next().expect("one program").expect("decode ok");
        assert!(
            (prog.flags & PROGRAM_FLAG_FIELD_RELOCS_PRESENT) != 0,
            "expected FIELD_RELOCS_PRESENT flag set; flags={:#x}",
            prog.flags
        );
        let mut decoded = decode_field_relocs(prog.field_relocs_bytes).expect("decode");
        let view = decoded.next().expect("one reloc").expect("ok");
        assert_eq!(view.insn_idx, 0);
        assert_eq!(view.access_kind, FIELD_RELOC_OFFSET);
        assert_eq!(view.byte_off_in_insn, 4);
        assert_eq!(view.struct_name, b"task_struct");
        assert_eq!(view.field_name, b"comm");
        assert!(decoded.next().is_none(), "exactly one reloc");
    }
}
