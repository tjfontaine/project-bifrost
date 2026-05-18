// BFR7 wrapper codec — single source of truth for encode/decode.
//
// Until this module landed, the encode side lived in
// `host/bifrost/src/cli/wrapper.rs::build_wrapper_bytes` and the
// decode side lived in
// `third_party/smolvm/libkrun/src/devices/src/virtio/bifrost/
// payload.rs::parse_wrapper_with_btf` — two independent
// implementations of one byte format, with the wrapper_golden.rs
// expectorate fixtures as the only thing keeping them in lockstep.
//
// This module replaces both: the encoder is a sink-driven builder
// (`WrapperBuilder`), the decoder is a streaming view iterator
// (`decode_bfr7` → `ProgramIter` → `ProgramView<'_>`).  Both share
// the same `WireError` and the same byte-level layout — so any
// change to the wire format is one edit, not three coordinated ones.
//
// `#![no_std]`-safe: the decoder returns slice views into the input
// buffer, no allocations.  The encoder is generic over a `WireSink`
// trait; the host crate provides a default impl for `Vec<u8>` behind
// the `alloc` feature.  Kernel-side decode (when we get there) needs
// no allocator at all.

use crate::typed::{BifrostProgramHeader, BifrostWrapperHeader, IntoWireBytes, ShmemRecordHeader};
use crate::*;

#[path = "codec_field_reloc.rs"]
mod field_reloc;
#[path = "codec_hello.rs"]
mod hello;
#[path = "codec_profile.rs"]
mod profile;
#[path = "codec_self_trace.rs"]
mod self_trace;

pub use field_reloc::*;
pub use hello::*;
pub use profile::*;
pub use self_trace::*;

// =====================================================================
// Errors
// =====================================================================

/// Wire-codec errors.  Plain enum — no `Display` impl in the core
/// crate so `#![no_std]` stays clean.  Host crates that want
/// `Display`/`std::error::Error` should add a thin `From` impl in
/// their own error type (see `host/bifrost/src/cli/wrapper.rs`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Buffer ran out before a length-prefixed field could be fully
    /// read.  `at` names the field for diagnostic context.
    Truncated {
        need: usize,
        have: usize,
        at: &'static str,
    },
    /// First four bytes weren't `b"BFR7"`.  Carries the actual bytes
    /// for diagnostic rendering.
    UnsupportedMagic([u8; 4]),
    /// Host-resolved uprobe path exceeded the 256-byte limit.
    PathTooLong { len: u32 },
    /// Basename empty or > 64 bytes.  Used for kernel-resolved
    /// uprobe-by-sym and USDT trailers.
    BasenameOutOfRange { len: u32 },
    /// Symbol empty or > 256 bytes.  Used for uprobe-by-sym trailer.
    SymbolOutOfRange { len: u32 },
    /// SDT provider empty or > 64 bytes.  USDT trailer.
    ProviderOutOfRange { len: u32 },
    /// SDT probe empty or > 256 bytes.  USDT trailer.
    ProbeOutOfRange { len: u32 },
    /// Kfunc reloc name empty or > 255 bytes.  Wire stores name_len
    /// as u8, so this is a hard cap.
    KfuncNameOutOfRange { len: usize },
    /// probe_type byte didn't decode to a known trailer shape.
    /// Currently 0/1 (retired kprobe/kretprobe), 2/3 (host-resolved
    /// uprobe), 4/5 (kernel-resolved uprobe), 6/7 (fbt), 8 (raw
    /// tracepoint), 9 (USDT) are recognized.
    BadProbeType { ty: u8 },
    /// Encoder rejected a value that exceeded its on-wire length cap
    /// (e.g. a per-program LOAD_PROG status detail string larger than
    /// the u16 length prefix can encode).
    TooLarge {
        limit: usize,
        got: usize,
        at: &'static str,
    },
}

// =====================================================================
// Decoder — borrowed views into the input buffer
// =====================================================================
//
// ## Iterator + borrow lifetime model
//
// Decode never allocates.  `decode_bfr7(&[u8])` validates the
// wrapper header and returns a `ProgramIter<'a>` whose lifetime
// `'a` is the input buffer's lifetime.  Each `ProgramIter::next()`
// yields a `ProgramView<'a>` containing slice references back into
// that same buffer (`target_name: &'a [u8; 32]`, `schema_bytes:
// &'a [u8]`, …).  The compiler guarantees the input outlives every
// view, so a record passes from on-the-wire bytes to the CLI
// renderer with zero allocation per record — important when the
// rate is in the hundreds of thousands of records per second.
//
// `TrailerView<'a>` is the same idea applied to the per-program
// trailer: `Path { path: &'a [u8], .. }`, `Symbol { basename: &'a
// [u8], symbol: &'a [u8] }`, `Usdt { .. }`.  Probe types that
// carry no trailer return `TrailerView::None`.
//
// Iteration is fail-stop: a parse error on program N sets
// `failed = true`, returns `Some(Err(..))`, and every subsequent
// `next()` returns `None`.  Callers that need to resume after a
// bad program must re-`decode_bfr7` with a different buffer; the
// iterator does not seek.

/// Per-program trailer view.  `None` for probe types that emit no
/// trailer (kprobe/kretprobe retired, fbt, tracepoint).
#[derive(Debug, Copy, Clone)]
pub enum TrailerView<'a> {
    /// No trailer — fbt (PROBE_TYPE_FENTRY/FEXIT), raw tracepoint
    /// (PROBE_TYPE_TRACEPOINT).  Caller must look up the probe-type
    /// to disambiguate.
    None,
    /// Host-resolved uprobe (PROBE_TYPE_UPROBE/URETPROBE).  Path is
    /// a guest-side filesystem path (e.g. `/usr/bin/redis-server`)
    /// that the host CLI resolved by mirroring the rootfs.
    Path { path: &'a [u8], file_offset: u64 },
    /// Kernel-resolved uprobe by symbol
    /// (PROBE_TYPE_UPROBE_BY_SYM/URETPROBE_BY_SYM).  Driver finds
    /// the running task by `comm == basename`, walks the ELF symtab.
    Symbol {
        basename: &'a [u8],
        symbol: &'a [u8],
    },
    /// USDT (PROBE_TYPE_USDT).  Same task lookup as Symbol; driver
    /// walks `.note.stapsdt` for the matching `(provider, probe)`
    /// entry, registers a uprobe at the recorded pc + ref_ctr_offset.
    Usdt {
        basename: &'a [u8],
        provider: &'a [u8],
        probe: &'a [u8],
    },
    /// Profile-timer (PROBE_TYPE_PROFILE_TIMER).  The trailer is a
    /// single u64 holding the perf_event sample period in
    /// nanoseconds; the guest module opens per-CPU
    /// `perf_event_create_kernel_counter` of type
    /// PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK with that
    /// `sample_period` and attaches the BPF program via
    /// `perf_event_ioctl(SET_BPF)`.
    ProfileTimer { period_ns: u64 },
}

/// One program from a BFR7 wrapper, viewed as borrowed slices into
/// the input buffer.  `'a` is the input buffer's lifetime.
#[derive(Debug)]
pub struct ProgramView<'a> {
    pub target_name: &'a [u8; 32],
    pub flags: u32,
    pub probe_type: u8,
    pub trailer: TrailerView<'a>,
    pub schema_bytes: &'a [u8],
    pub num_maps: u32,
    /// Concatenated map records, `num_maps × 52` bytes.  Each map
    /// is `[u32 type][u32 key_size][u32 value_size][u32
    /// max_entries][i32 fake_fd][u8;32 name]`.
    pub maps_bytes: &'a [u8],
    pub num_insns: u32,
    /// Raw eBPF bytes, `num_insns × 8`.
    pub insns: &'a [u8],
    /// Kfunc reloc table, **including** the leading `u32` count.
    /// Sliced verbatim so libkrun can ferry it into the LOAD_PROG
    /// payload without re-encoding.  Body: `[u32 num_relocs] [for
    /// each: u32 insn_idx, u8 name_len, u8;name_len name]`.
    pub kfunc_relocs_bytes: &'a [u8],
    /// Field-relocs payload (per the standalone
    /// `encode_field_relocs` layout, including the leading u32 count).
    /// Empty slice for programs that don't set
    /// `PROGRAM_FLAG_FIELD_RELOCS_PRESENT` in their flags.  libkrun's
    /// patcher walks `decode_field_relocs(field_relocs_bytes)` to
    /// resolve (struct, field) pairs against guest BTF at LOAD_PROG
    /// time and patch the eBPF stream in `insns`.
    pub field_relocs_bytes: &'a [u8],
}

/// Iterator over programs in a BFR7 wrapper.  Each `next()` advances
/// past one program; errors short-circuit the iteration (subsequent
/// `next()` calls return `None`).
#[derive(Debug)]
pub struct ProgramIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: u32,
    failed: bool,
}

impl<'a> ProgramIter<'a> {
    /// Current byte offset in the input.  Always 8 immediately after
    /// `decode_bfr7` returns (just past the wrapper header), and
    /// advances to one-past-end-of-program after each `next()`.
    /// Useful for legacy callers that frame their state in absolute
    /// offsets rather than program indices.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Number of programs not yet yielded.  Decrements with every
    /// successful `next()`.  Equals the declared `num_progs` when
    /// the iterator is fresh.
    pub fn remaining(&self) -> u32 {
        self.remaining
    }
}

impl<'a> Iterator for ProgramIter<'a> {
    type Item = Result<ProgramView<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining == 0 {
            return None;
        }
        match decode_one_program(self.bytes, self.cursor) {
            Ok((next_cursor, view)) => {
                self.cursor = next_cursor;
                self.remaining -= 1;
                Some(Ok(view))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

/// Validate the BFR7 header and return a streaming iterator over
/// the programs.  The iterator yields one `ProgramView<'a>` per
/// program; on a parse error mid-stream, the next call returns
/// `Some(Err(..))` and subsequent calls return `None`.
///
/// This is the canonical decode entry point.  Both
/// `host/bifrost/src/cli/wrapper.rs` (round-trip tests) and
/// `third_party/smolvm/libkrun/src/devices/src/virtio/bifrost/
/// payload.rs::parse_wrapper_with_btf` (the canonical libkrun-side
/// parser) call into here.
pub fn decode_bfr7(bytes: &[u8]) -> Result<ProgramIter<'_>, WireError> {
    if bytes.len() < 8 {
        return Err(WireError::Truncated {
            need: 8,
            have: bytes.len(),
            at: "wrapper-header",
        });
    }
    let magic: [u8; 4] = bytes[..4].try_into().unwrap();
    if magic != BFR7_MAGIC {
        return Err(WireError::UnsupportedMagic(magic));
    }
    let num_progs = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    Ok(ProgramIter {
        bytes,
        cursor: 8,
        remaining: num_progs,
        failed: false,
    })
}

fn decode_one_program(bytes: &[u8], off: usize) -> Result<(usize, ProgramView<'_>), WireError> {
    if bytes.len() < off + 36 {
        return Err(WireError::Truncated {
            need: off + 36,
            have: bytes.len(),
            at: "program-header",
        });
    }
    // SAFETY-of-cast: the slice is exactly 32 bytes (off..off+32),
    // so reinterpreting as `&[u8; 32]` is sound.  The transmute
    // would be `bytes[off..off+32].try_into().unwrap()` but that
    // produces an owned `[u8;32]`; we want a borrowed reference.
    let target_name: &[u8; 32] = (&bytes[off..off + 32]).try_into().unwrap();
    let flags = u32::from_le_bytes(bytes[off + 32..off + 36].try_into().unwrap());
    let probe_type = (flags & 0xff) as u8;

    let mut cursor = off + 36;

    // Trailer.  Probe type 9 (USDT) was added after 4/5; ordering
    // here matches the encoder's match ladder so any future
    // additions land at one site.
    let trailer = match probe_type {
        2 | 3 => {
            // host-resolved: u32 path_len, path, u64 file_offset
            need(bytes, cursor, 4, "uprobe-trailer-pathlen")?;
            let path_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            if path_len > 256 {
                return Err(WireError::PathTooLong { len: path_len });
            }
            cursor += 4;
            need(bytes, cursor, path_len as usize + 8, "uprobe-trailer-path")?;
            let path = &bytes[cursor..cursor + path_len as usize];
            cursor += path_len as usize;
            let file_offset = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            TrailerView::Path { path, file_offset }
        }
        4 | 5 => {
            // kernel-resolved-by-sym: u32 bn_len, basename, u32 sym_len, symbol
            need(bytes, cursor, 4, "sym-trailer-bnlen")?;
            let bn_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            if bn_len == 0 || bn_len > 64 {
                return Err(WireError::BasenameOutOfRange { len: bn_len });
            }
            cursor += 4;
            need(bytes, cursor, bn_len as usize + 4, "sym-trailer-bn")?;
            let basename = &bytes[cursor..cursor + bn_len as usize];
            cursor += bn_len as usize;
            let sym_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            if sym_len == 0 || sym_len > 256 {
                return Err(WireError::SymbolOutOfRange { len: sym_len });
            }
            cursor += 4;
            need(bytes, cursor, sym_len as usize, "sym-trailer-sym")?;
            let symbol = &bytes[cursor..cursor + sym_len as usize];
            cursor += sym_len as usize;
            TrailerView::Symbol { basename, symbol }
        }
        9 => {
            // USDT: u32 bn_len, bn, u32 prov_len, prov, u32 probe_len, probe
            need(bytes, cursor, 4, "usdt-trailer-bnlen")?;
            let bn_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            if bn_len == 0 || bn_len > 64 {
                return Err(WireError::BasenameOutOfRange { len: bn_len });
            }
            cursor += 4;
            need(bytes, cursor, bn_len as usize + 4, "usdt-trailer-bn")?;
            let basename = &bytes[cursor..cursor + bn_len as usize];
            cursor += bn_len as usize;
            let prov_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            if prov_len == 0 || prov_len > 64 {
                return Err(WireError::ProviderOutOfRange { len: prov_len });
            }
            cursor += 4;
            need(bytes, cursor, prov_len as usize + 4, "usdt-trailer-prov")?;
            let provider = &bytes[cursor..cursor + prov_len as usize];
            cursor += prov_len as usize;
            let probe_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
            if probe_len == 0 || probe_len > 256 {
                return Err(WireError::ProbeOutOfRange { len: probe_len });
            }
            cursor += 4;
            need(bytes, cursor, probe_len as usize, "usdt-trailer-probe")?;
            let probe = &bytes[cursor..cursor + probe_len as usize];
            cursor += probe_len as usize;
            TrailerView::Usdt {
                basename,
                provider,
                probe,
            }
        }
        // Profile-timer: u64 period_ns.
        10 => {
            need(bytes, cursor, 8, "profile-timer-trailer-period")?;
            let period_ns = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            TrailerView::ProfileTimer { period_ns }
        }
        // 0/1 retired kprobe/kretprobe.  6/7 fbt.  8 raw tracepoint.
        // None of these emit a trailer.  Other byte values are a
        // probe-type protocol error.
        0 | 1 | 6 | 7 | 8 => TrailerView::None,
        ty => return Err(WireError::BadProbeType { ty }),
    };

    // Schema, maps, insns, kfunc relocs — same byte layout for
    // every probe type past the trailer.
    need(bytes, cursor, 4, "schema-len")?;
    let schema_len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    need(bytes, cursor, schema_len, "schema-bytes")?;
    let schema_bytes = &bytes[cursor..cursor + schema_len];
    cursor += schema_len;

    need(bytes, cursor, 4, "num-maps")?;
    let num_maps = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let maps_bytes_len = (num_maps as usize) * 52;
    need(bytes, cursor, maps_bytes_len, "maps-bytes")?;
    let maps_bytes = &bytes[cursor..cursor + maps_bytes_len];
    cursor += maps_bytes_len;

    need(bytes, cursor, 4, "num-insns")?;
    let num_insns = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let insns_bytes_len = (num_insns as usize) * 8;
    need(bytes, cursor, insns_bytes_len, "insns-bytes")?;
    let insns = &bytes[cursor..cursor + insns_bytes_len];
    cursor += insns_bytes_len;

    // Kfunc reloc table — slice verbatim including the leading u32
    // count.  Walk to compute the end so libkrun can grab the whole
    // span as a `&[u8]` for verbatim ferry.
    let relocs_start = cursor;
    need(bytes, cursor, 4, "num-kfunc-relocs")?;
    let num_relocs = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    for _ in 0..num_relocs {
        need(bytes, cursor, 5, "kfunc-reloc-header")?;
        cursor += 4; // insn_idx u32
        let name_len = bytes[cursor] as usize;
        cursor += 1;
        need(bytes, cursor, name_len, "kfunc-reloc-name")?;
        cursor += name_len;
    }
    let kfunc_relocs_bytes = &bytes[relocs_start..cursor];

    // Field-relocs section.  Present only when the
    // program's flags carry PROGRAM_FLAG_FIELD_RELOCS_PRESENT.  Layout
    // matches the standalone `encode_field_relocs` codec:
    //   [u32 num_field_relocs]
    //   [for each: u32 insn_idx, u8 access_kind, u8 byte_off,
    //              u8 struct_name_len, u8 field_name_len,
    //              u8;struct_name_len, u8;field_name_len]
    // Old encoders never set the flag bit, so old wrappers parse as
    // before with `field_relocs_bytes = &[]`.
    let field_relocs_bytes: &[u8] = if (flags & PROGRAM_FLAG_FIELD_RELOCS_PRESENT) != 0 {
        let fr_start = cursor;
        need(bytes, cursor, 4, "num-field-relocs")?;
        let num_field = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        for _ in 0..num_field {
            need(bytes, cursor, 8, "field-reloc-record-header")?;
            cursor += 4; // insn_idx
            cursor += 1; // access_kind
            cursor += 1; // byte_off_in_insn
            let struct_name_len = bytes[cursor] as usize;
            cursor += 1;
            let field_name_len = bytes[cursor] as usize;
            cursor += 1;
            need(
                bytes,
                cursor,
                struct_name_len + field_name_len,
                "field-reloc-names",
            )?;
            cursor += struct_name_len + field_name_len;
        }
        &bytes[fr_start..cursor]
    } else {
        &[]
    };

    Ok((
        cursor,
        ProgramView {
            target_name,
            flags,
            probe_type,
            trailer,
            schema_bytes,
            num_maps,
            maps_bytes,
            num_insns,
            insns,
            kfunc_relocs_bytes,
            field_relocs_bytes,
        },
    ))
}

#[inline]
fn need(bytes: &[u8], at: usize, n: usize, field: &'static str) -> Result<(), WireError> {
    if bytes.len() < at + n {
        Err(WireError::Truncated {
            need: at + n,
            have: bytes.len(),
            at: field,
        })
    } else {
        Ok(())
    }
}

// =====================================================================
// Encoder — sink-driven so kernel-side callers can supply a
// `&mut [u8]` adapter without bringing `alloc` in.
// =====================================================================

/// Sink for encoded bytes.  Implementations decide how to grow
/// (heap-backed `Vec`, fixed-size buffer, ringbuf, etc.).  The
/// codec writes in finite chunks; sinks that can't grow signal
/// failure via `WireError::Truncated`.
pub trait WireSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), WireError>;
}

#[cfg(feature = "alloc")]
impl WireSink for alloc::vec::Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// Adapter for fixed-size buffers — kernel-side callers, tests, or
/// any sink that must operate without an allocator.  Returns
/// `Truncated` when the buffer is exhausted.
#[derive(Debug)]
pub struct SliceSink<'b> {
    buf: &'b mut [u8],
    cursor: usize,
}

impl<'b> SliceSink<'b> {
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, cursor: 0 }
    }
    pub fn written(&self) -> usize {
        self.cursor
    }
}

impl<'b> WireSink for SliceSink<'b> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let need = self.cursor + bytes.len();
        if need > self.buf.len() {
            return Err(WireError::Truncated {
                need,
                have: self.buf.len(),
                at: "slice-sink",
            });
        }
        self.buf[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        Ok(())
    }
}

/// Trailer-shape spec passed to the encoder.  Owned-by-caller via
/// `&str`/`&[u8]` slices — the encoder copies bytes into the sink
/// without retaining references.
#[derive(Debug, Copy, Clone)]
pub enum TrailerSpec<'a> {
    None,
    Path {
        path: &'a str,
        file_offset: u64,
    },
    Symbol {
        basename: &'a str,
        symbol: &'a str,
    },
    Usdt {
        basename: &'a str,
        provider: &'a str,
        probe: &'a str,
    },
    /// Profile-timer trailer carries one u64 nanosecond sample
    /// period.  See `TrailerView::ProfileTimer` for the matching
    /// decoder.
    ProfileTimer {
        period_ns: u64,
    },
}

/// One eBPF map declaration as it appears in the BFR7 wrapper.
/// 52 bytes on the wire: 20 bytes of MapDef + 32-byte NUL-padded
/// name.
#[derive(Debug, Copy, Clone)]
pub struct MapSpec<'a> {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub fake_fd: i32,
    pub name: &'a str,
}

/// Per-program input to `WrapperBuilder::push_program`.
#[derive(Debug, Copy, Clone)]
pub struct ProgramSpec<'a> {
    pub target_name: &'a str,
    pub probe_type: u8,
    pub trailer: TrailerSpec<'a>,
    pub schema_bytes: &'a [u8],
    pub maps: &'a [MapSpec<'a>],
    pub insns: &'a [u8],
    pub kfunc_relocs: &'a [(u32, &'a str)],
    /// BTF field relocations to apply at LOAD_PROG time.
    /// Empty slice ⇒ no field relocs and no flag bit set in the
    /// program header (today's path; old decoders parse fine).
    /// Non-empty ⇒ the encoder sets `PROGRAM_FLAG_FIELD_RELOCS_PRESENT`
    /// in the program flags and appends the field-reloc section
    /// after kfunc_relocs.
    pub field_relocs: &'a [FieldRelocInput<'a>],
}

/// Streaming BFR7 wrapper builder.  Caller constructs with a
/// `WireSink` and the declared `num_progs`, then calls
/// `push_program` exactly that many times.  No state machine
/// enforcement — over/underrun is the caller's contract — but the
/// header is written eagerly so tests that build empty wrappers
/// (`num_progs=0`) still produce valid bytes.
#[derive(Debug)]
pub struct WrapperBuilder<'sink, S: WireSink> {
    sink: &'sink mut S,
}

impl<'sink, S: WireSink> WrapperBuilder<'sink, S> {
    pub fn new(sink: &'sink mut S, num_progs: u32) -> Result<Self, WireError> {
        let header = BifrostWrapperHeader::new(num_progs);
        sink.write(header.as_bytes())?;
        Ok(Self { sink })
    }

    pub fn push_program(&mut self, p: &ProgramSpec<'_>) -> Result<(), WireError> {
        // Program flags carry probe_type in the low byte
        // and PROGRAM_FLAG_FIELD_RELOCS_PRESENT in bit 8 when field
        // relocs are attached.  Old decoders ignore bit 8 and stop
        // after kfunc_relocs; new decoders see the bit and read the
        // appended field-relocs section.
        let mut prog_hdr = BifrostProgramHeader::new(p.target_name, p.probe_type);
        if !p.field_relocs.is_empty() {
            prog_hdr.flags |= PROGRAM_FLAG_FIELD_RELOCS_PRESENT;
        }
        self.sink.write(prog_hdr.as_bytes())?;

        match p.trailer {
            TrailerSpec::None => {}
            TrailerSpec::Path { path, file_offset } => {
                let path_b = path.as_bytes();
                if path_b.len() > 256 {
                    return Err(WireError::PathTooLong {
                        len: path_b.len() as u32,
                    });
                }
                self.sink.write(&(path_b.len() as u32).to_le_bytes())?;
                self.sink.write(path_b)?;
                self.sink.write(&file_offset.to_le_bytes())?;
            }
            TrailerSpec::Symbol { basename, symbol } => {
                let bn = basename.as_bytes();
                let sym = symbol.as_bytes();
                if bn.is_empty() || bn.len() > 64 {
                    return Err(WireError::BasenameOutOfRange {
                        len: bn.len() as u32,
                    });
                }
                if sym.is_empty() || sym.len() > 256 {
                    return Err(WireError::SymbolOutOfRange {
                        len: sym.len() as u32,
                    });
                }
                self.sink.write(&(bn.len() as u32).to_le_bytes())?;
                self.sink.write(bn)?;
                self.sink.write(&(sym.len() as u32).to_le_bytes())?;
                self.sink.write(sym)?;
            }
            TrailerSpec::Usdt {
                basename,
                provider,
                probe,
            } => {
                let bn = basename.as_bytes();
                let prov = provider.as_bytes();
                let pr = probe.as_bytes();
                if bn.is_empty() || bn.len() > 64 {
                    return Err(WireError::BasenameOutOfRange {
                        len: bn.len() as u32,
                    });
                }
                if prov.is_empty() || prov.len() > 64 {
                    return Err(WireError::ProviderOutOfRange {
                        len: prov.len() as u32,
                    });
                }
                if pr.is_empty() || pr.len() > 256 {
                    return Err(WireError::ProbeOutOfRange {
                        len: pr.len() as u32,
                    });
                }
                self.sink.write(&(bn.len() as u32).to_le_bytes())?;
                self.sink.write(bn)?;
                self.sink.write(&(prov.len() as u32).to_le_bytes())?;
                self.sink.write(prov)?;
                self.sink.write(&(pr.len() as u32).to_le_bytes())?;
                self.sink.write(pr)?;
            }
            TrailerSpec::ProfileTimer { period_ns } => {
                self.sink.write(&period_ns.to_le_bytes())?;
            }
        }

        // Schema — pre-encoded bytes (RecordSchema lives in the
        // `bifrost` crate; the codec is wire-format agnostic about
        // its body).
        self.sink
            .write(&(p.schema_bytes.len() as u32).to_le_bytes())?;
        self.sink.write(p.schema_bytes)?;

        // Maps.
        self.sink.write(&(p.maps.len() as u32).to_le_bytes())?;
        for m in p.maps {
            self.sink.write(&m.map_type.to_le_bytes())?;
            self.sink.write(&m.key_size.to_le_bytes())?;
            self.sink.write(&m.value_size.to_le_bytes())?;
            self.sink.write(&m.max_entries.to_le_bytes())?;
            self.sink.write(&m.fake_fd.to_le_bytes())?;
            let mut name32 = [0u8; 32];
            let nb = m.name.as_bytes();
            let n = nb.len().min(31);
            name32[..n].copy_from_slice(&nb[..n]);
            self.sink.write(&name32)?;
        }

        // Insns — caller passes raw eBPF bytes (8-byte multiple);
        // num_insns is `bytes / 8`.
        let num_insns = (p.insns.len() / 8) as u32;
        self.sink.write(&num_insns.to_le_bytes())?;
        self.sink.write(p.insns)?;

        // Kfunc relocs.
        self.sink
            .write(&(p.kfunc_relocs.len() as u32).to_le_bytes())?;
        for (insn_idx, name) in p.kfunc_relocs {
            let nb = name.as_bytes();
            if nb.is_empty() || nb.len() > 255 {
                return Err(WireError::KfuncNameOutOfRange { len: nb.len() });
            }
            self.sink.write(&insn_idx.to_le_bytes())?;
            self.sink.write(&[nb.len() as u8])?;
            self.sink.write(nb)?;
        }

        // Field relocs.  Only emitted when non-empty
        // (matches the PROGRAM_FLAG_FIELD_RELOCS_PRESENT discipline);
        // old decoders that don't know about the section will never
        // see it because the flag bit isn't set.
        if !p.field_relocs.is_empty() {
            encode_field_relocs(self.sink, p.field_relocs)?;
        }

        Ok(())
    }
}

// =====================================================================
// SHMEM record header codec — small enough to inline rather than
// going through a sink.  Mirrors the existing `ShmemRecordHeader`
// typed struct; this gives callers a one-line round-trip without
// touching the zerocopy types directly.
// =====================================================================

pub fn shmem_record_hdr_encode(buf: &mut [u8; SHMEM_RECORD_HDR_SIZE], size: u32, flags: u32) {
    buf[0..4].copy_from_slice(&size.to_le_bytes());
    buf[4..8].copy_from_slice(&flags.to_le_bytes());
}

pub fn shmem_record_hdr_decode(buf: &[u8]) -> Result<ShmemRecordHeader, WireError> {
    if buf.len() < SHMEM_RECORD_HDR_SIZE {
        return Err(WireError::Truncated {
            need: SHMEM_RECORD_HDR_SIZE,
            have: buf.len(),
            at: "shmem-record-header",
        });
    }
    Ok(ShmemRecordHeader {
        size: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
        flags: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
    })
}

// =====================================================================
// Per-program LOAD_PROG response codec.  The response payload (carried
// in `D4_KIND_RSP_OK` after a `D4_KIND_LOAD_PROG` request) is:
//
//     [u32 LE   num_progs]
//     for each prog:
//         [u8   status]                         // RSP_LOADPROG_STATUS_*
//         [u16 LE detail_len]                   // 0 if no detail
//         [u8; detail_len detail_bytes]         // UTF-8, no trailing NUL
//
// `detail_bytes` carries the kernel-side diagnostic string for
// failures where it adds value over the bare status enum: the
// missing kfunc name for `BTF_RESOLVE_FAIL`, the unresolvable
// FENTRY/tracepoint target for `TARGET_NOT_FOUND`, etc. The
// encoder is sink-driven so kernel callers can write directly
// into a fixed buffer; the decoder returns a borrowed view that
// the host CLI prints alongside the human-readable status label.
// =====================================================================

/// One per-program entry in a LOAD_PROG status payload — the status
/// enum byte plus an optional kernel-side detail string borrowed
/// against the decoder's input buffer.
#[derive(Debug, Copy, Clone)]
pub struct LoadProgStatusEntry<'a> {
    pub status: u8,
    pub detail: &'a [u8],
}

/// Borrowed view of a LOAD_PROG status response payload.  Each
/// entry has the status byte (one of `RSP_LOADPROG_STATUS_*`) and a
/// possibly-empty `detail` byte slice. `detail` is UTF-8 but the
/// decoder does not validate it — the renderer falls back to a
/// lossy display if the kernel emits garbage.
#[derive(Debug, Clone)]
pub struct LoadProgStatusView<'a> {
    pub entries: alloc::vec::Vec<LoadProgStatusEntry<'a>>,
}

impl<'a> LoadProgStatusView<'a> {
    /// Convenience accessor for callers that only want the status
    /// bytes (e.g. counting failures by category).
    pub fn statuses(&self) -> alloc::vec::Vec<u8> {
        self.entries.iter().map(|e| e.status).collect()
    }
}

/// Encode a per-program status array into `sink`.  Each entry is
/// `(status, detail)` where `detail` is the empty string for
/// successes or status enums that carry no extra diagnostic.
pub fn encode_loadprog_status<S: WireSink>(
    sink: &mut S,
    entries: &[(u8, &[u8])],
) -> Result<(), WireError> {
    sink.write(&(entries.len() as u32).to_le_bytes())?;
    for (status, detail) in entries {
        sink.write(core::slice::from_ref(status))?;
        let len = detail.len();
        if len > u16::MAX as usize {
            return Err(WireError::TooLarge {
                limit: u16::MAX as usize,
                got: len,
                at: "loadprog-status-detail",
            });
        }
        sink.write(&(len as u16).to_le_bytes())?;
        sink.write(detail)?;
    }
    Ok(())
}

/// Decode a per-program status payload.  The returned view borrows
/// from `bytes`; the caller controls the lifetime.  Returns
/// `Truncated` if the payload is shorter than declared.
pub fn decode_loadprog_status(bytes: &[u8]) -> Result<LoadProgStatusView<'_>, WireError> {
    if bytes.len() < 4 {
        return Err(WireError::Truncated {
            need: 4,
            have: bytes.len(),
            at: "loadprog-status-count",
        });
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut off = 4usize;
    let mut entries = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n {
        if bytes.len() < off + 3 {
            return Err(WireError::Truncated {
                need: off + 3,
                have: bytes.len(),
                at: "loadprog-status-entry-header",
            });
        }
        let status = bytes[off];
        let detail_len =
            u16::from_le_bytes(bytes[off + 1..off + 3].try_into().unwrap()) as usize;
        off += 3;
        if bytes.len() < off + detail_len {
            return Err(WireError::Truncated {
                need: off + detail_len,
                have: bytes.len(),
                at: "loadprog-status-entry-detail",
            });
        }
        entries.push(LoadProgStatusEntry {
            status,
            detail: &bytes[off..off + detail_len],
        });
        off += detail_len;
    }
    Ok(LoadProgStatusView { entries })
}

/// Map a status byte to a short human-readable label suitable for
/// terminal rendering (e.g. `"slot_exhausted"`).  Unknown values
/// render as `"other"`; the catch-all `RSP_LOADPROG_STATUS_OTHER`
/// is also `"other"`.  `#![no_std]`-safe: returns a `&'static str`,
/// no allocations.
pub fn loadprog_status_label(status: u8) -> &'static str {
    match status {
        RSP_LOADPROG_STATUS_OK => "ok",
        RSP_LOADPROG_STATUS_SLOT_EXHAUSTED => "slot_exhausted",
        RSP_LOADPROG_STATUS_JIT_FAIL => "jit_fail",
        RSP_LOADPROG_STATUS_BTF_RESOLVE_FAIL => "btf_resolve_fail",
        RSP_LOADPROG_STATUS_VERIFIER_FAIL => "verifier_fail",
        RSP_LOADPROG_STATUS_TARGET_NOT_FOUND => "target_not_found",
        _ => "other",
    }
}

// =====================================================================
// Self-trace event codec.  Encode and
// decode the structured-event body (after the 8-byte SHMEM record
// header).  The driver, libkrun, and CLI all emit through this
// codec and receive through it; rendering happens at the CLI's
// drain-loop dispatch site.
// =====================================================================

// =====================================================================
// OBSERVER_HELLO / OBSERVER_HELLO_ACK codec — capability
// handshake.  Both record bodies open with a (wire_major, wire_minor,
// feature_bits) triple and end with a varint-keyed extension-field
// region using the same per-field layout as self-trace events
// (encode_one_field_owned / decode_one_field).  HELLO_ACK additionally
// carries a leading (accepted, reject_reason) pair so a refusing
// driver can name the reason without inventing a separate kind.
//
// The fields region is for forward-compat: wire_minor bumps that add
// purely additive extension fields don't require a wire_major bump,
// because old peers ignore unknown keys.  Concrete uses in the
// near term:
//
//   HELLO  (cli → driver):
//     "host_pid" U64        diagnostic; helps the driver render
//                           multi-observer error messages.
//     "host_uid" U64        future privilege model.
//     "required_features" U64
//                           bits the cli refuses to run without; the
//                           driver replies with REJECT_MISSING_REQUIRED_FEATURE
//                           if any aren't in driver-side feature_bits.
//
//   HELLO_ACK (driver → cli):
//     "reason" Bytes        human-readable on rejection; `None` on
//                           accept.
//     "kfunc_manifest_sha256" Bytes
//                           the live kfunc-manifest hash so the cli
//                           can refuse on signature drift even when
//                           wire_major still matches.
// =====================================================================

// =====================================================================
// BTF field-reloc codec — driver↔VMM kernel-version
// durability.  Standalone encode/decode for now; a later change wires
// the field-reloc section into the BFR7 wrapper body via
// PROGRAM_FLAG_FIELD_RELOCS_PRESENT.  Standalone first because the
// integration touches WrapperBuilder + decode_one_program in a way
// that's better landed with the libkrun-side patcher in the same
// commit (so the bytes go in and out together).
//
// Wire format (matches the per-program section that N.2 will land):
//   [u32 LE num_relocs]
//   [for each:
//     u32 LE insn_idx                  byte offset in program body
//     u8     access_kind               FIELD_RELOC_*
//     u8     byte_off_in_insn          0..7
//     u8     struct_name_len
//     u8     field_name_len
//     u8;struct_name_len struct_name
//     u8;field_name_len  field_name
//   ]
// =====================================================================
