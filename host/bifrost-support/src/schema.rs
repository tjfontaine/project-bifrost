// SPDX-License-Identifier: Apache-2.0
//! Schema for trace records the guest emits.
//!
//! Each probe declares a record schema once at enable-time. Records on
//! the wire are then raw payload bytes — the host decoder walks the
//! cached schema to pull fields out.
//!
//! This avoids per-probe decoder code in `bifrost.rs` (the BPF-fixture
//! `Openat`/`TcpConnect`/`Test` enum doesn't scale once D scripts can
//! emit arbitrary shapes from `trace()`, `printf()`, `stack()`, etc.).
//!
//! Wire layout for a `RecordSchema` (LE everywhere):
//!   [u16] num_fields
//!   For each field:
//!     [u8 tag][u8 name_len][name_bytes][type-specific tail]
//!
//! Type tail per `FieldKind`:
//!   U8/U16/U32/U64/I64        — no tail (size implied by tag)
//!   Bytes(max_len)            — [u32 max_len]
//!   String(max_len)           — [u32 max_len]   (NUL-terminated within max_len)
//!   KernelStack(max_depth)    — [u16 max_depth]
//!   UserStack(max_depth)      — [u16 max_depth]
//!   GuestPtr                  — [u8 elem_size]  (raw VA, host resolves)

#![allow(dead_code)]

use std::convert::TryInto;
use std::io::{self, Write};
use std::str::Utf8Error;
use thiserror::Error;

/// Errors from `RecordSchema::decode`.  Each variant points at a
/// specific malformed-input failure mode; callers can match on
/// the variant for diagnostics or `?`-bubble through anyhow.
#[derive(Debug, Error)]
pub enum SchemaDecodeError {
    #[error("schema header too short")]
    HeaderTooShort,
    #[error("schema field header out of range")]
    FieldHeaderOutOfRange,
    #[error("schema field name out of range")]
    FieldNameOutOfRange,
    #[error("schema field name not utf8: {0}")]
    FieldNameNotUtf8(#[source] Utf8Error),
    #[error("schema bytes/string len out of range")]
    BytesStringLenOutOfRange,
    #[error("schema stack max_depth out of range")]
    StackMaxDepthOutOfRange,
    #[error("schema guestptr elem_size out of range")]
    GuestPtrElemSizeOutOfRange,
    #[error("unknown schema field tag {0}")]
    UnknownFieldTag(u8),
    #[error("schema printf format len out of range")]
    PrintfFormatLenOutOfRange,
    #[error("schema printf format bytes out of range")]
    PrintfFormatBytesOutOfRange,
    #[error("schema printf format not utf8: {0}")]
    PrintfFormatNotUtf8(#[source] Utf8Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    U8,
    U16,
    U32,
    U64,
    I64,
    Bytes { max_len: u32 },
    String { max_len: u32 },
    KernelStack { max_depth: u16 },
    UserStack { max_depth: u16 },
    GuestPtr { elem_size: u8 },
}

impl FieldKind {
    /// Tag byte used on the wire.
    pub fn tag(&self) -> u8 {
        match self {
            FieldKind::U8 => 1,
            FieldKind::U16 => 2,
            FieldKind::U32 => 3,
            FieldKind::U64 => 4,
            FieldKind::I64 => 5,
            FieldKind::Bytes { .. } => 6,
            FieldKind::String { .. } => 7,
            FieldKind::KernelStack { .. } => 8,
            FieldKind::UserStack { .. } => 9,
            FieldKind::GuestPtr { .. } => 10,
        }
    }

    /// Number of bytes a field of this kind occupies in a raw record.
    /// Variable-length kinds (stacks, bytes, string) reserve their max.
    pub fn record_size(&self) -> usize {
        match self {
            FieldKind::U8 => 1,
            FieldKind::U16 => 2,
            FieldKind::U32 | FieldKind::GuestPtr { .. } => 4,
            FieldKind::U64 | FieldKind::I64 => 8,
            FieldKind::Bytes { max_len } | FieldKind::String { max_len } => *max_len as usize,
            FieldKind::KernelStack { max_depth } | FieldKind::UserStack { max_depth } => {
                (*max_depth as usize) * 8
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordSchema {
    pub fields: Vec<Field>,
    /// printf format string, if this schema is the record-shape for a
    /// `printf()` action inside a `bifrost:` clause. The host decoder
    /// renders the record by replaying the format string against the
    /// trailing u64 arg fields. None for non-printf schemas.
    pub printf_format: Option<String>,
}

impl RecordSchema {
    /// Total bytes one record occupies on the wire.
    pub fn record_size(&self) -> usize {
        self.fields.iter().map(|f| f.kind.record_size()).sum()
    }

    /// The byte offset (within a single record) where `field_idx` lives.
    pub fn field_offset(&self, field_idx: usize) -> usize {
        self.fields[..field_idx]
            .iter()
            .map(|f| f.kind.record_size())
            .sum()
    }

    /// Encode the schema to bytes for transport.
    ///
    /// Wire format: the high bit of the field-count u16 is a flag
    /// "schema carries a trailing printf format string"; the low 15
    /// bits hold the field count.  Older decoders read the low 15
    /// bits and proceed to parse fields normally; they ignore the
    /// high bit and the trailing format string, so the format
    /// extension is backwards compatible.  New decoders
    /// (this crate's `decode`) read the format string after the
    /// fields. Backwards-compatible by construction since 32k fields
    /// is way more than any realistic schema.
    pub fn encode<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let raw: u16 = self
            .fields
            .len()
            .try_into()
            .expect("schema field count fits u15");
        assert!(raw < 0x8000, "schema field count exceeds 15-bit limit");
        let header = if self.printf_format.is_some() {
            raw | 0x8000
        } else {
            raw
        };
        w.write_all(&header.to_le_bytes())?;
        for field in &self.fields {
            w.write_all(&[field.kind.tag()])?;
            let name_bytes = field.name.as_bytes();
            let name_len: u8 = name_bytes
                .len()
                .try_into()
                .expect("schema field name fits u8");
            w.write_all(&[name_len])?;
            w.write_all(name_bytes)?;
            match &field.kind {
                FieldKind::U8
                | FieldKind::U16
                | FieldKind::U32
                | FieldKind::U64
                | FieldKind::I64 => {}
                FieldKind::Bytes { max_len } | FieldKind::String { max_len } => {
                    w.write_all(&max_len.to_le_bytes())?;
                }
                FieldKind::KernelStack { max_depth } | FieldKind::UserStack { max_depth } => {
                    w.write_all(&max_depth.to_le_bytes())?;
                }
                FieldKind::GuestPtr { elem_size } => {
                    w.write_all(&[*elem_size])?;
                }
            }
        }
        if let Some(fmt) = &self.printf_format {
            let fmt_bytes = fmt.as_bytes();
            let fmt_len: u32 = fmt_bytes.len().try_into().expect("fmt fits u32");
            w.write_all(&fmt_len.to_le_bytes())?;
            w.write_all(fmt_bytes)?;
        }
        Ok(())
    }

    /// Decode a schema produced by `encode`.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), SchemaDecodeError> {
        if bytes.len() < 2 {
            return Err(SchemaDecodeError::HeaderTooShort);
        }
        let raw = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let has_printf_format = (raw & 0x8000) != 0;
        let n = raw & 0x7fff;
        let mut off = 2;
        let mut fields = Vec::with_capacity(n as usize);
        for _ in 0..n {
            if off + 2 > bytes.len() {
                return Err(SchemaDecodeError::FieldHeaderOutOfRange);
            }
            let tag = bytes[off];
            let name_len = bytes[off + 1] as usize;
            off += 2;
            if off + name_len > bytes.len() {
                return Err(SchemaDecodeError::FieldNameOutOfRange);
            }
            let name = std::str::from_utf8(&bytes[off..off + name_len])
                .map_err(SchemaDecodeError::FieldNameNotUtf8)?
                .to_string();
            off += name_len;

            let kind = match tag {
                1 => FieldKind::U8,
                2 => FieldKind::U16,
                3 => FieldKind::U32,
                4 => FieldKind::U64,
                5 => FieldKind::I64,
                6 | 7 => {
                    if off + 4 > bytes.len() {
                        return Err(SchemaDecodeError::BytesStringLenOutOfRange);
                    }
                    let max_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
                    off += 4;
                    if tag == 6 {
                        FieldKind::Bytes { max_len }
                    } else {
                        FieldKind::String { max_len }
                    }
                }
                8 | 9 => {
                    if off + 2 > bytes.len() {
                        return Err(SchemaDecodeError::StackMaxDepthOutOfRange);
                    }
                    let max_depth = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
                    off += 2;
                    if tag == 8 {
                        FieldKind::KernelStack { max_depth }
                    } else {
                        FieldKind::UserStack { max_depth }
                    }
                }
                10 => {
                    if off + 1 > bytes.len() {
                        return Err(SchemaDecodeError::GuestPtrElemSizeOutOfRange);
                    }
                    let elem_size = bytes[off];
                    off += 1;
                    FieldKind::GuestPtr { elem_size }
                }
                _ => return Err(SchemaDecodeError::UnknownFieldTag(tag)),
            };
            fields.push(Field { name, kind });
        }
        // Trailing printf format string (if the high-bit flag was set).
        let printf_format = if has_printf_format {
            if off + 4 > bytes.len() {
                return Err(SchemaDecodeError::PrintfFormatLenOutOfRange);
            }
            let fmt_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + fmt_len > bytes.len() {
                return Err(SchemaDecodeError::PrintfFormatBytesOutOfRange);
            }
            let fmt = std::str::from_utf8(&bytes[off..off + fmt_len])
                .map_err(SchemaDecodeError::PrintfFormatNotUtf8)?
                .to_string();
            off += fmt_len;
            Some(fmt)
        } else {
            None
        };
        Ok((RecordSchema { fields, printf_format }, off))
    }

    /// A reasonable default for `trace(<u64-expr>)` style probes —
    /// every record carries cross-domain correlation context plus
    /// the traced value.
    pub fn default_trace() -> Self {
        Self {
            fields: vec![
                Field {
                    name: "vmid".into(),
                    kind: FieldKind::U32,
                },
                // probe_id distinguishes which `bifrost:` clause emitted
                // this record when a multi-clause wrapper has multiple
                // programs sharing the ringbuf. Filled with a per-program
                // constant in the prologue. probe_id == 0 means
                // "single-clause / unspecified".
                Field {
                    name: "probe_id".into(),
                    kind: FieldKind::U32,
                },
                Field {
                    name: "gns".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "gpid".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "value".into(),
                    kind: FieldKind::U64,
                },
            ],
            printf_format: None,
        }
    }

    /// Schema for a clause whose action is `tracemem(addr, len)`.
    /// After the standard correlation header (`vmid`, `probe_id`,
    /// `gns`, `gpid`) the record carries a `tracemem` field of
    /// `Bytes { max_len }` capturing `max_len` raw bytes from the
    /// kernel pointer in `addr`.  The host renderer prints them as
    /// a libdtrace-style hex / ASCII dump.
    pub fn for_tracemem(max_len: u32) -> Self {
        Self {
            fields: vec![
                Field {
                    name: "vmid".into(),
                    kind: FieldKind::U32,
                },
                Field {
                    name: "probe_id".into(),
                    kind: FieldKind::U32,
                },
                Field {
                    name: "gns".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "gpid".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "tracemem".into(),
                    kind: FieldKind::Bytes { max_len },
                },
            ],
            printf_format: None,
        }
    }

    /// Schema for a clause whose first action is `stack()` — kernel
    /// stack capture written into a fixed-depth `kstack` field.
    pub fn for_kernel_stack(max_depth: u16) -> Self {
        Self {
            fields: vec![
                Field {
                    name: "vmid".into(),
                    kind: FieldKind::U32,
                },
                // probe_id distinguishes which `bifrost:` clause emitted
                // this record when a multi-clause wrapper has multiple
                // programs sharing the ringbuf. Filled with a per-program
                // constant in the prologue. probe_id == 0 means
                // "single-clause / unspecified".
                Field {
                    name: "probe_id".into(),
                    kind: FieldKind::U32,
                },
                Field {
                    name: "gns".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "gpid".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "kstack".into(),
                    kind: FieldKind::KernelStack { max_depth },
                },
            ],
            printf_format: None,
        }
    }

    /// Schema for `ustack()`.
    pub fn for_user_stack(max_depth: u16) -> Self {
        Self {
            fields: vec![
                Field {
                    name: "vmid".into(),
                    kind: FieldKind::U32,
                },
                // probe_id distinguishes which `bifrost:` clause emitted
                // this record when a multi-clause wrapper has multiple
                // programs sharing the ringbuf. Filled with a per-program
                // constant in the prologue. probe_id == 0 means
                // "single-clause / unspecified".
                Field {
                    name: "probe_id".into(),
                    kind: FieldKind::U32,
                },
                Field {
                    name: "gns".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "gpid".into(),
                    kind: FieldKind::U64,
                },
                Field {
                    name: "ustack".into(),
                    kind: FieldKind::UserStack { max_depth },
                },
                // Companion to ustack: the running task's executable
                // path (mm->exe_file via d_path), filled in by the
                // bifrost guest worker before the record is forwarded
                // to the host. The host can then symbolicate via the
                // ELF on disk (rootfs is host-accessible). 256 bytes
                // is enough for any reasonable PATH_MAX use case;
                // bifrost_task_exe_path truncates with -ENAMETOOLONG
                // beyond that.
                Field {
                    name: "exe_path".into(),
                    kind: FieldKind::String { max_len: 256 },
                },
            ],
            printf_format: None,
        }
    }

    /// Schema for `printf("fmt", a0, a1, …)` inside a `bifrost:` clause.
    /// Lays down the standard correlation header (vmid, probe_id, gns,
    /// gpid) followed by `n_args` slots holding each evaluated argument.
    /// The format string rides along in `printf_format` so the host
    /// renderer can replay it.
    ///
    /// `string_arg_indices` flags arg positions that should be widened
    /// from a u64 slot to a 16-byte `String { max_len: 16 }` slot —
    /// used when the arg is execname (loaded directly from
    /// `task->comm`, full TASK_COMM_LEN), so the host can render the
    /// bytes verbatim rather than truncating to the first 8.
    ///
    /// Args not in `string_arg_indices` are stored as u64; the format
    /// string's specifiers tell the host how to interpret each one.
    /// %s args still resolve correctly for non-string slots — the
    /// renderer's ASCII-detection heuristic recognises the lowering's
    /// inline-execname-bytes-in-u64 fallback (8-byte truncation).
    pub fn for_printf(format: &str, n_args: usize) -> Self {
        Self::for_printf_with_string_args(format, n_args, &[])
    }

    pub fn for_printf_with_string_args(
        format: &str,
        n_args: usize,
        string_arg_indices: &[usize],
    ) -> Self {
        let mut fields = vec![
            Field {
                name: "vmid".into(),
                kind: FieldKind::U32,
            },
            Field {
                name: "probe_id".into(),
                kind: FieldKind::U32,
            },
            Field {
                name: "gns".into(),
                kind: FieldKind::U64,
            },
            Field {
                name: "gpid".into(),
                kind: FieldKind::U64,
            },
        ];
        for i in 0..n_args {
            let kind = if string_arg_indices.contains(&i) {
                // 16 bytes = TASK_COMM_LEN, the full size of
                // task->comm. The lowering writes via
                // bpf_get_current_comm directly into the slot, so
                // the bytes are the actual comm contents (nul-
                // padded for shorter names).
                FieldKind::String { max_len: 16 }
            } else {
                FieldKind::U64
            };
            fields.push(Field {
                name: format!("arg{}", i),
                kind,
            });
        }
        Self {
            fields,
            printf_format: Some(format.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_trace_round_trip() {
        let schema = RecordSchema::default_trace();
        let mut buf = Vec::new();
        schema.encode(&mut buf).unwrap();
        let (decoded, consumed) = RecordSchema::decode(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.fields.len(), 5);
        assert_eq!(decoded.fields[0].name, "vmid");
        assert!(matches!(decoded.fields[0].kind, FieldKind::U32));
        assert!(matches!(decoded.fields[4].kind, FieldKind::U64));
    }

    #[test]
    fn record_size_is_sum() {
        let schema = RecordSchema::default_trace();
        // 4 + 4 + 8 + 8 + 8 = 32
        assert_eq!(schema.record_size(), 32);
        assert_eq!(schema.field_offset(0), 0);
        assert_eq!(schema.field_offset(1), 4);
        assert_eq!(schema.field_offset(2), 8);
        assert_eq!(schema.field_offset(3), 16);
        assert_eq!(schema.field_offset(4), 24);
    }

    #[test]
    fn variable_length_kinds_round_trip() {
        let schema = RecordSchema {
            fields: vec![
                Field {
                    name: "kstack".into(),
                    kind: FieldKind::KernelStack { max_depth: 32 },
                },
                Field {
                    name: "msg".into(),
                    kind: FieldKind::String { max_len: 64 },
                },
                Field {
                    name: "ptr".into(),
                    kind: FieldKind::GuestPtr { elem_size: 8 },
                },
            ],
            printf_format: None,
        };
        let mut buf = Vec::new();
        schema.encode(&mut buf).unwrap();
        let (decoded, _) = RecordSchema::decode(&buf).unwrap();
        assert_eq!(decoded.fields.len(), 3);
        assert!(matches!(
            decoded.fields[0].kind,
            FieldKind::KernelStack { max_depth: 32 }
        ));
        assert!(matches!(
            decoded.fields[1].kind,
            FieldKind::String { max_len: 64 }
        ));
        assert!(matches!(
            decoded.fields[2].kind,
            FieldKind::GuestPtr { elem_size: 8 }
        ));
    }
}
