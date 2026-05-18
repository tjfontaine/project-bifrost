use super::{WireError, WireSink};
use crate::*;

/// Borrowed view of one BTF field-reloc record.  All slices borrow
/// from the input buffer; the patcher reads them in place.
#[derive(Debug, Copy, Clone)]
pub struct FieldRelocView<'a> {
    pub insn_idx: u32,
    pub access_kind: u8,
    pub byte_off_in_insn: u8,
    pub struct_name: &'a [u8],
    pub field_name: &'a [u8],
}

/// Owning input shape passed to `encode_field_relocs`.  Strings are
/// borrowed slices to avoid an allocation on the encoder side; the
/// codec converts to UTF-8-bytes-on-wire one item at a time.
#[derive(Debug, Copy, Clone)]
pub struct FieldRelocInput<'a> {
    pub insn_idx: u32,
    pub access_kind: u8,
    pub byte_off_in_insn: u8,
    pub struct_name: &'a str,
    pub field_name: &'a str,
}

/// Encode a slice of field-reloc records into `sink`.  Names are
/// bounded at FIELD_RELOC_NAME_MAX; longer names surface as
/// `Truncated` because the wire stores `name_len` as `u8`.
pub fn encode_field_relocs<S: WireSink>(
    sink: &mut S,
    relocs: &[FieldRelocInput<'_>],
) -> Result<(), WireError> {
    sink.write(&(relocs.len() as u32).to_le_bytes())?;
    for r in relocs {
        let s = r.struct_name.as_bytes();
        let f = r.field_name.as_bytes();
        if s.is_empty() || s.len() > FIELD_RELOC_NAME_MAX {
            return Err(WireError::Truncated {
                need: FIELD_RELOC_NAME_MAX,
                have: s.len(),
                at: "field-reloc-struct-name-len",
            });
        }
        if f.is_empty() || f.len() > FIELD_RELOC_NAME_MAX {
            return Err(WireError::Truncated {
                need: FIELD_RELOC_NAME_MAX,
                have: f.len(),
                at: "field-reloc-field-name-len",
            });
        }
        sink.write(&r.insn_idx.to_le_bytes())?;
        sink.write(&[r.access_kind])?;
        sink.write(&[r.byte_off_in_insn])?;
        sink.write(&[s.len() as u8])?;
        sink.write(&[f.len() as u8])?;
        sink.write(s)?;
        sink.write(f)?;
    }
    Ok(())
}

/// Iterator over a borrowed field-relocs payload.  Errors
/// short-circuit further iteration.
#[derive(Debug)]
pub struct FieldRelocIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: u32,
    failed: bool,
}

impl<'a> Iterator for FieldRelocIter<'a> {
    type Item = Result<FieldRelocView<'a>, WireError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining == 0 {
            return None;
        }
        match decode_one_field_reloc(self.bytes, self.cursor) {
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

/// Decode a field-reloc payload.  Returns an iterator that yields
/// one borrowed `FieldRelocView` per record.  Per-record errors
/// short-circuit subsequent iteration.
pub fn decode_field_relocs(bytes: &[u8]) -> Result<FieldRelocIter<'_>, WireError> {
    if bytes.len() < 4 {
        return Err(WireError::Truncated {
            need: 4,
            have: bytes.len(),
            at: "field-relocs-count",
        });
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    Ok(FieldRelocIter {
        bytes,
        cursor: 4,
        remaining: n,
        failed: false,
    })
}

fn decode_one_field_reloc(
    bytes: &[u8],
    off: usize,
) -> Result<(usize, FieldRelocView<'_>), WireError> {
    if bytes.len() < off + 7 {
        return Err(WireError::Truncated {
            need: off + 7,
            have: bytes.len(),
            at: "field-reloc-record-header",
        });
    }
    let insn_idx = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    let access_kind = bytes[off + 4];
    let byte_off_in_insn = bytes[off + 5];
    let struct_name_len = bytes[off + 6] as usize;
    let field_name_len = bytes[off + 7] as usize;
    let cursor = off + 8;
    let need = cursor + struct_name_len + field_name_len;
    if bytes.len() < need {
        return Err(WireError::Truncated {
            need,
            have: bytes.len(),
            at: "field-reloc-names",
        });
    }
    let struct_name = &bytes[cursor..cursor + struct_name_len];
    let field_name = &bytes[cursor + struct_name_len..cursor + struct_name_len + field_name_len];
    Ok((
        need,
        FieldRelocView {
            insn_idx,
            access_kind,
            byte_off_in_insn,
            struct_name,
            field_name,
        },
    ))
}

/// Map a FIELD_RELOC_* byte to a short label.  Unknown ⇒ `"???"`.
pub fn field_reloc_kind_label(kind: u8) -> &'static str {
    match kind {
        FIELD_RELOC_OFFSET => "offset",
        FIELD_RELOC_SIZE => "size",
        FIELD_RELOC_EXISTS => "exists",
        _ => "???",
    }
}
