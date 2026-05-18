use super::{WireError, WireSink};
use crate::*;

/// Borrowed value of one structured field in a self-trace event.
/// Decoded from the wire by `decode_event`; the caller can
/// pattern-match on the variant to render or filter.
#[derive(Debug, Copy, Clone)]
pub enum SelfFieldValue<'a> {
    U64(u64),
    I64(i64),
    /// Byte slice — typically a UTF-8 string (target names, error
    /// messages); not enforced at the codec level.
    Bytes(&'a [u8]),
    Bool(bool),
}

/// One key=value field within a self-trace event.  Borrowed
/// against the input buffer — `'a` is the input lifetime.
#[derive(Debug, Copy, Clone)]
pub struct SelfFieldView<'a> {
    pub key: &'a [u8],
    pub value: SelfFieldValue<'a>,
}

/// Decoded view of one self-trace event body.  All slices borrow
/// against the caller-supplied input buffer.
#[derive(Debug, Copy, Clone)]
pub struct SelfEventView<'a> {
    pub level: u8,
    pub subsystem: u8,
    pub msg: &'a [u8],
    /// Raw fields region; iterate via `fields()` to get
    /// `SelfFieldView`s one at a time.  Stored as a raw byte slice
    /// so the codec can stay no_std without allocating a `Vec`.
    fields_bytes: &'a [u8],
    num_fields: u16,
}

impl<'a> SelfEventView<'a> {
    /// Iterator over the event's fields.  Errors short-circuit
    /// further iteration (subsequent `next()` returns `None`).
    pub fn fields(&self) -> SelfFieldIter<'a> {
        SelfFieldIter {
            bytes: self.fields_bytes,
            cursor: 0,
            remaining: self.num_fields,
            failed: false,
        }
    }
}

/// Iterator over the field-list region of a `SelfEventView`.
#[derive(Debug)]
pub struct SelfFieldIter<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) cursor: usize,
    pub(crate) remaining: u16,
    pub(crate) failed: bool,
}

impl<'a> Iterator for SelfFieldIter<'a> {
    type Item = Result<SelfFieldView<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining == 0 {
            return None;
        }
        match decode_one_field(self.bytes, self.cursor) {
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

/// Owning input shape for one field passed to `encode_event`.
#[derive(Debug, Copy, Clone)]
pub enum SelfFieldOwned<'a> {
    U64(u64),
    I64(i64),
    Bytes(&'a [u8]),
    Bool(bool),
}

/// Encode a self-trace event into `sink`.  The msg + every field
/// must fit within `SELF_TRACE_MAX_BODY` bytes (callers commonly
/// pass a stack-allocated `[u8; SELF_TRACE_MAX_BODY]` via
/// `SliceSink`).  Caller controls the `level`, `subsystem`, `msg`
/// and field list; the codec owns the byte layout.
pub fn encode_event<S: WireSink>(
    sink: &mut S,
    level: u8,
    subsystem: u8,
    msg: &[u8],
    fields: &[(&[u8], SelfFieldOwned<'_>)],
) -> Result<(), WireError> {
    if msg.len() > u16::MAX as usize {
        return Err(WireError::Truncated {
            need: u16::MAX as usize,
            have: msg.len(),
            at: "self-event-msg-len",
        });
    }
    if fields.len() > u16::MAX as usize {
        return Err(WireError::Truncated {
            need: u16::MAX as usize,
            have: fields.len(),
            at: "self-event-num-fields",
        });
    }
    sink.write(&[level])?;
    sink.write(&[subsystem])?;
    sink.write(&(fields.len() as u16).to_le_bytes())?;
    sink.write(&(msg.len() as u16).to_le_bytes())?;
    sink.write(msg)?;
    for (key, value) in fields {
        if key.len() > u16::MAX as usize {
            return Err(WireError::Truncated {
                need: u16::MAX as usize,
                have: key.len(),
                at: "self-event-field-key-len",
            });
        }
        sink.write(&(key.len() as u16).to_le_bytes())?;
        sink.write(key)?;
        match value {
            SelfFieldOwned::U64(v) => {
                sink.write(&[SELF_FIELD_U64])?;
                sink.write(&(8u16).to_le_bytes())?;
                sink.write(&v.to_le_bytes())?;
            }
            SelfFieldOwned::I64(v) => {
                sink.write(&[SELF_FIELD_I64])?;
                sink.write(&(8u16).to_le_bytes())?;
                sink.write(&v.to_le_bytes())?;
            }
            SelfFieldOwned::Bytes(b) => {
                if b.len() > u16::MAX as usize {
                    return Err(WireError::Truncated {
                        need: u16::MAX as usize,
                        have: b.len(),
                        at: "self-event-field-bytes-len",
                    });
                }
                sink.write(&[SELF_FIELD_BYTES])?;
                sink.write(&(b.len() as u16).to_le_bytes())?;
                sink.write(b)?;
            }
            SelfFieldOwned::Bool(v) => {
                sink.write(&[SELF_FIELD_BOOL])?;
                sink.write(&(1u16).to_le_bytes())?;
                sink.write(&[if *v { 1u8 } else { 0u8 }])?;
            }
        }
    }
    Ok(())
}

/// Decode a self-trace event body.  Returns a borrowed view; call
/// `fields()` on the view to walk the field list.  Returns
/// `Truncated` for any short-byte case; field-internal errors
/// surface only when iterating via `SelfFieldIter`.
pub fn decode_event(bytes: &[u8]) -> Result<SelfEventView<'_>, WireError> {
    if bytes.len() < 6 {
        return Err(WireError::Truncated {
            need: 6,
            have: bytes.len(),
            at: "self-event-header",
        });
    }
    let level = bytes[0];
    let subsystem = bytes[1];
    let num_fields = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
    let msg_len = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
    if bytes.len() < 6 + msg_len {
        return Err(WireError::Truncated {
            need: 6 + msg_len,
            have: bytes.len(),
            at: "self-event-msg",
        });
    }
    let msg = &bytes[6..6 + msg_len];
    let fields_bytes = &bytes[6 + msg_len..];
    Ok(SelfEventView {
        level,
        subsystem,
        msg,
        fields_bytes,
        num_fields,
    })
}

fn decode_one_field(bytes: &[u8], off: usize) -> Result<(usize, SelfFieldView<'_>), WireError> {
    if bytes.len() < off + 2 {
        return Err(WireError::Truncated {
            need: off + 2,
            have: bytes.len(),
            at: "self-field-key-len",
        });
    }
    let key_len = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
    let mut cursor = off + 2;
    if bytes.len() < cursor + key_len + 3 {
        return Err(WireError::Truncated {
            need: cursor + key_len + 3,
            have: bytes.len(),
            at: "self-field-key",
        });
    }
    let key = &bytes[cursor..cursor + key_len];
    cursor += key_len;
    let value_type = bytes[cursor];
    cursor += 1;
    let value_len = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;
    if bytes.len() < cursor + value_len {
        return Err(WireError::Truncated {
            need: cursor + value_len,
            have: bytes.len(),
            at: "self-field-value",
        });
    }
    let value_slice = &bytes[cursor..cursor + value_len];
    cursor += value_len;
    let value = match value_type {
        SELF_FIELD_U64 => {
            if value_len != 8 {
                return Err(WireError::Truncated {
                    need: 8,
                    have: value_len,
                    at: "self-field-u64-len",
                });
            }
            SelfFieldValue::U64(u64::from_le_bytes(value_slice.try_into().unwrap()))
        }
        SELF_FIELD_I64 => {
            if value_len != 8 {
                return Err(WireError::Truncated {
                    need: 8,
                    have: value_len,
                    at: "self-field-i64-len",
                });
            }
            SelfFieldValue::I64(i64::from_le_bytes(value_slice.try_into().unwrap()))
        }
        SELF_FIELD_BYTES => SelfFieldValue::Bytes(value_slice),
        SELF_FIELD_BOOL => {
            if value_len != 1 {
                return Err(WireError::Truncated {
                    need: 1,
                    have: value_len,
                    at: "self-field-bool-len",
                });
            }
            SelfFieldValue::Bool(value_slice[0] != 0)
        }
        unknown => {
            // Forward-compat: a future SELF_FIELD_* discriminant
            // that this decoder doesn't know about returns Bytes —
            // the renderer can still print the bytes as hex without
            // misinterpreting the structure.  False positives here
            // are benign; the alternative (hard error on unknown
            // type) would prevent rolling upgrades.
            let _ = unknown;
            SelfFieldValue::Bytes(value_slice)
        }
    };
    Ok((cursor, SelfFieldView { key, value }))
}

/// Map a level byte to a short label suitable for terminal
/// rendering.  Unknown levels render as `"???"`.
pub fn self_level_label(level: u8) -> &'static str {
    match level {
        SELF_LEVEL_TRACE => "trace",
        SELF_LEVEL_DEBUG => "debug",
        SELF_LEVEL_INFO => "info",
        SELF_LEVEL_WARN => "warn",
        SELF_LEVEL_ERROR => "error",
        _ => "???",
    }
}

/// Map a subsystem byte to a short label suitable for terminal
/// rendering.  Unknown subsystems render as `"???"`.
pub fn self_subsystem_label(subsys: u8) -> &'static str {
    match subsys {
        SELF_SUBSYS_LOADPROG => "loadprog",
        SELF_SUBSYS_SLOT => "slot",
        SELF_SUBSYS_UPROBE => "uprobe",
        SELF_SUBSYS_FBT => "fbt",
        SELF_SUBSYS_TRACEPT => "tracept",
        SELF_SUBSYS_USDT => "usdt",
        SELF_SUBSYS_AGG => "agg",
        SELF_SUBSYS_RECORD => "record",
        SELF_SUBSYS_OBSERVER => "observer",
        SELF_SUBSYS_CONTROL => "control",
        SELF_SUBSYS_PARSE => "parse",
        SELF_SUBSYS_LOWER => "lower",
        SELF_SUBSYS_RENDER => "render",
        _ => "???",
    }
}
