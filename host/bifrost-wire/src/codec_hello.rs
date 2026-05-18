use super::{SelfFieldIter, SelfFieldOwned, WireError, WireSink};
use crate::*;

/// Borrowed view of an OBSERVER_HELLO body.  Wire layout:
///   `[u32 wire_major][u32 wire_minor][u64 feature_bits]
///    [u16 num_fields][fields...]`
#[derive(Debug, Copy, Clone)]
pub struct HelloView<'a> {
    pub wire_major: u32,
    pub wire_minor: u32,
    pub feature_bits: u64,
    fields_bytes: &'a [u8],
    num_fields: u16,
}

impl<'a> HelloView<'a> {
    /// Iterator over extension fields.  Same per-field encoding as
    /// self-trace events, so `SelfFieldView` is reused — the field
    /// abstraction predates the "self-trace" framing and is just a
    /// general varint-keyed extension primitive.
    pub fn fields(&self) -> SelfFieldIter<'a> {
        SelfFieldIter {
            bytes: self.fields_bytes,
            cursor: 0,
            remaining: self.num_fields,
            failed: false,
        }
    }
}

/// Encode an OBSERVER_HELLO body into `sink`.  Caller supplies the
/// (wire_major, wire_minor, feature_bits) triple plus any extension
/// fields.  Field key/value layout matches `encode_event`'s.
pub fn encode_hello<S: WireSink>(
    sink: &mut S,
    wire_major: u32,
    wire_minor: u32,
    feature_bits: u64,
    fields: &[(&[u8], SelfFieldOwned<'_>)],
) -> Result<(), WireError> {
    if fields.len() > u16::MAX as usize {
        return Err(WireError::Truncated {
            need: u16::MAX as usize,
            have: fields.len(),
            at: "hello-num-fields",
        });
    }
    sink.write(&wire_major.to_le_bytes())?;
    sink.write(&wire_minor.to_le_bytes())?;
    sink.write(&feature_bits.to_le_bytes())?;
    sink.write(&(fields.len() as u16).to_le_bytes())?;
    for (key, value) in fields {
        encode_one_field_owned(sink, key, value, "hello")?;
    }
    Ok(())
}

/// Decode an OBSERVER_HELLO body.  Returns a borrowed view; iterate
/// fields via `view.fields()`.
pub fn decode_hello(bytes: &[u8]) -> Result<HelloView<'_>, WireError> {
    if bytes.len() < 18 {
        return Err(WireError::Truncated {
            need: 18,
            have: bytes.len(),
            at: "hello-header",
        });
    }
    let wire_major = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let wire_minor = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let feature_bits = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let num_fields = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
    Ok(HelloView {
        wire_major,
        wire_minor,
        feature_bits,
        fields_bytes: &bytes[18..],
        num_fields,
    })
}

/// Borrowed view of an OBSERVER_HELLO_ACK body.  Wire layout:
///   `[u8 accepted][u8 reject_reason][u32 wire_major][u32 wire_minor]
///    [u64 feature_bits][u16 num_fields][fields...]`
///
/// `accepted == 1, reject_reason == 0` ⇒ the connection is open and
/// `feature_bits` reflects the driver-side capability set the CLI
/// should AND with its own to get the negotiated set.
///
/// `accepted == 0, reject_reason != 0` ⇒ the CLI must not push
/// LOAD_PROG; the optional `"reason"` Bytes field carries a
/// diagnostic string.
#[derive(Debug, Copy, Clone)]
pub struct HelloAckView<'a> {
    pub accepted: bool,
    pub reject_reason: u8,
    pub wire_major: u32,
    pub wire_minor: u32,
    pub feature_bits: u64,
    fields_bytes: &'a [u8],
    num_fields: u16,
}

impl<'a> HelloAckView<'a> {
    pub fn fields(&self) -> SelfFieldIter<'a> {
        SelfFieldIter {
            bytes: self.fields_bytes,
            cursor: 0,
            remaining: self.num_fields,
            failed: false,
        }
    }
}

/// Encode an OBSERVER_HELLO_ACK body.  Caller specifies whether the
/// driver accepted the connection; the reject_reason is meaningful
/// only when `!accepted`.  Carrying both feature_bits and a
/// reject_reason on rejection lets the CLI render an actionable
/// error (e.g. "driver advertises only USDT+FBT; CLI required RAWTP").
pub fn encode_hello_ack<S: WireSink>(
    sink: &mut S,
    accepted: bool,
    reject_reason: u8,
    wire_major: u32,
    wire_minor: u32,
    feature_bits: u64,
    fields: &[(&[u8], SelfFieldOwned<'_>)],
) -> Result<(), WireError> {
    if fields.len() > u16::MAX as usize {
        return Err(WireError::Truncated {
            need: u16::MAX as usize,
            have: fields.len(),
            at: "hello-ack-num-fields",
        });
    }
    sink.write(&[if accepted { 1u8 } else { 0u8 }])?;
    sink.write(&[reject_reason])?;
    sink.write(&wire_major.to_le_bytes())?;
    sink.write(&wire_minor.to_le_bytes())?;
    sink.write(&feature_bits.to_le_bytes())?;
    sink.write(&(fields.len() as u16).to_le_bytes())?;
    for (key, value) in fields {
        encode_one_field_owned(sink, key, value, "hello-ack")?;
    }
    Ok(())
}

/// Decode an OBSERVER_HELLO_ACK body.
pub fn decode_hello_ack(bytes: &[u8]) -> Result<HelloAckView<'_>, WireError> {
    if bytes.len() < 20 {
        return Err(WireError::Truncated {
            need: 20,
            have: bytes.len(),
            at: "hello-ack-header",
        });
    }
    let accepted = bytes[0] != 0;
    let reject_reason = bytes[1];
    let wire_major = u32::from_le_bytes(bytes[2..6].try_into().unwrap());
    let wire_minor = u32::from_le_bytes(bytes[6..10].try_into().unwrap());
    let feature_bits = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
    let num_fields = u16::from_le_bytes(bytes[18..20].try_into().unwrap());
    Ok(HelloAckView {
        accepted,
        reject_reason,
        wire_major,
        wire_minor,
        feature_bits,
        fields_bytes: &bytes[20..],
        num_fields,
    })
}

/// Encode one (key, value) field into `sink` using the shared
/// field-encoding shape (extracted from `encode_event` so HELLO and
/// HELLO_ACK can reuse it without duplicating the bytes).  `at`
/// names the surrounding context for `WireError::Truncated`
/// diagnostics.
fn encode_one_field_owned<S: WireSink>(
    sink: &mut S,
    key: &[u8],
    value: &SelfFieldOwned<'_>,
    at: &'static str,
) -> Result<(), WireError> {
    if key.len() > u16::MAX as usize {
        return Err(WireError::Truncated {
            need: u16::MAX as usize,
            have: key.len(),
            at: match at {
                "hello" => "hello-field-key-len",
                "hello-ack" => "hello-ack-field-key-len",
                _ => "field-key-len",
            },
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
                    at: match at {
                        "hello" => "hello-field-bytes-len",
                        "hello-ack" => "hello-ack-field-bytes-len",
                        _ => "field-bytes-len",
                    },
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
    Ok(())
}

/// Map a HELLO_REJECT_* byte to a short label suitable for terminal
/// rendering.  Unknown values render as `"unknown"`; the catch-all
/// `HELLO_REJECT_OTHER` is `"other"`.
pub fn hello_reject_label(reason: u8) -> &'static str {
    match reason {
        0 => "ok",
        HELLO_REJECT_WIRE_MAJOR_MISMATCH => "wire_major_mismatch",
        HELLO_REJECT_MISSING_REQUIRED_FEATURE => "missing_required_feature",
        HELLO_REJECT_OBSERVER_BUSY => "observer_busy",
        HELLO_REJECT_OTHER => "other",
        _ => "unknown",
    }
}
