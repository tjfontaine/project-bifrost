// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// DTrace action kinds (`DTRACEACT_*`).
//
// Each `dof_actdesc_t` in an ECB chain carries a `dofa_kind` selecting
// one of these. The kind decides what the per-action DIFO's return
// value *means* — `DIFEXPR` traces it as the action's data, `PRINTF`
// uses it as a printf-argument register, an aggregation kind makes it
// the agg key/value, etc.
//
// We split the numeric space into ranges so the adapter can pattern
// match efficiently:
//
//   DTRACEACT_NONE              0x00
//   trace/printf-class          0x01..0x10
//   destructive (stop/breakpoint/chill/panic)  0x10..0x20
//   speculate                   0x20..0x30
//   exit                        0x30..0x40
//   speculation-control         0x40..0x50
//   commit/discard              0x50..0x60
//   aggregations                0x100..0x200 — see `agg::AggKind`

use crate::LowerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ActionKind {
    None = 0x00,
    /// `trace(expr)` — the DIFO's return value is recorded verbatim.
    DifExpr = 0x01,
    /// `printf(fmt, ...)` — DIFO return is one printf argument; the
    /// format descriptor lives in the action's `dofa_arg` strtab slot.
    Printf = 0x02,
    /// `printa(@agg)` — flush an aggregation snapshot inline. Adapters
    /// typically defer this to the host renderer.
    Printa = 0x03,
    /// `stack()`. DIFO encodes the depth argument.
    Stack = 0x04,
    /// `ustack()`. Depth + strsize encoded in `dofa_arg`.
    UStack = 0x05,
    /// `tracemem(addr, len)` — record an arbitrary-sized byte range.
    TraceMem = 0x06,
    /// `stringof()`/`copyinstr()` lowered records — the DIFO return
    /// is a strtab offset; record carries the string bytes.
    PrintfArg = 0x07,
    /// `discard()` — drop the current speculation.
    Discard = 0x20,
    /// `commit()` — publish the current speculation.
    Commit = 0x21,
    /// `speculate(id)` — bind the current clause to a speculation.
    Speculate = 0x22,
    /// `exit(code)` — schedule session termination.
    Exit = 0x30,
    /// `raise(sig)` / `stop()` — destructive. Adapters with no
    /// destructive support must `RejectReason::DestructiveDisabled`.
    Raise = 0x31,
    Stop = 0x32,
    Chill = 0x33,
    Panic = 0x34,
    Breakpoint = 0x35,
    /// `usym()`/`ustack()` userspace symbol lookup hint.
    USym = 0x06_00,
    /// `sym()`/`mod()` kernel symbol lookup hint.
    Sym = 0x06_01,
    /// An aggregation slot. The chain walker pairs the preceding
    /// `DifExpr` (the agg key) with the following `AggSentinel` /
    /// `AggKind` selector.
    AggSentinel = 0x07_00,
    /// Anything we don't model yet.
    Other = 0xffff_ffff,
}

impl ActionKind {
    pub fn from_u32(v: u32) -> Result<Self, LowerError> {
        Ok(match v {
            0x00 => Self::None,
            0x01 => Self::DifExpr,
            0x02 => Self::Printf,
            0x03 => Self::Printa,
            0x04 => Self::Stack,
            0x05 => Self::UStack,
            0x06 => Self::TraceMem,
            0x07 => Self::PrintfArg,
            0x20 => Self::Discard,
            0x21 => Self::Commit,
            0x22 => Self::Speculate,
            0x30 => Self::Exit,
            0x31 => Self::Raise,
            0x32 => Self::Stop,
            0x33 => Self::Chill,
            0x34 => Self::Panic,
            0x35 => Self::Breakpoint,
            0x06_00 => Self::USym,
            0x06_01 => Self::Sym,
            // Aggregation slot — exact agg kind is in the action's
            // `dofa_arg`/aux fields and decoded by `agg::AggKind`.
            0x0700..=0x07ff => Self::AggSentinel,
            _ => return Err(LowerError::UnknownActionKind(v)),
        })
    }

    /// True for actions that mutate target state (stop, raise, chill,
    /// panic, breakpoint). Adapters that haven't been told to allow
    /// destructive actions must reject these at ECB-walk time.
    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::Raise | Self::Stop | Self::Chill | Self::Panic | Self::Breakpoint
        )
    }
}

/// Parsed view of one `dof_actdesc_t` row.
#[derive(Debug, Clone, Copy)]
pub struct ActionDescriptor {
    pub kind: ActionKind,
    pub kind_raw: u32,
    /// Section index of this action's DIFO (or 0 for actions with no
    /// expression, like `commit`).
    pub difo_section: u32,
    /// `dofa_arg` — kind-specific. For `Printf` this is a strtab
    /// offset to the format string; for aggregations the agg slot id;
    /// for `Stack`/`UStack` the depth.
    pub arg: u64,
    /// `dofa_uarg` — second kind-specific argument (e.g. ustack
    /// strsize, tracemem byte count).
    pub uarg: u64,
}

/// Parse one `dof_actdesc_t` from its 32-byte on-wire form.
///
///   bytes  0..4   dofa_difo
///   bytes  4..8   dofa_strtab
///   bytes  8..16  dofa_kind   (u64 to match macOS 64-bit alignment)
///   bytes 16..24  dofa_arg
///   bytes 24..32  dofa_uarg
pub fn parse_action(raw: &[u8]) -> Result<ActionDescriptor, LowerError> {
    if raw.len() < 32 {
        return Err(LowerError::TruncatedDif);
    }
    let difo = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let kind_raw_lo = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let kind = ActionKind::from_u32(kind_raw_lo)?;
    let arg = u64::from_le_bytes([
        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
    ]);
    let uarg = u64::from_le_bytes([
        raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
    ]);
    Ok(ActionDescriptor {
        kind,
        kind_raw: kind_raw_lo,
        difo_section: difo,
        arg,
        uarg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trace_action() {
        let mut raw = [0u8; 32];
        raw[0..4].copy_from_slice(&7u32.to_le_bytes()); // DIFO section 7
        raw[8..12].copy_from_slice(&0x01u32.to_le_bytes()); // DifExpr
        raw[16..24].copy_from_slice(&0xdeadu64.to_le_bytes());
        let a = parse_action(&raw).unwrap();
        assert_eq!(a.kind, ActionKind::DifExpr);
        assert_eq!(a.difo_section, 7);
        assert_eq!(a.arg, 0xdead);
    }

    #[test]
    fn destructive_actions_marked() {
        assert!(ActionKind::Raise.is_destructive());
        assert!(ActionKind::Stop.is_destructive());
        assert!(!ActionKind::DifExpr.is_destructive());
        assert!(!ActionKind::Stack.is_destructive());
    }
}
