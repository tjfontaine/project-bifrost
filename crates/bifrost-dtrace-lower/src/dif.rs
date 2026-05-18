// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// DIF (DTrace Intermediate Format) — instruction decoder.
//
// A DIFO is a self-contained little machine: header, integer constant
// pool, string constant pool, variable table, type table, optional
// relocations, and the bytecode itself. libdtrace emits one DIFO per
// predicate and per action-value expression; this crate decodes the
// bytecode shape so the `KernelAdapter` can lower or interpret it.
//
// Opcodes are taken from `sys/dtrace.h`'s `DIF_OP_*` enumeration.
// libdtrace numbers them in declaration order; the constants below
// match. We intentionally do not include semantic interpretation here
// — that's the adapter's job (the Linux adapter lowers to eBPF; the
// FreeBSD adapter hands DIFOs to the native DTrace interpreter).
//
// Each instruction is exactly 4 bytes:
//
//   byte 0: opcode
//   byte 1: r1
//   byte 2: r2
//   byte 3: rd / immediate
//
// Loads, stores, and branches reinterpret the low three bytes
// according to the opcode. The decoder below splits an instruction
// into the raw bytes; the adapter pattern-matches on `DifOp`.

use crate::LowerError;

/// DIF opcodes. Values are fixed by libdtrace/`sys/dtrace.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum DifOp {
    Or = 0x01,
    Xor = 0x02,
    And = 0x03,
    Sll = 0x04,
    Srl = 0x05,
    Sub = 0x06,
    Add = 0x07,
    Mul = 0x08,
    Sdiv = 0x09,
    Udiv = 0x0a,
    Srem = 0x0b,
    Urem = 0x0c,
    Not = 0x0d,
    Mov = 0x0e,
    Cmp = 0x0f,
    Tst = 0x10,
    Ba = 0x11,
    Be = 0x12,
    Bne = 0x13,
    Bg = 0x14,
    Bgu = 0x15,
    Bge = 0x16,
    Bgeu = 0x17,
    Bl = 0x18,
    Blu = 0x19,
    Ble = 0x1a,
    Bleu = 0x1b,
    Ldsb = 0x1c,
    Ldsh = 0x1d,
    Ldsw = 0x1e,
    Ldub = 0x1f,
    Lduh = 0x20,
    Lduw = 0x21,
    Ldx = 0x22,
    Ret = 0x23,
    Nop = 0x24,
    Setx = 0x25,
    Sets = 0x26,
    Scmp = 0x27,
    Ldga = 0x28,
    Ldgs = 0x29,
    Stgs = 0x2a,
    Ldta = 0x2b,
    Ldts = 0x2c,
    Stts = 0x2d,
    Sra = 0x2e,
    Call = 0x2f,
    Pushtr = 0x30,
    Pushtv = 0x31,
    Popts = 0x32,
    Flushts = 0x33,
    Ldgaa = 0x34,
    Ldtaa = 0x35,
    Stgaa = 0x36,
    Sttaa = 0x37,
    Ldls = 0x38,
    Stls = 0x39,
    Allocs = 0x3a,
    Copys = 0x3b,
    Stb = 0x3c,
    Sth = 0x3d,
    Stw = 0x3e,
    Stx = 0x3f,
    Uldsb = 0x40,
    Uldsh = 0x41,
    Uldsw = 0x42,
    Uldub = 0x43,
    Ulduh = 0x44,
    Ulduw = 0x45,
    Uldx = 0x46,
    Rldsb = 0x47,
    Rldsh = 0x48,
    Rldsw = 0x49,
    Rldub = 0x4a,
    Rlduh = 0x4b,
    Rlduw = 0x4c,
    Rldx = 0x4d,
    Xlate = 0x4e,
    Xlarg = 0x4f,
}

impl DifOp {
    pub fn from_u8(v: u8) -> Result<Self, LowerError> {
        // Use a transmute-free match so unknown opcodes are surfaced
        // as `UnknownDifOp(byte)` rather than panicking.
        Ok(match v {
            0x01 => Self::Or, 0x02 => Self::Xor, 0x03 => Self::And,
            0x04 => Self::Sll, 0x05 => Self::Srl, 0x06 => Self::Sub,
            0x07 => Self::Add, 0x08 => Self::Mul, 0x09 => Self::Sdiv,
            0x0a => Self::Udiv, 0x0b => Self::Srem, 0x0c => Self::Urem,
            0x0d => Self::Not, 0x0e => Self::Mov, 0x0f => Self::Cmp,
            0x10 => Self::Tst, 0x11 => Self::Ba, 0x12 => Self::Be,
            0x13 => Self::Bne, 0x14 => Self::Bg, 0x15 => Self::Bgu,
            0x16 => Self::Bge, 0x17 => Self::Bgeu, 0x18 => Self::Bl,
            0x19 => Self::Blu, 0x1a => Self::Ble, 0x1b => Self::Bleu,
            0x1c => Self::Ldsb, 0x1d => Self::Ldsh, 0x1e => Self::Ldsw,
            0x1f => Self::Ldub, 0x20 => Self::Lduh, 0x21 => Self::Lduw,
            0x22 => Self::Ldx, 0x23 => Self::Ret, 0x24 => Self::Nop,
            0x25 => Self::Setx, 0x26 => Self::Sets, 0x27 => Self::Scmp,
            0x28 => Self::Ldga, 0x29 => Self::Ldgs, 0x2a => Self::Stgs,
            0x2b => Self::Ldta, 0x2c => Self::Ldts, 0x2d => Self::Stts,
            0x2e => Self::Sra, 0x2f => Self::Call, 0x30 => Self::Pushtr,
            0x31 => Self::Pushtv, 0x32 => Self::Popts, 0x33 => Self::Flushts,
            0x34 => Self::Ldgaa, 0x35 => Self::Ldtaa, 0x36 => Self::Stgaa,
            0x37 => Self::Sttaa, 0x38 => Self::Ldls, 0x39 => Self::Stls,
            0x3a => Self::Allocs, 0x3b => Self::Copys, 0x3c => Self::Stb,
            0x3d => Self::Sth, 0x3e => Self::Stw, 0x3f => Self::Stx,
            0x40 => Self::Uldsb, 0x41 => Self::Uldsh, 0x42 => Self::Uldsw,
            0x43 => Self::Uldub, 0x44 => Self::Ulduh, 0x45 => Self::Ulduw,
            0x46 => Self::Uldx, 0x47 => Self::Rldsb, 0x48 => Self::Rldsh,
            0x49 => Self::Rldsw, 0x4a => Self::Rldub, 0x4b => Self::Rlduh,
            0x4c => Self::Rlduw, 0x4d => Self::Rldx, 0x4e => Self::Xlate,
            0x4f => Self::Xlarg,
            other => return Err(LowerError::UnknownDifOp(other)),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Insn {
    pub op: DifOp,
    pub r1: u8,
    pub r2: u8,
    pub rd: u8,
}

/// Decode a DIF bytecode buffer into a fixed-size iterator. The buffer
/// is expected to be a multiple of 4 bytes; remainder bytes cause
/// `TruncatedDif`.
pub fn decode<'a>(bytecode: &'a [u8]) -> Result<InsnIter<'a>, LowerError> {
    if bytecode.len() % 4 != 0 {
        return Err(LowerError::TruncatedDif);
    }
    Ok(InsnIter { bytes: bytecode, pos: 0 })
}

#[derive(Debug)]
pub struct InsnIter<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for InsnIter<'a> {
    type Item = Result<Insn, LowerError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.bytes.len() {
            return None;
        }
        if self.pos + 4 > self.bytes.len() {
            return Some(Err(LowerError::TruncatedDif));
        }
        let raw = &self.bytes[self.pos..self.pos + 4];
        self.pos += 4;
        match DifOp::from_u8(raw[0]) {
            Ok(op) => Some(Ok(Insn { op, r1: raw[1], r2: raw[2], rd: raw[3] })),
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nop_ret() {
        // NOP, RET %r0
        let prog = [0x24, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00];
        let mut it = decode(&prog).unwrap();
        assert_eq!(it.next().unwrap().unwrap().op, DifOp::Nop);
        assert_eq!(it.next().unwrap().unwrap().op, DifOp::Ret);
        assert!(it.next().is_none());
    }

    #[test]
    fn rejects_truncated() {
        let prog = [0x24, 0x00, 0x00];
        assert_eq!(decode(&prog).unwrap_err(), LowerError::TruncatedDif);
    }

    #[test]
    fn unknown_opcode_surfaced() {
        let prog = [0xfe, 0x00, 0x00, 0x00];
        let mut it = decode(&prog).unwrap();
        match it.next().unwrap().unwrap_err() {
            LowerError::UnknownDifOp(0xfe) => {}
            other => panic!("expected UnknownDifOp(0xfe), got {:?}", other),
        }
    }
}
