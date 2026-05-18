// SPDX-License-Identifier: Apache-2.0
//! DOF / DIF parser for project-bifrost.
//!
//! libdtrace on macOS produces a DOF (DTrace Object Format) blob from a
//! compiled D program. The interesting payload is the DIF bytecode, which
//! is what the lowering compiler will translate to eBPF (or to our own
//! interpreter for residue ops). This module reads the DOF byte layout
//! described in /usr/include/sys/dtrace.h and surfaces it as Rust types.
//!
//! Only the sections we need are typed — others are surfaced raw with
//! their kind tag so the caller can ignore or extend.

#![allow(dead_code)]

use std::convert::TryInto;

pub mod backend;
#[cfg(target_os = "macos")]
pub mod btf;
pub mod cli;
pub mod control_shmem;
#[cfg(target_os = "macos")]
pub mod dtrace_consumer;
pub mod dtrace_ffi;
pub mod elf_syms;

pub mod logging;
pub mod lower;
pub mod merge;
pub mod parse;
pub mod plan;
pub mod schema;
#[cfg(target_os = "macos")]
pub mod translators;
pub mod vdso;
pub mod verify;

pub const DOF_MAG_STRING: &[u8] = b"\x7fDOF";
pub const DOF_HDR_SIZE: usize = 64;
pub const DOF_SEC_SIZE: usize = 32;

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DOF parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// `enum dof_secidx_t` — DOF section type codes from sys/dtrace.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SectKind {
    None = 0,
    Comments = 1,
    Source = 2,
    EcbDesc = 3,
    ProbeDesc = 4,
    ActDesc = 5,
    DifoHdr = 6,
    Dif = 7,
    StrTab = 8,
    VarTab = 9,
    RelTab = 10,
    TypTab = 11,
    UrelHdr = 12,
    KrelHdr = 13,
    OptDesc = 14,
    Provider = 15,
    Probes = 16,
    PrArgs = 17,
    PrOffs = 18,
    IntTab = 19,
    UtsName = 20,
    XlTab = 21,
    XlMembers = 22,
    XlImport = 23,
    XlExport = 24,
    PrExport = 25,
    PrEnoffs = 26,
    Other(u32),
}

impl SectKind {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Comments,
            2 => Self::Source,
            3 => Self::EcbDesc,
            4 => Self::ProbeDesc,
            5 => Self::ActDesc,
            6 => Self::DifoHdr,
            7 => Self::Dif,
            8 => Self::StrTab,
            9 => Self::VarTab,
            10 => Self::RelTab,
            11 => Self::TypTab,
            12 => Self::UrelHdr,
            13 => Self::KrelHdr,
            14 => Self::OptDesc,
            15 => Self::Provider,
            16 => Self::Probes,
            17 => Self::PrArgs,
            18 => Self::PrOffs,
            19 => Self::IntTab,
            20 => Self::UtsName,
            21 => Self::XlTab,
            22 => Self::XlMembers,
            23 => Self::XlImport,
            24 => Self::XlExport,
            25 => Self::PrExport,
            26 => Self::PrEnoffs,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DofHeader {
    pub flags: u32,
    pub hdrsize: u32,
    pub secsize: u32,
    pub secnum: u32,
    pub secoff: u64,
    pub loadsz: u64,
    pub filesz: u64,
}

#[derive(Debug, Clone)]
pub struct DofSection {
    pub kind: SectKind,
    pub align: u32,
    pub flags: u32,
    pub entsize: u32,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct Dof<'a> {
    pub header: DofHeader,
    pub sections: Vec<DofSection>,
    raw: &'a [u8],
}

impl<'a> Dof<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, ParseError> {
        if raw.len() < DOF_HDR_SIZE {
            return Err(ParseError(format!("input too short: {} bytes", raw.len())));
        }
        if &raw[0..4] != DOF_MAG_STRING {
            return Err(ParseError(format!("bad DOF magic: {:?}", &raw[0..4])));
        }
        let header = DofHeader {
            flags: u32_at(raw, 16)?,
            hdrsize: u32_at(raw, 20)?,
            secsize: u32_at(raw, 24)?,
            secnum: u32_at(raw, 28)?,
            secoff: u64_at(raw, 32)?,
            loadsz: u64_at(raw, 40)?,
            filesz: u64_at(raw, 48)?,
        };
        if header.secsize as usize != DOF_SEC_SIZE {
            return Err(ParseError(format!(
                "unexpected section header size {}, want {}",
                header.secsize, DOF_SEC_SIZE
            )));
        }
        let mut sections = Vec::with_capacity(header.secnum as usize);
        for i in 0..header.secnum as usize {
            let off = header.secoff as usize + i * DOF_SEC_SIZE;
            sections.push(DofSection {
                kind: SectKind::from_u32(u32_at(raw, off)?),
                align: u32_at(raw, off + 4)?,
                flags: u32_at(raw, off + 8)?,
                entsize: u32_at(raw, off + 12)?,
                offset: u64_at(raw, off + 16)?,
                size: u64_at(raw, off + 24)?,
            });
        }
        Ok(Dof {
            header,
            sections,
            raw,
        })
    }

    /// Bytes of a section (within the DOF blob).
    pub fn section_bytes(&self, sec: &DofSection) -> &'a [u8] {
        let start = sec.offset as usize;
        let end = start + sec.size as usize;
        &self.raw[start..end]
    }

    /// Iterate (index, &section) for sections of a given kind.
    pub fn sections_of(&self, kind: SectKind) -> impl Iterator<Item = (usize, &DofSection)> {
        self.sections
            .iter()
            .enumerate()
            .filter(move |(_, s)| s.kind == kind)
    }

    /// Decode a SECT_DIF section's bytecode as 32-bit little-endian instructions.
    pub fn dif_instructions(&self, sec: &DofSection) -> Vec<DifInstr> {
        let bytes = self.section_bytes(sec);
        bytes
            .chunks_exact(4)
            .map(|c| {
                let raw = u32::from_ne_bytes(c.try_into().unwrap());
                DifInstr::decode(raw)
            })
            .collect()
    }
}

/// Decoded DIF instruction. Per `DIF_INSTR_FMT(op, r1, r2, rd)` in
/// sys/dtrace.h the byte layout high-to-low is:
///   31:24 op | 23:16 r1 | 15:8 r2 | 7:0 rd
/// SETX/SETS combine `r1+r2` (bits 23:8) into a 16-bit table index;
/// `rd` is always the destination register in the low byte.
#[derive(Debug, Clone, Copy)]
pub struct DifInstr {
    pub raw: u32,
    pub op: u8,
    pub r1: u8,
    pub r2: u8,
    pub rd: u8,
}

impl DifInstr {
    pub fn decode(raw: u32) -> Self {
        DifInstr {
            raw,
            op: ((raw >> 24) & 0xff) as u8,
            r1: ((raw >> 16) & 0xff) as u8,
            r2: ((raw >> 8) & 0xff) as u8,
            rd: (raw & 0xff) as u8,
        }
    }

    /// Combined 16-bit table index (bits 23:8). Used by SETX, SETS,
    /// CALL — fields where the low byte is `rd` and the index lives in
    /// the middle two bytes.
    pub fn imm16(&self) -> u16 {
        ((self.r1 as u16) << 8) | self.r2 as u16
    }

    /// 24-bit branch label (bits 23:0). DIF's `DIF_INSTR_BRANCH(op, label)`
    /// macro packs `label` into the low 24 bits of the instruction —
    /// for small programs this is just the `rd` byte, but anything past
    /// 256 instructions needs the full 24-bit decode.
    pub fn branch_target(&self) -> u32 {
        ((self.r1 as u32) << 16) | ((self.r2 as u32) << 8) | self.rd as u32
    }

    /// Mnemonic, if recognized. Codes from sys/dtrace.h.
    pub fn mnemonic(&self) -> &'static str {
        match self.op {
            0x01 => "OR",
            0x02 => "XOR",
            0x03 => "AND",
            0x04 => "SLL",
            0x05 => "SRL",
            0x06 => "SUB",
            0x07 => "ADD",
            0x08 => "MUL",
            0x09 => "SDIV",
            0x0a => "UDIV",
            0x0b => "SREM",
            0x0c => "UREM",
            0x0d => "NOT",
            0x0e => "MOV",
            0x0f => "CMP",
            0x10 => "TST",
            0x11 => "BA",
            0x12 => "BE",
            0x13 => "BNE",
            0x14 => "BG",
            0x15 => "BGU",
            0x16 => "BGE",
            0x17 => "BGEU",
            0x18 => "BL",
            0x19 => "BLU",
            0x1a => "BLE",
            0x1b => "BLEU",
            0x1c => "LDSB",
            0x1d => "LDSH",
            0x1e => "LDSW",
            0x1f => "LDUB",
            0x20 => "LDUH",
            0x21 => "LDUW",
            0x22 => "LDX",
            0x23 => "RET",
            0x24 => "NOP",
            0x25 => "SETX",
            0x26 => "SETS",
            0x27 => "SCMP",
            0x28 => "LDGA",
            0x29 => "LDGS",
            0x2a => "STGS",
            0x2b => "LDTA",
            0x2c => "LDTS",
            0x2d => "STTS",
            0x2e => "SRA",
            0x2f => "CALL",
            0x30 => "PUSHTR",
            0x31 => "PUSHTV",
            0x32 => "POPTS",
            0x33 => "FLUSHTS",
            0x34 => "LDGAA",
            0x35 => "LDTAA",
            0x36 => "STGAA",
            0x37 => "STTAA",
            0x38 => "LDLS",
            0x39 => "STLS",
            0x3a => "ALLOCS",
            0x3b => "COPYS",
            0x3c => "STB",
            0x3d => "STH",
            0x3e => "STW",
            0x3f => "STX",
            0x40 => "ULDSB",
            0x41 => "ULDSH",
            0x42 => "ULDSW",
            0x43 => "ULDUB",
            0x44 => "ULDUH",
            0x45 => "ULDUW",
            0x46 => "ULDX",
            0x47 => "RLDSB",
            0x48 => "RLDSH",
            0x49 => "RLDSW",
            0x4a => "RLDUB",
            0x4b => "RLDUH",
            0x4c => "RLDUW",
            0x4d => "RLDX",
            0x4e => "XLATE",
            0x4f => "XLARG",
            _ => "?",
        }
    }
}

fn u32_at(buf: &[u8], off: usize) -> Result<u32, ParseError> {
    buf.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or_else(|| ParseError(format!("u32 read OOB at {}", off)))
}

fn u64_at(buf: &[u8], off: usize) -> Result<u64, ParseError> {
    buf.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_ne_bytes)
        .ok_or_else(|| ParseError(format!("u64 read OOB at {}", off)))
}

/// Sentinel for a missing section reference (DOF_SECIDX_NONE).
pub const DOF_SECIDX_NONE: u32 = !0u32;

/// `dof_ecbdesc_t` — Enabled Control Block descriptor. Links a probe
/// description to an optional predicate DIFO and a chain of actions.
#[derive(Debug, Clone)]
pub struct Ecb {
    pub probes: u32,  // section index of DOF_SECT_PROBEDESC
    pub pred: u32,    // section index of DOF_SECT_DIFOHDR (or DOF_SECIDX_NONE)
    pub actions: u32, // section index of DOF_SECT_ACTDESC (first in chain)
    pub uarg: u64,
}

impl Ecb {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 24 {
            return Err(ParseError("ECBDESC too short".into()));
        }
        Ok(Ecb {
            probes: u32_at(bytes, 0)?,
            pred: u32_at(bytes, 4)?,
            actions: u32_at(bytes, 8)?,
            // bytes 12..16 = pad
            uarg: u64_at(bytes, 16)?,
        })
    }
}

/// `dof_actdesc_t` — one action in an ECB's action chain. The chain is
/// stored as a flat array in the DOF_SECT_ACTDESC section; subsequent
/// actions live at successive 32-byte offsets within the same section.
#[derive(Debug, Clone)]
pub struct Action {
    pub difo: u32, // section index of DOF_SECT_DIFOHDR (or DOF_SECIDX_NONE)
    pub strtab: u32,
    pub kind: u32, // DTRACEACT_* constant
    pub ntuple: u32,
    pub arg: u64,
    pub uarg: u64,
}

impl Action {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 32 {
            return Err(ParseError("ACTDESC too short".into()));
        }
        Ok(Action {
            difo: u32_at(bytes, 0)?,
            strtab: u32_at(bytes, 4)?,
            kind: u32_at(bytes, 8)?,
            ntuple: u32_at(bytes, 12)?,
            arg: u64_at(bytes, 16)?,
            uarg: u64_at(bytes, 24)?,
        })
    }
}

/// `dof_difohdr_t` — the link record for a DIFO. Followed by an array
/// of `dof_secidx_t` entries (`dofd_links[]`) pointing to the DIF, the
/// inttab, the strtab, the vartab, etc. The number of links is implied
/// by the section's total size minus the 8-byte type header.
#[derive(Debug, Clone)]
pub struct Difo {
    /// Indices into the DOF section table; semantics depend on the
    /// kernel's DIFO loader. Empirically, dofd_links[0] is the DIF
    /// section and remaining indices reference inttab, strtab, vartab.
    pub links: Vec<u32>,
    /// `dtdt_size` field from the `dtrace_diftype_t` prefix — the
    /// return type's byte width.  Used by `tracemem(addr, len)`
    /// where Apple's libdtrace stashes `len` here rather than in
    /// `action.arg`; OpenDTrace put it in `arg`, but Apple's
    /// libdtrace encodes it on the DIFO type instead.
    pub rtype_size: u32,
    /// `dtdt_kind` (DIF_TYPE_CTF=0, DIF_TYPE_STRING=1).
    pub rtype_kind: u8,
}

impl Difo {
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError("DIFOHDR too short".into()));
        }
        // Apple's dtrace_diftype_t is 8 bytes:
        //   [u8 kind][u8 ckind][u8 flags][u8 pad][u32 size]
        // Remainder is the dofd_links[] array of u32 section indices.
        let rtype_kind = bytes[0];
        let rtype_size = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let links_bytes = &bytes[8..];
        if !links_bytes.len().is_multiple_of(4) {
            return Err(ParseError(format!(
                "DIFOHDR links region not a multiple of 4: {}",
                links_bytes.len()
            )));
        }
        let links = links_bytes
            .chunks_exact(4)
            .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
            .collect();
        Ok(Difo {
            links,
            rtype_size,
            rtype_kind,
        })
    }

    /// First link is the DIF bytecode section.
    pub fn dif_section(&self) -> Option<u32> {
        self.links.first().copied()
    }

    /// Find the DIFO's IntTab section by walking links and matching by
    /// kind. Each DIFO has its own IntTab; clauses with both a
    /// predicate and an action have TWO inttabs that must not alias —
    /// the predicate's `arg1 != 0` puts {0, 1} in its inttab, while
    /// the action's `count()` value DIF puts {1} in its own inttab.
    /// SETX imm16 indexes per-DIFO, not globally.
    pub fn inttab_section_in(&self, dof: &Dof) -> Option<u32> {
        for &idx in &self.links {
            if let Some(sec) = dof.sections.get(idx as usize)
                && sec.kind == SectKind::IntTab
            {
                return Some(idx);
            }
        }
        None
    }

    /// Find the DIFO's StrTab section by walking links and matching
    /// by kind. SETS uses imm16 as a byte offset into this strtab.
    /// libdtrace builds one strtab per DIFO containing every string
    /// literal the bytecode references; the string at offset N starts
    /// at strtab[N] and runs to the next NUL.
    pub fn strtab_section_in(&self, dof: &Dof) -> Option<u32> {
        for &idx in &self.links {
            if let Some(sec) = dof.sections.get(idx as usize)
                && sec.kind == SectKind::StrTab
            {
                return Some(idx);
            }
        }
        None
    }
}

impl<'a> Dof<'a> {
    /// Find the first ECB descriptor in this DOF.  Retained for
    /// single-ECB call sites; use [`Dof::all_ecbs`] when a clause
    /// may have produced more than one ECB.
    pub fn first_ecb(&self) -> Option<Ecb> {
        let (_, sec) = self.sections_of(SectKind::EcbDesc).next()?;
        Ecb::parse(self.section_bytes(sec)).ok()
    }

    /// Every ECB descriptor in this DOF, in section order.  libdtrace
    /// emits one ECB per probe-clause (and one per probe inside a
    /// clause that names multiple probes), so a D script with several
    /// clauses produces several ECBs that all need to be drained for
    /// faithful DTrace semantics.
    pub fn all_ecbs(&self) -> Vec<Ecb> {
        self.sections_of(SectKind::EcbDesc)
            .filter_map(|(_, sec)| Ecb::parse(self.section_bytes(sec)).ok())
            .collect()
    }

    /// Walk the ACTDESC chain starting at section `start_sec_idx`. The
    /// chain is the entries within that single section, packed back-to-back.
    pub fn actions_in_chain(&self, start_sec_idx: u32) -> Vec<Action> {
        if start_sec_idx == DOF_SECIDX_NONE {
            return Vec::new();
        }
        let Some(sec) = self.sections.get(start_sec_idx as usize) else {
            return Vec::new();
        };
        if sec.kind != SectKind::ActDesc {
            return Vec::new();
        }
        let bytes = self.section_bytes(sec);
        bytes
            .chunks_exact(32)
            .filter_map(|c| Action::parse(c).ok())
            .collect()
    }

    /// Look up a DIFOHDR section by index and parse it.
    pub fn difo(&self, sec_idx: u32) -> Option<Difo> {
        if sec_idx == DOF_SECIDX_NONE {
            return None;
        }
        let sec = self.sections.get(sec_idx as usize)?;
        if sec.kind != SectKind::DifoHdr {
            return None;
        }
        Difo::parse(self.section_bytes(sec)).ok()
    }

    /// Parse every probe descriptor in a DOF_SECT_PROBEDESC section.
    ///
    /// Each `dof_probedesc_t` is 24 bytes:
    ///     [secidx strtab][stridx provider][stridx mod]
    ///     [stridx func ][stridx name    ][u32    id ]
    /// Strings are resolved against the referenced strtab.  Used by
    /// the FreeBSD native backend's host-side preflight so we can
    /// reject `fbt:/syscall:/profile:` etc. with a useful message
    /// while the kernel wrapper still only handles `dtrace:::BEGIN`.
    pub fn probe_descs(&self, sec_idx: u32) -> Vec<ProbeDescTuple> {
        if sec_idx == DOF_SECIDX_NONE {
            return Vec::new();
        }
        let Some(sec) = self.sections.get(sec_idx as usize) else {
            return Vec::new();
        };
        if sec.kind != SectKind::ProbeDesc {
            return Vec::new();
        }
        let bytes = self.section_bytes(sec);
        let mut out = Vec::new();
        for chunk in bytes.chunks_exact(24) {
            let Ok(strtab_idx) = u32_at(chunk, 0) else {
                continue;
            };
            let Ok(prov) = u32_at(chunk, 4) else {
                continue;
            };
            let Ok(modn) = u32_at(chunk, 8) else {
                continue;
            };
            let Ok(func) = u32_at(chunk, 12) else {
                continue;
            };
            let Ok(name) = u32_at(chunk, 16) else {
                continue;
            };
            let Ok(id) = u32_at(chunk, 20) else {
                continue;
            };
            let read_str = |stridx: u32| -> String {
                self.sections
                    .get(strtab_idx as usize)
                    .filter(|s| s.kind == SectKind::StrTab)
                    .map(|s| self.section_bytes(s))
                    .and_then(|tab| {
                        let start = stridx as usize;
                        if start >= tab.len() {
                            return None;
                        }
                        let end = tab[start..]
                            .iter()
                            .position(|&b| b == 0)
                            .map(|p| start + p)
                            .unwrap_or(tab.len());
                        std::str::from_utf8(&tab[start..end]).ok().map(str::to_owned)
                    })
                    .unwrap_or_default()
            };
            out.push(ProbeDescTuple {
                provider: read_str(prov),
                module: read_str(modn),
                function: read_str(func),
                name: read_str(name),
                id,
            });
        }
        out
    }
}

/// One probe descriptor — the four `provider:module:function:name`
/// strings the user wrote (or libdtrace expanded), plus the runtime
/// probe id (zero before kernel binding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeDescTuple {
    pub provider: String,
    pub module: String,
    pub function: String,
    pub name: String,
    pub id: u32,
}

impl ProbeDescTuple {
    pub fn render(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.provider, self.module, self.function, self.name
        )
    }
}
