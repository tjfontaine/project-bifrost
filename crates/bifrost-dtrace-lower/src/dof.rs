// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// DOF (DTrace Object Format) parser — borrowed-slice, no_std.
//
// libdtrace emits a DOF blob describing the compiled D program. The
// canonical layout (sys/dtrace.h on illumos, macOS, FreeBSD, and the
// libdtrace-for-Linux port) is:
//
//   dof_hdr_t                    (64 bytes, magic, sect count, ...)
//   dof_sec_t[hdr.dofh_secnum]   (32 bytes each, type/offset/size)
//   <section payloads, packed>
//
// Each section is one of `SectKind::*` — most of what we care about
// here is DIFO/ECB/Provider/Probe metadata plus the constant pools
// (StrTab, IntTab). The `parse_blob` entry point returns a `DofView`
// with bounds-checked accessors; section payloads are returned as
// `&[u8]` slices so callers can layer their own typed views.

use crate::LowerError;

pub const DOF_MAG_BYTES: [u8; 4] = [0x7f, b'D', b'O', b'F'];
pub const DOF_HDR_SIZE: usize = 64;
pub const DOF_SEC_SIZE: usize = 32;

/// Canonical on-wire layout of a DOF header (`dof_hdr_t` in
/// `sys/dtrace.h` — see `/usr/include/sys/dtrace.h` on macOS,
/// `sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h` in
/// FreeBSD, and the libdtrace-for-Linux mirror).  `#[repr(C, packed)]`
/// so byte offsets are fixed regardless of the consumer's alignment
/// rules — the `const_assert` pins the size at 64 bytes so any
/// future field reshuffle fails the build instead of silently
/// shifting offsets (which is exactly what bit us before this
/// refactor).  Always decode via `core::ptr::read_unaligned` because
/// DOF blobs are not guaranteed to be 8-byte aligned in the SHMEM
/// session arena.
///
/// FOLLOW-UP: replace this hand-rolled struct with a bindgen output
/// from `sys/dtrace.h` so the layout is owned by libdtrace, not us.
/// The struct is small enough (10 fields) that hand-rolling is
/// tolerable in the short term as long as the const-assert holds.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct DofHeaderRaw {
    /// `dofh_ident[16]` — the leading magic + per-byte metadata
    /// (model, encoding, version, difvers, difireg, diftreg) plus
    /// six reserved bytes.  Treated as opaque here; access magic
    /// via `ident[0..4]`.
    pub ident: [u8; 16],
    pub flags: u32,
    pub hdrsize: u32,
    pub secsize: u32,
    pub secnum: u32,
    pub secoff: u64,
    pub loadsz: u64,
    pub filesz: u64,
    /// `dofh_pad` — trailing u64 reserved by the canonical header.
    pub _pad: u64,
}
const _: () = assert!(core::mem::size_of::<DofHeaderRaw>() == DOF_HDR_SIZE);

/// Canonical on-wire layout of a DOF section header (`dof_sec_t`).
/// Same packed-struct + const-assert discipline as `DofHeaderRaw`.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct DofSectionRaw {
    pub kind: u32,
    pub align: u32,
    pub flags: u32,
    pub entsize: u32,
    pub offset: u64,
    pub size: u64,
}
const _: () = assert!(core::mem::size_of::<DofSectionRaw>() == DOF_SEC_SIZE);

/// DOF section type codes from `sys/dtrace.h`. The numeric values are
/// fixed by libdtrace; do not renumber.
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
    Prexport = 25,
    PrenOffs = 26,
    /// Anything we don't model yet. The numeric tag is preserved on
    /// `SectionHeader::kind_raw` so the caller can still reason about
    /// drift without us shipping a new enum variant.
    Other = 0xffff_ffff,
}

impl SectKind {
    pub fn from_u32(v: u32) -> Self {
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
            25 => Self::Prexport,
            26 => Self::PrenOffs,
            _ => Self::Other,
        }
    }
}

/// One row of the DOF section table.
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub kind: SectKind,
    pub kind_raw: u32,
    pub flags: u32,
    pub align: u32,
    pub entsize: u32,
    pub offset: u64,
    pub size: u64,
}

/// A bounds-checked view over a DOF blob. Construct via `parse_blob`.
/// The view borrows the input slice; no copies, no allocation.
#[derive(Debug)]
pub struct DofView<'a> {
    blob: &'a [u8],
    sections: &'a [u8],
    section_count: u32,
}

impl<'a> DofView<'a> {
    pub fn section_count(&self) -> u32 {
        self.section_count
    }

    pub fn blob(&self) -> &'a [u8] {
        self.blob
    }

    /// Iterate the parsed section headers in declaration order.
    pub fn sections(&self) -> SectionIter<'a> {
        SectionIter {
            blob: self.sections,
            remaining: self.section_count,
            index: 0,
        }
    }

    /// Return the payload bytes for a section by index, with bounds
    /// checked against the blob. Section payload offsets are absolute
    /// from the start of the blob (canonical libdtrace layout).
    pub fn section_bytes(&self, index: u32) -> Result<&'a [u8], LowerError> {
        let hdr = self
            .section_at(index)
            .ok_or(LowerError::SectionIndexOutOfRange {
                referenced: index,
                section_count: self.section_count,
            })?;
        let off = hdr.offset as usize;
        let size = hdr.size as usize;
        if off.checked_add(size).map(|end| end > self.blob.len()) != Some(false) {
            return Err(LowerError::SectionOutOfBounds {
                section_index: index,
                section_offset: hdr.offset,
                section_size: hdr.size,
                blob_len: self.blob.len() as u64,
            });
        }
        if hdr.entsize != 0 && hdr.size % (hdr.entsize as u64) != 0 {
            return Err(LowerError::SectionEntsizeMismatch {
                section_index: index,
                entsize: hdr.entsize,
                size: hdr.size,
            });
        }
        Ok(&self.blob[off..off + size])
    }

    pub fn section_at(&self, index: u32) -> Option<SectionHeader> {
        if index >= self.section_count {
            return None;
        }
        let base = (index as usize) * DOF_SEC_SIZE;
        let raw = self.sections.get(base..base + DOF_SEC_SIZE)?;
        Some(parse_section_header(raw))
    }
}

pub struct SectionIter<'a> {
    blob: &'a [u8],
    remaining: u32,
    index: u32,
}

impl<'a> Iterator for SectionIter<'a> {
    type Item = (u32, SectionHeader);
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let base = (self.index as usize) * DOF_SEC_SIZE;
        let raw = self.blob.get(base..base + DOF_SEC_SIZE)?;
        let hdr = parse_section_header(raw);
        let i = self.index;
        self.index += 1;
        self.remaining -= 1;
        Some((i, hdr))
    }
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

fn parse_section_header(raw: &[u8]) -> SectionHeader {
    // Layout: u32 dofs_type, u32 dofs_align, u32 dofs_flags, u32 dofs_entsize,
    //         u64 dofs_offset, u64 dofs_size.
    let kind_raw = read_u32_le(raw, 0).unwrap_or(0);
    let align = read_u32_le(raw, 4).unwrap_or(0);
    let flags = read_u32_le(raw, 8).unwrap_or(0);
    let entsize = read_u32_le(raw, 12).unwrap_or(0);
    let offset = read_u64_le(raw, 16).unwrap_or(0);
    let size = read_u64_le(raw, 24).unwrap_or(0);
    SectionHeader {
        kind: SectKind::from_u32(kind_raw),
        kind_raw,
        flags,
        align,
        entsize,
        offset,
        size,
    }
}

/// Read a `DofHeaderRaw` from the start of `blob` without assuming
/// alignment. The const-assert in the struct definition guarantees
/// the on-wire layout matches `dof_hdr_t`.
pub fn read_header(blob: &[u8]) -> Option<DofHeaderRaw> {
    if blob.len() < DOF_HDR_SIZE {
        return None;
    }
    // SAFETY: `DofHeaderRaw` is `#[repr(C, packed)]` so the layout
    // is byte-for-byte the on-wire shape; the size assert ensures
    // we read exactly DOF_HDR_SIZE bytes; `read_unaligned` makes the
    // call sound for any input alignment.
    Some(unsafe { core::ptr::read_unaligned(blob.as_ptr() as *const DofHeaderRaw) })
}

/// Read a `DofSectionRaw` from `blob[off..]`. Returns `None` if `off`
/// + `DOF_SEC_SIZE` exceeds the slice.
pub fn read_section(blob: &[u8], off: usize) -> Option<DofSectionRaw> {
    if off.checked_add(DOF_SEC_SIZE)? > blob.len() {
        return None;
    }
    // SAFETY: bounds-checked above; struct is `#[repr(C, packed)]`.
    Some(unsafe {
        core::ptr::read_unaligned(blob.as_ptr().add(off) as *const DofSectionRaw)
    })
}

/// Parse the DOF header + section table. Does not walk sections.
pub fn parse_blob(blob: &[u8]) -> Result<DofView<'_>, LowerError> {
    if blob.len() < DOF_HDR_SIZE {
        return Err(LowerError::ShortHeader);
    }
    let hdr = read_header(blob).ok_or(LowerError::ShortHeader)?;
    if hdr.ident[0..4] != DOF_MAG_BYTES {
        return Err(LowerError::BadMagic);
    }
    // `packed` fields can't be borrowed directly — copy into local
    // u-typed bindings so usage stays trivially aligned.
    let sec_size = hdr.secsize;
    let sec_num = hdr.secnum;
    let sec_off = hdr.secoff;
    if sec_size as usize != DOF_SEC_SIZE {
        return Err(LowerError::ShortHeader);
    }
    let sec_off_usize = sec_off as usize;
    let table_bytes = (sec_num as usize)
        .checked_mul(DOF_SEC_SIZE)
        .ok_or(LowerError::ShortHeader)?;
    let end = sec_off_usize
        .checked_add(table_bytes)
        .ok_or(LowerError::ShortHeader)?;
    if end > blob.len() {
        return Err(LowerError::ShortHeader);
    }
    Ok(DofView {
        blob,
        sections: &blob[sec_off_usize..end],
        section_count: sec_num,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_minimal_dof() -> [u8; 96] {
        // Smallest legal DOF: one zero section at offset 64. Not a
        // valid program, but it exercises the parser bounds.
        // Build via the packed struct so the offsets stay correct
        // even if `DofHeaderRaw` field order changes (the const
        // assert keeps the total size pinned).
        let mut blob = [0u8; 96];
        let hdr = DofHeaderRaw {
            ident: {
                let mut id = [0u8; 16];
                id[0..4].copy_from_slice(&DOF_MAG_BYTES);
                id
            },
            flags: 0,
            hdrsize: DOF_HDR_SIZE as u32,
            secsize: DOF_SEC_SIZE as u32,
            secnum: 1,
            secoff: 64,
            loadsz: 0,
            filesz: 0,
            _pad: 0,
        };
        unsafe {
            core::ptr::write_unaligned(blob.as_mut_ptr() as *mut DofHeaderRaw, hdr);
        }
        // Section 0 header at offset 64: zero everything (SectKind::None).
        blob
    }

    #[test]
    fn parses_minimal_dof() {
        let blob = synth_minimal_dof();
        let view = parse_blob(&blob).expect("minimal DOF parses");
        assert_eq!(view.section_count(), 1);
        let hdr = view.section_at(0).expect("section 0 visible");
        assert_eq!(hdr.kind, SectKind::None);
    }

    #[test]
    fn rejects_short_blob() {
        let blob = [0u8; 16];
        assert_eq!(parse_blob(&blob).unwrap_err(), LowerError::ShortHeader);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = [0u8; 96];
        // Right size, wrong magic.
        blob[0..4].copy_from_slice(b"XXXX");
        assert_eq!(parse_blob(&blob).unwrap_err(), LowerError::BadMagic);
    }

    #[test]
    fn section_out_of_bounds_caught() {
        // Manufacture a DOF whose only section claims a 16 MB payload
        // starting past the blob end.
        let mut blob = [0u8; 96];
        let hdr = DofHeaderRaw {
            ident: {
                let mut id = [0u8; 16];
                id[0..4].copy_from_slice(&DOF_MAG_BYTES);
                id
            },
            flags: 0,
            hdrsize: DOF_HDR_SIZE as u32,
            secsize: DOF_SEC_SIZE as u32,
            secnum: 1,
            secoff: 64,
            loadsz: 0,
            filesz: 0,
            _pad: 0,
        };
        unsafe {
            core::ptr::write_unaligned(blob.as_mut_ptr() as *mut DofHeaderRaw, hdr);
        }
        // Section claims size = 0x1_0000_0000 (overflow) at offset 0xdead.
        blob[64 + 16..64 + 24].copy_from_slice(&0xdead_u64.to_le_bytes());
        blob[64 + 24..64 + 32].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
        let view = parse_blob(&blob).expect("header still parses");
        let err = view.section_bytes(0).unwrap_err();
        match err {
            LowerError::SectionOutOfBounds { .. } => {}
            other => panic!("expected out-of-bounds, got {:?}", other),
        }
    }
}
