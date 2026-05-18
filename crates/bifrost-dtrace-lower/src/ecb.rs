// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// ECB (Enabling Control Block) descriptors + action-chain walker.
//
// One ECB binds a probe-description to an action chain (and an
// optional predicate DIFO). libdtrace lays them out as:
//
//   SectKind::EcbDesc rows reference:
//     - a SectKind::ProbeDesc row (provider:module:function:name)
//     - a predicate DIFO section index (or 0)
//     - the first SectKind::ActDesc row + count
//
// `parse_ecb` decodes one row; the session walker iterates the table
// section's `entsize`-divided byte slice.

use crate::LowerError;
use crate::action::{ActionDescriptor, parse_action};
use crate::dof::{DofView, SectKind};

/// One `dof_ecbdesc_t` row.
#[derive(Debug, Clone, Copy)]
pub struct EcbDescriptor {
    /// Section index of the matching ProbeDesc row.
    pub probe_section: u32,
    /// Index of this ECB's row inside the probe-desc table.
    pub probe_index: u32,
    /// Section index of the predicate DIFO, or 0 if none.
    pub pred_section: u32,
    /// Section index of the action table (`SectKind::ActDesc`).
    pub action_section: u32,
    /// Index of the first action row.
    pub action_first: u32,
    /// Number of action rows in this chain.
    pub action_count: u32,
}

pub fn parse_ecb(raw: &[u8]) -> Result<EcbDescriptor, LowerError> {
    // Canonical libdtrace layout (24 bytes packed; macOS pads to 32):
    //   u32 dofe_probes        (probe-desc section index)
    //   u32 dofe_pred          (predicate DIFO section index)
    //   u32 dofe_actions       (act-desc section index)
    //   u32 dofe_uarg          (libdtrace use; ignored here)
    //   u32 dofe_first         (first action row)
    //   u32 dofe_count         (action row count)
    if raw.len() < 24 {
        return Err(LowerError::TruncatedDif);
    }
    let probe_section = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let pred_section = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let action_section = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    // raw[12..16] = dofe_uarg, not needed for adaptation.
    let action_first = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
    let action_count = u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]);
    Ok(EcbDescriptor {
        probe_section,
        probe_index: 0,
        pred_section,
        action_section,
        action_first,
        action_count,
    })
}

/// Iterate all ECBs declared in a DOF blob. Yields one
/// `EcbDescriptor` per row across every `SectKind::EcbDesc` section.
pub fn iter_ecbs<'a>(view: &'a DofView<'a>) -> EcbIter<'a> {
    EcbIter {
        view,
        next_section: 0,
        current_payload: None,
        cursor: 0,
        entsize: 0,
    }
}

pub struct EcbIter<'a> {
    view: &'a DofView<'a>,
    next_section: u32,
    current_payload: Option<&'a [u8]>,
    cursor: usize,
    entsize: usize,
}

impl<'a> Iterator for EcbIter<'a> {
    type Item = Result<EcbDescriptor, LowerError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If we have an open section, try to emit the next row.
            if let Some(payload) = self.current_payload {
                if self.cursor + self.entsize <= payload.len() {
                    let row = &payload[self.cursor..self.cursor + self.entsize];
                    self.cursor += self.entsize;
                    return Some(parse_ecb(row));
                }
                self.current_payload = None;
            }
            // Find next ECB section.
            let count = self.view.section_count();
            while self.next_section < count {
                let idx = self.next_section;
                self.next_section += 1;
                let hdr = match self.view.section_at(idx) {
                    Some(h) => h,
                    None => continue,
                };
                if hdr.kind != SectKind::EcbDesc {
                    continue;
                }
                let payload = match self.view.section_bytes(idx) {
                    Ok(p) => p,
                    Err(e) => return Some(Err(e)),
                };
                if hdr.entsize == 0 {
                    continue;
                }
                self.current_payload = Some(payload);
                self.cursor = 0;
                self.entsize = hdr.entsize as usize;
                break;
            }
            if self.current_payload.is_none() {
                return None;
            }
        }
    }
}

/// Walk every action descriptor in one ECB chain, dispatching each row
/// into the supplied closure. Bounds-checks the action section before
/// touching the bytes.
pub fn walk_actions<'a, F>(
    view: &'a DofView<'a>,
    ecb: &EcbDescriptor,
    mut on_action: F,
) -> Result<(), LowerError>
where
    F: FnMut(u32, ActionDescriptor) -> Result<(), LowerError>,
{
    if ecb.action_count == 0 {
        return Ok(());
    }
    let section = view.section_bytes(ecb.action_section)?;
    let hdr = view
        .section_at(ecb.action_section)
        .ok_or(LowerError::SectionIndexOutOfRange {
            referenced: ecb.action_section,
            section_count: view.section_count(),
        })?;
    let entsize = hdr.entsize as usize;
    if entsize == 0 {
        return Err(LowerError::SectionEntsizeMismatch {
            section_index: ecb.action_section,
            entsize: 0,
            size: hdr.size,
        });
    }
    let first = ecb.action_first as usize;
    for i in 0..ecb.action_count {
        let row_index = first + i as usize;
        let start = row_index.checked_mul(entsize).ok_or(LowerError::CapacityExceeded {
            limit: u32::MAX,
        })?;
        if start + entsize > section.len() {
            return Err(LowerError::SectionOutOfBounds {
                section_index: ecb.action_section,
                section_offset: start as u64,
                section_size: entsize as u64,
                blob_len: section.len() as u64,
            });
        }
        let desc = parse_action(&section[start..start + entsize])?;
        on_action(i, desc)?;
    }
    Ok(())
}
