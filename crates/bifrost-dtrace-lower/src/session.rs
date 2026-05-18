// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
//
// Session driver — walks a parsed DOF blob and dispatches each ECB +
// action into a `KernelAdapter`.
//
// This is the canonical reference implementation. Each guest's adapter
// is allowed to drive the walker differently (e.g. batching attaches,
// pre-resolving symbols), but the default driver guarantees:
//
//   1. Each ECB's `provider_supports` is checked before any DIFO work.
//   2. Attached probes are tracked so `detach_all` can clean them up
//      even after partial-failure attaches.
//   3. Action-walk errors are converted to `EcbStatus::Rejected`
//      rather than aborting the whole session — the goal is "every
//      ECB gets a verdict the host can fanout".
//
// Heap usage is gated on the `alloc` feature. Without `alloc` the
// caller must drive the walker manually via `walk_ecb` and supply its
// own per-ECB status buffer.

use crate::LowerError;
use crate::action::ActionKind;
use crate::adapter::{EcbStatus, KernelAdapter, ProbeTarget, RejectReason, SessionEvent};
use crate::dof::{DofView, SectKind};
use crate::ecb::{EcbDescriptor, iter_ecbs, walk_actions};

/// Drive `adapter` against every ECB in `view`. Returns the number of
/// ECBs that were accepted; per-ECB verdicts are reported through
/// `on_status`.
///
/// `on_status` is called exactly once per ECB, in declaration order,
/// with `(ecb_index, EcbStatus)`. The host's capability fanout uses
/// this to build the per-target status report sent back over SHMEM.
pub fn drive<A, F>(
    view: &DofView<'_>,
    adapter: &mut A,
    mut on_status: F,
) -> Result<u32, LowerError>
where
    A: KernelAdapter,
    F: FnMut(u32, EcbStatus),
{
    adapter.on_session_event(SessionEvent::Begin)?;
    let mut accepted = 0u32;
    let mut ecb_index = 0u32;
    for ecb in iter_ecbs(view) {
        let ecb = ecb?;
        let status = drive_one(view, adapter, &ecb)?;
        if matches!(status, EcbStatus::Accepted { .. }) {
            accepted += 1;
        }
        on_status(ecb_index, status);
        ecb_index += 1;
    }
    adapter.on_session_event(SessionEvent::End)?;
    Ok(accepted)
}

fn drive_one<A: KernelAdapter>(
    view: &DofView<'_>,
    adapter: &mut A,
    ecb: &EcbDescriptor,
) -> Result<EcbStatus, LowerError> {
    let target = match resolve_probe_target(view, ecb.probe_section, ecb.probe_index)? {
        Some(t) => t,
        None => return Ok(EcbStatus::ZeroMatch),
    };
    if !adapter.provider_supports(target.provider) {
        return Ok(EcbStatus::Rejected(RejectReason::NoProvider));
    }
    let attached_id = match adapter.attach_probe(target) {
        Ok(id) => id,
        Err(r) => return Ok(EcbStatus::Rejected(r)),
    };
    if ecb.pred_section != 0 {
        let bytes = view.section_bytes(ecb.pred_section)?;
        if let Err(r) = adapter.bind_predicate(attached_id, bytes) {
            adapter.detach_probe(attached_id);
            return Ok(EcbStatus::Rejected(r));
        }
    }
    let mut action_err: Option<RejectReason> = None;
    walk_actions(view, ecb, |_idx, action| {
        if action_err.is_some() {
            return Ok(());
        }
        // Bounce destructive actions before asking the adapter — the
        // adapter trait carries `DestructiveDisabled` for policy but
        // many adapters never opt into the work. Treat the static
        // kind check as the floor; adapters that *do* support
        // destructive actions can override `record_action` to opt in.
        if action.kind.is_destructive() {
            action_err = Some(RejectReason::DestructiveDisabled);
            return Ok(());
        }
        // Actions without an attached DIFO (commit/discard/exit)
        // have `difo_section == 0`; pass an empty slice.
        let difo_bytes = if action.difo_section == 0 {
            &[][..]
        } else {
            view.section_bytes(action.difo_section)?
        };
        match adapter.record_action(attached_id, &action, difo_bytes) {
            Ok(()) => {}
            Err(r) => action_err = Some(r),
        }
        // Aggregation sentinel actions also need the agg slot
        // declared so the adapter can pre-size buckets.
        if matches!(action.kind, ActionKind::AggSentinel) {
            let var_id = (action.arg & 0xffff_ffff) as u32;
            let kind_raw = (action.kind_raw >> 8) as u32;
            // Best-effort decode — unknown agg kinds become a reject
            // reason rather than aborting the whole session.
            if let Ok(agg_kind) = crate::agg::AggKind::from_u32(kind_raw) {
                let buckets = agg_kind.default_bucket_count();
                if let Err(r) = adapter.declare_aggregation(var_id, agg_kind, buckets) {
                    action_err.get_or_insert(r);
                }
            } else {
                action_err.get_or_insert(RejectReason::AggKindUnsupported);
            }
        }
        Ok(())
    })?;
    if let Some(r) = action_err {
        adapter.detach_probe(attached_id);
        return Ok(EcbStatus::Rejected(r));
    }
    Ok(EcbStatus::Accepted { attached_id })
}

/// Resolve the probe-desc strings for a given ECB. Returns `None` if
/// the probe row is present but its strings are empty (libdtrace
/// canonicalises this for `BEGIN`/`END`/`ERROR`; treat as a real
/// ECB by passing the empty strings through).
fn resolve_probe_target<'a>(
    view: &'a DofView<'a>,
    probe_section: u32,
    probe_index: u32,
) -> Result<Option<ProbeTarget<'a>>, LowerError> {
    let hdr = view
        .section_at(probe_section)
        .ok_or(LowerError::SectionIndexOutOfRange {
            referenced: probe_section,
            section_count: view.section_count(),
        })?;
    if hdr.kind != SectKind::ProbeDesc {
        return Err(LowerError::SectionIndexOutOfRange {
            referenced: probe_section,
            section_count: view.section_count(),
        });
    }
    let section = view.section_bytes(probe_section)?;
    let entsize = hdr.entsize as usize;
    if entsize < 16 {
        return Ok(None);
    }
    let off = (probe_index as usize)
        .checked_mul(entsize)
        .ok_or(LowerError::CapacityExceeded { limit: u32::MAX })?;
    if off + entsize > section.len() {
        return Ok(None);
    }
    let row = &section[off..off + entsize];
    // dof_probedesc_t layout (16 bytes):
    //   u32 dofp_strtab
    //   u32 dofp_provider
    //   u32 dofp_mod
    //   u32 dofp_func
    //   u32 dofp_name
    let strtab_section = u32::from_le_bytes([row[0], row[1], row[2], row[3]]);
    let provider_off = u32::from_le_bytes([row[4], row[5], row[6], row[7]]) as usize;
    let mod_off = u32::from_le_bytes([row[8], row[9], row[10], row[11]]) as usize;
    let func_off = u32::from_le_bytes([row[12], row[13], row[14], row[15]]) as usize;
    let name_off = if entsize >= 20 {
        u32::from_le_bytes([row[16], row[17], row[18], row[19]]) as usize
    } else {
        0
    };
    let strtab = view.section_bytes(strtab_section)?;
    let provider = read_cstr(strtab, provider_off);
    let module = read_cstr(strtab, mod_off);
    let function = read_cstr(strtab, func_off);
    let name = read_cstr(strtab, name_off);
    Ok(Some(ProbeTarget {
        provider,
        module,
        function,
        name,
    }))
}

fn read_cstr(buf: &[u8], off: usize) -> &str {
    if off >= buf.len() {
        return "";
    }
    let tail = &buf[off..];
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    core::str::from_utf8(&tail[..end]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::StubAdapter;
    use crate::dof::{
        DOF_HDR_SIZE, DOF_MAG_BYTES, DOF_SEC_SIZE, DofHeaderRaw, SectKind, parse_blob,
    };

    // Synthesize a DOF blob with one ECB whose probe is
    // `bifrost:guest:test:entry`, action chain is a single
    // `DTRACEACT_DIFEXPR` with an empty DIFO.
    //
    // Sections (in order):
    //   0: StrTab   — null + "bifrost\0guest\0test\0entry\0"
    //   1: ProbeDesc — one 20-byte row pointing into StrTab
    //   2: ActDesc  — one 32-byte row, kind = DifExpr (no DIFO)
    //   3: EcbDesc  — one 24-byte row referencing sections 1/2
    fn synth_one_ecb_dof() -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let strtab: alloc::vec::Vec<u8> = {
            let mut v = Vec::new();
            v.push(0); // index 0 = ""
            v.extend_from_slice(b"bifrost\0");
            v.extend_from_slice(b"guest\0");
            v.extend_from_slice(b"test\0");
            v.extend_from_slice(b"entry\0");
            v
        };
        let provider_off = 1u32;
        let module_off = 1u32 + b"bifrost\0".len() as u32;
        let function_off = module_off + b"guest\0".len() as u32;
        let name_off = function_off + b"test\0".len() as u32;

        let mut probe_row = [0u8; 20];
        probe_row[0..4].copy_from_slice(&0u32.to_le_bytes()); // strtab section index 0
        probe_row[4..8].copy_from_slice(&provider_off.to_le_bytes());
        probe_row[8..12].copy_from_slice(&module_off.to_le_bytes());
        probe_row[12..16].copy_from_slice(&function_off.to_le_bytes());
        probe_row[16..20].copy_from_slice(&name_off.to_le_bytes());

        let mut act_row = [0u8; 32];
        // dofa_difo = 0 (no DIFO bytes — adapter sees an empty slice)
        // dofa_kind low u32 at offset 8 = 1 (DifExpr)
        act_row[8..12].copy_from_slice(&1u32.to_le_bytes());

        let mut ecb_row = [0u8; 24];
        ecb_row[0..4].copy_from_slice(&1u32.to_le_bytes());   // probe section = 1
        ecb_row[4..8].copy_from_slice(&0u32.to_le_bytes());   // pred section = 0
        ecb_row[8..12].copy_from_slice(&2u32.to_le_bytes());  // action section = 2
        ecb_row[16..20].copy_from_slice(&0u32.to_le_bytes()); // first row = 0
        ecb_row[20..24].copy_from_slice(&1u32.to_le_bytes()); // row count = 1

        // Layout payload after the section table.
        let header_size = DOF_HDR_SIZE;
        let section_count = 4u32;
        let sec_table_size = (section_count as usize) * DOF_SEC_SIZE;
        let payload_start = header_size + sec_table_size;

        let mut payload: Vec<u8> = Vec::new();
        let strtab_off = payload_start as u64;
        payload.extend_from_slice(&strtab);

        let probe_off = (payload_start + payload.len()) as u64;
        payload.extend_from_slice(&probe_row);

        let act_off = (payload_start + payload.len()) as u64;
        payload.extend_from_slice(&act_row);

        let ecb_off = (payload_start + payload.len()) as u64;
        payload.extend_from_slice(&ecb_row);

        // Build the full blob via the packed struct so the offsets
        // can't drift if `DofHeaderRaw` field order changes.
        let mut blob: Vec<u8> = Vec::new();
        blob.resize(payload_start, 0);
        let hdr = DofHeaderRaw {
            ident: {
                let mut id = [0u8; 16];
                id[0..4].copy_from_slice(&DOF_MAG_BYTES);
                id
            },
            flags: 0,
            hdrsize: DOF_HDR_SIZE as u32,
            secsize: DOF_SEC_SIZE as u32,
            secnum: section_count,
            secoff: header_size as u64,
            loadsz: 0,
            filesz: 0,
            _pad: 0,
        };
        unsafe {
            core::ptr::write_unaligned(blob.as_mut_ptr() as *mut DofHeaderRaw, hdr);
        }

        // Section table — 4 rows of 32 bytes each.
        for (i, (kind, off, size, entsize)) in [
            (SectKind::StrTab, strtab_off, strtab.len() as u64, 0u32),
            (SectKind::ProbeDesc, probe_off, probe_row.len() as u64, 20u32),
            (SectKind::ActDesc, act_off, act_row.len() as u64, 32u32),
            (SectKind::EcbDesc, ecb_off, ecb_row.len() as u64, 24u32),
        ]
        .iter()
        .enumerate()
        {
            let base = header_size + i * DOF_SEC_SIZE;
            blob[base..base + 4].copy_from_slice(&(*kind as u32).to_le_bytes());
            blob[base + 12..base + 16].copy_from_slice(&entsize.to_le_bytes());
            blob[base + 16..base + 24].copy_from_slice(&off.to_le_bytes());
            blob[base + 24..base + 32].copy_from_slice(&size.to_le_bytes());
        }
        blob.extend_from_slice(&payload);
        blob
    }

    #[test]
    fn drives_one_ecb_through_stub_adapter() {
        extern crate alloc;
        let blob = synth_one_ecb_dof();
        let view = parse_blob(&blob).expect("synthesized DOF parses");
        let mut stub = StubAdapter::new();
        let mut statuses = alloc::vec::Vec::<EcbStatus>::new();
        let accepted = drive(&view, &mut stub, |_, s| statuses.push(s)).unwrap();
        assert_eq!(accepted, 1);
        assert_eq!(statuses.len(), 1);
        assert!(matches!(statuses[0], EcbStatus::Accepted { .. }));
        assert_eq!(stub.attached, 1);
        assert_eq!(stub.records, 1);
    }
}

#[cfg(test)]
extern crate alloc;
