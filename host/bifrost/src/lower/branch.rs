// SPDX-License-Identifier: Apache-2.0
use super::LoweringError;
use super::state::LowerState;

/// Patch each pending branch's i16 slot-offset using the recorded
/// dif_idx -> body byte map.
pub fn fixup_branches(state: &mut LowerState) -> Result<(), LoweringError> {
    for &(branch_off, dif_target) in &state.pending_branches {
        let target_byte = *state
            .insn_offsets
            .get(dif_target as usize)
            .ok_or(LoweringError::BadDifInstrCount)?;
        let slot_off: isize = (target_byte as isize - branch_off as isize - 8) / 8;
        let off_i16 = slot_off as i16;
        // Patch bytes [branch_off+2 .. branch_off+4] (the i16 off field).
        state.body[branch_off + 2..branch_off + 4].copy_from_slice(&off_i16.to_le_bytes());
    }
    Ok(())
}

/// Emit a placeholder branch (off=0) at the current body position and
/// record the dif_target for fixup. Used by Bxx and BA lowering.
pub fn emit_branch_placeholder(state: &mut LowerState, insn: [u8; 8], dif_target: u32) {
    let pos = state.body.len();
    state.body.extend_from_slice(&insn);
    state.pending_branches.push((pos, dif_target));
}
