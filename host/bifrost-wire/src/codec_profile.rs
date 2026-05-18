use super::{WireError, WireSink};
use crate::*;

/// Borrowed view of one profile-N sample body.
#[derive(Debug, Copy, Clone)]
pub struct ProfileSampleView<'a> {
    pub pid: u32,
    pub tid: u32,
    pub cpu_id: u32,
    pub flags: u32,
    pub num_frames: u32,
    /// Raw bytes for the frame_pc array — `num_frames * 8` bytes
    /// in length.  Iterate via `frames()` to get u64 values.
    frames_bytes: &'a [u8],
}

impl<'a> ProfileSampleView<'a> {
    /// Iterator over the sample's stack frames, top-of-stack first.
    /// Each yielded `u64` is a guest-side instruction pointer; the
    /// host CLI symbolicates via kallsyms (kernel context, per
    /// `flags & PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT`) or the per-task
    /// symtab side-channel (user context).
    pub fn frames(&self) -> ProfileFrameIter<'a> {
        ProfileFrameIter {
            bytes: self.frames_bytes,
            cursor: 0,
            remaining: self.num_frames as usize,
        }
    }
}

/// Iterator over the frame_pc array of a `ProfileSampleView`.
#[derive(Debug)]
pub struct ProfileFrameIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for ProfileFrameIter<'a> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.remaining == 0 || self.cursor + 8 > self.bytes.len() {
            return None;
        }
        let pc = u64::from_le_bytes(self.bytes[self.cursor..self.cursor + 8].try_into().unwrap());
        self.cursor += 8;
        self.remaining -= 1;
        Some(pc)
    }
}

/// Encode a profile-N sample into `sink`.  Caller bounds `frames`
/// at `MAX_PROFILE_FRAMES` upstream; the encoder rejects longer
/// arrays with `Truncated` carrying the cap as `need`.
pub fn encode_profile_sample<S: WireSink>(
    sink: &mut S,
    pid: u32,
    tid: u32,
    cpu_id: u32,
    flags: u32,
    frames: &[u64],
) -> Result<(), WireError> {
    if frames.len() > MAX_PROFILE_FRAMES {
        return Err(WireError::Truncated {
            need: MAX_PROFILE_FRAMES,
            have: frames.len(),
            at: "profile-sample-num-frames",
        });
    }
    sink.write(&pid.to_le_bytes())?;
    sink.write(&tid.to_le_bytes())?;
    sink.write(&cpu_id.to_le_bytes())?;
    sink.write(&flags.to_le_bytes())?;
    sink.write(&(frames.len() as u32).to_le_bytes())?;
    for pc in frames {
        sink.write(&pc.to_le_bytes())?;
    }
    Ok(())
}

/// Decode a profile-N sample body.  Returns a borrowed view; iterate
/// `view.frames()` to walk the stack.
pub fn decode_profile_sample(bytes: &[u8]) -> Result<ProfileSampleView<'_>, WireError> {
    if bytes.len() < 20 {
        return Err(WireError::Truncated {
            need: 20,
            have: bytes.len(),
            at: "profile-sample-header",
        });
    }
    let pid = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let tid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let cpu_id = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let num_frames = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let need = 20 + (num_frames as usize) * 8;
    if bytes.len() < need {
        return Err(WireError::Truncated {
            need,
            have: bytes.len(),
            at: "profile-sample-frames",
        });
    }
    Ok(ProfileSampleView {
        pid,
        tid,
        cpu_id,
        flags,
        num_frames,
        frames_bytes: &bytes[20..need],
    })
}

/// Map a flags u32 to a short comma-separated label suitable for
/// terminal rendering (e.g. `"kernel,truncated"`).  Empty for
/// `flags == 0` (user mode, complete stack).
pub fn profile_sample_flags_label(flags: u32) -> &'static str {
    // We can't allocate (no_std) and there are only a few combinations
    // worth naming; precompute the labels for the bits that matter.
    let kernel = (flags & PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT) != 0;
    let truncated = (flags & PROFILE_SAMPLE_FLAG_STACK_TRUNCATED) != 0;
    let incomplete = (flags & PROFILE_SAMPLE_FLAG_STACK_INCOMPLETE) != 0;
    match (kernel, truncated, incomplete) {
        (false, false, false) => "",
        (true, false, false) => "kernel",
        (false, true, false) => "truncated",
        (false, false, true) => "incomplete",
        (true, true, false) => "kernel,truncated",
        (true, false, true) => "kernel,incomplete",
        (false, true, true) => "truncated,incomplete",
        (true, true, true) => "kernel,truncated,incomplete",
    }
}
