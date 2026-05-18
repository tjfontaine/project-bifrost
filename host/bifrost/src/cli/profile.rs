// Profile-sample consumer for the bifrost CLI.
//
// This module owns the `bifrost profile` subcommand and its renderer.
// The attach/data runtime stays in `runtime.rs`.

#![cfg(target_os = "macos")]

use crate::cli::args::default_vmlinux;

use anyhow::{Result, anyhow};
use std::process::ExitCode;
use tracing::warn;

/// Consume profile-N samples from a running target.
/// The VMM no longer owns profile sample generation; until guest-side
/// profile records are produced in the data SHM, this subcommand keeps
/// the CLI renderer/demo path alive with a local synthetic sample when
/// no transport sample arrives.
///
/// Exits after `max_samples` (default 16) or on SIGINT.
pub fn run_profile(pid: u32, max_samples: u32) -> Result<ExitCode> {
    use crate::control_shmem::ControlShmAttachment;

    println!("bifrost profile -p {}", pid);
    println!("  status  attaching control SHM");
    let attachment =
        ControlShmAttachment::open(pid).map_err(|e| anyhow!("attach to pid {}: {}", pid, e))?;

    // Best-effort vmlinux symtab load for symbolicating kernel-context
    // frames (`func+0xNN` instead of raw hex PCs).  When vmlinux is
    // absent or unparseable we fall through with `None` and the
    // renderer prints raw hex — same behavior as before this M.5
    // follow-up.  Per-task user-mode symtab resolution is out of
    // scope; user-context frames always render as hex today.
    let kernel_symtab = load_vmlinux_symtab_for_profile();
    if kernel_symtab.is_some() {
        println!("  symtab  vmlinux loaded; kernel frames will resolve");
    } else {
        println!(
            "  symtab  vmlinux unavailable; kernel frames will render as hex \
             (set BIFROST_VMLINUX to enable resolution)"
        );
    }

    println!("  status  draining profile samples (max={})", max_samples);
    println!("  ─────────────────────────────────────────────────");

    let drain_timeout = std::time::Duration::from_secs(5);
    let mut received: u32 = 0;
    let deadline = std::time::Instant::now() + drain_timeout;
    while received < max_samples && std::time::Instant::now() < deadline {
        // Use poll_rsp with no seq filter (None) to take *any*
        // unsolicited push.  Drain frequently so we don't lose
        // samples to ring overflow.
        let poll_to = std::time::Duration::from_millis(50);
        match attachment.poll_rsp(None, poll_to).ok().flatten() {
            Some((kind, _, payload)) if kind == crate::control_shmem::KIND_PROFILE_SAMPLE => {
                received += 1;
                render_profile_sample(received, &payload, kernel_symtab.as_ref());
            }
            Some((_kind, _, _)) => {
                // Some other unsolicited push (SELF_TRACE_PUSH,
                // AGG/RECORD).  Discard quietly —
                // this is the profile consumer, not the trace one.
            }
            None => {
                // Timeout / no record.  Fall through and re-loop
                // until the outer deadline fires.
            }
        }
    }
    if received == 0 {
        println!(
            "  status  no transport profile samples received in {:?}",
            drain_timeout
        );
        println!("  info    emitting CLI-owned synthetic sample");
        if let Some(payload) = synthetic_profile_sample_payload() {
            received += 1;
            render_profile_sample(received, &payload, kernel_symtab.as_ref());
        }
    } else {
        println!("  status  received {} profile sample(s)", received);
    }

    Ok(ExitCode::from(0))
}

fn synthetic_profile_sample_payload() -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&bifrost_wire::PROFILE_SAMPLE_PROBE_ID.to_le_bytes());
    bifrost_wire::codec::encode_profile_sample(
        &mut payload,
        std::process::id(),
        0,
        0,
        bifrost_wire::PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT,
        &[0xffffff800dead000],
    )
    .ok()?;
    Some(payload)
}

/// Best-effort load of the guest vmlinux ELF symbol table for
/// symbolicating kernel-context profile frames.  Returns `None` (and
/// logs a warning) if vmlinux can't be found, read, or parsed —
/// callers are expected to fall back to raw hex rendering.  Never
/// errors: a missing vmlinux is the steady-state for users who
/// haven't fetched the kernel source tree.
fn load_vmlinux_symtab_for_profile() -> Option<crate::elf_syms::SymTab> {
    use std::io::Read;
    let path = default_vmlinux();
    let canon = std::path::Path::new(&path);
    if !canon.exists() {
        warn!(
            "vmlinux not found at {} — kernel-context frames in `bifrost profile` \
             will render as raw hex (set BIFROST_VMLINUX to enable symbolication)",
            path
        );
        return None;
    }
    let mut f = match std::fs::File::open(canon) {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "open vmlinux at {}: {} — falling back to hex frames",
                path, e
            );
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = f.read_to_end(&mut bytes) {
        warn!(
            "read vmlinux at {}: {} — falling back to hex frames",
            path, e
        );
        return None;
    }
    match crate::elf_syms::SymTab::from_bytes(&bytes) {
        Ok(st) if st.is_empty() => {
            warn!(
                "vmlinux at {} has no .symtab — falling back to hex frames",
                path
            );
            None
        }
        Ok(st) => Some(st),
        Err(e) => {
            warn!(
                "parse vmlinux symtab at {}: {} — falling back to hex frames",
                path, e
            );
            None
        }
    }
}

/// Render a single PC against an optional kernel symbol table.
///
/// Returns a `func+0xNN` string when `symtab` is present and resolves
/// `pc`, falling back to a fixed-width hex literal otherwise.  Pure
/// function — pulled out of `render_profile_sample` so the symbolication
/// path can be unit-tested with a synthetic SymTab without spinning up
/// the control SHM / VM stack.
fn symbolicate_pc(pc: u64, symtab: Option<&crate::elf_syms::SymTab>) -> String {
    if let Some(st) = symtab {
        if let Some((name, offset)) = st.lookup(pc) {
            return format!("{}+{:#x}", name, offset);
        }
    }
    format!("{:#018x}", pc)
}

/// Render one profile-sample payload to stdout.  The payload is the
/// raw rsp-ring body, which includes the 4-byte
/// PROFILE_SAMPLE_PROBE_ID prefix that the libkrun emit side wraps
/// the codec output with.
///
/// `kernel_symtab`, when provided, resolves kernel-context frames
/// (`flags & PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT`) to `func+0xNN` form.
/// User-context frames always render as raw hex — per-task user-mode
/// symtab resolution is a deeper follow-up, see commit
/// 47f8458.
fn render_profile_sample(
    idx: u32,
    payload: &[u8],
    kernel_symtab: Option<&crate::elf_syms::SymTab>,
) {
    if payload.len() < 4 {
        println!("  #{:<4}  malformed (payload < 4 bytes)", idx);
        return;
    }
    let probe_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if probe_id != bifrost_wire::PROFILE_SAMPLE_PROBE_ID {
        println!(
            "  #{:<4}  unexpected probe_id {:#x} (want {:#x})",
            idx,
            probe_id,
            bifrost_wire::PROFILE_SAMPLE_PROBE_ID,
        );
        return;
    }
    let body = &payload[4..];
    let view = match bifrost_wire::codec::decode_profile_sample(body) {
        Ok(v) => v,
        Err(e) => {
            println!("  #{:<4}  decode error: {:?}", idx, e);
            return;
        }
    };
    let flags_label = bifrost_wire::codec::profile_sample_flags_label(view.flags);
    let is_kernel = (view.flags & bifrost_wire::PROFILE_SAMPLE_FLAG_KERNEL_CONTEXT) != 0;
    let frame_symtab: Option<&crate::elf_syms::SymTab> =
        if is_kernel { kernel_symtab } else { None };
    print!(
        "  #{:<4}  pid={} tid={} cpu={} flags=[{}] frames=[",
        idx, view.pid, view.tid, view.cpu_id, flags_label,
    );
    let mut first = true;
    for pc in view.frames() {
        if !first {
            print!(", ");
        }
        first = false;
        print!("{}", symbolicate_pc(pc, frame_symtab));
    }
    println!("]");
}

#[cfg(test)]
mod profile_render_tests {
    use super::*;
    use crate::elf_syms::{Sym, SymTab};

    /// Build a synthetic SymTab carrying two kernel-flavor symbols at
    /// canonical kernel addresses.  The constructor is `pub(crate)`
    /// inside `elf_syms` for exactly this purpose: tests get to feed
    /// in a known shape without going through ELF parsing.
    fn synth_symtab() -> SymTab {
        SymTab::from_syms_for_test(
            vec![
                Sym {
                    addr: 0xffff_ff80_0010_0000,
                    size: 0x100,
                    name: "do_sys_openat2".to_string(),
                },
                Sym {
                    addr: 0xffff_ff80_0011_0000,
                    size: 0x80,
                    name: "vfs_open".to_string(),
                },
            ],
            true,
        )
    }

    /// PC inside a known symbol resolves to `name+0xoff`, with `0x0`
    /// at the symbol's first byte.
    #[test]
    fn symbolicate_resolves_known_pc() {
        let st = synth_symtab();
        assert_eq!(
            symbolicate_pc(0xffff_ff80_0010_0040, Some(&st)),
            "do_sys_openat2+0x40",
        );
        assert_eq!(
            symbolicate_pc(0xffff_ff80_0010_0000, Some(&st)),
            "do_sys_openat2+0x0",
        );
    }

    /// PC outside any symbol's coverage falls back to fixed-width hex.
    #[test]
    fn symbolicate_unknown_pc_falls_back_to_hex() {
        let st = synth_symtab();
        assert_eq!(
            symbolicate_pc(0xdead_beef_0000_0000, Some(&st)),
            "0xdeadbeef00000000",
        );
    }

    /// `None` symtab always renders raw hex — this is the user-context
    /// fallback path and the no-vmlinux startup path.
    #[test]
    fn symbolicate_no_symtab_renders_hex() {
        assert_eq!(
            symbolicate_pc(0xffff_ff80_0010_0040, None),
            "0xffffff8000100040",
        );
    }
}
