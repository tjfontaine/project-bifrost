// SPDX-License-Identifier: Apache-2.0
//! vDSO blob extraction from a vmlinux ELF.
//!
//! The arm64 / x86_64 vDSO is embedded in vmlinux as a small ELF
//! between the `vdso_start` and `vdso_end` kernel symbols. perf's
//! strategy (`tools/perf/util/vdso.c`) is to mmap the live `[vdso]`
//! mapping out of a target process and reuse libelf. We don't have
//! a target-process angle in this configuration (the guest is a
//! libkrun VM and the host doesn't speak guest virt), but we *do*
//! have vmlinux on disk — so we extract the vDSO bytes once at
//! host boot, parse `.dynsym`, and cache. The result is a static
//! per-kernel-build symbol table that any guest process's [vdso]
//! frames can be resolved against.
//!
//! Caveat: vmlinux's `vdso_start` is a *kernel virtual* address.
//! To find the bytes inside the on-disk ELF we map it through the
//! program-header table (PT_LOAD): for the segment that contains
//! `vdso_start`, file_offset = p_offset + (vdso_start - p_vaddr).
//! On compressed kernels (`Image.gz`) this won't work — the user
//! must provide an unstripped vmlinux ELF, which is what
//! `BIFROST_VMLINUX` already points at for BTF.

use std::io;

/// Extract the vDSO ELF bytes from in-memory vmlinux ELF bytes.
/// Returns the slice between `vdso_start` and `vdso_end` resolved
/// through PT_LOAD segments, or `None` if either symbol is absent
/// (very stripped kernel) or the addresses don't map cleanly.
pub fn extract_vdso(vmlinux: &[u8]) -> io::Result<Vec<u8>> {
    if vmlinux.len() < 64 || &vmlinux[0..4] != b"\x7fELF" || vmlinux[4] != 2 || vmlinux[5] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmlinux: not ELF-64 LE",
        ));
    }
    // ELF-64 header offsets we care about: e_phoff(32), e_shoff(40),
    // e_phentsize(54), e_phnum(56), e_shentsize(58), e_shnum(60),
    // e_shstrndx(62).
    let phoff = u64::from_le_bytes(vmlinux[32..40].try_into().unwrap()) as usize;
    let shoff = u64::from_le_bytes(vmlinux[40..48].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(vmlinux[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(vmlinux[56..58].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(vmlinux[58..60].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(vmlinux[60..62].try_into().unwrap()) as usize;
    let shstrndx = u16::from_le_bytes(vmlinux[62..64].try_into().unwrap()) as usize;

    if shoff + shnum * shentsize > vmlinux.len() || shstrndx >= shnum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmlinux: bad section table",
        ));
    }
    if phoff + phnum * phentsize > vmlinux.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmlinux: bad program header table",
        ));
    }

    // Walk section headers to find .symtab + .strtab and look up
    // vdso_start / vdso_end. vmlinux has the unstripped symtab; we
    // don't bother with .dynsym because vmlinux's dynsym typically
    // doesn't include vdso markers.
    let read_sh = |idx: usize| -> (u32, u32, u64, u64, u32) {
        let p = shoff + idx * shentsize;
        let name = u32::from_le_bytes(vmlinux[p..p + 4].try_into().unwrap());
        let stype = u32::from_le_bytes(vmlinux[p + 4..p + 8].try_into().unwrap());
        let off = u64::from_le_bytes(vmlinux[p + 24..p + 32].try_into().unwrap());
        let size = u64::from_le_bytes(vmlinux[p + 32..p + 40].try_into().unwrap());
        let link = u32::from_le_bytes(vmlinux[p + 40..p + 44].try_into().unwrap());
        (name, stype, off, size, link)
    };
    let (_, _, shstr_off, shstr_size, _) = read_sh(shstrndx);
    let shstr_off = shstr_off as usize;
    let shstr_size = shstr_size as usize;
    let sh_name_at = |off: u32| -> &str {
        let start = shstr_off + off as usize;
        if start >= shstr_off + shstr_size {
            return "";
        }
        let max_end = shstr_off + shstr_size;
        let nul = vmlinux[start..max_end]
            .iter()
            .position(|&b| b == 0)
            .map(|n| start + n)
            .unwrap_or(max_end);
        std::str::from_utf8(&vmlinux[start..nul]).unwrap_or("")
    };

    let mut sym_off = 0usize;
    let mut sym_size = 0usize;
    let mut sym_link: usize = 0;
    for i in 0..shnum {
        let (name_off, stype, off, size, link) = read_sh(i);
        if stype == 2 && sh_name_at(name_off) == ".symtab" {
            sym_off = off as usize;
            sym_size = size as usize;
            sym_link = link as usize;
            break;
        }
    }
    if sym_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "vmlinux: .symtab absent (stripped image?)",
        ));
    }
    let (_, _, str_off, str_size, _) = read_sh(sym_link);
    let str_off = str_off as usize;
    let str_size = str_size as usize;
    let str_at = |off: u32| -> &str {
        let start = str_off + off as usize;
        if start >= str_off + str_size {
            return "";
        }
        let max_end = str_off + str_size;
        let nul = vmlinux[start..max_end]
            .iter()
            .position(|&b| b == 0)
            .map(|n| start + n)
            .unwrap_or(max_end);
        std::str::from_utf8(&vmlinux[start..nul]).unwrap_or("")
    };

    let mut vdso_start: Option<u64> = None;
    let mut vdso_end: Option<u64> = None;
    let mut p = sym_off;
    while p + 24 <= sym_off + sym_size {
        let st_name = u32::from_le_bytes(vmlinux[p..p + 4].try_into().unwrap());
        let st_value = u64::from_le_bytes(vmlinux[p + 8..p + 16].try_into().unwrap());
        let n = str_at(st_name);
        match n {
            "vdso_start" => vdso_start = Some(st_value),
            "vdso_end" => vdso_end = Some(st_value),
            _ => {}
        }
        if vdso_start.is_some() && vdso_end.is_some() {
            break;
        }
        p += 24;
    }
    let (start, end) = match (vdso_start, vdso_end) {
        (Some(a), Some(b)) if b > a => (a, b),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "vmlinux: vdso_start/vdso_end not found",
            ));
        }
    };

    // Translate kernel virtual address → file offset via PT_LOAD.
    // PT_LOAD entry layout (ELF-64): p_type(4) | p_flags(4) |
    // p_offset(8) | p_vaddr(8) | p_paddr(8) | p_filesz(8) | ...
    let mut file_off: Option<u64> = None;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(vmlinux[p..p + 4].try_into().unwrap());
        if p_type != 1 {
            continue; // PT_LOAD == 1
        }
        let p_offset = u64::from_le_bytes(vmlinux[p + 8..p + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(vmlinux[p + 16..p + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(vmlinux[p + 32..p + 40].try_into().unwrap());
        if start >= p_vaddr && end <= p_vaddr + p_filesz {
            file_off = Some(p_offset + (start - p_vaddr));
            break;
        }
    }
    let off = file_off.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "vmlinux: vdso bytes not in any PT_LOAD",
        )
    })? as usize;
    let len = (end - start) as usize;
    if off + len > vmlinux.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmlinux: vdso slice out of bounds",
        ));
    }
    let blob = vmlinux[off..off + len].to_vec();
    // Sanity: must itself be ELF-64 LE.
    if blob.len() < 64 || &blob[0..4] != b"\x7fELF" || blob[4] != 2 || blob[5] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vdso blob: not ELF-64 LE",
        ));
    }
    Ok(blob)
}
