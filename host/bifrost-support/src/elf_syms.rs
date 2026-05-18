// SPDX-License-Identifier: Apache-2.0
//! Minimal ELF-64 LE symbol-table reader for host-side userspace stack
//! symbolication.
//!
//! Reads `.symtab` (or falls back to `.dynsym` if the binary is
//! stripped of `.symtab`) plus the matching string table, returning a
//! sorted `Vec<(addr, size, name)>` of FUNC-typed symbols. The
//! companion `lookup` does a binary search for the symbol covering a
//! given PC and returns `(name, offset_within_symbol)`.
//!
//! Used by the bifrost host's gustack renderer to turn raw u64 PCs
//! into `function+0x<offset>` strings against the binary path the
//! guest worker ferried in the record's `exe_path` field.
//!
//! Bounded scope: only ELF-64 little-endian (arm64 / x86_64). Only
//! FUNC + GNU_IFUNC types. No PIE-aware load-base resolution — for
//! statically linked PIE binaries (musl-static rust, our agent),
//! symbol values match runtime PCs because the binary's vaddr base
//! is 0 and the loader maps text at that base + a randomized offset
//! that the kernel reports as part of the PC in stack walks too.
//! For dynamically linked / shared-library callers we return None
//! and let the caller fall back to raw hex — proper resolution
//! requires the per-VMA load-base info we don't yet ferry.

use std::io;
use thiserror::Error;

/// Errors returned by uprobe-target resolution.  Per Oxide's
/// rust-cli-recommendations: thiserror at module boundaries so
/// callers (`cli/runtime.rs`) can match variants when needed and
/// the binary entry point can `?`-bubble through anyhow.
#[derive(Debug, Error)]
pub enum UprobeTargetError {
    #[error(
        "uprobe binary slot must be a basename, got '{0}' (the CLI \
         searches usr/sbin, usr/bin, /, then any path under the rootfs)"
    )]
    BasenameContainsSlash(String),
    #[error("read {path}: {source}")]
    ReadBinary {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("parse {path} as ELF: {source}")]
    ParseElf {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "uprobe target {0} is ET_EXEC (non-PIE); only PIE binaries \
         supported in this release"
    )]
    NotPie(String),
    #[error("uprobe target {basename}:{symbol} not found under {rootfs}; tried: {tried}")]
    NotFound {
        basename: String,
        symbol: String,
        rootfs: String,
        tried: String,
    },
}

#[derive(Debug, Clone)]
pub struct Sym {
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

pub struct SymTab {
    /// Sorted by addr ascending; binary searched in `lookup`.
    syms: Vec<Sym>,
    /// True iff the source ELF is `ET_DYN` (PIE executable or shared
    /// object). For PIE binaries `Sym::addr` (= `st_value`) is the
    /// file offset, which is what `uprobe_register` needs. Non-PIE
    /// binaries (`ET_EXEC`) report `addr` as a virtual address that
    /// must be adjusted by the load segment vaddr to recover the
    /// file offset — see `Sym::file_offset`.
    is_pie: bool,
}

impl SymTab {
    /// Parse `.symtab`/`.strtab` (or `.dynsym`/`.dynstr` if `.symtab`
    /// is absent) from in-memory ELF bytes. Returns an empty SymTab
    /// if no symbols are available — caller handles that case.
    /// Callers read the file bytes themselves so this module doesn't
    /// take a path-shaped attack surface.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        Self::parse_elf64(bytes, /* dynsym_only */ false)
    }

    /// Parse `.dynsym`/`.dynstr` from in-memory ELF bytes. Used for
    /// the arm64 vDSO blob — extracted out of vmlinux at host boot
    /// time, it has no `.symtab` (per `kernel/vdso/Makefile` strip
    /// rules). Mirrors perf's "back the [vdso] DSO with real data"
    /// strategy.
    pub fn from_bytes_dynsym(bytes: &[u8]) -> io::Result<Self> {
        Self::parse_elf64(bytes, /* dynsym_only */ true)
    }

    fn parse_elf64(bytes: &[u8], dynsym_only: bool) -> io::Result<Self> {
        if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not an ELF-64 LE file",
            ));
        }
        // e_type at offset 16: ET_EXEC=2 (non-PIE), ET_DYN=3 (PIE / .so).
        let e_type = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
        let is_pie = e_type == 3;
        let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
        let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
        let shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;

        if shoff + shnum * shentsize > bytes.len() || shstrndx >= shnum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF section table out of bounds",
            ));
        }

        // Locate the section header string table to resolve sh_name
        // values into ASCII section names.
        let read_sh = |idx: usize| -> (u32, u32, u64, u64, u32) {
            // Returns (sh_name, sh_type, sh_offset, sh_size, sh_link).
            let p = shoff + idx * shentsize;
            let name = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            let stype = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap());
            let off = u64::from_le_bytes(bytes[p + 24..p + 32].try_into().unwrap());
            let size = u64::from_le_bytes(bytes[p + 32..p + 40].try_into().unwrap());
            let link = u32::from_le_bytes(bytes[p + 40..p + 44].try_into().unwrap());
            (name, stype, off, size, link)
        };
        let (_, _, shstr_off, shstr_size, _) = read_sh(shstrndx);
        let shstr_off = shstr_off as usize;
        let shstr_size = shstr_size as usize;
        if shstr_off + shstr_size > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF .shstrtab out of bounds",
            ));
        }
        let sh_name_at = |off: u32| -> &str {
            let start = shstr_off + off as usize;
            if start >= bytes.len() {
                return "";
            }
            let nul = bytes[start..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(0);
            std::str::from_utf8(&bytes[start..start + nul]).unwrap_or("")
        };

        // Prefer .symtab/.strtab; fall back to .dynsym/.dynstr.
        // dynsym_only callers (vDSO) skip the .symtab pass — vDSO
        // ELFs are stripped to only `.dynsym`.
        let mut sym_off = 0usize;
        let mut sym_size = 0usize;
        let mut sym_link: usize = 0; // sh_link → strtab section index
        if !dynsym_only {
            for i in 0..shnum {
                let (name_off, stype, off, size, link) = read_sh(i);
                let name = sh_name_at(name_off);
                // SHT_SYMTAB = 2.
                if stype == 2 && name == ".symtab" {
                    sym_off = off as usize;
                    sym_size = size as usize;
                    sym_link = link as usize;
                    break;
                }
            }
        }
        if sym_size == 0 {
            for i in 0..shnum {
                let (name_off, stype, off, size, link) = read_sh(i);
                let name = sh_name_at(name_off);
                // SHT_DYNSYM = 11.
                if stype == 11 && name == ".dynsym" {
                    sym_off = off as usize;
                    sym_size = size as usize;
                    sym_link = link as usize;
                    break;
                }
            }
        }
        if sym_size == 0 {
            return Ok(Self { syms: Vec::new(), is_pie });
        }
        if sym_off + sym_size > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF .symtab/.dynsym out of bounds",
            ));
        }
        if sym_link >= shnum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF .symtab sh_link out of bounds",
            ));
        }
        let (_, _, str_off, str_size, _) = read_sh(sym_link);
        let str_off = str_off as usize;
        let str_size = str_size as usize;
        if str_off + str_size > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF symbol .strtab out of bounds",
            ));
        }
        let str_at = |off: u32| -> String {
            let start = str_off + off as usize;
            if start >= str_off + str_size {
                return String::new();
            }
            let max_end = str_off + str_size;
            let nul = bytes[start..max_end]
                .iter()
                .position(|&b| b == 0)
                .map(|n| start + n)
                .unwrap_or(max_end);
            String::from_utf8_lossy(&bytes[start..nul]).into_owned()
        };

        // Walk Elf64_Sym entries (24 bytes each).
        // st_name (4) | st_info (1) | st_other (1) | st_shndx (2) | st_value (8) | st_size (8)
        let mut syms = Vec::new();
        let mut p = sym_off;
        while p + 24 <= sym_off + sym_size {
            let st_name = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            let st_info = bytes[p + 4];
            let st_value = u64::from_le_bytes(bytes[p + 8..p + 16].try_into().unwrap());
            let st_size = u64::from_le_bytes(bytes[p + 16..p + 24].try_into().unwrap());
            let st_type = st_info & 0x0f;
            // STT_FUNC = 2, STT_GNU_IFUNC = 10.
            if (st_type == 2 || st_type == 10) && st_value != 0 {
                let name = str_at(st_name);
                if !name.is_empty() {
                    syms.push(Sym {
                        addr: st_value,
                        size: st_size,
                        name,
                    });
                }
            }
            p += 24;
        }
        syms.sort_by_key(|s| s.addr);
        // Dedupe consecutive same-addr (multiple aliases for the same
        // function) — keep the first (shortest, often canonical).
        syms.dedup_by_key(|s| s.addr);
        Ok(Self { syms, is_pie })
    }

    /// Look up the symbol covering `pc`. Returns `(name, offset)` where
    /// offset is the byte distance from the symbol's start.
    pub fn lookup(&self, pc: u64) -> Option<(&str, u64)> {
        if self.syms.is_empty() {
            return None;
        }
        // Binary search for largest addr ≤ pc.
        let idx = match self.syms.binary_search_by_key(&pc, |s| s.addr) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let s = &self.syms[idx];
        let off = pc - s.addr;
        // st_size of 0 is common for hand-asm or partially-stripped
        // symtabs; in that case accept any forward distance up to a
        // reasonable cap (16 KB) so very-near PCs still resolve.
        let cap = if s.size == 0 { 16 * 1024 } else { s.size };
        if off > cap {
            return None;
        }
        Some((&s.name, off))
    }

    pub fn is_empty(&self) -> bool {
        self.syms.is_empty()
    }

    /// Iterate every parsed FUNC-typed symbol in address-sorted
    /// order. Used by the bifrost CLI's probe-listing path
    /// (`bifrost -l`) to walk vmlinux's symtab and emit one
    /// `bifrost:guest_kernel:<name>:entry|return` line per kprobe-
    /// able function.
    pub fn iter(&self) -> impl Iterator<Item = &Sym> {
        self.syms.iter()
    }

    /// True iff the source ELF is `ET_DYN` (PIE executable / shared
    /// object). For PIE ELFs, `Sym::addr` is the file offset suitable
    /// for `uprobe_register`; for `ET_EXEC` it isn't (see
    /// `lookup_by_name_for_uprobe`).
    pub fn is_pie(&self) -> bool {
        self.is_pie
    }

    /// Linear scan for a symbol by exact name. Used by the uprobe
    /// resolver (one lookup per LOAD_PROG, never per-fire). Returns
    /// the first match — symtabs may contain weak duplicates; if
    /// the caller cares, they can iterate.
    pub fn lookup_by_name(&self, name: &str) -> Option<&Sym> {
        self.syms.iter().find(|s| s.name == name)
    }

    /// Construct a SymTab directly from a pre-built symbol vector.
    /// Crate-internal helper for tests that want to feed a known shape
    /// in without going through ELF parsing — used by the
    /// `cli::runtime::symbolicate_pc` unit tests so they stay
    /// lockstep with `lookup`'s real behavior.  The vector is sorted
    /// by addr ascending (mirroring the parse path).
    #[doc(hidden)]
    pub fn from_syms_for_test(mut syms: Vec<Sym>, is_pie: bool) -> Self {
        syms.sort_by_key(|s| s.addr);
        Self { syms, is_pie }
    }
}

/// Result of resolving a `bifrost:guest_user:<bin>:<sym>:entry|return`
/// probe spec. Two flavors:
///
/// * **Kernel-resolved** (default, `probe_type 4/5`): only `basename` and
///   `symbol` are populated. The CLI does not read any host-side rootfs;
///   the bifrost driver in the guest walks the task list to find a matching
///   binary, parses its ELF symtab in-kernel, and computes the file offset
///   itself. Portable across VMMs — no host-side rootfs mirror, no agent
///   cooperation, no VMM-specific shims.
///
/// * **Host-resolved** (legacy, `probe_type 2/3`, opt-in via
///   `BIFROST_HOST_RESOLVE_UPROBE=1`): `guest_path` and `file_offset` are
///   filled in by the CLI's host-side `resolve_uprobe_target`. Requires
///   the user to maintain a rootfs mirror under `BIFROST_ROOTFS`. Kept
///   for backward compatibility with the legacy harness path.
#[derive(Debug, Clone, Default)]
pub struct UprobeTarget {
    /// Absolute path inside the guest rootfs (e.g. `/usr/sbin/nginx`).
    /// Empty string when kernel-resolved.
    pub guest_path: String,
    /// File offset of the symbol's first instruction. Zero when
    /// kernel-resolved (the driver computes this itself after parsing
    /// the binary's ELF).
    pub file_offset: u64,
    /// Symbol size, kept for future single-step / return-probe placement.
    pub sym_size: u64,
    /// Binary basename for kernel-resolved registrations (e.g.
    /// `redis-server`). Empty when host-resolved (basename is implicit
    /// in `guest_path`).
    pub basename: String,
    /// Symbol name for kernel-resolved registrations (e.g.
    /// `processCommand`).  For the USDT (probe_type 9, kernel-
    /// resolved) shape this carries the SDT probe name (e.g.
    /// `query__start`).  Empty when host-resolved.
    pub symbol: String,
    /// `.note.stapsdt` provider name for USDT registrations (e.g.
    /// `postgresql`).  Empty for plain uprobe registrations.  The
    /// driver's `.note.stapsdt` walk needs both `(symbol, provider)`
    /// to disambiguate — multiple providers can ship probes with the
    /// same name.
    pub sdt_provider: String,
}

/// Resolve `(rootfs, basename, symbol)` to an `UprobeTarget`.
///
/// Walks common executable locations, including the smolvm-provisioned
/// `/workspace` path used by uprobe demos, until it finds an executable
/// ELF containing `symbol`. Returns the first match and reports the
/// guest-relative path so the wire format stays portable.
///
/// Errors on `ET_EXEC` (non-PIE) for now — the demo workloads (nginx,
/// redis-server) are all PIE. Adding ET_EXEC support means
/// subtracting the load-segment vaddr; deferred until a real non-PIE
/// target shows up.
pub fn resolve_uprobe_target(
    rootfs: &std::path::Path,
    basename: &str,
    symbol: &str,
) -> Result<UprobeTarget, UprobeTargetError> {
    if basename.contains('/') {
        return Err(UprobeTargetError::BasenameContainsSlash(basename.to_string()));
    }

    let candidates = [
        format!("usr/local/sbin/{}", basename),
        format!("usr/local/bin/{}", basename),
        format!("usr/sbin/{}", basename),
        format!("usr/bin/{}", basename),
        format!("sbin/{}", basename),
        format!("bin/{}", basename),
        format!("workspace/{}", basename),
        basename.to_string(),
    ];

    let mut tried = Vec::new();
    for rel in &candidates {
        let host_path = rootfs.join(rel);
        if !host_path.is_file() {
            tried.push(rel.clone());
            continue;
        }
        let bytes = std::fs::read(&host_path).map_err(|source| {
            UprobeTargetError::ReadBinary {
                path: host_path.display().to_string(),
                source,
            }
        })?;
        let symtab = SymTab::from_bytes(&bytes).map_err(|source| {
            UprobeTargetError::ParseElf {
                path: host_path.display().to_string(),
                source,
            }
        })?;
        let sym = match symtab.lookup_by_name(symbol) {
            Some(s) => s,
            None => {
                tried.push(format!("{} (no symbol {})", rel, symbol));
                continue;
            }
        };
        if !symtab.is_pie() {
            return Err(UprobeTargetError::NotPie(rel.clone()));
        }
        return Ok(UprobeTarget {
            guest_path: format!("/{}", rel),
            file_offset: sym.addr,
            sym_size: sym.size,
            ..Default::default()
        });
    }

    Err(UprobeTargetError::NotFound {
        basename: basename.to_string(),
        symbol: symbol.to_string(),
        rootfs: rootfs.display().to_string(),
        tried: tried.join(", "),
    })
}

// =====================================================================
// USDT (`.note.stapsdt`) parsing.
//
// SystemTap-compatible USDT macros (used by postgres' `--enable-dtrace`
// build, by libstapsdt, by glibc's pthread tracepoints, etc.) emit a
// per-probe entry into the `.note.stapsdt` ELF section.  Each entry
// records:
//
//   u64 pc           — link-time virtual address of the NOP instruction
//   u64 base         — link-time vaddr of the `.stapsdt.base` section
//                      (only used for prelink relocation; we ignore)
//   u64 semaphore    — link-time vaddr of an unsigned-short `flag` in
//                      `.probes`; the probe body short-circuits when
//                      the flag is 0 (no consumer attached)
//   nul-terminated provider, probe name, argument descriptor
//
// To attach an eBPF uprobe at one of these sites we need:
//
//   • the file offset of `pc`        (for `uprobe_register`'s offset)
//   • the file offset of `semaphore` (for `ref_ctr_offset`; the kernel
//     atomically bumps the flag on attach so the probe body fires)
//
// Both translations are vaddr→file_offset, computed from the PT_LOAD
// segment that covers the address: file_offset = vaddr - p_vaddr +
// p_offset.  For a non-prelinked PIE binary the text segment has
// p_vaddr == p_offset == 0, so the probe site translates to its
// vaddr directly; the data segment differs by the alignment padding,
// so the semaphore translation is genuinely non-trivial.
// =====================================================================

#[derive(Debug, Clone)]
pub struct StapsdtNote {
    pub provider: String,
    pub name: String,
    /// File offset of the probe site (NOP).  Suitable as
    /// `uprobe_register`'s `offset` argument.
    pub pc_file_offset: u64,
    /// File offset of the per-probe semaphore (`unsigned short` in
    /// `.probes`), or 0 if the probe doesn't use one.  Suitable as
    /// `uprobe_register`'s `ref_ctr_offset` argument; the kernel
    /// atomically increments this u16 on attach.
    pub semaphore_file_offset: u64,
    /// Argument descriptor string, kept verbatim (e.g. `"8@x27"` or
    /// `"4@[x0, 60]"`).  Not interpreted yet; reserved for future
    /// `arg0..argN` expression support in the lowering pipeline.
    pub args: String,
}

/// Parse the `.note.stapsdt` section of a 64-bit LE ELF and return
/// every USDT probe note found.  Returns an empty Vec if the section
/// is absent (binary was not built with `--enable-dtrace` or
/// equivalent); never errors on a missing section.  Errors only on
/// structurally malformed ELF or note bytes.
pub fn parse_stapsdt(bytes: &[u8]) -> io::Result<Vec<StapsdtNote>> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an ELF-64 LE file",
        ));
    }
    // Read program headers (PT_LOAD list, for vaddr→offset xlation).
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // (p_vaddr, p_offset, p_memsz)
    if phoff + phnum * phentsize <= bytes.len() {
        for i in 0..phnum {
            let p = phoff + i * phentsize;
            // Elf64_Phdr: u32 p_type | u32 p_flags | u64 p_offset
            //           | u64 p_vaddr | u64 p_paddr | u64 p_filesz
            //           | u64 p_memsz | u64 p_align
            let p_type = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            if p_type != 1 {
                continue; // PT_LOAD = 1
            }
            let p_offset = u64::from_le_bytes(bytes[p + 8..p + 16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(bytes[p + 16..p + 24].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(bytes[p + 40..p + 48].try_into().unwrap());
            loads.push((p_vaddr, p_offset, p_memsz));
        }
    }
    let vaddr_to_file_offset = |vaddr: u64| -> Option<u64> {
        if vaddr == 0 {
            return Some(0); // semaphore == 0 sentinel: no semaphore
        }
        for &(p_vaddr, p_offset, p_memsz) in &loads {
            if vaddr >= p_vaddr && vaddr < p_vaddr.saturating_add(p_memsz) {
                return Some(vaddr - p_vaddr + p_offset);
            }
        }
        None
    };

    // Walk section headers to locate `.note.stapsdt` (SHT_NOTE = 7).
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    let shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;
    if shoff == 0 || shnum == 0 || shoff + shnum * shentsize > bytes.len() || shstrndx >= shnum {
        return Ok(Vec::new());
    }
    let read_sh = |idx: usize| -> (u32, u32, u64, u64) {
        let p = shoff + idx * shentsize;
        let name = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        let stype = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap());
        let off = u64::from_le_bytes(bytes[p + 24..p + 32].try_into().unwrap());
        let size = u64::from_le_bytes(bytes[p + 32..p + 40].try_into().unwrap());
        (name, stype, off, size)
    };
    let (_, _, shstr_off, shstr_size) = read_sh(shstrndx);
    let shstr_off = shstr_off as usize;
    let shstr_size = shstr_size as usize;
    if shstr_off + shstr_size > bytes.len() {
        return Ok(Vec::new());
    }
    let sh_name_at = |off: u32| -> &str {
        let start = shstr_off + off as usize;
        if start >= shstr_off + shstr_size {
            return "";
        }
        let nul = bytes[start..shstr_off + shstr_size]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        std::str::from_utf8(&bytes[start..start + nul]).unwrap_or("")
    };
    let mut note_off = 0usize;
    let mut note_size = 0usize;
    for i in 0..shnum {
        let (name_off, stype, off, size) = read_sh(i);
        if stype != 7 {
            continue; // SHT_NOTE = 7
        }
        if sh_name_at(name_off) == ".note.stapsdt" {
            note_off = off as usize;
            note_size = size as usize;
            break;
        }
    }
    if note_size == 0 || note_off + note_size > bytes.len() {
        return Ok(Vec::new());
    }

    // Walk Elf_Note entries.  Each:
    //   u32 n_namesz | u32 n_descsz | u32 n_type | name (padded 4) | desc (padded 4)
    // Provider must be "stapsdt\0" (8 bytes incl. NUL → namesz==8) and
    // n_type must be NT_STAPSDT (3).  desc layout: u64 pc | u64 base
    // | u64 sema | provider\0 | name\0 | args\0.
    let mut notes = Vec::new();
    let end = note_off + note_size;
    let mut p = note_off;
    while p + 12 <= end {
        let namesz = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
        let descsz = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap()) as usize;
        let ntype = u32::from_le_bytes(bytes[p + 8..p + 12].try_into().unwrap());
        let name_start = p + 12;
        let name_end = name_start.saturating_add(namesz);
        let desc_start = name_end + ((4 - (namesz & 3)) & 3); // align name to 4
        let desc_end = desc_start.saturating_add(descsz);
        let next = desc_end + ((4 - (descsz & 3)) & 3); // align desc to 4
        if next > end || desc_end > end {
            break;
        }
        // NT_STAPSDT == 3 and the name is "stapsdt".  Skip other note
        // types in this section just in case.
        let ok = ntype == 3
            && namesz >= 8
            && &bytes[name_start..name_start + 7] == b"stapsdt"
            && bytes[name_start + 7] == 0;
        if ok && descsz >= 24 {
            let pc = u64::from_le_bytes(bytes[desc_start..desc_start + 8].try_into().unwrap());
            // base at desc_start+8 — currently ignored (only matters
            // for prelinked binaries; PIE bins are not prelinked).
            let semaphore =
                u64::from_le_bytes(bytes[desc_start + 16..desc_start + 24].try_into().unwrap());
            // Three NUL-terminated strings follow.
            let mut s = desc_start + 24;
            let read_cstr = |start: &mut usize| -> String {
                let begin = *start;
                let mut end = begin;
                while end < desc_end && bytes[end] != 0 {
                    end += 1;
                }
                let out = String::from_utf8_lossy(&bytes[begin..end]).into_owned();
                *start = (end + 1).min(desc_end);
                out
            };
            let provider = read_cstr(&mut s);
            let name = read_cstr(&mut s);
            let args = read_cstr(&mut s);
            // vaddr → file-offset translation; skip notes whose
            // pc isn't covered (corrupt or alien linker output).
            if let Some(pc_off) = vaddr_to_file_offset(pc) {
                let sema_off = vaddr_to_file_offset(semaphore).unwrap_or(0);
                notes.push(StapsdtNote {
                    provider,
                    name,
                    pc_file_offset: pc_off,
                    semaphore_file_offset: sema_off,
                    args,
                });
            }
        }
        p = next;
    }
    Ok(notes)
}

// `resolve_usdt_targets` was prototyped here as a host-side rootfs
// walker that read `.note.stapsdt` and emitted one `UprobeTarget`
// per matching call site.  It got replaced by the kernel-resolved
// USDT shape (PROBE_TYPE_USDT trailer = `(basename, sdt_provider,
// sdt_probe)`): the driver grabs `task->exe_file` of the running
// target, walks `.note.stapsdt` in-kernel, and registers uprobes
// directly — same pattern `attach_slot_uprobe_by_sym` uses for
// `.symtab` lookups.  No host-side rootfs mirror, no path-mismatch
// risk between host and guest views of the binary.  `parse_stapsdt`
// stays here for offline use (e.g. a future `bifrost --list-usdt`).

#[cfg(test)]
mod tests {
    use super::*;

    /// Reject non-ELF input cleanly. The macOS test runner is Mach-O,
    /// so this also covers the host-platform case.
    #[test]
    fn rejects_non_elf_input() {
        let bytes = b"#!/bin/sh\necho hello\n";
        assert!(SymTab::from_bytes(bytes).is_err());
    }

    /// On an empty SymTab, lookup_by_name returns None instead of
    /// panicking.
    #[test]
    fn empty_symtab_lookup_safe() {
        let st = SymTab { syms: Vec::new(), is_pie: true };
        assert!(st.lookup_by_name("anything").is_none());
        assert!(st.is_empty());
    }

    #[test]
    fn resolve_uprobe_rejects_slashes_in_basename() {
        let tmp = std::env::temp_dir();
        let err = resolve_uprobe_target(&tmp, "usr/bin/nginx", "main")
            .expect_err("slash in basename must error");
        assert!(
            matches!(err, UprobeTargetError::BasenameContainsSlash(_)),
            "wrong variant: {:?}",
            err
        );
    }

    #[test]
    fn resolve_uprobe_reports_missing_target() {
        let tmp = std::env::temp_dir();
        let err = resolve_uprobe_target(&tmp, "definitely-not-installed-xyz", "main")
            .expect_err("missing target must error");
        assert!(
            matches!(err, UprobeTargetError::NotFound { .. }),
            "wrong variant: {:?}",
            err
        );
    }

    /// Build a minimal byte-exact ET_DYN ELF-64 LE with one PT_LOAD
    /// segment plus a `.note.stapsdt` section carrying a single
    /// well-formed NT_STAPSDT note (provider=`p`, name=`probe`,
    /// args=`8@x0`).  Asserts `parse_stapsdt` decodes the note and
    /// resolves `pc` to a file offset via the PT_LOAD's vaddr→offset
    /// mapping.  Pinning byte counts directly catches regressions in
    /// the note-record padding arithmetic — the most likely place
    /// for a parser bug.
    #[test]
    fn parse_stapsdt_minimal_note() {
        // Layout (offsets are within the file):
        //   0x000  ELF64 header (64 bytes)
        //   0x040  Program header table (1 entry, 56 bytes)
        //   0x080  PT_LOAD-covered region (vaddr=0x1000, contains pc & sema)
        //          For the test pc=0x1234 maps to file_offset 0x1234-0x1000+0x80=0x314.
        //   0x100  .note.stapsdt section data
        //   0x140  Section header table (3 entries: NULL, .shstrtab, .note.stapsdt)
        //
        // Easier to construct a synthetic note section content first
        // and then layout from there.

        // Note record: u32 namesz=8 | u32 descsz | u32 type=3 | "stapsdt\0" | desc | (pad)
        // desc = u64 pc=0x1234 | u64 base=0 | u64 sema=0x2010 | "p\0" | "probe\0" | "8@x0\0"
        let mut desc = Vec::<u8>::new();
        desc.extend_from_slice(&0x1234u64.to_le_bytes());
        desc.extend_from_slice(&0u64.to_le_bytes());
        desc.extend_from_slice(&0x2010u64.to_le_bytes());
        desc.extend_from_slice(b"p\0");
        desc.extend_from_slice(b"probe\0");
        desc.extend_from_slice(b"8@x0\0");
        let descsz = desc.len() as u32;
        let mut note = Vec::<u8>::new();
        note.extend_from_slice(&8u32.to_le_bytes()); // namesz: "stapsdt\0"
        note.extend_from_slice(&descsz.to_le_bytes());
        note.extend_from_slice(&3u32.to_le_bytes()); // NT_STAPSDT
        note.extend_from_slice(b"stapsdt\0"); // 8 bytes, already aligned
        note.extend_from_slice(&desc);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        let note_size = note.len();

        // shstrtab: index 0 NUL, then ".shstrtab\0", then ".note.stapsdt\0"
        let mut shstr = Vec::<u8>::new();
        shstr.push(0);
        let off_shstr = shstr.len() as u32;
        shstr.extend_from_slice(b".shstrtab\0");
        let off_note = shstr.len() as u32;
        shstr.extend_from_slice(b".note.stapsdt\0");
        let shstr_size = shstr.len();

        // Final layout — sized so each region has its own slot.
        let phoff = 0x40usize;
        let load_off = 0x80usize; // PT_LOAD covers [load_off, load_off+0x4000)
        let load_vaddr = 0x1000u64;
        let load_size = 0x4000u64;
        let note_off = 0x100usize;
        let shstr_off = note_off + note_size;
        // Section headers (each 64 bytes) — keep aligned.
        let mut shoff = shstr_off + shstr_size;
        if shoff % 8 != 0 {
            shoff += 8 - (shoff % 8);
        }
        let total_size = shoff + 3 * 64;
        let mut bytes = vec![0u8; total_size];

        // ELF header (Elf64_Ehdr).
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // EI_CLASS = ELFCLASS64
        bytes[5] = 1; // EI_DATA = ELFDATA2LSB
        bytes[6] = 1; // EI_VERSION
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type ET_DYN (PIE)
        bytes[18..20].copy_from_slice(&0xb7u16.to_le_bytes()); // EM_AARCH64 (arbitrary)
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        bytes[32..40].copy_from_slice(&(phoff as u64).to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        bytes[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx -> sec[1]

        // Program header (Elf64_Phdr) — single PT_LOAD.
        let p = phoff;
        bytes[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        bytes[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes()); // p_flags = RWX
        bytes[p + 8..p + 16].copy_from_slice(&(load_off as u64).to_le_bytes()); // p_offset
        bytes[p + 16..p + 24].copy_from_slice(&load_vaddr.to_le_bytes()); // p_vaddr
        bytes[p + 24..p + 32].copy_from_slice(&load_vaddr.to_le_bytes()); // p_paddr
        bytes[p + 32..p + 40].copy_from_slice(&load_size.to_le_bytes()); // p_filesz
        bytes[p + 40..p + 48].copy_from_slice(&load_size.to_le_bytes()); // p_memsz

        // Note section content.
        bytes[note_off..note_off + note_size].copy_from_slice(&note);
        // shstrtab content.
        bytes[shstr_off..shstr_off + shstr_size].copy_from_slice(&shstr);

        // Section headers.  sec[0] is the SHT_NULL sentinel (zeroed).
        // sec[1] = .shstrtab, sec[2] = .note.stapsdt.
        let write_sh =
            |dst: &mut [u8], name_off: u32, stype: u32, off: u64, size: u64, link: u32| {
                dst[0..4].copy_from_slice(&name_off.to_le_bytes());
                dst[4..8].copy_from_slice(&stype.to_le_bytes());
                dst[24..32].copy_from_slice(&off.to_le_bytes());
                dst[32..40].copy_from_slice(&size.to_le_bytes());
                dst[40..44].copy_from_slice(&link.to_le_bytes());
            };
        write_sh(
            &mut bytes[shoff + 64..shoff + 128],
            off_shstr,
            3, /* SHT_STRTAB */
            shstr_off as u64,
            shstr_size as u64,
            0,
        );
        write_sh(
            &mut bytes[shoff + 128..shoff + 192],
            off_note,
            7, /* SHT_NOTE */
            note_off as u64,
            note_size as u64,
            0,
        );

        // Decode and assert.
        let notes = parse_stapsdt(&bytes).expect("parse stapsdt");
        assert_eq!(notes.len(), 1);
        let n = &notes[0];
        assert_eq!(n.provider, "p");
        assert_eq!(n.name, "probe");
        assert_eq!(n.args, "8@x0");
        // pc 0x1234 in PT_LOAD [vaddr=0x1000, off=0x80] → 0x1234 - 0x1000 + 0x80 = 0x314.
        assert_eq!(n.pc_file_offset, 0x1234 - 0x1000 + 0x80);
        // sema 0x2010 → 0x2010 - 0x1000 + 0x80 = 0x1090.
        assert_eq!(n.semaphore_file_offset, 0x2010 - 0x1000 + 0x80);
    }

    /// Integration check against a real `postgres:16` binary, if one
    /// has been extracted to `/tmp/pg16-binary`.  Pull with:
    ///   cid=$(docker create postgres:16) && \
    ///     docker cp $cid:/usr/lib/postgresql/16/bin/postgres /tmp/pg16-binary && \
    ///     docker rm $cid
    /// Skipped silently when the file isn't present so CI / fresh
    /// checkouts don't fail.
    #[test]
    fn parse_stapsdt_against_real_postgres() {
        let path = "/tmp/pg16-binary";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let notes = parse_stapsdt(&bytes).expect("parse postgres .note.stapsdt");
        // The Debian-built postgres:16 image ships --enable-dtrace; if
        // we got 0 notes from a real binary the parser missed them.
        assert!(notes.len() >= 56, "expected ≥56 stapsdt notes, got {}", notes.len());
        let qs: Vec<_> = notes.iter().filter(|n| n.name == "query__start").collect();
        assert_eq!(qs.len(), 1, "query__start should have a single site");
        // Args descriptor is `8@x27` on the aarch64 build; pin shape, not value.
        assert!(qs[0].args.starts_with("8@"), "args = {:?}", qs[0].args);
        // Provider is "postgresql" for every postgres-emitted probe.
        assert!(notes.iter().all(|n| n.provider == "postgresql"));
        // Semaphores are all non-zero on this build (PostgreSQL emits
        // semaphore-gated SDT probes throughout).
        let nonzero_sema = notes.iter().filter(|n| n.semaphore_file_offset != 0).count();
        assert!(
            nonzero_sema > notes.len() / 2,
            "expected most probes to have semaphores, got {}/{} non-zero",
            nonzero_sema,
            notes.len()
        );
    }

    /// `.note.stapsdt` absent: returns Ok(empty) rather than erroring.
    /// Most non-DTrace builds of ELF binaries have no such section.
    #[test]
    fn parse_stapsdt_missing_section_is_empty() {
        // Reuse the from_bytes path with an ELF that has a section
        // table but no `.note.stapsdt`.  An ELF64 minimal header with
        // shnum=0 (or shoff=0) is the empty-shtab degenerate case.
        let mut bytes = vec![0u8; 128];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        // Leaving e_shoff=0 / e_shnum=0 — parser short-circuits to empty.
        let notes = parse_stapsdt(&bytes).expect("absent .note.stapsdt is not an error");
        assert!(notes.is_empty());
    }
}
