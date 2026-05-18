// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct VmaEntry {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub prot: u32,
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct VmaTable {
    pub entries: Vec<VmaEntry>,
}

impl VmaTable {
    pub fn parse(body: &[u8]) -> Option<Self> {
        // Header layout is fixed at 16 bytes; the per-VMA entry size
        // is 32. Guest-supplied counts are decoded with checked
        // arithmetic and bounded by the actual body length before any
        // allocation — a corrupt record degrades to `None` rather than
        // panicking or attempting an enormous reserve.
        if body.len() < 16 {
            return None;
        }
        let n_vmas = u32::from_le_bytes(body[0..4].try_into().ok()?) as usize;
        let strings_off = u32::from_le_bytes(body[4..8].try_into().ok()?) as usize;
        let strings_len = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
        if n_vmas == 0 || n_vmas == 0xFFFFFFFE {
            return None;
        }
        const HDR_SIZE: usize = 16;
        const ENTRY_SIZE: usize = 32;
        let entries_end = n_vmas
            .checked_mul(ENTRY_SIZE)
            .and_then(|n| n.checked_add(HDR_SIZE))?;
        let strings_end = strings_off.checked_add(strings_len)?;
        if entries_end > body.len() || strings_end > body.len() {
            return None;
        }
        let strings = &body[strings_off..strings_end];
        let mut entries = Vec::with_capacity(n_vmas);
        for i in 0..n_vmas {
            let p = HDR_SIZE + i * ENTRY_SIZE;
            let start = u64::from_le_bytes(body[p..p + 8].try_into().ok()?);
            let end = u64::from_le_bytes(body[p + 8..p + 16].try_into().ok()?);
            let file_offset = u64::from_le_bytes(body[p + 16..p + 24].try_into().ok()?);
            let prot = u32::from_le_bytes(body[p + 24..p + 28].try_into().ok()?);
            let path_off = u32::from_le_bytes(body[p + 28..p + 32].try_into().ok()?) as usize;
            let path = if path_off < strings.len() {
                let nul = strings[path_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(strings.len() - path_off);
                String::from_utf8_lossy(&strings[path_off..path_off + nul]).into_owned()
            } else {
                String::new()
            };
            entries.push(VmaEntry {
                start,
                end,
                file_offset,
                prot,
                path,
            });
        }
        Some(Self { entries })
    }

    pub fn find_for_pc(&self, pc: u64) -> Option<&VmaEntry> {
        const VM_EXEC: u32 = 0x4;
        self.entries
            .iter()
            .find(|v| v.start <= pc && pc < v.end && (v.prot & VM_EXEC) != 0)
    }
}

#[derive(Debug, Clone)]
pub struct PushedSymEntry {
    pub file_offset: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct PushedSymTab {
    pub entries: Vec<PushedSymEntry>,
}

impl PushedSymTab {
    pub fn parse(body: &[u8]) -> Option<(String, Self)> {
        // Guest-supplied n_syms / path lengths are decoded with checked
        // arithmetic and bounded by the body length before any
        // allocation — a corrupt record degrades to `None` rather than
        // panicking or attempting an enormous reserve.
        const HDR_SIZE: usize = 24;
        const ENTRY_SIZE: usize = 24;
        if body.len() < HDR_SIZE {
            return None;
        }
        let path_off = u32::from_le_bytes(body[0..4].try_into().ok()?) as usize;
        let path_len = u32::from_le_bytes(body[4..8].try_into().ok()?) as usize;
        let n_syms = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
        let strings_off = u32::from_le_bytes(body[12..16].try_into().ok()?) as usize;
        let strings_len = u32::from_le_bytes(body[16..20].try_into().ok()?) as usize;

        let strings_end = strings_off.checked_add(strings_len)?;
        if strings_end > body.len() {
            return None;
        }
        let strings = &body[strings_off..strings_end];
        let path_end = path_off.checked_add(path_len)?;
        if path_end > strings.len() {
            return None;
        }
        let path = String::from_utf8_lossy(&strings[path_off..path_end]).into_owned();

        let entries_end = n_syms
            .checked_mul(ENTRY_SIZE)
            .and_then(|n| n.checked_add(HDR_SIZE))?;
        if entries_end > body.len() {
            return None;
        }
        let mut entries = Vec::with_capacity(n_syms);
        for i in 0..n_syms {
            let p = HDR_SIZE + i * ENTRY_SIZE;
            let st_value = u64::from_le_bytes(body[p..p + 8].try_into().ok()?);
            let st_size = u64::from_le_bytes(body[p + 8..p + 16].try_into().ok()?);
            let name_off = u32::from_le_bytes(body[p + 16..p + 20].try_into().ok()?) as usize;
            if st_value == 0 || name_off >= strings.len() {
                continue;
            }
            let name_max = strings.len() - name_off;
            let nul = strings[name_off..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_max);
            if nul == 0 {
                continue;
            }
            let name = String::from_utf8_lossy(&strings[name_off..name_off + nul]).into_owned();
            entries.push(PushedSymEntry {
                file_offset: st_value,
                size: st_size,
                name,
            });
        }
        entries.sort_by_key(|e| e.file_offset);
        Some((path, Self { entries }))
    }

    pub fn lookup(&self, file_offset: u64) -> Option<(&str, u64)> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = match self
            .entries
            .binary_search_by_key(&file_offset, |e| e.file_offset)
        {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let entry = &self.entries[idx];
        let off = file_offset - entry.file_offset;
        if entry.size > 0 && off >= entry.size {
            return None;
        }
        Some((entry.name.as_str(), off))
    }
}

#[derive(Default)]
pub struct DirectSymbolState {
    pub ksyms: Vec<(u64, String)>,
    pub ksym_cache: HashMap<u64, String>,
    pub vma_cache: HashMap<u64, VmaTable>,
    pub pushed_syms: HashMap<String, Arc<PushedSymTab>>,
}

impl DirectSymbolState {
    pub fn ingest_vma_record(&mut self, payload: &[u8]) {
        if payload.len() <= 24 {
            return;
        }
        let gpid = u64::from_le_bytes(payload[16..24].try_into().unwrap());
        if let Some(table) = VmaTable::parse(&payload[24..]) {
            self.vma_cache.insert(gpid, table);
        }
    }

    pub fn ingest_sym_record(&mut self, payload: &[u8]) {
        if payload.len() <= 24 {
            return;
        }
        let Some((path, mut table)) = PushedSymTab::parse(&payload[24..]) else {
            return;
        };
        let merged = match self.pushed_syms.remove(&path) {
            Some(existing) => {
                let mut entries = existing.entries.clone();
                entries.append(&mut table.entries);
                entries.sort_by_key(|e| e.file_offset);
                entries.dedup_by_key(|e| e.file_offset);
                PushedSymTab { entries }
            }
            None => table,
        };
        self.pushed_syms.insert(path, Arc::new(merged));
    }

    pub fn render_kernel_pc(&mut self, pc: u64) -> String {
        if let Some(s) = self.ksym_cache.get(&pc) {
            return s.clone();
        }
        let rendered = if self.ksyms.is_empty() {
            format!("0x{:x}", pc)
        } else {
            match self.ksyms.binary_search_by_key(&pc, |&(addr, _)| addr) {
                Ok(idx) => self.ksyms[idx].1.clone(),
                Err(0) => format!("0x{:x}", pc),
                Err(idx) => {
                    let (base, name) = &self.ksyms[idx - 1];
                    format!("{}+0x{:x}", name, pc - base)
                }
            }
        };
        self.ksym_cache.insert(pc, rendered.clone());
        rendered
    }

    pub fn render_user_pc(&mut self, gpid: u64, pc: u64) -> String {
        let Some(vma) = self.vma_cache.get(&gpid).and_then(|t| t.find_for_pc(pc)) else {
            return format!("0x{:x}", pc);
        };
        if vma.path == "[vvar]" {
            return format!("[vvar]+0x{:x}", pc - vma.start);
        }
        let basename = Path::new(&vma.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(vma.path.as_str());
        let file_off = (pc - vma.start) + vma.file_offset;
        let fallback = || format!("{}+0x{:x}", basename, file_off);
        if vma.path == "[vdso]" {
            return fallback();
        }
        if let Some(table) = self.pushed_syms.get(vma.path.as_str())
            && let Some((name, sym_off)) = table.lookup(file_off)
        {
            return if sym_off == 0 {
                format!("{}!{}", basename, name)
            } else {
                format!("{}!{}+0x{:x}", basename, name, sym_off)
            };
        }
        fallback()
    }
}

pub fn parse_kallsyms_blob(buf: &[u8]) -> Vec<(u64, String)> {
    let mut syms = Vec::new();
    let mut p = 0usize;
    while p + 9 <= buf.len() {
        let addr = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
        let name_len = buf[p + 8] as usize;
        p += 9;
        if p + name_len > buf.len() {
            break;
        }
        let name = String::from_utf8_lossy(&buf[p..p + name_len]).into_owned();
        syms.push((addr, name));
        p += name_len;
    }
    syms.sort_by_key(|(addr, _)| *addr);
    syms.dedup_by_key(|(addr, _)| *addr);
    syms
}
