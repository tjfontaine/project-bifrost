// SPDX-License-Identifier: Apache-2.0
//! Minimal BTF parser for compile-time struct field offset lookups.
//!
//! Just enough BTF to resolve `(struct_name, field_name) → (offset_bytes,
//! size_bytes)` against a kernel's vmlinux BTF blob. Used by the bifrost
//! preprocessor to rewrite `OFFSETOF(task_struct, tgid)` in D source to
//! the literal integer offset before libdtrace sees the script.
//!
//! Wire format reference: linux/Documentation/bpf/btf.rst.
//!
//! Bitfield members aren't supported — the lookup returns
//! `BtfError::Bitfield` if a queried field happens to be a bitfield.
//! For the fields D scripts actually want (pointer-size or u32/u64),
//! this is fine.

use std::collections::HashMap;
use std::io;
use std::path::Path;

const BTF_MAGIC: u16 = 0xeB9F;

/// `linux/btf.h` BTF_KIND_* values.
mod kind {
    pub const INT: u8 = 1;
    pub const PTR: u8 = 2;
    pub const ARRAY: u8 = 3;
    pub const STRUCT: u8 = 4;
    pub const UNION: u8 = 5;
    pub const ENUM: u8 = 6;
    pub const FWD: u8 = 7;
    pub const TYPEDEF: u8 = 8;
    pub const VOLATILE: u8 = 9;
    pub const CONST: u8 = 10;
    pub const RESTRICT: u8 = 11;
    pub const FUNC: u8 = 12;
    pub const FUNC_PROTO: u8 = 13;
    pub const VAR: u8 = 14;
    pub const DATASEC: u8 = 15;
    pub const FLOAT: u8 = 16;
    pub const DECL_TAG: u8 = 17;
    pub const TYPE_TAG: u8 = 18;
    pub const ENUM64: u8 = 19;
}

#[derive(Debug)]
pub enum BtfError {
    BadMagic {
        found: u16,
    },
    Truncated {
        needed: usize,
        got: usize,
    },
    UnsupportedHdrLen {
        hdr_len: u32,
    },
    StructNotFound {
        name: String,
    },
    FieldNotFound {
        struct_name: String,
        field: String,
    },
    Bitfield {
        struct_name: String,
        field: String,
        offset_bits: u32,
    },
    FuncNotFound {
        name: String,
    },
}

impl std::fmt::Display for BtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic { found } => {
                write!(
                    f,
                    "BTF: bad magic 0x{:x} (expected 0x{:x})",
                    found, BTF_MAGIC
                )
            }
            Self::Truncated { needed, got } => {
                write!(f, "BTF: truncated, needed {} got {}", needed, got)
            }
            Self::UnsupportedHdrLen { hdr_len } => {
                write!(f, "BTF: unsupported header length {}", hdr_len)
            }
            Self::StructNotFound { name } => write!(f, "BTF: struct '{}' not found", name),
            Self::FieldNotFound { struct_name, field } => {
                write!(
                    f,
                    "BTF: field '{}' not found in struct '{}'",
                    field, struct_name
                )
            }
            Self::Bitfield {
                struct_name,
                field,
                offset_bits,
            } => write!(
                f,
                "BTF: field '{}.{}' is a bitfield (offset_bits={}), not supported",
                struct_name, field, offset_bits
            ),
            Self::FuncNotFound { name } => {
                write!(f, "BTF: func '{}' not found (kfunc unregistered?)", name)
            }
        }
    }
}

impl std::error::Error for BtfError {}

#[derive(Debug, Clone)]
pub enum BtfType {
    Void,
    Int {
        size: u32,
    },
    Ptr {
        type_id: u32,
    },
    Array {
        elem_type_id: u32,
        nelems: u32,
    },
    Struct {
        size: u32,
        members: Vec<BtfMember>,
    },
    Union {
        size: u32,
        members: Vec<BtfMember>,
    },
    Enum {
        size: u32,
    },
    Fwd,
    /// TYPEDEF / VOLATILE / CONST / RESTRICT / TYPE_TAG. Resolves to
    /// `type_id`; we peel transparently during lookups.
    Alias {
        type_id: u32,
    },
    /// FUNC — its `name` (in the parallel `names` table) plus this
    /// type id is what kfunc-call lowering needs (insn.imm = btf_id
    /// for `BPF_PSEUDO_KFUNC_CALL`). `proto_id` references the
    /// matching FUNC_PROTO; resolving through it gives parameter
    /// arity, which the host CLI uses to lower `retval` references
    /// in fexit clauses.
    Func {
        proto_id: u32,
    },
    /// FUNC_PROTO — `n_params` is the number of parameters the
    /// associated FUNC takes (vlen field in the BTF wire format).
    /// Type info for individual params is not parsed; the only
    /// thing the host CLI needs from FUNC_PROTOs today is the
    /// arity.
    FuncProto {
        n_params: u32,
    },
    /// Anything we don't model in detail (DATASEC, FLOAT, etc.).
    /// Held as a placeholder so subsequent type IDs stay aligned to
    /// their wire-format positions.
    Other,
}

#[derive(Debug, Clone)]
pub struct BtfMember {
    pub name_off: u32,
    pub type_id: u32,
    /// Bit offset within the parent struct.
    pub offset_bits: u32,
    /// Bitfield size in bits (0 if not a bitfield).
    pub bit_size: u8,
}

pub struct Btf {
    types: Vec<BtfType>,
    /// Parallel name table. `names[type_id]` is `Some(name)` if the
    /// type was emitted with a name (STRUCT, UNION, TYPEDEF, etc.).
    names: Vec<Option<String>>,
    /// Raw string table (NUL-separated).
    strs: Vec<u8>,
    /// Lazy index of struct/union name → type_id.
    struct_index: HashMap<String, u32>,
    /// Lazy index of FUNC name → type_id (the BTF id used as
    /// `insn.imm` for `BPF_PSEUDO_KFUNC_CALL`).
    func_index: HashMap<String, u32>,
}

impl Btf {
    fn str_at(&self, off: u32) -> Option<&str> {
        let off = off as usize;
        if off >= self.strs.len() {
            return None;
        }
        let nul = self.strs[off..].iter().position(|&b| b == 0)?;
        std::str::from_utf8(&self.strs[off..off + nul]).ok()
    }

    /// Strip wrapper types (TYPEDEF / VOLATILE / CONST / RESTRICT /
    /// TYPE_TAG) and return the underlying real type id.
    fn resolve(&self, mut type_id: u32) -> u32 {
        for _ in 0..32 {
            match self.types.get(type_id as usize) {
                Some(BtfType::Alias { type_id: inner }) => type_id = *inner,
                _ => break,
            }
        }
        type_id
    }

    /// Compute the byte size of a type, walking through aliases.
    fn type_size(&self, type_id: u32) -> Option<u32> {
        let id = self.resolve(type_id) as usize;
        match self.types.get(id)? {
            BtfType::Int { size } => Some(*size),
            BtfType::Ptr { .. } => Some(8), // arm64 / x86_64
            BtfType::Array {
                elem_type_id,
                nelems,
            } => Some(self.type_size(*elem_type_id)? * nelems),
            BtfType::Struct { size, .. } => Some(*size),
            BtfType::Union { size, .. } => Some(*size),
            BtfType::Enum { size } => Some(*size),
            BtfType::Fwd
            | BtfType::Alias { .. }
            | BtfType::Func { .. }
            | BtfType::FuncProto { .. }
            | BtfType::Other => None,
            BtfType::Void => Some(0),
        }
    }

    /// Find a struct/union by name, returning its type id. Lazily
    /// builds the name index on first call.
    pub fn find_struct(&mut self, name: &str) -> Option<u32> {
        if self.struct_index.is_empty() {
            for (id, name_opt) in self.names.iter().enumerate() {
                if let (Some(n), Some(t)) = (name_opt.as_deref(), self.types.get(id))
                    && matches!(t, BtfType::Struct { .. } | BtfType::Union { .. })
                {
                    self.struct_index.insert(n.to_string(), id as u32);
                }
            }
        }
        self.struct_index.get(name).copied()
    }

    /// Find a FUNC by name, returning its BTF type id. The kernel
    /// BPF verifier resolves a `BPF_PSEUDO_KFUNC_CALL` instruction's
    /// `imm` field against this id (vmlinux BTF, `insn.off == 0`).
    pub fn find_func(&mut self, name: &str) -> Result<u32, BtfError> {
        if self.func_index.is_empty() {
            for (id, name_opt) in self.names.iter().enumerate() {
                if let (Some(n), Some(BtfType::Func { .. })) =
                    (name_opt.as_deref(), self.types.get(id))
                {
                    self.func_index.insert(n.to_string(), id as u32);
                }
            }
        }
        self.func_index
            .get(name)
            .copied()
            .ok_or_else(|| BtfError::FuncNotFound { name: name.into() })
    }

    /// Look up the parameter count (arity) of a kernel function by
    /// name.  Used by the host CLI to lower `retval` references in
    /// fexit clauses: `retval` rewrites to `arg<arity>`, which the
    /// existing arg0..arg9 lowering reads as `ctx[arity * 8]` —
    /// exactly the slot a BPF_TRACE_FEXIT trampoline writes the
    /// return value into.  Returns `None` if the function isn't in
    /// vmlinux BTF or its FUNC_PROTO is malformed.
    pub fn func_arity(&mut self, name: &str) -> Option<u32> {
        let func_id = self.find_func(name).ok()? as usize;
        let proto_id = match self.types.get(func_id)? {
            BtfType::Func { proto_id } => *proto_id,
            _ => return None,
        };
        // Resolve through any alias chain (rare for FUNC_PROTO but
        // cheap to handle).
        let resolved = self.resolve(proto_id) as usize;
        match self.types.get(resolved)? {
            BtfType::FuncProto { n_params } => Some(*n_params),
            _ => None,
        }
    }

    /// Classify a struct member as embedded-struct / pointer /
    /// scalar — used by the typed-translator expander when
    /// descending an `args[N]->a->b->c` chain through embedded
    /// structs.  Returns `None` if the named field doesn't exist on
    /// the given struct.  The returned `String` for `EmbeddedStruct`
    /// is the inner struct's BTF name, the next hop's root type.
    pub fn member_descend(
        &mut self,
        struct_name: &str,
        field: &str,
    ) -> Option<crate::translators::MemberKind> {
        let sid = self.find_struct(struct_name)?;
        let member = self.find_member_raw(sid, field, 0)?;
        let resolved = self.resolve(member.type_id) as usize;
        match self.types.get(resolved)? {
            BtfType::Struct { .. } | BtfType::Union { .. } => {
                let name = self
                    .names
                    .get(resolved)
                    .and_then(|n| n.clone())
                    .unwrap_or_default();
                Some(crate::translators::MemberKind::EmbeddedStruct(name))
            }
            BtfType::Ptr { type_id } => {
                let inner = self.resolve(*type_id) as usize;
                let inner_name = self
                    .names
                    .get(inner)
                    .and_then(|n| n.clone())
                    .unwrap_or_default();
                Some(crate::translators::MemberKind::Pointer(inner_name))
            }
            BtfType::Int { .. } | BtfType::Enum { .. } | BtfType::Array { .. } | BtfType::Fwd => {
                Some(crate::translators::MemberKind::Scalar)
            }
            _ => Some(crate::translators::MemberKind::Scalar),
        }
    }

    /// Look up a member record (not just its offset) by name.  Walks
    /// anonymous nested members the same way `find_member` does.
    fn find_member_raw(
        &self,
        struct_id: u32,
        field: &str,
        _base_offset_bits: u32,
    ) -> Option<BtfMember> {
        let id = self.resolve(struct_id) as usize;
        let members = match self.types.get(id)? {
            BtfType::Struct { members, .. } | BtfType::Union { members, .. } => members,
            _ => return None,
        };
        for m in members {
            let mname = self.str_at(m.name_off).unwrap_or("");
            if mname.is_empty() {
                if let Some(hit) = self.find_member_raw(m.type_id, field, 0) {
                    return Some(hit);
                }
            } else if mname == field {
                return Some(m.clone());
            }
        }
        None
    }

    /// Returns `(offset_bytes, size_bytes)` for `struct_name.field`.
    /// Walks anonymous nested struct/union members depth-first — same
    /// rule C uses to resolve member access through anon members.
    pub fn field_offset(&mut self, struct_name: &str, field: &str) -> Result<(u32, u32), BtfError> {
        let sid = self
            .find_struct(struct_name)
            .ok_or_else(|| BtfError::StructNotFound {
                name: struct_name.into(),
            })?;
        match self.find_member(sid, field, 0) {
            Some(Ok(hit)) => Ok(hit),
            Some(Err(off_bits)) => Err(BtfError::Bitfield {
                struct_name: struct_name.into(),
                field: field.into(),
                offset_bits: off_bits,
            }),
            None => Err(BtfError::FieldNotFound {
                struct_name: struct_name.into(),
                field: field.into(),
            }),
        }
    }

    /// True iff `struct_name.field` exists in the BTF.  Anonymous
    /// nested struct/union walking matches `field_offset`, but this
    /// accepts bitfields because FIELD_RELOC_EXISTS only needs an
    /// availability predicate.
    pub fn field_exists(&mut self, struct_name: &str, field: &str) -> bool {
        let Some(sid) = self.find_struct(struct_name) else {
            return false;
        };
        self.find_member_exists(sid, field)
    }

    fn find_member_exists(&self, struct_id: u32, field: &str) -> bool {
        let id = self.resolve(struct_id) as usize;
        let members = match self.types.get(id) {
            Some(BtfType::Struct { members, .. }) | Some(BtfType::Union { members, .. }) => members,
            _ => return false,
        };
        for m in members {
            let mname = self.str_at(m.name_off).unwrap_or("");
            if mname.is_empty() {
                if self.find_member_exists(m.type_id, field) {
                    return true;
                }
            } else if mname == field {
                return true;
            }
        }
        false
    }

    /// Returns:
    ///   - `None` if not found
    ///   - `Some(Err(off_bits))` if found but bitfield
    ///   - `Some(Ok((offset_bytes, size_bytes)))` if found, byte-aligned
    fn find_member(
        &self,
        struct_id: u32,
        field: &str,
        base_offset_bits: u32,
    ) -> Option<Result<(u32, u32), u32>> {
        let id = self.resolve(struct_id) as usize;
        let members = match self.types.get(id)? {
            BtfType::Struct { members, .. } | BtfType::Union { members, .. } => members,
            _ => return None,
        };
        for m in members {
            let mname = self.str_at(m.name_off).unwrap_or("");
            let abs_bits = base_offset_bits + m.offset_bits;
            if mname.is_empty() {
                if let Some(hit) = self.find_member(m.type_id, field, abs_bits) {
                    return Some(hit);
                }
            } else if mname == field {
                if !abs_bits.is_multiple_of(8) || m.bit_size != 0 {
                    return Some(Err(abs_bits));
                }
                let size = self.type_size(m.type_id)?;
                return Some(Ok((abs_bits / 8, size)));
            }
        }
        None
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, BtfError> {
    if at + 4 > bytes.len() {
        return Err(BtfError::Truncated {
            needed: at + 4,
            got: bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
    ]))
}

/// Parse one BTF type starting at `bytes[0]`. Returns the parsed type
/// and the number of bytes consumed (header + per-kind tail).
fn parse_one(bytes: &[u8]) -> Result<(BtfType, usize), BtfError> {
    if bytes.len() < 12 {
        return Err(BtfError::Truncated {
            needed: 12,
            got: bytes.len(),
        });
    }
    let info = read_u32(bytes, 4)?;
    let size_or_type = read_u32(bytes, 8)?;
    let kind = ((info >> 24) & 0x1f) as u8;
    let vlen = (info & 0xffff) as u32;
    let kind_flag = (info >> 31) & 1;
    let mut consumed = 12usize;
    let parsed = match kind {
        kind::INT => {
            consumed += 4; // tail: u32 (encoding | offset | bits)
            BtfType::Int { size: size_or_type }
        }
        kind::PTR => BtfType::Ptr {
            type_id: size_or_type,
        },
        kind::ARRAY => {
            // Tail: btf_array { elem_type, index_type, nelems } (12 bytes).
            if bytes.len() < consumed + 12 {
                return Err(BtfError::Truncated {
                    needed: consumed + 12,
                    got: bytes.len(),
                });
            }
            let elem = read_u32(bytes, consumed)?;
            let nelems = read_u32(bytes, consumed + 8)?;
            consumed += 12;
            BtfType::Array {
                elem_type_id: elem,
                nelems,
            }
        }
        kind::STRUCT | kind::UNION => {
            // Tail: vlen × btf_member { name_off, type, offset } (12B each).
            let mut members = Vec::with_capacity(vlen as usize);
            for _ in 0..vlen {
                if bytes.len() < consumed + 12 {
                    return Err(BtfError::Truncated {
                        needed: consumed + 12,
                        got: bytes.len(),
                    });
                }
                let n = read_u32(bytes, consumed)?;
                let t = read_u32(bytes, consumed + 4)?;
                let o = read_u32(bytes, consumed + 8)?;
                let (offset_bits, bit_size) = if kind_flag == 1 {
                    // High 8 bits = bit_size, low 24 = offset.
                    (o & 0x00ff_ffff, ((o >> 24) & 0xff) as u8)
                } else {
                    (o, 0)
                };
                members.push(BtfMember {
                    name_off: n,
                    type_id: t,
                    offset_bits,
                    bit_size,
                });
                consumed += 12;
            }
            if kind == kind::STRUCT {
                BtfType::Struct {
                    size: size_or_type,
                    members,
                }
            } else {
                BtfType::Union {
                    size: size_or_type,
                    members,
                }
            }
        }
        kind::ENUM => {
            consumed += (vlen as usize) * 8;
            BtfType::Enum { size: size_or_type }
        }
        kind::ENUM64 => {
            consumed += (vlen as usize) * 12;
            BtfType::Enum { size: size_or_type }
        }
        kind::FWD => BtfType::Fwd,
        kind::TYPEDEF | kind::VOLATILE | kind::CONST | kind::RESTRICT | kind::TYPE_TAG => {
            BtfType::Alias {
                type_id: size_or_type,
            }
        }
        kind::FUNC => BtfType::Func {
            proto_id: size_or_type,
        },
        kind::FUNC_PROTO => {
            consumed += (vlen as usize) * 8;
            BtfType::FuncProto { n_params: vlen }
        }
        kind::VAR => {
            consumed += 4;
            BtfType::Other
        }
        kind::DATASEC => {
            consumed += (vlen as usize) * 12;
            BtfType::Other
        }
        kind::FLOAT => BtfType::Other,
        kind::DECL_TAG => {
            consumed += 4;
            BtfType::Other
        }
        _ => BtfType::Other,
    };
    Ok((parsed, consumed))
}

/// Parse a raw BTF blob (the `.BTF` section bytes).
pub fn parse(bytes: &[u8]) -> Result<Btf, BtfError> {
    if bytes.len() < 24 {
        return Err(BtfError::Truncated {
            needed: 24,
            got: bytes.len(),
        });
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if magic != BTF_MAGIC {
        return Err(BtfError::BadMagic { found: magic });
    }
    // bytes[2] = version, bytes[3] = flags — tolerate any.
    let hdr_len = read_u32(bytes, 4)?;
    if (hdr_len as usize) < 24 {
        return Err(BtfError::UnsupportedHdrLen { hdr_len });
    }
    let type_off = read_u32(bytes, 8)? as usize;
    let type_len = read_u32(bytes, 12)? as usize;
    let str_off = read_u32(bytes, 16)? as usize;
    let str_len = read_u32(bytes, 20)? as usize;
    let hdr_len_us = hdr_len as usize;

    let type_start = hdr_len_us + type_off;
    let type_end = type_start
        .checked_add(type_len)
        .ok_or(BtfError::Truncated {
            needed: type_len,
            got: 0,
        })?;
    let str_start = hdr_len_us + str_off;
    let str_end = str_start.checked_add(str_len).ok_or(BtfError::Truncated {
        needed: str_len,
        got: 0,
    })?;
    if type_end > bytes.len() || str_end > bytes.len() {
        return Err(BtfError::Truncated {
            needed: type_end.max(str_end),
            got: bytes.len(),
        });
    }

    let strs = bytes[str_start..str_end].to_vec();
    let mut types = vec![BtfType::Void];
    let mut names: Vec<Option<String>> = vec![None];
    let mut p = type_start;
    while p < type_end {
        if p + 12 > type_end {
            break;
        }
        let name_off = read_u32(bytes, p)?;
        let (parsed, consumed) = parse_one(&bytes[p..type_end])?;
        let name = if name_off != 0 {
            let off = name_off as usize;
            if off < strs.len() {
                let nul = strs[off..].iter().position(|&b| b == 0).unwrap_or(0);
                std::str::from_utf8(&strs[off..off + nul])
                    .ok()
                    .map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
        };
        types.push(parsed);
        names.push(name);
        p += consumed;
    }

    Ok(Btf {
        types,
        names,
        strs,
        struct_index: HashMap::new(),
        func_index: HashMap::new(),
    })
}

/// Extract the `.BTF` section bytes from an ELF-64 LE file. The path is
/// supplied by the caller (developer-controlled — kernel binary
/// location); we read the file as-is and find the named section.
pub fn extract_btf_section(vmlinux_path: &Path) -> io::Result<Vec<u8>> {
    // `vmlinux_path` is a developer-supplied kernel-binary path
    // (CLI tool, not a web service); the path-traversal warning
    // semgrep emits here doesn't apply.
    let bytes = std::fs::read(vmlinux_path)?; // nosemgrep
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an ELF-64 LE file",
        ));
    }
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
    let read_sh = |idx: usize| -> (u32, u64, u64) {
        // Returns (sh_name, sh_offset, sh_size).
        let p = shoff + idx * shentsize;
        let name = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        let off = u64::from_le_bytes(bytes[p + 24..p + 32].try_into().unwrap());
        let size = u64::from_le_bytes(bytes[p + 32..p + 40].try_into().unwrap());
        (name, off, size)
    };
    let (_, strtab_off, strtab_size) = read_sh(shstrndx);
    let strtab_off = strtab_off as usize;
    let strtab_size = strtab_size as usize;
    if strtab_off + strtab_size > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ELF .shstrtab out of bounds",
        ));
    }
    for i in 0..shnum {
        let (name_off, off, size) = read_sh(i);
        let name_start = strtab_off + name_off as usize;
        if name_start >= bytes.len() {
            continue;
        }
        let nul = bytes[name_start..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        let name = std::str::from_utf8(&bytes[name_start..name_start + nul]).unwrap_or("");
        if name == ".BTF" {
            let off = off as usize;
            let size = size as usize;
            if off + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ".BTF section out of bounds",
                ));
            }
            return Ok(bytes[off..off + size].to_vec());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        ".BTF section not present in ELF",
    ))
}
