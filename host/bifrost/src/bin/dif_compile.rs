// SPDX-License-Identifier: Apache-2.0
//! Compile a D script to DOF via libdtrace, parse it, and dump the DIF
//! bytecode it produced. Optionally lower DIF -> eBPF and emit a wrapper
//! file consumable by libkrun's BIFROST_RAW_EBPF path.
//!
//! Usage:
//!   dif_compile [SCRIPT]                        — print DIF + lowered eBPF
//!   dif_compile -o OUT.dof [SCRIPT]             — also save the raw DOF blob
//!   dif_compile --emit-ebpf OUT.bin --target SYM [SCRIPT]
//!                                               — lower to eBPF and write
//!                                                 a BIFROST_RAW_EBPF wrapper
//!                                                 attaching to kprobe SYM
//!
//! Wrapper layout v2 (matches build_load_prog_payload_raw in libkrun):
//!   [u32]    magic (b"BFR\0")
//!   [u8;32]  target_name (NUL-padded)
//!   [u32]    schema_len (LE)
//!   [u8;schema_len]  encoded RecordSchema
//!   [u32]    num_insns (LE)
//!   [u8;8*n] raw eBPF instructions
//!
//! Requires root on macOS for libdtrace. With a `host/*/*` NOPASSWD
//! sudoers entry, run via the symlink at `host/bifrost/dif_compile`.

use bifrost::{Dof, SectKind, lower};
use std::env;
use std::fs;
use std::process::ExitCode;

const DEFAULT_SCRIPT: &str = "BEGIN { trace(42); }";

#[cfg(target_os = "macos")]
fn run() -> Result<ExitCode, String> {
    use bifrost::dtrace_ffi::DtraceHandle;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut out_path: Option<String> = None;
    let mut emit_ebpf: Option<String> = None;
    let mut target: Option<String> = None;
    let mut script: String = DEFAULT_SCRIPT.to_string();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "-o" {
            out_path = Some(iter.next().ok_or("-o needs a path")?);
        } else if arg == "--emit-ebpf" {
            emit_ebpf = Some(iter.next().ok_or("--emit-ebpf needs a path")?);
        } else if arg == "--target" {
            target = Some(iter.next().ok_or("--target needs a kprobe symbol")?);
        } else if !arg.starts_with('-') {
            script = arg;
        }
    }

    let mut hdl = DtraceHandle::open().map_err(|e| e.to_string())?;
    println!("[ok] dtrace_open");
    let dof = hdl.compile_to_dof(&script).map_err(|e| e.to_string())?;
    println!(
        "[ok] compiled D script ({} bytes DOF): {}",
        dof.len(),
        script
    );

    let parsed = Dof::parse(&dof).map_err(|e| e.to_string())?;
    let h = &parsed.header;
    println!(
        "DOF: hdrsize={} secsize={} secnum={} filesz={} loadsz={}",
        h.hdrsize, h.secsize, h.secnum, h.filesz, h.loadsz
    );
    for (idx, sec) in parsed.sections.iter().enumerate() {
        println!(
            "  sec[{:2}] kind={:?} size={} offset={} align={} entsize={}",
            idx, sec.kind, sec.size, sec.offset, sec.align, sec.entsize
        );
    }
    for (idx, sec) in parsed.sections_of(SectKind::Dif) {
        println!("\nDIF section [{}] — {} instructions:", idx, sec.size / 4);
        for (i, ins) in parsed.dif_instructions(sec).into_iter().enumerate() {
            println!(
                "  [{:3}] 0x{:08x}  {:<6} rd={:<3} r1={:<3} r2={:<3} imm16={}",
                i,
                ins.raw,
                ins.mnemonic(),
                ins.rd,
                ins.r1,
                ins.r2,
                ins.imm16()
            );
        }
    }

    if let Some(p) = out_path {
        fs::write(&p, &dof).map_err(|e| format!("write {}: {}", p, e))?;
        println!("[ok] wrote {} bytes of DOF to {}", dof.len(), p);
    }

    // Lowering — when emitting a wrapper file we pick a schema based on
    // the first ACTDESC kind in the DOF: DIFEXPR → default_trace (with
    // a `value` u64), STACK → kstack field, USTACK → ustack field.
    // Without `--emit-ebpf` we still print the schemaless form for
    // visibility.
    let target_schema = if emit_ebpf.is_some() {
        Some(pick_schema_for(&parsed))
    } else {
        None
    };
    let ebpf_result = lower::lower_with(&parsed, target_schema.as_ref());
    match &ebpf_result {
        Ok(ebpf) => {
            println!(
                "\n[ok] lowered to {} bytes ({} eBPF instructions)",
                ebpf.len(),
                ebpf.len() / 8
            );
            print!("{}", lower::disasm_ebpf(ebpf));
        }
        Err(e) => println!("\n[lowering] {}", e),
    }

    if let Some(path) = emit_ebpf {
        let ebpf = ebpf_result.map_err(|e| e.to_string())?;
        let target = target.ok_or("--emit-ebpf requires --target <kprobe-symbol>")?;
        let schema = target_schema.unwrap();
        let mut schema_bytes = Vec::new();
        schema
            .encode(&mut schema_bytes)
            .map_err(|e| format!("schema encode: {}", e))?;

        let mut wrapped = Vec::with_capacity(4 + 32 + 4 + schema_bytes.len() + 4 + ebpf.len());
        wrapped.extend_from_slice(b"BFR\0"); // magic, distinguishes v2 from v1
        let mut name_bytes = [0u8; 32];
        let raw = target.as_bytes();
        let copy = raw.len().min(31);
        name_bytes[..copy].copy_from_slice(&raw[..copy]);
        wrapped.extend_from_slice(&name_bytes);
        wrapped.extend_from_slice(&(schema_bytes.len() as u32).to_le_bytes());
        wrapped.extend_from_slice(&schema_bytes);
        let num_insns = (ebpf.len() / 8) as u32;
        wrapped.extend_from_slice(&num_insns.to_le_bytes());
        wrapped.extend_from_slice(&ebpf);
        fs::write(&path, &wrapped).map_err(|e| format!("write {}: {}", path, e))?;
        println!(
            "[ok] wrote BIFROST_RAW_EBPF wrapper ({} bytes, schema {} bytes) to {} (target={})",
            wrapped.len(),
            schema_bytes.len(),
            path,
            target
        );
        println!(
            "    record schema: {} fields ({}-byte records)",
            schema.fields.len(),
            schema.record_size()
        );
        for f in &schema.fields {
            println!("      {:8} {:?}", f.name, f.kind);
        }
    }

    Ok(ExitCode::SUCCESS)
}

#[cfg(not(target_os = "macos"))]
fn run() -> Result<ExitCode, String> {
    Err("dif_compile only links libdtrace on macOS".to_string())
}

fn main() -> ExitCode {
    match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// Inspect the DOF's first ECB and pick a record schema appropriate
/// for the action kind. Defaults to `default_trace` (a `value` u64) for
/// DIFEXPR or anything we don't yet recognize.
fn pick_schema_for(dof: &bifrost::Dof) -> bifrost::schema::RecordSchema {
    use bifrost::lower::{DTRACEACT_STACK, DTRACEACT_USTACK};
    use bifrost::schema::RecordSchema;
    if let Some(ecb) = dof.first_ecb() {
        let actions = dof.actions_in_chain(ecb.actions);
        if let Some(action) = actions.first() {
            match action.kind {
                DTRACEACT_STACK => return RecordSchema::for_kernel_stack(32),
                DTRACEACT_USTACK => return RecordSchema::for_user_stack(32),
                _ => {}
            }
        }
    }
    RecordSchema::default_trace()
}
