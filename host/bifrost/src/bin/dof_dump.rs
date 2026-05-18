// SPDX-License-Identifier: Apache-2.0
//! Dump a DOF blob's structure and DIF bytecode.
//!
//! Usage:  dof_dump <path-to-.dof>
//!
//! Reads a DOF file produced by `dif_compile -o file.dof`, parses it with
//! `bifrost::Dof`, and prints the section table plus any DIF bytecode.
//! This is the consumption side of the pipeline that the DIF → eBPF
//! lowering pass will plug into.

use bifrost::{Dof, SectKind};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: dof_dump <path-to-.dof>");
            return ExitCode::from(2);
        }
    };
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {}: {}", path, e);
            return ExitCode::from(1);
        }
    };
    let dof = match Dof::parse(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(1);
        }
    };
    let h = &dof.header;
    println!(
        "DOF: hdrsize={} secsize={} secnum={} filesz={} loadsz={}",
        h.hdrsize, h.secsize, h.secnum, h.filesz, h.loadsz
    );
    for (idx, sec) in dof.sections.iter().enumerate() {
        println!(
            "  sec[{:2}] kind={:?} size={} offset={} align={} entsize={}",
            idx, sec.kind, sec.size, sec.offset, sec.align, sec.entsize
        );
    }

    for (idx, sec) in dof.sections_of(SectKind::Dif) {
        println!("\nDIF section [{}] — {} instructions:", idx, sec.size / 4);
        for (i, ins) in dof.dif_instructions(sec).into_iter().enumerate() {
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
    ExitCode::SUCCESS
}
