// SPDX-License-Identifier: Apache-2.0
//! Quick sanity check: parse vmlinux ELF, count function symbols,
//! print the first few near a known address. Used to validate the
//! host-side symbolicator before plumbing it through the consumer.
//!
//! Usage:  ksym_test <path-to-vmlinux> [hex-pc]

use object::{Object, ObjectSymbol, SymbolKind};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: ksym_test <path-to-vmlinux> [hex-pc]");
            return ExitCode::from(2);
        }
    };
    let probe_pc = args
        .next()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read {}: {}", path, e);
            return ExitCode::from(1);
        }
    };
    let file = match object::File::parse(&*data) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("parse: {}", e);
            return ExitCode::from(1);
        }
    };

    let mut syms: Vec<(u64, String)> = file
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0)
        .filter_map(|s| s.name().ok().map(|n| (s.address(), n.to_string())))
        .filter(|(_, n)| !n.is_empty())
        .collect();
    syms.sort_by_key(|(a, _)| *a);
    syms.dedup_by_key(|(a, _)| *a);

    println!("loaded {} text symbols", syms.len());
    if syms.len() >= 3 {
        println!("first: {:#x} {}", syms[0].0, syms[0].1);
        println!(
            "last:  {:#x} {}",
            syms[syms.len() - 1].0,
            syms[syms.len() - 1].1
        );
    }

    if let Some(pc) = probe_pc {
        match syms.binary_search_by_key(&pc, |&(a, _)| a) {
            Ok(idx) => println!("0x{:x} -> {} (exact)", pc, syms[idx].1),
            Err(0) => println!("0x{:x} -> <below first symbol>", pc),
            Err(idx) => {
                let (base, name) = &syms[idx - 1];
                println!("0x{:x} -> {}+0x{:x}", pc, name, pc - base);
            }
        }
    }

    ExitCode::SUCCESS
}
