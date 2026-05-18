// SPDX-License-Identifier: Apache-2.0
use bifrost::btf;
use std::path::Path;

fn main() {
    let path = std::env::var("BIFROST_VMLINUX").unwrap();
    let bytes = btf::extract_btf_section(Path::new(&path)).unwrap();
    let mut b = btf::parse(&bytes).unwrap();
    for n in [
        "bifrost_kfunc_current_exe_path",
        "bifrost_kfunc_emit_vma_table",
        "bifrost_emit_vma_table",
        "bifrost_task_exe_path",
    ] {
        match b.find_func(n) {
            Ok(id) => println!("  {} = btf_id {}", n, id),
            Err(e) => println!("  {} = NOT FOUND ({})", n, e),
        }
    }
}
