// CLI-layer modules for the `bifrost` binary.
//
// These modules hold logic that is application-specific (BFR7 wire
// format, attach-mode runtime, output rendering) and were extracted
// from `src/bin/bifrost.rs` to keep the binary entrypoint navigable.
// Each submodule is independently testable; binaries link them via
// the public `bifrost::cli::*` re-exports.

pub mod agg_decl;
pub mod args;
pub mod capability_fanout;
pub mod wrapper;

#[cfg(target_os = "macos")]
pub mod direct_load;

#[cfg(target_os = "macos")]
pub mod launcher;

#[cfg(target_os = "macos")]
pub mod macos_host;

#[cfg(target_os = "macos")]
pub mod printa;

#[cfg(target_os = "macos")]
pub mod qmp;

#[cfg(target_os = "macos")]
pub mod linux_compile;

#[cfg(target_os = "macos")]
pub mod orchestrate;

#[cfg(target_os = "macos")]
pub mod direct_symbols;

#[cfg(target_os = "macos")]
pub mod profile;

#[cfg(target_os = "macos")]
pub mod runtime;

#[cfg(target_os = "macos")]
pub mod schema_pick;

#[cfg(target_os = "macos")]
pub mod source_rewrite;

#[cfg(target_os = "macos")]
pub mod trace_render;

#[cfg(target_os = "macos")]
pub mod xagg;

#[cfg(target_os = "macos")]
pub mod xstack;
