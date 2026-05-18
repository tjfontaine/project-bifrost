// SPDX-License-Identifier: Apache-2.0
//! Focused shared support code used by the host CLI and libkrun device.
//!
//! Keep this crate free of DTrace, DIF lowering, CLI, and macOS-only host
//! runtime dependencies. It exists so libkrun can decode/render Bifrost
//! records without depending on the full `bifrost` host crate.

pub mod elf_syms;
pub mod schema;
pub mod vdso;
