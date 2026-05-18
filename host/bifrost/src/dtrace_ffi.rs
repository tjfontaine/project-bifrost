// SPDX-License-Identifier: Apache-2.0
//! Minimal FFI bindings to macOS libdtrace — covers two use cases:
//!
//!   1. Compile a D script to a DOF blob (used by older guest-side
//!      injection paths). `DtraceHandle::compile_to_dof`.
//!   2. Run an in-process libdtrace consumer attached to a target pid,
//!      receive probe data via callbacks, and surface records as Rust
//!      structs. `Consumer` + `record_loop`. The in-process consumer
//!      keeps the protocol structured and lets us add binary
//!      `tracemem` records without changing a stdout wire format.
//!
//! Keeps the dependency surface small (no bindgen) and the linkage
//! explicit. The kernel-side ABI bits we care about live in dtrace.h
//! / sys/dtrace.h on the system; we mirror only what we use.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::ptr;
use std::slice;
use thiserror::Error;

/// Errors from libdtrace FFI calls.  Wraps the libdtrace errmsg
/// strings (we don't try to enumerate every libdtrace errno; the
/// upstream API is "free-form errmsg string + numeric errno" and
/// we surface both).
#[derive(Debug, Error)]
pub enum DtraceFfiError {
    #[error("dtrace_open failed: err={errno} ({msg})")]
    OpenFailed { errno: i32, msg: String },
    #[error("script has NUL byte: {0}")]
    ScriptHasNul(String),
    #[error("compile failed: {0}")]
    CompileFailed(String),
    #[error("dof_create failed: {0}")]
    DofCreateFailed(String),
}

/// `DTRACE_VERSION` from <dtrace.h>.
pub const DTRACE_VERSION: c_int = 3;

/// `dtrace_probespec_t` (sys/dtrace.h enum values).
pub const DTRACE_PROBESPEC_PROVIDER: c_int = 0;
pub const DTRACE_PROBESPEC_MOD: c_int = 1;
pub const DTRACE_PROBESPEC_FUNC: c_int = 2;
pub const DTRACE_PROBESPEC_NAME: c_int = 3;

/// `DTRACE_C_*` compile flags from <dtrace.h>.
pub const DTRACE_C_DIFV: c_uint = 0x0001;
pub const DTRACE_C_ZDEFS: c_uint = 0x0004;
pub const DTRACE_C_KNODEF: c_uint = 0x0020;

/// `DTRACE_O_*` open flags.
pub const DTRACE_O_NOSYS: c_int = 0x02;
pub const DTRACE_O_LP64: c_int = 0x04;

/// `dtrace_workstatus_t` from <dtrace.h>.
pub const DTRACE_WORKSTATUS_OKAY: c_int = 0;
pub const DTRACE_WORKSTATUS_DONE: c_int = 1;
pub const DTRACE_WORKSTATUS_ERROR: c_int = -1;

/// `DTRACE_CONSUME_*` callback return codes.
pub const DTRACE_CONSUME_THIS: c_int = 0;
pub const DTRACE_CONSUME_NEXT: c_int = 1;
pub const DTRACE_CONSUME_ERROR: c_int = -1;
pub const DTRACE_CONSUME_ABORT: c_int = 2;

/// Subset of `dtrace_probedata_t` we expose to Rust callbacks.
/// Field offsets must match libdtrace's layout (verified against
/// the SDK header at compile time via offsetof asserts in
/// `dtrace_consumer.rs`). Today we read the probedesc pointer to
/// recover the firing probe's name; the rest is opaque.
#[repr(C)]
pub struct DtraceProbeData {
    pub dtpda_handle: *mut c_void,         // dtrace_hdl_t *
    pub dtpda_edesc: *mut c_void,          // dtrace_eprobedesc_t *
    pub dtpda_pdesc: *mut DtraceProbeDesc, // dtrace_probedesc_t *
    pub dtpda_cpu: c_int,                  // processorid_t
    pub dtpda_data: *mut c_char,           // caddr_t (raw record bytes)
    pub dtpda_flow: c_int,
    pub dtpda_prefix: *const c_char,
    pub dtpda_indent: c_int,
}

/// Subset of `dtrace_probedesc_t`: just the four name parts we
/// route on (provider:module:function:name).
#[repr(C)]
pub struct DtraceProbeDesc {
    pub dtpd_id: c_uint,
    pub dtpd_provider: [c_char; 64],
    pub dtpd_mod: [c_char; 64],
    pub dtpd_func: [c_char; 192],
    pub dtpd_name: [c_char; 64],
}

/// Subset of `dtrace_recdesc_t` exposed to record callbacks. We
/// peek at `dtrd_action` (DTRACEACT_*) and `dtrd_size` to
/// distinguish printf-action records from binary scalars/stacks.
#[repr(C)]
pub struct DtraceRecDesc {
    pub dtrd_action: c_uint,
    pub dtrd_size: c_uint,
    pub dtrd_offset: c_uint,
    pub dtrd_alignment: c_ushort,
    pub dtrd_format: c_ushort,
    pub dtrd_arg: u64,
    pub dtrd_uarg: u64,
}

#[allow(non_camel_case_types)]
type c_ushort = u16;

/// `DTRACEACT_*` action types from `<sys/dtrace.h>`. `printf` records
/// arrive as `DTRACEACT_PRINTF`; raw scalar `trace()` as
/// `DTRACEACT_DIFEXPR`; user-space stack walks as `DTRACEACT_USTACK`;
/// kernel stack walks as `DTRACEACT_STACK`. The high-class bits
/// (`PROC = 0x100`, `KERNEL = 0x400`) match the SDK header.
pub const DTRACEACT_NONE: c_uint = 0;
pub const DTRACEACT_DIFEXPR: c_uint = 1;
pub const DTRACEACT_PRINTF: c_uint = 3;
pub const DTRACEACT_TRACEMEM: c_uint = 6;
pub const DTRACEACT_TRACEMEM_DYNSIZE: c_uint = 7;
pub const DTRACEACT_PROC: c_uint = 0x100;
pub const DTRACEACT_USTACK: c_uint = DTRACEACT_PROC + 1; // 0x101
pub const DTRACEACT_JSTACK: c_uint = DTRACEACT_PROC + 2; // 0x102
pub const DTRACEACT_KERNEL: c_uint = 0x400;
pub const DTRACEACT_STACK: c_uint = DTRACEACT_KERNEL + 1; // 0x401

/// `dtrace_dropkind_t` values from `<dtrace.h>` (matches the enum order
/// in the SDK header — used to decode `dtrace_dropdata_t.dtdda_kind`).
pub const DTRACEDROP_PRINCIPAL: c_int = 0;
pub const DTRACEDROP_AGGREGATION: c_int = 1;
pub const DTRACEDROP_DYNAMIC: c_int = 2;
pub const DTRACEDROP_DYNRINSE: c_int = 3;
pub const DTRACEDROP_DYNDIRTY: c_int = 4;
pub const DTRACEDROP_SPEC: c_int = 5;
pub const DTRACEDROP_SPECBUSY: c_int = 6;
pub const DTRACEDROP_SPECUNAVAIL: c_int = 7;
pub const DTRACEDROP_STKSTROVERFLOW: c_int = 8;
pub const DTRACEDROP_DBLERROR: c_int = 9;

/// Handler return codes — same for both drop and err handlers.
pub const DTRACE_HANDLE_ABORT: c_int = -1;
pub const DTRACE_HANDLE_OK: c_int = 0;

/// `dtrace_status_t` return codes from `<dtrace.h>`. `dtrace_status()`
/// returns one of these (or -1 on error) to indicate consumer state.
pub const DTRACE_STATUS_NONE: c_int = 0;
pub const DTRACE_STATUS_OKAY: c_int = 1;
pub const DTRACE_STATUS_EXITED: c_int = 2;
pub const DTRACE_STATUS_FILLED: c_int = 3;
pub const DTRACE_STATUS_STOPPED: c_int = 4;

/// Mirrors `dtrace_dropdata_t` from `<dtrace.h>`. The drop handler
/// receives one of these per kernel-side drop event; `dtdda_kind`
/// tells us why (principal-buffer overflow vs dynamic-variable
/// drop vs aggregation drop) and `dtdda_drops`/`dtdda_total` give
/// the per-event delta plus running total since tracing began.
#[repr(C)]
pub struct DtraceDropData {
    pub dtdda_handle: *mut c_void,
    pub dtdda_cpu: c_int,
    pub dtdda_kind: c_int,
    pub dtdda_drops: u64,
    pub dtdda_total: u64,
    pub dtdda_msg: *const c_char,
}

/// Mirrors `dtrace_errdata_t` for the err handler. We only inspect
/// `dteda_msg`, but keep the layout faithful so libdtrace's struct
/// pointer reads cleanly through the cast.
#[repr(C)]
pub struct DtraceErrData {
    pub dteda_handle: *mut c_void,
    pub dteda_edesc: *mut c_void,
    pub dteda_pdesc: *mut DtraceProbeDesc,
    pub dteda_cpu: c_int,
    pub dteda_action: c_int,
    pub dteda_offset: c_int,
    pub dteda_fault: c_int,
    pub dteda_addr: u64,
    pub dteda_msg: *const c_char,
}

pub type HandleDropFn = unsafe extern "C" fn(*const DtraceDropData, *mut c_void) -> c_int;
pub type HandleErrFn = unsafe extern "C" fn(*const DtraceErrData, *mut c_void) -> c_int;

#[link(name = "dtrace")]
unsafe extern "C" {
    pub fn dtrace_open(version: c_int, flags: c_int, errp: *mut c_int) -> *mut c_void;
    pub fn dtrace_close(hdl: *mut c_void);
    pub fn dtrace_errno(hdl: *mut c_void) -> c_int;
    pub fn dtrace_errmsg(hdl: *mut c_void, err: c_int) -> *const c_char;
    pub fn dtrace_program_strcompile(
        hdl: *mut c_void,
        s: *const c_char,
        spec: c_int,
        cflags: c_uint,
        argc: c_int,
        argv: *const *const c_char,
    ) -> *mut c_void;
    pub fn dtrace_program_exec(hdl: *mut c_void, prog: *mut c_void, info: *mut c_void) -> c_int;
    pub fn dtrace_dof_create(hdl: *mut c_void, prog: *mut c_void, flags: c_uint) -> *mut c_void;
    pub fn dtrace_dof_destroy(hdl: *mut c_void, dof: *mut c_void);
    pub fn dtrace_setopt(hdl: *mut c_void, opt: *const c_char, val: *const c_char) -> c_int;
    pub fn dtrace_proc_grab(hdl: *mut c_void, pid: c_int, flags: c_int) -> *mut c_void;
    pub fn dtrace_proc_release(hdl: *mut c_void, p: *mut c_void);
    /// Resume execution of a process suspended by `dtrace_proc_grab`.
    /// macOS's libproc backend uses ptrace-style stop semantics; the
    /// process is frozen until either `dtrace_proc_continue` or
    /// `dtrace_proc_release` is called.
    pub fn dtrace_proc_continue(hdl: *mut c_void, p: *mut c_void);
    pub fn dtrace_go(hdl: *mut c_void) -> c_int;
    pub fn dtrace_stop(hdl: *mut c_void) -> c_int;
    pub fn dtrace_work(
        hdl: *mut c_void,
        fp: *mut libc::FILE,
        probe_cb: ConsumeProbeFn,
        rec_cb: ConsumeRecFn,
        arg: *mut c_void,
    ) -> c_int;
    pub fn dtrace_sleep(hdl: *mut c_void);
    /// Refresh the consumer's status snapshot (drop counts, exited
    /// flag, filled-buffer count). Returns one of the
    /// `DTRACE_STATUS_*` codes; -1 on error.
    pub fn dtrace_status(hdl: *mut c_void) -> c_int;
    /// Register a drop-event callback. libdtrace invokes the handler
    /// inside `dtrace_work` when the kernel reports principal-buffer
    /// drops, dynamic-variable drops, aggregation drops, etc. Returns
    /// 0 on success.
    pub fn dtrace_handle_drop(hdl: *mut c_void, handler: HandleDropFn, arg: *mut c_void) -> c_int;
    /// Register an ERROR-probe callback. Fires when a clause traps
    /// (DIF fault: bad load, divide-by-zero, etc.) — useful for
    /// distinguishing "kernel kept tracing but the clause errored"
    /// from "kernel dropped records".
    pub fn dtrace_handle_err(hdl: *mut c_void, handler: HandleErrFn, arg: *mut c_void) -> c_int;
    /// Snapshot all aggregations into the consumer's per-cpu buffers.
    /// Must be called before `dtrace_aggregate_print`, otherwise the
    /// printer walks empty buffers. Returns 0 on success.
    pub fn dtrace_aggregate_snap(hdl: *mut c_void) -> c_int;
    /// Format every aggregation into the given FILE*. The third arg
    /// is a custom walker (we pass NULL to use the default sorted
    /// walker, which mirrors `dtrace -a`'s on-exit dump).
    pub fn dtrace_aggregate_print(
        hdl: *mut c_void,
        fp: *mut libc::FILE,
        walker: *mut c_void,
    ) -> c_int;
    /// Format a userspace address into `module`function+offset` for a
    /// given pid. Same backend libdtrace uses internally for the
    /// default `ustack()` formatter — calling it from our rec
    /// callback gets us symbolicated frames without needing to
    /// extract dlopen image maps ourselves.
    pub fn dtrace_uaddr2str(
        hdl: *mut c_void,
        pid: c_int,
        addr: u64,
        buf: *mut c_char,
        len: c_int,
    ) -> c_int;
    /// Format a kernel address (kallsyms-equivalent) the same way.
    pub fn dtrace_addr2str(hdl: *mut c_void, addr: u64, buf: *mut c_char, len: c_int) -> c_int;
}

pub type ConsumeProbeFn = unsafe extern "C" fn(*const DtraceProbeData, *mut c_void) -> c_int;
pub type ConsumeRecFn =
    unsafe extern "C" fn(*const DtraceProbeData, *const DtraceRecDesc, *mut c_void) -> c_int;

/// RAII handle around `dtrace_hdl_t *`. Closes on drop.
pub struct DtraceHandle(*mut c_void);

unsafe impl Send for DtraceHandle {}

impl DtraceHandle {
    /// Open a libdtrace handle. Requires root on macOS — libdtrace returns
    /// "DTrace requires additional privileges" otherwise.
    pub fn open() -> Result<Self, DtraceFfiError> {
        let mut err: c_int = 0;
        // Pass flags=0 so libdtrace loads /system/object — needed because the
        // bundled darwin.d references kernel types like `uthread_t`.
        let hdl = unsafe { dtrace_open(DTRACE_VERSION, 0, &mut err) };
        if hdl.is_null() {
            let msg = unsafe {
                let p = dtrace_errmsg(ptr::null_mut(), err);
                if p.is_null() {
                    String::from("(no message)")
                } else {
                    CStr::from_ptr(p).to_string_lossy().into_owned()
                }
            };
            return Err(DtraceFfiError::OpenFailed { errno: err, msg });
        }
        Ok(DtraceHandle(hdl))
    }

    fn errmsg(&self) -> String {
        unsafe {
            let err = dtrace_errno(self.0);
            let p = dtrace_errmsg(self.0, err);
            if p.is_null() {
                String::from("(no message)")
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        }
    }

    /// Compile a D script and return its DOF blob as owned bytes.
    pub fn compile_to_dof(&mut self, script: &str) -> Result<Vec<u8>, DtraceFfiError> {
        let cscript =
            CString::new(script).map_err(|e| DtraceFfiError::ScriptHasNul(e.to_string()))?;
        let prog = unsafe {
            dtrace_program_strcompile(
                self.0,
                cscript.as_ptr(),
                DTRACE_PROBESPEC_NAME,
                DTRACE_C_ZDEFS,
                0,
                ptr::null(),
            )
        };
        if prog.is_null() {
            return Err(DtraceFfiError::CompileFailed(self.errmsg()));
        }
        let dof = unsafe { dtrace_dof_create(self.0, prog, 0) };
        if dof.is_null() {
            return Err(DtraceFfiError::DofCreateFailed(self.errmsg()));
        }
        // Read the DOF header to discover the total file size, then copy out
        // before destroy. Layout per sys/dtrace.h:
        //   off  0: 16 bytes ident
        //   off 16: u32 flags
        //   off 20: u32 hdrsize
        //   off 24: u32 secsize
        //   off 28: u32 secnum
        //   off 32: u64 secoff
        //   off 40: u64 loadsz
        //   off 48: u64 filesz
        let bytes = unsafe { slice::from_raw_parts(dof as *const u8, 64) };
        let mut filesz_le = [0u8; 8];
        filesz_le.copy_from_slice(&bytes[48..56]);
        let filesz = u64::from_ne_bytes(filesz_le) as usize;
        let owned: Vec<u8> = unsafe { slice::from_raw_parts(dof as *const u8, filesz).to_vec() };
        unsafe { dtrace_dof_destroy(self.0, dof) };
        Ok(owned)
    }
}

impl Drop for DtraceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { dtrace_close(self.0) };
        }
    }
}
