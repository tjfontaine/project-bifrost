// SPDX-License-Identifier: Apache-2.0
//! In-process libdtrace consumer.
//!
//! Drives libdtrace from inside the bifrost CLI process rather than
//! spawning `/usr/sbin/dtrace -p $pid -s file.d` and parsing its
//! stdout.  With this consumer we:
//!
//!   1. Open a libdtrace handle in our own process (root-only, same as
//!      the dtrace CLI).
//!   2. Compile a D source string in-memory.
//!   3. Grab the target pid (the harness or, in attach-mode, an external
//!      libkrun consumer).
//!   4. Run a work loop that delivers probe records via callbacks AND
//!      surfaces printf-style output to a `FILE *` sink we control.
//!
//! As a first step we keep the existing printf-based marker
//! protocol but route it through a memory pipe instead of a child
//! process's stdout. That removes the fragile cross-process pipe
//! parser without requiring the tracemem-binary record schema
//! yet — that's a follow-up, layered on top.

use crate::dtrace_ffi as ffi;
use std::ffi::CString;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use thiserror::Error;

/// Errors from libdtrace consumer setup + run.  Each variant
/// names the libdtrace API call that failed; the body carries the
/// upstream errmsg string (libdtrace's API is "free-form errmsg
/// + numeric errno", so we can't enumerate underlying causes
/// without parsing strings — that's not worth the maintenance
/// cost for a tracing tool's diagnostics).
#[derive(Debug, Error)]
pub enum ConsumerError {
    #[error("pipe(2) failed")]
    PipeFailed,
    #[error("fdopen on pipe write end failed")]
    FdopenFailed,
    #[error("dtrace_open: err={0}")]
    DtraceOpen(i32),
    #[error("dtrace_proc_grab(pid={pid}): {msg}")]
    ProcGrab { pid: i32, msg: String },
    #[error("dtrace_program_strcompile: {0}")]
    StrCompile(String),
    #[error("dtrace_program_exec: {0}")]
    ProgramExec(String),
    #[error("dtrace_go: {0}")]
    DtraceGo(String),
    #[error("dtrace_work failed: {0}")]
    DtraceWork(String),
    #[error("source has NUL: {0}")]
    SourceHasNul(#[source] std::ffi::NulError),
}

/// Process-wide drop counters populated by `drop_handler`. We keep
/// them static (rather than threading through the handler's `arg`)
/// because libdtrace's drop callback fires from inside `dtrace_work`
/// — a context where the calling Consumer is borrowed mutably and
/// passing self-pointers in is awkward without unsafe gymnastics.
/// Bifrost runs at most one Consumer per process, so a global
/// counter is the simpler honest model.
pub static DROP_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static DROP_PRINCIPAL: AtomicU64 = AtomicU64::new(0);
pub static DROP_AGGREGATION: AtomicU64 = AtomicU64::new(0);
pub static DROP_DYNAMIC: AtomicU64 = AtomicU64::new(0);
pub static DROP_DYNRINSE: AtomicU64 = AtomicU64::new(0);
pub static DROP_DYNDIRTY: AtomicU64 = AtomicU64::new(0);
pub static DROP_SPEC: AtomicU64 = AtomicU64::new(0);
pub static DROP_SPECBUSY: AtomicU64 = AtomicU64::new(0);
pub static DROP_SPECUNAVAIL: AtomicU64 = AtomicU64::new(0);
pub static DROP_STKSTROVERFLOW: AtomicU64 = AtomicU64::new(0);
pub static DROP_DBLERROR: AtomicU64 = AtomicU64::new(0);
pub static ERR_TOTAL: AtomicU64 = AtomicU64::new(0);

/// libdtrace drop handler. Logs each drop event to stderr (every drop
/// matters here — they're rare and load-bearing for debugging) and
/// bumps per-kind atomic counters so a final summary can be printed.
/// Returns `DTRACE_HANDLE_OK` to keep tracing.
unsafe extern "C" fn drop_handler(
    data: *const ffi::DtraceDropData,
    _arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    if data.is_null() {
        return ffi::DTRACE_HANDLE_OK;
    }
    let d = unsafe { &*data };
    let kind = d.dtdda_kind;
    let drops = d.dtdda_drops;
    let total = d.dtdda_total;
    let cpu = d.dtdda_cpu;
    let kind_str = match kind {
        ffi::DTRACEDROP_PRINCIPAL => {
            DROP_PRINCIPAL.fetch_add(drops, Ordering::Relaxed);
            "principal"
        }
        ffi::DTRACEDROP_AGGREGATION => {
            DROP_AGGREGATION.fetch_add(drops, Ordering::Relaxed);
            "aggregation"
        }
        ffi::DTRACEDROP_DYNAMIC => {
            DROP_DYNAMIC.fetch_add(drops, Ordering::Relaxed);
            "dynamic"
        }
        ffi::DTRACEDROP_DYNRINSE => {
            DROP_DYNRINSE.fetch_add(drops, Ordering::Relaxed);
            "dyn-rinse"
        }
        ffi::DTRACEDROP_DYNDIRTY => {
            DROP_DYNDIRTY.fetch_add(drops, Ordering::Relaxed);
            "dyn-dirty"
        }
        ffi::DTRACEDROP_SPEC => {
            DROP_SPEC.fetch_add(drops, Ordering::Relaxed);
            "spec"
        }
        ffi::DTRACEDROP_SPECBUSY => {
            DROP_SPECBUSY.fetch_add(drops, Ordering::Relaxed);
            "spec-busy"
        }
        ffi::DTRACEDROP_SPECUNAVAIL => {
            DROP_SPECUNAVAIL.fetch_add(drops, Ordering::Relaxed);
            "spec-unavail"
        }
        ffi::DTRACEDROP_STKSTROVERFLOW => {
            DROP_STKSTROVERFLOW.fetch_add(drops, Ordering::Relaxed);
            "stkstr-overflow"
        }
        ffi::DTRACEDROP_DBLERROR => {
            DROP_DBLERROR.fetch_add(drops, Ordering::Relaxed);
            "dbl-error"
        }
        _ => "unknown",
    };
    DROP_TOTAL.fetch_add(drops, Ordering::Relaxed);
    let msg = if d.dtdda_msg.is_null() {
        String::new()
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(d.dtdda_msg)
                .to_string_lossy()
                .into_owned()
        }
    };
    eprintln!(
        "[bifrost] DROP kind={} cpu={} count={} total={} msg={:?}",
        kind_str, cpu, drops, total, msg,
    );
    ffi::DTRACE_HANDLE_OK
}

/// libdtrace error handler — fires when a clause traps (bad load,
/// divide-by-zero, etc.). Distinct from drops: the kernel kept
/// tracing, the *clause* errored. Surfacing these keeps "kernel
/// dropped records" and "our DIF faulted" from looking the same in
/// downstream throughput numbers.
unsafe extern "C" fn err_handler(
    data: *const ffi::DtraceErrData,
    _arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    if data.is_null() {
        return ffi::DTRACE_HANDLE_OK;
    }
    let d = unsafe { &*data };
    ERR_TOTAL.fetch_add(1, Ordering::Relaxed);
    let msg = if d.dteda_msg.is_null() {
        String::new()
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(d.dteda_msg)
                .to_string_lossy()
                .into_owned()
        }
    };
    eprintln!(
        "[bifrost] ERR cpu={} action={} offset={} fault={} addr=0x{:x} msg={:?}",
        d.dteda_cpu, d.dteda_action, d.dteda_offset, d.dteda_fault, d.dteda_addr, msg,
    );
    ffi::DTRACE_HANDLE_OK
}

/// Print a one-line drop/err summary to stderr. Called by the
/// consumer driver after `run` returns so users see totals even
/// when no per-event drop fired (zero-drop runs print "0/0/...").
pub fn print_drop_summary() {
    let total = DROP_TOTAL.load(Ordering::Relaxed);
    let errs = ERR_TOTAL.load(Ordering::Relaxed);
    let principal = DROP_PRINCIPAL.load(Ordering::Relaxed);
    let agg = DROP_AGGREGATION.load(Ordering::Relaxed);
    let dynamic = DROP_DYNAMIC.load(Ordering::Relaxed);
    let dynrinse = DROP_DYNRINSE.load(Ordering::Relaxed);
    let dyndirty = DROP_DYNDIRTY.load(Ordering::Relaxed);
    let spec = DROP_SPEC.load(Ordering::Relaxed)
        + DROP_SPECBUSY.load(Ordering::Relaxed)
        + DROP_SPECUNAVAIL.load(Ordering::Relaxed);
    let stk = DROP_STKSTROVERFLOW.load(Ordering::Relaxed);
    let dbl = DROP_DBLERROR.load(Ordering::Relaxed);
    eprintln!(
        "[bifrost] dtrace summary: drops={} (principal={} agg={} dyn={} rinse={} dirty={} spec={} stkstr={} dblerr={}) errs={}",
        total, principal, agg, dynamic, dynrinse, dyndirty, spec, stk, dbl, errs,
    );
}

/// Owned in-process consumer running against a single target pid.
/// Drop closes the libdtrace handle.
pub struct Consumer {
    hdl: *mut std::ffi::c_void,
    proc_handle: *mut std::ffi::c_void,
    /// FILE* over the write end of an internal pipe; libdtrace writes
    /// printf-action output here.
    sink: *mut libc::FILE,
    /// Read-side buffered reader. The work loop hands lines off to a
    /// caller-provided callback.
    sink_reader: BufReader<std::fs::File>,
    /// Partial-line carry-over: when `drain_sink` reads past EAGAIN
    /// in the middle of a line, the bytes we already consumed are
    /// stashed here so the next call can splice them with the
    /// remainder once the producer flushes the trailing `\n`.
    partial: Vec<u8>,
    /// True once dtrace_go has succeeded.
    started: bool,
}

unsafe impl Send for Consumer {}

impl Consumer {
    /// Open a fresh dtrace handle, compile the D source, attach to
    /// `target_pid`, and prepare the consumer. Caller drives the work
    /// loop via `Consumer::run` (blocking) or feeds individual ticks
    /// via `Consumer::work_once`.
    pub fn new(target_pid: i32, source: &str) -> Result<Self, ConsumerError> {
        // Set up an OS pipe for libdtrace's printf sink. Read side becomes
        // a Rust File so we can BufReader::lines it; write side is wrapped
        // in a libc FILE* via fdopen. dtrace_work uses this FILE* for any
        // probe action that produces text output (printf, trace+default
        // formatting, ustack/stack pretty-printing).
        let (rfd, wfd) = pipe_pair()?;
        let mode = CString::new("w").unwrap();
        let sink = unsafe { libc::fdopen(wfd, mode.as_ptr()) };
        if sink.is_null() {
            unsafe {
                libc::close(rfd);
                libc::close(wfd);
            }
            return Err(ConsumerError::FdopenFailed);
        }
        // Line-buffer the FILE* — we want each printf line out
        // promptly, not buffered up to BUFSIZ.
        unsafe {
            libc::setvbuf(sink, std::ptr::null_mut(), libc::_IOLBF, 0);
        }
        // O_NONBLOCK on the read end — drain_sink polls by
        // attempting reads and treats EAGAIN as "no data right
        // now". Without this, BufReader::read_until blocks until
        // the next \n arrives, wedging the consumer thread between
        // probe firings.
        unsafe {
            let flags = libc::fcntl(rfd, libc::F_GETFL, 0);
            if flags >= 0 {
                libc::fcntl(rfd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let sink_reader = BufReader::new(unsafe { std::fs::File::from_raw_fd(rfd) });

        // Open libdtrace. DTRACE_O_LP64 selects the 64-bit data
        // model used by macOS arm64 (and modern x86_64) processes;
        // without it dtrace's pid-provider symbol lookup may emit
        // raw addresses instead of `module!symbol+offset`.
        let mut err: std::ffi::c_int = 0;
        let hdl = unsafe { ffi::dtrace_open(ffi::DTRACE_VERSION, ffi::DTRACE_O_LP64, &mut err) };
        if hdl.is_null() {
            unsafe { libc::fclose(sink) };
            return Err(ConsumerError::DtraceOpen(err));
        }

        // Apply the same options the CLI uses for our auto-injected
        // protocol: -q (quiet), -s defaults.  The auto-injected D
        // source already embeds `#pragma D option quiet`, but setting
        // it here too keeps the contract explicit.
        let q = CString::new("quiet").unwrap();
        let one = CString::new("1").unwrap();
        let _ = unsafe { ffi::dtrace_setopt(hdl, q.as_ptr(), one.as_ptr()) };
        // bufsize=16m: each-cpu trace buffer. At ~4500 rec/s through
        // bifrost_event_received with two ~80-byte copyinstrs per
        // fire, ~700KB/s per CPU; 16MB gives ~22s of headroom against
        // the kernel-side scratch+raw layout (libdtrace pads each
        // record to a wider per-EPID slot than the user payload).
        let bufsize = CString::new("bufsize").unwrap();
        let bsval = CString::new("16m").unwrap();
        let _ = unsafe { ffi::dtrace_setopt(hdl, bufsize.as_ptr(), bsval.as_ptr()) };
        // aggsize for cross-domain probes that emit stacks/quantize
        // alongside scalar aggs. The default 1m is too small for
        // probes that combine ustack(32) + multiple aggs at high
        // rate — `dtrace_go` returns "Enabling exceeds size of
        // buffer" on the ENABLING phase. 8m gives comfortable
        // headroom and matches dtrace(1)'s effective default for
        // similar workloads.
        let aggsize = CString::new("aggsize").unwrap();
        let aggval = CString::new("8m").unwrap();
        let _ = unsafe { ffi::dtrace_setopt(hdl, aggsize.as_ptr(), aggval.as_ptr()) };
        // strsize=512 to fit the resolved kprobe label in copyinstr(arg1).
        let strsz = CString::new("strsize").unwrap();
        let strval = CString::new("512").unwrap();
        let _ = unsafe { ffi::dtrace_setopt(hdl, strsz.as_ptr(), strval.as_ptr()) };
        // switchrate controls how often the kernel flips its
        // double-buffered per-cpu trace buffers so the consumer can
        // drain.  Default is 1 Hz — way too slow for bifrost record
        // delivery at thousands of fires/s, leading to long stretches
        // where dtrace_work has no records to read because the
        // active buffer hasn't been flipped yet, and the resulting
        // throttle cascades into per-cpu drops despite the 16MB
        // buffer being mostly empty.  100ms (10 Hz) matches the
        // consumer driver loop's 10ms work_once cadence with a
        // comfortable margin.
        let switchrate = CString::new("switchrate").unwrap();
        let switchval = CString::new("100ms").unwrap();
        let _ = unsafe { ffi::dtrace_setopt(hdl, switchrate.as_ptr(), switchval.as_ptr()) };

        // Grab the target process FIRST so `$target` resolves to a
        // real pid when the D source compiles. Flag 0 = attach
        // without stopping execution (we don't want to perturb the
        // harness).
        let proc_handle = unsafe { ffi::dtrace_proc_grab(hdl, target_pid, 0) };
        if proc_handle.is_null() {
            let msg = errmsg(hdl);
            unsafe {
                libc::fclose(sink);
                ffi::dtrace_close(hdl);
            }
            return Err(ConsumerError::ProcGrab {
                pid: target_pid,
                msg,
            });
        }

        // Compile (after proc_grab so $target substitutes correctly).
        let csrc = CString::new(source).map_err(ConsumerError::SourceHasNul)?;
        let prog = unsafe {
            ffi::dtrace_program_strcompile(
                hdl,
                csrc.as_ptr(),
                ffi::DTRACE_PROBESPEC_NAME,
                ffi::DTRACE_C_ZDEFS,
                0,
                std::ptr::null(),
            )
        };
        if prog.is_null() {
            let msg = errmsg(hdl);
            unsafe {
                ffi::dtrace_proc_release(hdl, proc_handle);
                libc::fclose(sink);
                ffi::dtrace_close(hdl);
            }
            return Err(ConsumerError::StrCompile(msg));
        }

        // Register drop + err handlers BEFORE program_exec so any
        // setup-time anomalies surface through the same channel as
        // runtime drops. Failures here are non-fatal — without
        // handlers we just lose drop visibility, not correctness.
        unsafe {
            let rc = ffi::dtrace_handle_drop(hdl, drop_handler, std::ptr::null_mut());
            if rc != 0 {
                eprintln!("[bifrost] WARN: dtrace_handle_drop failed: {}", errmsg(hdl));
            }
            let rc = ffi::dtrace_handle_err(hdl, err_handler, std::ptr::null_mut());
            if rc != 0 {
                eprintln!("[bifrost] WARN: dtrace_handle_err failed: {}", errmsg(hdl));
            }
        }

        // Link the program into the kernel (resolves probe descriptions
        // against the live target's symbols, allocates kernel buffers).
        let rc = unsafe { ffi::dtrace_program_exec(hdl, prog, std::ptr::null_mut()) };
        if rc != 0 {
            let msg = errmsg(hdl);
            unsafe {
                ffi::dtrace_proc_release(hdl, proc_handle);
                libc::fclose(sink);
                ffi::dtrace_close(hdl);
            }
            return Err(ConsumerError::ProgramExec(msg));
        }

        Ok(Consumer {
            hdl,
            proc_handle,
            sink,
            sink_reader,
            partial: Vec::new(),
            started: false,
        })
    }

    /// Borrow the printf-sink FILE* for use as a `RecCbCtx.fp`. The
    /// returned pointer is valid for the lifetime of `self`.
    pub fn sink_fp(&self) -> *mut libc::FILE {
        self.sink
    }

    /// Expose the raw libdtrace handle for callers that want to
    /// invoke symbol-resolution APIs (`dtrace_uaddr2str`,
    /// `dtrace_addr2str`) outside the rec-callback context. The
    /// pointer is valid until `Consumer` is dropped.
    pub fn handle(&self) -> *mut std::ffi::c_void {
        self.hdl
    }

    /// Symbolicate a raw user-space PC against the target process'
    /// dyld image map (the same lookup libdtrace's own `ustack()`
    /// formatter uses internally). Returns a string of the form
    /// `module`function+offset` or the raw `0x…` hex address when
    /// the resolver can't bind the PC to a symbol.
    pub fn uaddr2str(&self, target_pid: i32, pc: u64) -> String {
        let mut buf = [0u8; 512];
        let rc = unsafe {
            ffi::dtrace_uaddr2str(
                self.hdl,
                target_pid,
                pc,
                buf.as_mut_ptr() as *mut std::ffi::c_char,
                buf.len() as std::ffi::c_int,
            )
        };
        if rc == 0 {
            let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const std::ffi::c_char) };
            let s = cstr.to_string_lossy();
            if !s.trim().is_empty() {
                return s.into_owned();
            }
        }
        format!("0x{:x}", pc)
    }

    /// Snapshot + dump all aggregations to the printf sink. Mirrors
    /// `dtrace -a`'s on-exit behaviour: count() / sum() / quantize()
    /// totals buffer guest-side and only emit at flush time, so
    /// without this the per-fire output stream looks suspiciously
    /// empty for agg-heavy probes. Caller should run this once
    /// during graceful shutdown, before drop, with the same sink
    /// used during the work loop so output threads through
    /// `drain_sink` and the user's normal stdout pipeline.
    ///
    /// Returns the rc from dtrace_aggregate_print (0 on success;
    /// libdtrace also surfaces snap/print errors via dtrace_errmsg).
    pub fn flush_aggs(&mut self) -> i32 {
        unsafe {
            let snap_rc = ffi::dtrace_aggregate_snap(self.hdl);
            if snap_rc != 0 {
                return snap_rc;
            }
            ffi::dtrace_aggregate_print(self.hdl, self.sink, std::ptr::null_mut())
        }
    }

    /// Begin tracing. After this, `work_once` produces records, and
    /// the target process is resumed (libdtrace's libproc backend
    /// stops the process at `dtrace_proc_grab` time so its symbol
    /// tables are stable for compile + exec; we resume it here once
    /// probes are armed and the consumer is ready to drain records).
    pub fn go(&mut self) -> Result<(), ConsumerError> {
        let rc = unsafe { ffi::dtrace_go(self.hdl) };
        if rc != 0 {
            return Err(ConsumerError::DtraceGo(errmsg(self.hdl)));
        }
        self.started = true;
        // Resume the target. Without this the harness sits frozen
        // forever — proc_grab(flags=0) is ptrace-style stop semantics.
        unsafe { ffi::dtrace_proc_continue(self.hdl, self.proc_handle) };
        Ok(())
    }

    /// One tick of the work loop. Drains all currently-buffered records
    /// through libdtrace's callbacks (printf goes to `self.sink`, raw
    /// records pass through `rec_cb`). Returns the dtrace_work status.
    /// # Safety
    /// `arg` is passed verbatim to `probe_cb` / `rec_cb`; libdtrace
    /// will dereference it inside the callbacks. The caller must
    /// ensure `arg` outlives the call and points at storage compatible
    /// with what the callbacks expect.
    pub unsafe fn work_once(
        &mut self,
        probe_cb: ffi::ConsumeProbeFn,
        rec_cb: ffi::ConsumeRecFn,
        arg: *mut std::ffi::c_void,
    ) -> i32 {
        unsafe { ffi::dtrace_work(self.hdl, self.sink, probe_cb, rec_cb, arg) }
    }

    /// Drain queued printf-sink lines via a callback. Should be called
    /// alongside `work_once` in the consumer driver loop.
    ///
    /// The pipe's read end is `O_NONBLOCK`; once no full line is
    /// immediately available, `read_until` returns `WouldBlock` and
    /// we exit so the next `work_once` tick can run. Any partial
    /// line is held in the BufReader for the next call.
    pub fn drain_sink<F: FnMut(&str)>(&mut self, mut f: F) {
        let mut buf = Vec::with_capacity(4096);
        loop {
            buf.clear();
            match self.sink_reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) if buf.ends_with(b"\n") => {
                    let s = String::from_utf8_lossy(&buf);
                    f(s.trim_end_matches('\n'));
                }
                Ok(_) => {
                    // Partial line — push back so we don't lose it.
                    // (BufReader doesn't expose a "put back" hook;
                    // we simulate via stash on Self.)
                    self.partial.extend_from_slice(&buf);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        // If the previous tick left a partial line and the pipe has
        // since produced its newline, splice them and emit.
        if !self.partial.is_empty() {
            buf.clear();
            match self.sink_reader.read_until(b'\n', &mut buf) {
                Ok(_) if buf.ends_with(b"\n") => {
                    let mut whole = std::mem::take(&mut self.partial);
                    whole.extend_from_slice(&buf);
                    let s = String::from_utf8_lossy(&whole);
                    f(s.trim_end_matches('\n'));
                }
                Ok(_) => {
                    self.partial.extend_from_slice(&buf);
                }
                Err(_) => {}
            }
        }
    }

    /// Run the consumer until `stop` flips true. Drives `work_once` +
    /// `drain_sink` in a tight loop with a small sleep so we don't
    /// busy-burn CPU. Caller-provided line handler is invoked for each
    /// printf line.
    ///
    /// # Safety
    /// `arg` is forwarded into libdtrace's record callback. Caller
    /// must ensure it outlives the consumer and matches what the
    /// callback expects.
    pub unsafe fn run<F: FnMut(&str)>(
        mut self,
        stop: Arc<AtomicBool>,
        probe_cb: ffi::ConsumeProbeFn,
        rec_cb: ffi::ConsumeRecFn,
        arg: *mut std::ffi::c_void,
        mut line_handler: F,
    ) -> Result<(), ConsumerError> {
        if !self.started {
            self.go()?;
        }
        // Throttle dtrace_status calls. The function drives the
        // dynamic/aggregation/spec drop handlers via DTRACEIOC_STATUS
        // (principal drops surface through dtrace_work directly), so
        // calling it every tick is excess syscall traffic but never
        // calling it leaves dyn/agg drops invisible. ~250ms cadence
        // (every ~25 work_once ticks) matches the dtrace CLI's own
        // statusrate default.
        let mut last_status = std::time::Instant::now();
        let status_interval = std::time::Duration::from_millis(250);
        while !stop.load(Ordering::SeqCst) {
            // SAFETY: caller of `run` is responsible for `arg`'s
            // validity over the consumer's lifetime; we only
            // forward it to libdtrace.
            let st = unsafe { self.work_once(probe_cb, rec_cb, arg) };
            self.drain_sink(&mut line_handler);
            if last_status.elapsed() >= status_interval {
                let s = unsafe { ffi::dtrace_status(self.hdl) };
                last_status = std::time::Instant::now();
                if s == ffi::DTRACE_STATUS_EXITED || s == ffi::DTRACE_STATUS_STOPPED {
                    break;
                }
            }
            match st {
                ffi::DTRACE_WORKSTATUS_OKAY => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                ffi::DTRACE_WORKSTATUS_DONE => break,
                _ => {
                    return Err(ConsumerError::DtraceWork(errmsg(self.hdl)));
                }
            }
        }
        // Final drain to flush any tail records, plus one last
        // status pass so post-loop drop totals reflect any kernel
        // drop events that landed during the final tick.
        // SAFETY: same as the in-loop call above.
        let _ = unsafe { self.work_once(probe_cb, rec_cb, arg) };
        self.drain_sink(&mut line_handler);
        let _ = unsafe { ffi::dtrace_status(self.hdl) };
        print_drop_summary();
        Ok(())
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        unsafe {
            if self.started {
                let _ = ffi::dtrace_stop(self.hdl);
            }
            if !self.proc_handle.is_null() {
                ffi::dtrace_proc_release(self.hdl, self.proc_handle);
            }
            if !self.sink.is_null() {
                libc::fclose(self.sink);
            }
            if !self.hdl.is_null() {
                ffi::dtrace_close(self.hdl);
            }
        }
    }
}

fn errmsg(hdl: *mut std::ffi::c_void) -> String {
    unsafe {
        let err = ffi::dtrace_errno(hdl);
        let p = ffi::dtrace_errmsg(hdl, err);
        if p.is_null() {
            "(no message)".into()
        } else {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

fn pipe_pair() -> Result<(i32, i32), ConsumerError> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(ConsumerError::PipeFailed);
    }
    Ok((fds[0], fds[1]))
}

/// Probe callback for the xstack-assembly path: accepts every
/// record (CONSUME_THIS) and resets the per-firing field counter
/// at the start of each `hv_vcpu_run:return` firing so the rec_cb
/// decodes records in source order from index 0.
pub unsafe extern "C" fn probe_cb_assemble(
    _data: *const ffi::DtraceProbeData,
    arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    if !arg.is_null() {
        let ctx = unsafe { &*(arg as *const RecCbCtx) };
        if !ctx.firing.is_null() {
            let f = unsafe { &mut *ctx.firing };
            f.field_idx = 0;
        }
    }
    ffi::DTRACE_CONSUME_THIS
}

pub unsafe extern "C" fn probe_cb_accept(
    _data: *const ffi::DtraceProbeData,
    _arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    ffi::DTRACE_CONSUME_THIS
}

/// Binary-record assembling rec callback context.
/// The auto-injected D source emits an all-u64 sequence of
/// trace() actions per `hv_vcpu_run:return` firing followed by
/// ustack(N). The rec callback decodes them in source order via
/// `firing.field_idx`, builds an `XstackBlock` in memory,
/// symbolicates the ustack frames Rust-side via
/// `dtrace_uaddr2str`, and emits the unified block via println!
///
/// No string parsing on the bifrost CLI side — libdtrace's
/// printf sink is irrelevant. The earlier marker-protocol
/// architecture (##xstack-pending##|seq|...) is replaced
/// entirely.
///
/// All mutable state lives heap-pinned (Box::leak) so the
/// rec_cb's raw pointers stay valid across compiler relocation
/// of the surrounding closure.
#[repr(C)]
pub struct RecCbCtx {
    pub fp: *mut libc::FILE,
    pub target_pid: i32,
    /// Per-firing accumulator; reset by `probe_cb_assemble`.
    pub firing: *mut FiringState,
    /// Probe-id → label map, populated by the bifrost CLI from
    /// the wrapper it built. probe_id is 1-based (libkrun
    /// convention); index 0 is reserved.
    pub labels: *const Vec<String>,
}

/// What kind of probe a firing belongs to. Forced-exit (xstack
/// default) carries seq/probe_id/gpid (tags 1..3); SAMPLE carries
/// timestamp instead (tag 5). Both carry tid (tag 4 forced, 6
/// sample). The renderer dispatches on this to print the right
/// header line.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum FiringKind {
    #[default]
    Forced,
    Sample,
}

#[derive(Default)]
pub struct FiringState {
    pub kind: FiringKind,
    /// Position within the current firing's record sequence.
    pub field_idx: u8,
    pub seq: u64,
    pub probe_id: u64,
    pub gpid: u64,
    pub tid: u64,
    /// Sample-only: profile-* timestamp (ns since boot).
    pub timestamp: u64,
}

/// Symbolicating rec callback. For `DTRACEACT_USTACK` records we
/// walk the raw frame array, call `dtrace_uaddr2str` per frame to
/// resolve `module`function+offset`, write each line to the sink
/// FILE*, and return `CONSUME_NEXT` so libdtrace's default
/// formatter doesn't also emit raw addresses. Other action types
/// fall through to libdtrace's default handling via `CONSUME_THIS`.
pub unsafe extern "C" fn rec_cb_symbolicate(
    data: *const ffi::DtraceProbeData,
    rec: *const ffi::DtraceRecDesc,
    arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    if rec.is_null() || data.is_null() || arg.is_null() {
        return ffi::DTRACE_CONSUME_THIS;
    }
    let _ctx = unsafe { &*(arg as *const RecCbCtx) };
    let action = unsafe { (*rec).dtrd_action };
    if std::env::var_os("BIFROST_REC_DEBUG").is_some() {
        // Diagnostic addition (D2.2 calibration): dump dtrd_format
        // and dtrd_arg alongside the action/size/offset. If each
        // source `trace()` callsite gets a distinct dtrd_format,
        // we can route fields by format ID instead of position.
        unsafe {
            eprintln!(
                "[rec_cb-fmt] action=0x{:x} size={} offset={} dtrd_arg=0x{:x} dtrd_format={} dtrd_uarg=0x{:x}",
                (*rec).dtrd_action,
                (*rec).dtrd_size,
                (*rec).dtrd_offset,
                (*rec).dtrd_arg,
                (*rec).dtrd_format,
                (*rec).dtrd_uarg,
            );
        }
        // Decode the probe name from dtpda_pdesc — gives us
        // provider:module:function:name so we can tell which
        // clause emitted this record. Crucial for D2.2: the
        // canary lets us isolate which slot in which probe we
        // need to decode.
        let probe = if unsafe { !(*data).dtpda_pdesc.is_null() } {
            let p = unsafe { &*(*data).dtpda_pdesc };
            let cstr = |b: *const std::ffi::c_char| -> String {
                if b.is_null() {
                    String::new()
                } else {
                    unsafe { std::ffi::CStr::from_ptr(b).to_string_lossy().into_owned() }
                }
            };
            format!(
                "{}:{}:{}:{}",
                cstr(p.dtpd_provider.as_ptr()),
                cstr(p.dtpd_mod.as_ptr()),
                cstr(p.dtpd_func.as_ptr()),
                cstr(p.dtpd_name.as_ptr()),
            )
        } else {
            "(no pdesc)".into()
        };
        let size = unsafe { (*rec).dtrd_size } as usize;
        let offset = unsafe { (*rec).dtrd_offset } as usize;
        // dtpda_data is rebased per-record by libdtrace; do not add
        // dtrd_offset.
        let base = unsafe { (*data).dtpda_data };
        let preview_u64 = if size >= 8 {
            let mut buf = [0u8; 8];
            unsafe {
                std::ptr::copy_nonoverlapping(base as *const u8, buf.as_mut_ptr(), 8);
            }
            u64::from_le_bytes(buf)
        } else {
            0
        };
        let preview_str = if size > 0 && size <= 64 {
            let s = unsafe { std::slice::from_raw_parts(base as *const u8, size.min(32)) };
            let printable: String = s
                .iter()
                .map(|&b| {
                    if (0x20..=0x7e).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            printable
        } else {
            String::new()
        };
        eprintln!(
            "[rec_cb] probe={} action=0x{:x} size={} offset={} u64=0x{:016x} ascii={:?}",
            probe, action, size, offset, preview_u64, preview_str,
        );
    }
    let ctx = unsafe { &*(arg as *const RecCbCtx) };
    if ctx.firing.is_null() {
        return ffi::DTRACE_CONSUME_THIS;
    }
    let firing = unsafe { &mut *ctx.firing };
    let size = unsafe { (*rec).dtrd_size } as usize;
    // libdtrace's rec callback contract: `dtpda_data` is rebased per
    // record to point at THIS record's value. `dtrd_offset` is the
    // offset in the full firing buffer (informational); do NOT add
    // it to dtpda_data again — that double-counts and reads past the
    // record into other memory. Verified empirically against an
    // illumos D source review (see commit message).
    let base = unsafe { (*data).dtpda_data };

    // Scope to host-stack-capture firings: the auto-injected
    // forced-exit clause on hv_vcpu_run:return or the auto-injected
    // profile-* sampler. Other probes' records pass through to
    // libdtrace's default formatter unchanged (BEGIN banner,
    // harness clauses, etc.).
    let kind = if unsafe { !(*data).dtpda_pdesc.is_null() } {
        let p = unsafe { &*(*data).dtpda_pdesc };
        let func = unsafe { std::ffi::CStr::from_ptr(p.dtpd_func.as_ptr()).to_string_lossy() };
        let provider =
            unsafe { std::ffi::CStr::from_ptr(p.dtpd_provider.as_ptr()).to_string_lossy() };
        if func.starts_with("hv_vcpu_run") {
            Some(FiringKind::Forced)
        } else if provider == "profile" {
            Some(FiringKind::Sample)
        } else {
            None
        }
    } else {
        None
    };
    let kind = match kind {
        Some(k) => k,
        None => return ffi::DTRACE_CONSUME_THIS,
    };
    firing.kind = kind;

    match action {
        ffi::DTRACEACT_DIFEXPR if size == 8 => {
            // Tagged-value decoding. The auto-injected
            // D source ORs a source-position tag into the high
            // 4 bits of each traced u64. Buffer layout is non-
            // source-order (round-2 calibration confirmed) but
            // each value carries its own tag, so decoding is
            // layout-independent.
            //
            //   bits [63:60] = source position tag
            //     1..4 forced-exit (seq, probe_id, gpid, tid)
            //     5..6 sample (timestamp, tid)
            //   bits [59:0]  = actual field value
            let mut buf = [0u8; 8];
            unsafe {
                std::ptr::copy_nonoverlapping(base as *const u8, buf.as_mut_ptr(), 8);
            }
            let raw = u64::from_le_bytes(buf);
            let tag = (raw >> 60) & 0xF;
            let v = raw & ((1u64 << 60) - 1);
            match tag {
                1 => firing.seq = v,
                2 => firing.probe_id = v,
                3 => firing.gpid = v,
                4 => firing.tid = v,
                5 => firing.timestamp = v,
                6 => firing.tid = v,
                _ => {
                    // Untagged record (BEGIN clauses, harness
                    // probes, dtrace metadata). Pass through.
                }
            }
            firing.field_idx = firing.field_idx.saturating_add(1);
            ffi::DTRACE_CONSUME_NEXT
        }
        ffi::DTRACEACT_USTACK | ffi::DTRACEACT_JSTACK => {
            // End-of-firing — assemble + emit the unified block.
            let n_requested = unsafe { ((*rec).dtrd_arg & 0xFFFF) as usize };
            let frame_array = unsafe { base.add(8) as *const u64 };
            let hdl = unsafe { (*data).dtpda_handle };

            println!();
            match firing.kind {
                FiringKind::Forced => {
                    let label = if !ctx.labels.is_null() {
                        let labels = unsafe { &*ctx.labels };
                        let idx = (firing.probe_id as usize).saturating_sub(1);
                        labels
                            .get(idx)
                            .cloned()
                            .unwrap_or_else(|| format!("probe-{}", firing.probe_id))
                    } else {
                        format!("probe-{}", firing.probe_id)
                    };
                    println!("  ┄┄┄ host stack (vCPU thread, hv_vcpu_run:return) ┄┄┄");
                    println!(
                        "    seq={}  for guest fire: {}  gpid=0x{:x}  vcpu_tid={}",
                        firing.seq, label, firing.gpid, firing.tid,
                    );
                }
                FiringKind::Sample => {
                    println!("  ┄┄┄ host stack (sampled, profile-997) ┄┄┄");
                    println!(
                        "    timestamp={}  vcpu_tid={}",
                        firing.timestamp, firing.tid,
                    );
                }
            }
            let mut sym_buf = [0u8; 512];
            for i in 0..n_requested {
                let pc = unsafe { *frame_array.add(i) };
                if pc == 0 {
                    break;
                }
                for b in sym_buf.iter_mut() {
                    *b = 0;
                }
                let rc = unsafe {
                    ffi::dtrace_uaddr2str(
                        hdl,
                        ctx.target_pid,
                        pc,
                        sym_buf.as_mut_ptr() as *mut std::ffi::c_char,
                        sym_buf.len() as std::ffi::c_int,
                    )
                };
                let cstr = unsafe {
                    std::ffi::CStr::from_ptr(sym_buf.as_ptr() as *const std::ffi::c_char)
                };
                let s = cstr.to_string_lossy();
                if rc == 0 && !s.trim().is_empty() {
                    println!("    {}", s);
                } else {
                    println!("    0x{:x}", pc);
                }
            }
            println!("  ┄┄┄ end ┄┄┄");

            // Reset for the next firing — defensive; probe_cb
            // also resets at firing boundary.
            firing.field_idx = 0;
            firing.seq = 0;
            firing.probe_id = 0;
            firing.gpid = 0;
            firing.tid = 0;
            firing.timestamp = 0;
            firing.kind = FiringKind::default();
            ffi::DTRACE_CONSUME_NEXT
        }
        _ => ffi::DTRACE_CONSUME_THIS,
    }
}

/// Stub — kept for crate consumers that pre-built against the
/// `BufRead` import. The compiler dead-code lint flags it otherwise.
#[allow(dead_code)]
fn _force_link() {
    let _ = std::any::type_name::<dyn Read>();
}
