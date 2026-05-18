// SPDX-License-Identifier: Apache-2.0
//! `tracing`-based diagnostic logging for the bifrost CLI.
//!
//! Replaces the ad-hoc `eprintln!("[bifrost] ...")` sites
//! scattered through `cli/runtime.rs`.  Each diagnostic event
//! becomes a `tracing::info!` / `warn!` / `error!` call; the
//! global subscriber renders them as `[bifrost] <message>` to
//! stderr to preserve the existing CLI UX byte-for-byte.
//!
//! User-facing stdout output (the indented "  load    pushing
//! ..." status lines) stays as `println!` — that is the CLI's
//! primary output, not log noise.
//!
//! RUST_LOG controls verbosity (`info` is the default, matching
//! the eprintln-everything behavior we replaced).  Set
//! `RUST_LOG=debug` to surface any future `tracing::debug!`
//! instrumentation.

use std::io;
use std::sync::Once;

use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::{
    self, FmtContext, FormatEvent, FormatFields,
    format::{FmtSpan, Writer},
};
use tracing_subscriber::registry::LookupSpan;

/// Render a tracing event as `[bifrost] <message>\n`.
///
/// Drops timestamps, target, level — bifrost's stderr output has
/// always been a stream of unadorned `[bifrost] $msg` lines, and
/// downstream parsers (CI scripts, the redis-smoke-test grep
/// pipeline) match on that prefix.  Changing the format would
/// surface as test-output churn for zero functional gain.
struct BifrostFormat;

impl<S, N> FormatEvent<S, N> for BifrostFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        write!(writer, "[bifrost] ")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

static INIT: Once = Once::new();

/// Install the global `tracing` subscriber.  Idempotent — calling
/// twice is a no-op (the first registration wins).  Safe to call
/// from `main()` before any other CLI work.
pub fn init() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .with_span_events(FmtSpan::NONE)
            .event_format(BifrostFormat)
            .finish();
        // ignore set_global_default error — only fails if a
        // subscriber is already installed (e.g. test harness).
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}
