//! Ending an instrumented process early without losing its trace.
//!
//! `std::process::exit` runs no destructors, so the guard that flushes queued
//! spans on a normal return never gets the chance. The helpers here flush the
//! process's export first and then exit.

use std::time::Duration;

use crate::otlp::ExportSlot;

/// The process's trace export, installed by [`crate::init_with_filter`] when a
/// collector is configured.
pub(crate) static EXPORT: ExportSlot = ExportSlot::new();

/// How long [`exit_after_interrupt`] waits for queued spans.
///
/// Someone who pressed Ctrl-C wants the prompt back. Waiting out the full
/// export timeout (ten seconds by default) for a slow collector would read as
/// a hung process, so an interrupt keeps only what can be sent quickly.
pub const INTERRUPT_FLUSH_BOUND: Duration = Duration::from_secs(1);

/// End the process with `code`, first flushing spans queued for export.
///
/// This is the way to end an instrumented process early. The flush waits at
/// most the configured export timeout. With no exporter configured, or once
/// the export has already been flushed, it exits immediately.
pub fn exit(code: i32) -> ! {
    EXPORT.flush_within(Duration::MAX);
    std::process::exit(code)
}

/// End the process with `code` after an interrupt, flushing queued spans for
/// at most [`INTERRUPT_FLUSH_BOUND`].
///
/// Use this instead of [`exit`] from a Ctrl-C handler. With no exporter
/// configured it exits immediately.
pub fn exit_after_interrupt(code: i32) -> ! {
    EXPORT.flush_within(INTERRUPT_FLUSH_BOUND);
    std::process::exit(code)
}
