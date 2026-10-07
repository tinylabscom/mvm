//! Where host-side notices go.
//!
//! A notice is something the host says over a workload's output: an egress
//! refusal as it happens, or the summary of them at exit. The library decides
//! what a notice says; the caller decides where it lands. The CLI writes them
//! to stderr under one process-wide lock; a test keeps them to read back.

/// A destination for host-side notices.
pub trait NoticeSink: Send + Sync {
    /// Write `lines` as one block nothing else interleaves with.
    fn block(&self, lines: &[String]);

    /// Write one whole notice line.
    fn line(&self, text: &str) {
        self.block(&[text.to_string()]);
    }
}
