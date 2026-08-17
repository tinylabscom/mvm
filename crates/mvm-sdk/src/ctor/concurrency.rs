use crate::ir::{Concurrency, InProcessMode, WarmProcessConfig};

/// Opt a function entrypoint into the warm-process tier: the wrapper
/// stays alive across calls instead of a fresh process per call.
///
/// Per-call latency drops to the dispatch cost, but cross-call state
/// becomes the caller's problem — globals, `/tmp`, and open descriptors
/// persist, so one call can taint the next. Defaults to a single worker
/// dispatching serially with no queue cap; use [`ConcurrencyExt`] to
/// override.
pub fn warm_process(max_calls_per_worker: u64, max_rss_mb: u64) -> Concurrency {
    Concurrency::WarmProcess(WarmProcessConfig {
        max_calls_per_worker,
        max_rss_mb,
        pool_size: 1,
        in_process: InProcessMode::Serial,
        max_queue_depth: None,
    })
}

/// Chained setters over [`Concurrency`]. Bring into scope via
/// `use mvm_sdk::*;`.
pub trait ConcurrencyExt: Sized {
    /// Set the number of worker processes per microVM.
    fn with_pool_size(self, pool_size: usize) -> Self;
    /// Set the in-worker dispatch mode.
    fn with_in_process(self, in_process: InProcessMode) -> Self;
    /// Cap the number of calls queued in front of the pool.
    fn with_max_queue_depth(self, max_queue_depth: usize) -> Self;
}

impl ConcurrencyExt for Concurrency {
    fn with_pool_size(self, pool_size: usize) -> Self {
        let Concurrency::WarmProcess(mut cfg) = self;
        cfg.pool_size = pool_size;
        Concurrency::WarmProcess(cfg)
    }

    fn with_in_process(self, in_process: InProcessMode) -> Self {
        let Concurrency::WarmProcess(mut cfg) = self;
        cfg.in_process = in_process;
        Concurrency::WarmProcess(cfg)
    }

    fn with_max_queue_depth(self, max_queue_depth: usize) -> Self {
        let Concurrency::WarmProcess(mut cfg) = self;
        cfg.max_queue_depth = Some(max_queue_depth);
        Concurrency::WarmProcess(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_process_defaults_to_one_serial_worker_without_a_queue_cap() {
        let Concurrency::WarmProcess(cfg) = warm_process(1000, 256);
        assert_eq!(cfg.max_calls_per_worker, 1000);
        assert_eq!(cfg.max_rss_mb, 256);
        assert_eq!(cfg.pool_size, 1);
        assert_eq!(cfg.in_process, InProcessMode::Serial);
        assert_eq!(cfg.max_queue_depth, None);
    }

    #[test]
    fn setters_override_only_what_they_name() {
        let Concurrency::WarmProcess(cfg) = warm_process(1000, 256)
            .with_pool_size(4)
            .with_max_queue_depth(32);
        assert_eq!(cfg.pool_size, 4);
        assert_eq!(cfg.max_queue_depth, Some(32));
        // Untouched by either setter.
        assert_eq!(cfg.in_process, InProcessMode::Serial);
        assert_eq!(cfg.max_calls_per_worker, 1000);
    }

    #[test]
    fn in_process_mode_is_a_type_not_a_string() {
        // The Python and TypeScript surfaces take `in_process` as a
        // string and reject an unknown one at runtime. Rust cannot
        // express the invalid case at all, which is why that check is
        // declared in the constructor registry rather than recovered
        // from this function.
        let Concurrency::WarmProcess(cfg) =
            warm_process(1000, 256).with_in_process(InProcessMode::Concurrent);
        assert_eq!(cfg.in_process, InProcessMode::Concurrent);
    }
}
