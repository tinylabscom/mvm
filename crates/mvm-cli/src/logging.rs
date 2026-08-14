//! CLI logging setup.
//!
//! The subscriber assembly itself lives in `mvm_observability::logging`;
//! this module only maps the CLI's `-v` count onto a filter.

pub use mvm_observability::LogFormat;

/// The default tracing filter for a `-v` count when `RUST_LOG` is unset.
/// 0 = quiet (errors only); each `-v` widens it.
pub fn filter_for_verbosity(verbosity: u8) -> &'static str {
    match verbosity {
        0 => "error",
        1 => "mvm=info,warn",
        2 => "debug",
        _ => "trace",
    }
}

/// Initialize the global tracing subscriber.
///
/// Without `-v` the filter is `error` (quiet by default). Each `-v` widens it:
/// `-v` → `mvm=info,warn`, `-vv` → `debug`, `-vvv` → `trace`.
/// `RUST_LOG=<filter>` overrides verbosity entirely.
///
/// Span profiling is independent of verbosity: when `MVM_SPAN_TIMINGS` is set,
/// spans are measured even at the default quiet filter.
pub fn init(format: LogFormat, verbosity: u8) {
    mvm_observability::init_with_filter(format, filter_for_verbosity(verbosity));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_equality() {
        assert_eq!(LogFormat::Human, LogFormat::Human);
        assert_eq!(LogFormat::Json, LogFormat::Json);
        assert_ne!(LogFormat::Human, LogFormat::Json);
    }

    #[test]
    fn test_filter_for_verbosity() {
        assert_eq!(filter_for_verbosity(0), "error");
        assert!(filter_for_verbosity(1).contains("info"));
        assert_eq!(filter_for_verbosity(2), "debug");
        assert_eq!(filter_for_verbosity(5), "trace");
    }

    #[test]
    fn verbosity_widens_monotonically() {
        // Each step must not narrow the previous one; the quiet default is the
        // reason span timing needs its own filter rather than riding on this.
        assert_eq!(filter_for_verbosity(0), "error");
        assert_ne!(filter_for_verbosity(0), filter_for_verbosity(1));
        assert_ne!(filter_for_verbosity(1), filter_for_verbosity(2));
    }
}
