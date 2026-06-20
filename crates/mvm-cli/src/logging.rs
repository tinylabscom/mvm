use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable colored output (for interactive CLI use).
    Human,
    /// Structured JSON output (for daemon/agent mode).
    Json,
}

/// The default tracing filter for a `-v` count when `RUST_LOG` is unset.
/// 0 = quiet (errors only); each `-v` widens it.
fn filter_for_verbosity(verbosity: u8) -> &'static str {
    match verbosity {
        0 => "error",
        1 => "mvm=info,warn",
        2 => "debug",
        _ => "trace",
    }
}

/// Initialize the global tracing subscriber.
///
/// Call once at program startup. Without `-v` the filter is `error` (quiet by
/// default). Each `-v` widens it: `-v` → `mvm=info,warn`, `-vv` → `debug`,
/// `-vvv` → `trace`. `RUST_LOG=<filter>` overrides verbosity entirely.
pub fn init(format: LogFormat, verbosity: u8) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(filter_for_verbosity(verbosity)));

    match format {
        LogFormat::Human => {
            let subscriber = fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .compact();
            tracing_subscriber::registry()
                .with(env_filter)
                .with(subscriber)
                .init();
        }
        LogFormat::Json => {
            let subscriber = fmt::layer().json().with_target(true);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(subscriber)
                .init();
        }
    }
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
}
