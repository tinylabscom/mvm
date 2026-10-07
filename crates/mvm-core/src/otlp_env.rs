//! Standard OpenTelemetry exporter environment-variable names shared by host
//! components that decide whether to collect and export telemetry.

/// Signal-specific endpoint, used exactly as given.
pub const ENV_TRACES_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
/// Base endpoint; consumers append their signal-specific path.
pub const ENV_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
/// `name=value` pairs separated by commas, values percent-encoded.
pub const ENV_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";
/// Per-request timeout in milliseconds.
pub const ENV_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_TIMEOUT";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_the_standard_otlp_environment_contract() {
        assert_eq!(ENV_TRACES_ENDPOINT, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
        assert_eq!(ENV_ENDPOINT, "OTEL_EXPORTER_OTLP_ENDPOINT");
        assert_eq!(ENV_HEADERS, "OTEL_EXPORTER_OTLP_HEADERS");
        assert_eq!(ENV_TIMEOUT, "OTEL_EXPORTER_OTLP_TIMEOUT");
    }
}
