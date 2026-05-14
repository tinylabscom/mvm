//! Kernel-cmdline parser for `mvm.builder.*` flags. Plan 71 W3.
//!
//! `LibkrunBuilderVm` constructs the kernel cmdline once per launch
//! (see `mvm_build::libkrun_builder::builder_kernel_cmdline`); this
//! module reads it from `/proc/cmdline` inside the guest and pulls
//! out the builder-specific flags. Keeping the parser in the lib
//! crate lets us test it cross-platform; the binary calls into it
//! after mounting `/proc`.
//!
//! Supported flags (extend as W4/W5 grow):
//!   - `mvm.builder.offline=1` — skip network bring-up; force Nix to
//!     build from source against the seed `/nix`. Used by
//!     `LibkrunBuilderVm::with_offline()` (W4 follow-up).
//!   - `mvm.builder.job=<id>` — purely informational; lets the guest
//!     stamp logs with the host's job id. Optional.
//!
//! Unknown `mvm.builder.*` flags are recorded in
//! [`BuilderCmdline::unknown`] so the init can log a warning rather
//! than silently ignoring them.

/// Parsed view of the kernel cmdline, scoped to the `mvm.builder.*`
/// namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuilderCmdline {
    pub offline: bool,
    pub job_id: Option<String>,
    /// Any `mvm.builder.foo=bar` tokens we didn't recognize. The
    /// init logs these but keeps booting — forward-compat is more
    /// important than strictness here.
    pub unknown: Vec<String>,
}

impl BuilderCmdline {
    /// Parse a cmdline string (the contents of `/proc/cmdline`,
    /// whitespace-separated tokens).
    pub fn parse(cmdline: &str) -> Self {
        let mut out = Self::default();
        for tok in cmdline.split_ascii_whitespace() {
            let Some(rest) = tok.strip_prefix("mvm.builder.") else {
                continue;
            };
            let (key, value) = match rest.split_once('=') {
                Some((k, v)) => (k, v),
                None => (rest, ""),
            };
            match key {
                "offline" => out.offline = matches!(value, "1" | "true" | "yes" | ""),
                "job" => {
                    if !value.is_empty() {
                        out.job_id = Some(value.to_owned());
                    }
                }
                _ => out.unknown.push(tok.to_owned()),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cmdline_parses_to_default() {
        assert_eq!(BuilderCmdline::parse(""), BuilderCmdline::default());
    }

    #[test]
    fn ignores_non_mvm_flags() {
        let c = BuilderCmdline::parse("console=hvc0 root=/dev/vda ro");
        assert_eq!(c, BuilderCmdline::default());
    }

    #[test]
    fn parses_offline_flag_variants() {
        for value in ["1", "true", "yes", ""] {
            let line = format!("mvm.builder.offline={value}");
            let c = BuilderCmdline::parse(&line);
            assert!(c.offline, "value {value:?} should enable offline");
        }
        // Bare flag with no `=` also enables offline.
        assert!(BuilderCmdline::parse("mvm.builder.offline").offline);
        // Explicit-false stays off.
        assert!(!BuilderCmdline::parse("mvm.builder.offline=0").offline);
    }

    #[test]
    fn parses_job_id() {
        let c = BuilderCmdline::parse("mvm.builder.job=abc123");
        assert_eq!(c.job_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn empty_job_value_yields_none() {
        let c = BuilderCmdline::parse("mvm.builder.job=");
        assert_eq!(c.job_id, None);
    }

    #[test]
    fn unknown_flags_are_recorded() {
        let c = BuilderCmdline::parse("mvm.builder.future=42 mvm.builder.offline=1");
        assert!(c.offline);
        assert_eq!(c.unknown, vec!["mvm.builder.future=42"]);
    }

    #[test]
    fn handles_mixed_real_cmdline() {
        let line =
            "console=hvc0 root=/dev/vda ro mvm.builder.offline=1 mvm.builder.job=j42 quiet";
        let c = BuilderCmdline::parse(line);
        assert!(c.offline);
        assert_eq!(c.job_id.as_deref(), Some("j42"));
        assert!(c.unknown.is_empty());
    }
}
