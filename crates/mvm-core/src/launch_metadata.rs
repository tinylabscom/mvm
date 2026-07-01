//! Flat launch metadata for `mvm-init`.
//!
//! The static guest PID-1 supervisor reads the workload's command, environment,
//! working directory, and user from flat files (`/mvm/argv`, `/mvm/env.base`,
//! `/mvm/workdir`, `/mvm/user`) rather than parsing a large JSON blob in PID 1.
//! These parsers are the flat-format readers: argv is NUL-delimited, env is
//! `KEY=VALUE` lines. Both are bounded (a malformed or oversized metadata file
//! cannot drive an unbounded allocation) and reject non-UTF-8 input.

use core::fmt;

/// Hard ceiling on argv entries.
pub const MAX_ARGV: usize = 1024;
/// Hard ceiling on environment entries.
pub const MAX_ENV: usize = 4096;

/// Why flat launch metadata could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// A field was not valid UTF-8.
    NotUtf8,
    /// A count exceeded its hard ceiling.
    TooMany { name: &'static str, max: usize },
    /// An env line was not `KEY=VALUE` with a non-empty key.
    MalformedEnvLine(String),
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataError::NotUtf8 => write!(f, "launch metadata is not valid UTF-8"),
            MetadataError::TooMany { name, max } => {
                write!(f, "too many {name} entries (max {max})")
            }
            MetadataError::MalformedEnvLine(line) => {
                write!(f, "malformed env line (want KEY=VALUE): {line:?}")
            }
        }
    }
}

impl std::error::Error for MetadataError {}

/// Parse NUL-delimited argv. A single trailing NUL is ignored; empty input is
/// an empty argv. Bounded by [`MAX_ARGV`].
pub fn parse_argv(bytes: &[u8]) -> Result<Vec<String>, MetadataError> {
    let s = std::str::from_utf8(bytes).map_err(|_| MetadataError::NotUtf8)?;
    let trimmed = s.strip_suffix('\0').unwrap_or(s);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = trimmed.split('\0').collect();
    if parts.len() > MAX_ARGV {
        return Err(MetadataError::TooMany {
            name: "argv",
            max: MAX_ARGV,
        });
    }
    Ok(parts.into_iter().map(str::to_string).collect())
}

/// Parse `KEY=VALUE` env lines. Blank lines are skipped; a line without `=` or
/// with an empty key is rejected. Bounded by [`MAX_ENV`].
pub fn parse_env(bytes: &[u8]) -> Result<Vec<(String, String)>, MetadataError> {
    let s = std::str::from_utf8(bytes).map_err(|_| MetadataError::NotUtf8)?;
    let mut out = Vec::new();
    for line in s.lines() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| MetadataError::MalformedEnvLine(line.to_string()))?;
        if key.is_empty() {
            return Err(MetadataError::MalformedEnvLine(line.to_string()));
        }
        if out.len() >= MAX_ENV {
            return Err(MetadataError::TooMany {
                name: "env",
                max: MAX_ENV,
            });
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

/// Parse a single-line field (workdir, user): trimmed; empty is `None`.
pub fn parse_single_line(bytes: &[u8]) -> Result<Option<String>, MetadataError> {
    let s = std::str::from_utf8(bytes).map_err(|_| MetadataError::NotUtf8)?;
    let trimmed = s.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

/// The workload's flat launch metadata, assembled by `mvm-init` from the
/// individual files it reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchMetadata {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub user: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_argv_splits_nul_delimited() {
        assert_eq!(
            parse_argv(b"/bin/sh\0-c\0echo hi").unwrap(),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string()
            ]
        );
        assert!(parse_argv(b"").unwrap().is_empty());
    }

    #[test]
    fn parse_argv_ignores_single_trailing_nul() {
        assert_eq!(parse_argv(b"/bin/true\0").unwrap(), vec!["/bin/true"]);
        assert!(parse_argv(b"\0").unwrap().is_empty());
    }

    #[test]
    fn parse_argv_rejects_non_utf8() {
        assert_eq!(
            parse_argv(&[0xff, 0xfe]).unwrap_err(),
            MetadataError::NotUtf8
        );
    }

    #[test]
    fn parse_env_reads_pairs_and_skips_blanks() {
        let env = parse_env(b"PATH=/bin\n\nHOME=/root\n").unwrap();
        assert_eq!(
            env,
            vec![
                ("PATH".to_string(), "/bin".to_string()),
                ("HOME".to_string(), "/root".to_string()),
            ]
        );
        // A value may itself contain '='.
        assert_eq!(
            parse_env(b"K=a=b").unwrap(),
            vec![("K".to_string(), "a=b".to_string())]
        );
    }

    #[test]
    fn parse_env_rejects_malformed_lines() {
        assert!(matches!(
            parse_env(b"NOEQUALS").unwrap_err(),
            MetadataError::MalformedEnvLine(_)
        ));
        assert!(matches!(
            parse_env(b"=novalue").unwrap_err(),
            MetadataError::MalformedEnvLine(_)
        ));
    }

    #[test]
    fn parse_single_line_trims_and_maps_empty_to_none() {
        assert_eq!(
            parse_single_line(b"  /work \n").unwrap(),
            Some("/work".to_string())
        );
        assert_eq!(parse_single_line(b"   ").unwrap(), None);
        assert_eq!(parse_single_line(b"").unwrap(), None);
    }

    #[test]
    fn parse_argv_caps_entry_count() {
        // (MAX_ARGV + 1) NUL-separated entries must exceed the cap.
        let many: Vec<u8> = std::iter::repeat_n(b"x\0", MAX_ARGV + 1)
            .flatten()
            .copied()
            .collect();
        assert!(matches!(
            parse_argv(&many).unwrap_err(),
            MetadataError::TooMany { name: "argv", .. }
        ));
    }
}
