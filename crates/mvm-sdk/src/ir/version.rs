use std::fmt;

pub const IR_MAJOR: u32 = 0;
pub const IR_MINOR: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum VersionError {
    UnsupportedMajor { found: u32, supported: u32 },
    MinorTooHigh { found: u32, max: u32 },
    Malformed(String),
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMajor { found, supported } => write!(
                f,
                "unsupported schema version major: {found} (host supports {supported})"
            ),
            Self::MinorTooHigh { found, max } => {
                write!(f, "schema minor {found} exceeds host's known minor {max}")
            }
            Self::Malformed(s) => write!(f, "malformed schema version: {s:?}"),
        }
    }
}

impl std::error::Error for VersionError {}

pub fn validate_schema_version(s: &str) -> Result<(), VersionError> {
    let mut parts = s.split('.');
    let major = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| VersionError::Malformed(s.to_string()))?;
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| VersionError::Malformed(s.to_string()))?;
    if parts.next().is_some() {
        return Err(VersionError::Malformed(s.to_string()));
    }
    if major != IR_MAJOR {
        return Err(VersionError::UnsupportedMajor {
            found: major,
            supported: IR_MAJOR,
        });
    }
    if minor > IR_MINOR {
        return Err(VersionError::MinorTooHigh {
            found: minor,
            max: IR_MINOR,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_current_version() {
        assert_eq!(validate_schema_version("0.1"), Ok(()));
    }

    #[test]
    fn rejects_unsupported_major() {
        assert_eq!(
            validate_schema_version("1.0"),
            Err(VersionError::UnsupportedMajor {
                found: 1,
                supported: 0,
            })
        );
    }

    #[test]
    fn rejects_minor_too_high() {
        assert_eq!(
            validate_schema_version("0.9"),
            Err(VersionError::MinorTooHigh { found: 9, max: 2 })
        );
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["", "0", "0.1.0", "x.y", "0.x"] {
            assert!(matches!(
                validate_schema_version(bad),
                Err(VersionError::Malformed(_))
            ));
        }
    }
}
