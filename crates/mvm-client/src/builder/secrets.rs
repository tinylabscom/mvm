//! Secret detection at the recording-promotion boundary.

use mvm_hostd::supervisor::secrets_scanner::SecretsScanner;

/// Scans recording literals without retaining or returning the scanned bytes.
///
/// Only rule identifiers leave this boundary. Locations belong to the caller's
/// recording structure, not to the matched secret.
pub struct RecordingSecretScanner {
    scanner: SecretsScanner,
}

impl Default for RecordingSecretScanner {
    fn default() -> Self {
        Self {
            scanner: SecretsScanner::with_default_rules(),
        }
    }
}

impl RecordingSecretScanner {
    /// Return the names of matching rules, never the matched values.
    pub fn scan(&self, bytes: &[u8]) -> Vec<String> {
        self.scanner
            .scan(bytes)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_and_empty_literals_have_no_findings() {
        let scanner = RecordingSecretScanner::default();
        assert!(scanner.scan(b"").is_empty());
        assert!(scanner.scan(b"/bin/true").is_empty());
    }

    #[test]
    fn a_secret_returns_only_rule_identifiers() {
        let value = b"AKIAIOSFODNN7EXAMPLE";
        let report = RecordingSecretScanner::default().scan(value);
        assert!(report.iter().any(|rule| rule == "aws_access_key_id"));
        assert!(!format!("{report:?}").contains(std::str::from_utf8(value).unwrap()));
    }
}
