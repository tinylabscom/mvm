//! Install-spec parsing for the application-deps install pipeline
//! (Plan 73 Followup B.2, ADR-047).
//!
//! The host stages a JSON spec at `/job/install_spec.json` and
//! `mvm-host-vm-init`, at PID 1, parses it and dispatches the
//! per-language install protocol. This module is cross-platform on
//! purpose — the install-spec shape is part of the host↔guest wire
//! contract and the parser sees coverage from `cargo test` on every
//! developer host, not just the Linux cross-compile. The actual
//! installer dispatch (which `Command::spawn`s `uv` / `pnpm` etc.)
//! lives in `linux::install` and is gated to the in-VM target.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "language": "python" | "node",
//!   "lockfile_relative_path": "uv.lock",
//!   "source_mount": "/work",
//!   "gate": "prod" | "dev"
//! }
//! ```
//!
//! Hand-rolled parser rather than pulling `serde_json` in: the
//! Plan 72 W3 size budget caps the init binary at ≤ 1.5 MiB on
//! aarch64-linux. The shape is closed (four fields, two enums) and
//! the parser sees ~zero churn — adding `serde_json` for one
//! load-bearing read isn't worth ~150 KiB of binary growth.

use std::fmt;

/// Which language ecosystem to install for. Mirrors
/// `mvm_build::app_deps::Language` on the host side, with the same
/// wire tokens, so the spec round-trips unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Python,
    Node,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
        }
    }
}

/// Audit-gate strictness. Mirrors `mvm_build::app_deps::GateLevel`.
/// The builder VM honors this when running the SBOM + CVE side
/// pipeline (it doesn't fail the install on missing optional
/// gates today; ADR-047 §"Lifecycle gates" formalizes the strict
/// mode in a follow-on slice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateLevel {
    Dev,
    Prod,
}

impl GateLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Prod => "prod",
        }
    }
}

/// Parsed install spec. Fields use plain `String` rather than typed
/// paths so the spec stays portable across the host (which staged
/// it from `LibkrunBuilderVm`) and the guest (which interprets it
/// against in-VM mounts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSpec {
    pub language: Language,
    pub lockfile_relative_path: String,
    pub source_mount: String,
    pub gate: GateLevel,
}

#[derive(Debug)]
pub enum SpecError {
    /// JSON wasn't an object or had a structural defect (unbalanced
    /// braces, trailing garbage, …).
    Malformed(String),
    /// A required key was missing.
    MissingField(&'static str),
    /// A field had the wrong type or an out-of-enum value.
    InvalidField { field: &'static str, value: String },
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "install_spec.json is malformed: {why}"),
            Self::MissingField(name) => {
                write!(f, "install_spec.json is missing required field `{name}`")
            }
            Self::InvalidField { field, value } => {
                write!(
                    f,
                    "install_spec.json field `{field}` has invalid value `{value}`"
                )
            }
        }
    }
}

impl std::error::Error for SpecError {}

/// Parse the spec JSON from a raw byte slice. Accepts only the
/// closed shape documented above; any unknown top-level key fails
/// closed (`Malformed`) so a future field-name typo on the host
/// surfaces immediately rather than being silently ignored.
///
/// Hand-rolled minimal JSON parser — supports the exact subset the
/// install spec needs:
///
/// - Top-level object `{ ... }`.
/// - String values (`"..."`) with backslash escapes (`\"`, `\\`,
///   `\n`, `\r`, `\t`).
/// - No nested objects, arrays, numbers, booleans, or nulls (the
///   spec doesn't use them).
/// - Insignificant whitespace anywhere.
pub fn parse(bytes: &[u8]) -> Result<InstallSpec, SpecError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| SpecError::Malformed(format!("not UTF-8: {e}")))?;
    let pairs = parse_top_object(text)?;

    let mut language: Option<Language> = None;
    let mut lockfile: Option<String> = None;
    let mut source_mount: Option<String> = None;
    let mut gate: Option<GateLevel> = None;

    for (key, value) in pairs {
        match key.as_str() {
            "language" => {
                language = Some(match value.as_str() {
                    "python" => Language::Python,
                    "node" => Language::Node,
                    other => {
                        return Err(SpecError::InvalidField {
                            field: "language",
                            value: other.to_string(),
                        });
                    }
                });
            }
            "lockfile_relative_path" => {
                if value.is_empty() {
                    return Err(SpecError::InvalidField {
                        field: "lockfile_relative_path",
                        value: value.clone(),
                    });
                }
                lockfile = Some(value);
            }
            "source_mount" => {
                if value.is_empty() {
                    return Err(SpecError::InvalidField {
                        field: "source_mount",
                        value: value.clone(),
                    });
                }
                source_mount = Some(value);
            }
            "gate" => {
                gate = Some(match value.as_str() {
                    "dev" => GateLevel::Dev,
                    "prod" => GateLevel::Prod,
                    other => {
                        return Err(SpecError::InvalidField {
                            field: "gate",
                            value: other.to_string(),
                        });
                    }
                });
            }
            other => {
                return Err(SpecError::Malformed(format!(
                    "unknown top-level field `{other}`"
                )));
            }
        }
    }

    Ok(InstallSpec {
        language: language.ok_or(SpecError::MissingField("language"))?,
        lockfile_relative_path: lockfile
            .ok_or(SpecError::MissingField("lockfile_relative_path"))?,
        source_mount: source_mount.ok_or(SpecError::MissingField("source_mount"))?,
        gate: gate.ok_or(SpecError::MissingField("gate"))?,
    })
}

/// Parse a top-level JSON object into `(key, value)` pairs of string
/// → string. The closed install-spec shape has only string fields,
/// so this is sufficient.
fn parse_top_object(text: &str) -> Result<Vec<(String, String)>, SpecError> {
    let mut cur = Cursor::new(text);
    cur.skip_ws();
    cur.expect('{')?;
    let mut pairs = Vec::new();
    cur.skip_ws();
    if cur.peek() == Some('}') {
        cur.advance();
        cur.skip_ws();
        if cur.peek().is_some() {
            return Err(SpecError::Malformed(
                "trailing content after closing brace".to_string(),
            ));
        }
        return Ok(pairs);
    }
    loop {
        cur.skip_ws();
        let key = cur.parse_string()?;
        cur.skip_ws();
        cur.expect(':')?;
        cur.skip_ws();
        let value = cur.parse_string()?;
        pairs.push((key, value));
        cur.skip_ws();
        match cur.peek() {
            Some(',') => {
                cur.advance();
            }
            Some('}') => {
                cur.advance();
                cur.skip_ws();
                if cur.peek().is_some() {
                    return Err(SpecError::Malformed(
                        "trailing content after closing brace".to_string(),
                    ));
                }
                return Ok(pairs);
            }
            Some(c) => {
                return Err(SpecError::Malformed(format!(
                    "expected ',' or '}}' after value, got '{c}'"
                )));
            }
            None => {
                return Err(SpecError::Malformed(
                    "unexpected end of input inside object".to_string(),
                ));
            }
        }
    }
}

struct Cursor<'a> {
    src: &'a str,
    idx: usize,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, idx: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.idx..].chars().next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.peek() {
            self.idx += c.len_utf8();
        }
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: char) -> Result<(), SpecError> {
        match self.peek() {
            Some(got) if got == c => {
                self.advance();
                Ok(())
            }
            Some(got) => Err(SpecError::Malformed(format!("expected '{c}', got '{got}'"))),
            None => Err(SpecError::Malformed(format!(
                "expected '{c}', got end of input"
            ))),
        }
    }

    fn parse_string(&mut self) -> Result<String, SpecError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                Some('"') => {
                    self.advance();
                    return Ok(out);
                }
                Some('\\') => {
                    self.advance();
                    match self.peek() {
                        Some('"') => out.push('"'),
                        Some('\\') => out.push('\\'),
                        Some('/') => out.push('/'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some('t') => out.push('\t'),
                        Some(c) => {
                            return Err(SpecError::Malformed(format!(
                                "unsupported escape sequence `\\{c}`"
                            )));
                        }
                        None => {
                            return Err(SpecError::Malformed(
                                "string ended after backslash".to_string(),
                            ));
                        }
                    }
                    self.advance();
                }
                Some(c) => {
                    out.push(c);
                    self.advance();
                }
                None => {
                    return Err(SpecError::Malformed(
                        "string was not terminated".to_string(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_spec() -> &'static str {
        r#"{
            "language": "python",
            "lockfile_relative_path": "uv.lock",
            "source_mount": "/work",
            "gate": "dev"
        }"#
    }

    #[test]
    fn parses_minimal_python_spec() {
        let spec = parse(ok_spec().as_bytes()).unwrap();
        assert_eq!(spec.language, Language::Python);
        assert_eq!(spec.lockfile_relative_path, "uv.lock");
        assert_eq!(spec.source_mount, "/work");
        assert_eq!(spec.gate, GateLevel::Dev);
    }

    #[test]
    fn parses_node_prod_spec() {
        let body = r#"{"language":"node","lockfile_relative_path":"pnpm-lock.yaml","source_mount":"/work","gate":"prod"}"#;
        let spec = parse(body.as_bytes()).unwrap();
        assert_eq!(spec.language, Language::Node);
        assert_eq!(spec.gate, GateLevel::Prod);
    }

    #[test]
    fn rejects_unknown_language() {
        let body = r#"{"language":"ruby","lockfile_relative_path":"Gemfile.lock","source_mount":"/work","gate":"dev"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        match err {
            SpecError::InvalidField { field, value } => {
                assert_eq!(field, "language");
                assert_eq!(value, "ruby");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_gate() {
        let body = r#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"strict"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(err, SpecError::InvalidField { field: "gate", .. }));
    }

    #[test]
    fn rejects_missing_language() {
        let body = r#"{"lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"dev"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(err, SpecError::MissingField("language")));
    }

    #[test]
    fn rejects_missing_lockfile() {
        let body = r#"{"language":"python","source_mount":"/work","gate":"dev"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            SpecError::MissingField("lockfile_relative_path")
        ));
    }

    #[test]
    fn rejects_missing_source_mount() {
        let body = r#"{"language":"python","lockfile_relative_path":"uv.lock","gate":"dev"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(err, SpecError::MissingField("source_mount")));
    }

    #[test]
    fn rejects_missing_gate() {
        let body =
            r#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(err, SpecError::MissingField("gate")));
    }

    #[test]
    fn rejects_empty_string_fields() {
        let body = r#"{"language":"python","lockfile_relative_path":"","source_mount":"/work","gate":"dev"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            SpecError::InvalidField {
                field: "lockfile_relative_path",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        // `deny_unknown_fields`-style behavior — a typo in the host
        // staging code surfaces here, not silently.
        let body = r#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"dev","extra":"oops"}"#;
        let err = parse(body.as_bytes()).unwrap_err();
        match err {
            SpecError::Malformed(why) => assert!(why.contains("extra"), "msg: {why}"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_non_utf8_bytes() {
        let err = parse(b"\xff\xff\xff").unwrap_err();
        assert!(matches!(err, SpecError::Malformed(_)));
    }

    #[test]
    fn rejects_truncated_input() {
        let err = parse(b"{\"language\":\"python\"").unwrap_err();
        assert!(matches!(err, SpecError::Malformed(_)));
    }

    #[test]
    fn handles_string_escapes_in_path() {
        let body = r#"{"language":"python","lockfile_relative_path":"sub\\dir\\uv.lock","source_mount":"/work","gate":"dev"}"#;
        let spec = parse(body.as_bytes()).unwrap();
        assert_eq!(spec.lockfile_relative_path, "sub\\dir\\uv.lock");
    }

    #[test]
    fn rejects_trailing_garbage() {
        let body = r#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"dev"} extra"#;
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(matches!(err, SpecError::Malformed(_)));
    }

    #[test]
    fn language_token_round_trip() {
        assert_eq!(Language::Python.as_str(), "python");
        assert_eq!(Language::Node.as_str(), "node");
        assert_eq!(GateLevel::Dev.as_str(), "dev");
        assert_eq!(GateLevel::Prod.as_str(), "prod");
    }
}
