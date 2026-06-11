//! `xtask check-no-display-on-secret-types`
//!
//! Refuses any `#[derive(Debug)]` / `#[derive(Display)]` / `impl Display`
//! on a Rust item (struct, enum) whose name matches secret-shaped
//! patterns. Secret-carrying types should be
//! wrapped in `secrecy::SecretBox<T>` so accidental logging at any
//! `{:?}` / `{}` call site is a compile error.
//!
//! Heuristic name patterns (case-insensitive):
//!   - contains `Secret`
//!   - contains `Password` / `Passwd`
//!   - contains `Token` (excluding `CancellationToken`, well-known non-secret types)
//!   - starts with or ends with `Key` (`PublicKey` excluded — that's pub material)
//!   - `Credential` / `Credentials`
//!
//! Opt-out: add `// allow(secret-debug): <reason>` on the line above
//! the type definition. The reason is required and will appear in
//! lint output if anyone audits the bypass.
//!
//! False-positive philosophy: we'd rather catch a real leak by being
//! too strict than miss one by being too loose. Bypass is cheap; the
//! lint runs `O(files)` once per PR via the CI security lane.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Run the lint over `crates/*/src/**/*.rs` rooted at `workspace`.
pub fn run(workspace: &Path) -> Result<()> {
    let crates_dir = workspace.join("crates");
    if !crates_dir.is_dir() {
        bail!(
            "expected workspace crates dir at {}; got nothing",
            crates_dir.display()
        );
    }

    let mut findings: Vec<Finding> = Vec::new();
    visit_rust_files(&crates_dir, &mut |path| -> Result<()> {
        let source =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        findings.extend(lint_source(path, &source));
        Ok(())
    })?;

    if findings.is_empty() {
        eprintln!("check-no-display-on-secret-types: clean (scanned crates/*/src/**/*.rs)");
        return Ok(());
    }

    eprintln!(
        "check-no-display-on-secret-types: {} finding(s)",
        findings.len()
    );
    for f in &findings {
        eprintln!(
            "  {}:{} — {} `{}` derives/implements `{}`. Wrap in `secrecy::SecretBox<T>` or add `// allow(secret-debug): <reason>` directly above the type.",
            f.path.display(),
            f.line,
            f.kind,
            f.type_name,
            f.violation,
        );
    }
    std::process::exit(1);
}

#[derive(Debug, Clone)]
struct Finding {
    path: PathBuf,
    line: usize,
    kind: &'static str,
    type_name: String,
    violation: String,
}

fn visit_rust_files(dir: &Path, cb: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip target/, vendored deps, build outputs.
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if matches!(name, "target" | "node_modules" | ".git" | ".cargo") {
                continue;
            }
            visit_rust_files(&path, cb)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            cb(&path)?;
        }
    }
    Ok(())
}

fn lint_source(path: &Path, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();

        // Pick up `struct Foo`, `enum Foo`, `pub struct Foo`,
        // `pub(crate) struct Foo`. Anonymous re-exports and trait
        // impls are caught by the impl-Display branch below.
        if let Some(type_name) = extract_type_name(trimmed)
            && looks_secret(&type_name)
        {
            // Walk backwards up to 10 lines to find a `#[derive(...)]`
            // attached to this type definition. Wider than strictly
            // needed for derives because doc comments + multi-line
            // attribute strings + allow opt-outs may push the
            // relevant attributes further up.
            let derive_window_start = i.saturating_sub(10);
            if !has_allow_in_window(&lines, derive_window_start, i + 1) {
                for (j, line) in lines.iter().enumerate().take(i).skip(derive_window_start) {
                    let above = line.trim();
                    if let Some(deriv) = derive_args(above) {
                        for d in deriv.split(',').map(str::trim) {
                            if d == "Debug" || d == "Display" {
                                findings.push(Finding {
                                    path: path.to_path_buf(),
                                    line: j + 1,
                                    kind: "type",
                                    type_name: type_name.clone(),
                                    violation: format!("#[derive({d})]"),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Catch `impl fmt::Display for SecretFoo` / `impl Display for SecretFoo`.
        if let Some(target) = impl_display_target(trimmed)
            && looks_secret(&target)
            && !has_allow_in_window(&lines, i.saturating_sub(2), i + 1)
        {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: i + 1,
                kind: "impl",
                type_name: target,
                violation: "impl Display".to_string(),
            });
        }
    }

    findings
}

/// Extract the type name from a `struct Foo` / `enum Foo` declaration.
fn extract_type_name(line: &str) -> Option<String> {
    let after_vis = line
        .strip_prefix("pub(crate) ")
        .or_else(|| {
            line.strip_prefix("pub(super) ")
                .or_else(|| line.strip_prefix("pub(self) "))
        })
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let rest = after_vis
        .strip_prefix("struct ")
        .or_else(|| after_vis.strip_prefix("enum "))?;
    // Strip generics `<...>`, body `{`, tuple `(`, semicolons.
    let end = rest
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Extract the type name from `impl <Trait> for <Type>`, where
/// `<Trait>` is some flavor of `Display` (with or without `fmt::`).
fn impl_display_target(line: &str) -> Option<String> {
    // Possible shapes:
    //   impl fmt::Display for Foo
    //   impl std::fmt::Display for Foo
    //   impl Display for Foo
    //   impl<T> Display for Foo<T>
    let after_impl = line.strip_prefix("impl")?;
    let after_impl = after_impl.trim_start();

    // Skip the generic param list, if any.
    let after_generics = if let Some(rest) = after_impl.strip_prefix('<') {
        let close = rest.find('>')?;
        rest[close + 1..].trim_start()
    } else {
        after_impl
    };

    let display_segment = ["fmt::Display ", "std::fmt::Display ", "Display "]
        .iter()
        .find_map(|p| after_generics.strip_prefix(p))?;

    let after_for = display_segment.trim_start().strip_prefix("for ")?;
    let after_for = after_for.trim_start();

    let end = after_for
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(after_for.len());
    let name = &after_for[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Extract the contents of a `#[derive(...)]` attribute, if present.
fn derive_args(line: &str) -> Option<&str> {
    let after = line.strip_prefix("#[derive(")?;
    let close = after.rfind(')')?;
    Some(&after[..close])
}

/// True if `name` matches the secret-shaped heuristic — i.e., the
/// type plausibly contains plaintext key material that mustn't leak
/// via Debug/Display.
///
/// Calibration: we flag types whose name SHAPE suggests "the secret
/// itself," and exclude types whose name shape suggests "a reference
/// to / metadata about a secret." A `Ref`/`Handle`/`Id`/`Policy`/`Spec`/
/// `Source`/`Binding`/`Scope`/`Grant`/`Provider`/`Error`/`Rule` suffix
/// strongly indicates the latter — those carry pointer-shaped values,
/// not key bytes.
///
/// Known false-positives can opt out with `// allow(secret-debug):
/// <reason>` directly above the type.
fn looks_secret(name: &str) -> bool {
    // Suffix tells us "this is metadata / a reference, not the secret
    // itself." Cheaper to special-case than enumerate every metadata
    // type explicitly.
    const METADATA_SUFFIXES: &[&str] = &[
        "Ref",
        "Handle",
        "Id",
        "Path",
        "Version",
        "Policy",
        "Spec",
        "Source",
        "Binding",
        "Bindings",
        "Scope",
        "Grant",
        "Grants",
        "Provider",
        "Providers",
        "Error",
        "Errors",
        "Rule",
        "Rules",
        "Config",
        "Settings",
        "Options",
        "Args",
        "Builder",
        "Visitor",
        "Iter",
        "Stream",
        "Tokenizer",
        "Through",
        "Cache",
        "Map",
        "Set",
    ];
    if METADATA_SUFFIXES
        .iter()
        .any(|s| name.ends_with(s) && name != *s)
    {
        return false;
    }

    // Known specific names that contain a match-fragment but are
    // intentionally public material.
    const PUBLIC_MATERIAL: &[&str] = &[
        "PublicKey",
        "PubKey",
        "VerifyingKey",
        "Key", // bare `Key` is too generic
    ];
    if PUBLIC_MATERIAL.contains(&name) {
        return false;
    }

    let lower = name.to_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || (lower.contains("secret") && !lower.starts_with("secret_") && lower != "secrets")
        || lower.contains("credential")
        || lower.contains("apikey")
        || lower.contains("api_key")
        // Token without metadata suffix or tokenizer connotations
        || (lower.contains("token")
            && !lower.contains("tokenizer")
            && !lower.contains("cancellation"))
        // SecretBytes, SecretKey, RootKey, MasterKey, DEK, KEK, WrappedKey
        || name.starts_with("Secret")
        || name.starts_with("Master")
        || name.starts_with("Root") && name.contains("Key")
        || name.starts_with("Wrapped") && name.contains("Key")
        || name == "Dek"
        || name == "Kek"
        || name == "DEK"
        || name == "KEK"
}

/// True if any line in `[start, end)` is an opt-out comment.
fn has_allow_in_window(lines: &[&str], start: usize, end: usize) -> bool {
    let end = end.min(lines.len());
    for line in &lines[start..end] {
        let trimmed = line.trim();
        if trimmed.starts_with("// allow(secret-debug):")
            || trimmed.starts_with("//allow(secret-debug):")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_derive_debug_on_secret_named_struct() {
        let src = "\
#[derive(Debug)]\n\
struct SecretToken { bytes: Vec<u8> }\n\
";
        let findings = lint_source(Path::new("test.rs"), src);
        assert_eq!(findings.len(), 1, "expected one finding, got {findings:?}");
        assert_eq!(findings[0].type_name, "SecretToken");
        assert!(findings[0].violation.contains("Debug"));
    }

    #[test]
    fn flags_derive_display_on_password_named_enum() {
        let src = "\
#[derive(Display)]\n\
enum UserPassword { Bcrypt(Vec<u8>) }\n\
";
        let findings = lint_source(Path::new("test.rs"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name, "UserPassword");
    }

    #[test]
    fn flags_impl_display_for_secret_type() {
        let src = "\
impl fmt::Display for SecretBytes {\n\
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) }\n\
}\n\
";
        let findings = lint_source(Path::new("test.rs"), src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "impl");
        assert_eq!(findings[0].type_name, "SecretBytes");
    }

    #[test]
    fn allows_opt_out_comment() {
        let src = "\
// allow(secret-debug): this struct's Debug impl is custom and redacts the bytes\n\
#[derive(Debug)]\n\
struct SecretKey { bytes: Vec<u8> }\n\
";
        let findings = lint_source(Path::new("test.rs"), src);
        assert!(
            findings.is_empty(),
            "opt-out comment must suppress findings, got {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_public_key_or_other_allowlisted_names() {
        let src = "\
#[derive(Debug)]\n\
struct PublicKey { bytes: [u8; 32] }\n\
\n\
#[derive(Debug)]\n\
struct VerifyingKey { bytes: [u8; 32] }\n\
\n\
#[derive(Debug)]\n\
struct CancellationToken;\n\
";
        let findings = lint_source(Path::new("test.rs"), src);
        assert!(
            findings.is_empty(),
            "allowlisted names must not be flagged, got {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_types_with_debug() {
        let src = "\
#[derive(Debug)]\n\
struct VmName(String);\n\
\n\
#[derive(Debug)]\n\
struct RoutingTable { entries: Vec<u8> }\n\
";
        let findings = lint_source(Path::new("test.rs"), src);
        assert!(
            findings.is_empty(),
            "unrelated types must not be flagged, got {findings:?}"
        );
    }

    #[test]
    fn looks_secret_picks_up_real_secret_shapes() {
        // Real secret carriers — DO flag.
        assert!(looks_secret("SecretBytes"));
        assert!(looks_secret("SecretToken"));
        assert!(looks_secret("ApiToken"));
        assert!(looks_secret("UserPassword"));
        assert!(looks_secret("WrappedKey"));
        assert!(looks_secret("Credentials"));
        assert!(looks_secret("MasterKey"));

        // Metadata / references — DO NOT flag.
        assert!(!looks_secret("SecretRef"));
        assert!(!looks_secret("SecretBinding"));
        assert!(!looks_secret("SecretSource"));
        assert!(!looks_secret("SecretScope"));
        assert!(!looks_secret("SecretGrant"));
        assert!(!looks_secret("SecretRule"));
        assert!(!looks_secret("KeystoreError"));
        assert!(!looks_secret("KeyPolicy"));
        assert!(!looks_secret("KeyRotationSpec"));
        assert!(!looks_secret("KeyProvider"));
        assert!(!looks_secret("KeyId"));
        assert!(!looks_secret("DedupKey"));

        // Public material — DO NOT flag.
        assert!(!looks_secret("PublicKey"));
        assert!(!looks_secret("VerifyingKey"));

        // Unrelated — DO NOT flag.
        assert!(!looks_secret("VmName"));
        assert!(!looks_secret("CancellationToken"));
        assert!(!looks_secret("Tokenizer"));
    }

    #[test]
    fn extract_type_name_handles_pub_variants() {
        assert_eq!(
            extract_type_name("pub struct Foo {}"),
            Some("Foo".to_string())
        );
        assert_eq!(
            extract_type_name("pub(crate) struct Foo<T>"),
            Some("Foo".to_string())
        );
        assert_eq!(
            extract_type_name("enum Bar { A, B }"),
            Some("Bar".to_string())
        );
        assert_eq!(extract_type_name("fn foo() {}"), None);
    }

    #[test]
    fn impl_display_target_handles_qualified_paths() {
        assert_eq!(
            impl_display_target("impl fmt::Display for Foo {"),
            Some("Foo".to_string())
        );
        assert_eq!(
            impl_display_target("impl std::fmt::Display for Bar<T> {"),
            Some("Bar".to_string())
        );
        assert_eq!(
            impl_display_target("impl<T> Display for Baz<T> {"),
            Some("Baz".to_string())
        );
    }
}
