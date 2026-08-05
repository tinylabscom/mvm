//! `xtask check-dormant-controls`
//!
//! The failure mode this exists for is a control that reports present and
//! cannot fire. An admission gate reading an argv nobody populates, a broker
//! nothing constructs, a scan whose bound set is always empty. Each of those
//! shipped correct, tested, and unreachable, and each was found by review
//! rather than by CI — which is not a control either.
//!
//! `xtask/dormant-controls.toml` declares the security-relevant symbols worth
//! tracking and whether each is currently reachable. The gate compares the
//! declaration against the tree in both directions:
//!
//! - a control declared **live** that has lost its last production caller has
//!   gone quietly dormant, which is the defect;
//! - a control declared **dormant** that has *gained* one has a stale
//!   declaration, and the entry should go. That is what makes the list a
//!   ratchet: it may only shrink.
//!
//! ## What counts as a caller
//!
//! A mention in production Rust, outside the file that defines the symbol and
//! outside any `#[cfg(test)]` module or `tests/` tree. Tests are excluded on
//! purpose: a symbol exercised only by its own tests is exactly the shape
//! being hunted, and counting them would make the gate agree with every defect
//! it exists to catch.
//!
//! ## What this cannot do
//!
//! It reads text, not a call graph. A symbol named in a comment counts as a
//! caller, and a symbol reached only through a trait object or a macro may not
//! be seen. Both fail toward *more* work rather than less: the first can hide
//! a dormant control if someone writes its name in prose next to no call, and
//! the second can flag a live one. Neither is silent — a wrong answer here
//! produces a red gate, not a quiet pass.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// Where the declaration lives.
const MANIFEST: &str = "xtask/dormant-controls.toml";

/// Above this many matching files, a symbol is naming a common word rather
/// than a control. Generous: a genuinely popular helper still sits well under
/// it, and the bare `validate` that prompted this matched over two hundred.
const GENERIC_SYMBOL_LIMIT: usize = 40;

/// A control under construction, before its required keys are all present.
#[derive(Default)]
struct PartialControl {
    symbol: Option<String>,
    file: Option<String>,
    dormant: Option<bool>,
    why: Option<String>,
}

/// One declared control.
#[derive(Debug, Clone)]
struct Control {
    symbol: String,
    file: String,
    dormant: bool,
    why: String,
}

/// Parse the manifest. Hand-rolled rather than pulling `toml` into xtask for
/// four keys; the format is fixed and the parser refuses anything it does not
/// recognise rather than skipping it.
fn parse_manifest(text: &str) -> Result<Vec<Control>> {
    let mut controls = Vec::new();
    let mut current: Option<PartialControl> = None;
    let mut lines = text.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed == "[[control]]" {
            if let Some(entry) = current.take() {
                controls.push(finish(entry)?);
            }
            current = Some(PartialControl::default());
            continue;
        }
        let Some(slot) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        // A `"""` block runs to its closing delimiter, possibly over many
        // lines. Collect it here rather than leaving stray text to be parsed
        // as further keys.
        let value = if let Some(rest) = value.strip_prefix(r#"""""#) {
            let mut buf = String::from(rest.trim_end_matches('\\'));
            if !rest.trim_end().ends_with(r#"""""#) {
                for cont in lines.by_ref() {
                    let cont_trimmed = cont.trim_end();
                    if let Some(last) = cont_trimmed.strip_suffix(r#"""""#) {
                        buf.push_str(last);
                        break;
                    }
                    buf.push_str(cont_trimmed.trim_end_matches('\\'));
                }
            }
            buf.trim().to_string()
        } else {
            value.trim_matches('"').to_string()
        };

        match key {
            "symbol" => slot.symbol = Some(value),
            "file" => slot.file = Some(value),
            "dormant" => slot.dormant = Some(value == "true"),
            "why" => slot.why = Some(value),
            other => bail!("{MANIFEST}: unknown key {other:?}"),
        }
    }
    if let Some(entry) = current.take() {
        controls.push(finish(entry)?);
    }
    Ok(controls)
}

fn finish(entry: PartialControl) -> Result<Control> {
    let symbol = entry.symbol.context("a [[control]] is missing `symbol`")?;
    Ok(Control {
        file: entry
            .file
            .with_context(|| format!("control {symbol:?} is missing `file`"))?,
        dormant: entry
            .dormant
            .with_context(|| format!("control {symbol:?} is missing `dormant`"))?,
        why: entry
            .why
            .with_context(|| format!("control {symbol:?} is missing `why`"))?,
        symbol,
    })
}

/// Every production `.rs` file: no `tests/` trees, no `target/`, no fuzz
/// corpora.
fn production_sources(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if matches!(name.as_str(), "target" | "tests" | "fuzz" | "benches") {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Strip `#[cfg(test)]` modules so a symbol used only by its own tests does
/// not read as reachable.
///
/// Brace-counts from the `mod` that follows the attribute. Crude, and it has
/// to be: the alternative is parsing Rust, and a gate that needs a parser to
/// answer "is this dead" will not survive contact with the next refactor.
fn strip_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(idx) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx..];
        let Some(open) = after.find('{') else {
            break;
        };
        let mut depth = 0usize;
        let mut end = None;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) => rest = &after[e..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Files that mention `symbol` outside `defining_file`, with test modules
/// removed.
fn callers(root: &Path, symbol: &str, defining_file: &str) -> Result<Vec<String>> {
    let defining = root.join(defining_file);
    let mut hits = Vec::new();
    for path in production_sources(root)? {
        if path == defining {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !src.contains(symbol) {
            continue;
        }
        if strip_test_modules(&src).contains(symbol) {
            hits.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }
    Ok(hits)
}

/// Run the gate.
///
/// # Errors
///
/// When a declared-live control has no production caller, or a declared-dormant
/// one has acquired a caller, or the manifest names a file that does not exist.
pub fn run(root: &Path) -> Result<()> {
    let manifest_path = root.join(MANIFEST);
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let controls = parse_manifest(&text)?;
    if controls.is_empty() {
        bail!("{MANIFEST} declares no controls — an empty gate asserts nothing");
    }

    let mut errors: Vec<String> = Vec::new();
    let (mut live, mut dormant) = (0usize, 0usize);

    for control in &controls {
        if !root.join(&control.file).exists() {
            errors.push(format!(
                "control {:?}: declared in {} which does not exist — the symbol moved, so the \
                 declaration is describing a control that is not there",
                control.symbol, control.file
            ));
            continue;
        }
        if control.why.trim().is_empty() {
            errors.push(format!(
                "control {:?}: `why` is empty — a declaration without a reason is an assertion \
                 nobody can check",
                control.symbol
            ));
        }

        let found = callers(root, &control.symbol, &control.file)?;
        // A symbol that matches implausibly widely is not identifying anything:
        // it reports reachable whatever the tree does, so its verdict is noise
        // rather than evidence. `validate` matched a third of the workspace
        // before this fired.
        if found.len() > GENERIC_SYMBOL_LIMIT {
            errors.push(format!(
                "control {:?} matches {} files — too generic to identify one control. Name it by \
                 its re-exported alias or a qualified path instead; as written it would report \
                 reachable no matter what the tree did.",
                control.symbol,
                found.len()
            ));
            continue;
        }
        match (control.dormant, found.is_empty()) {
            (true, true) => dormant += 1,
            (false, false) => live += 1,
            (false, true) => errors.push(format!(
                "control {:?} is declared live but has no production caller outside {}. It went \
                 dormant without anyone saying so, which is the defect this gate exists for. \
                 Either restore the caller, or move it to `dormant = true` with a reason.",
                control.symbol, control.file
            )),
            (true, false) => errors.push(format!(
                "control {:?} is declared dormant but is now referenced by: {}. The declaration \
                 is stale — delete the entry. This list may only shrink.",
                control.symbol,
                found.join(", ")
            )),
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("[error] {err}");
        }
        bail!(
            "check-dormant-controls: {} problem(s) across {} declared control(s)",
            errors.len(),
            controls.len()
        );
    }

    println!(
        "check-dormant-controls: clean ({live} live, {dormant} declared dormant, {} total)",
        controls.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_parses_and_every_entry_is_complete() {
        let root = crate::workspace_root();
        let text = std::fs::read_to_string(root.join(MANIFEST)).expect("manifest readable");
        let controls = parse_manifest(&text).expect("manifest parses");
        assert!(!controls.is_empty(), "the manifest declares nothing");
        for c in &controls {
            assert!(!c.symbol.is_empty(), "a control has no symbol");
            assert!(
                !c.why.trim().is_empty(),
                "control {:?} has no reason",
                c.symbol
            );
        }
    }

    /// A multi-line `"""` reason must not leak into the next key. If it did,
    /// the parser would read prose as a `[[control]]` field and the gate would
    /// start asserting about symbols nobody declared.
    #[test]
    fn a_multiline_reason_is_captured_whole() {
        let controls = parse_manifest(
            r#"
[[control]]
symbol = "a"
file = "src/a.rs"
dormant = true
why = """
first line \
second line"""

[[control]]
symbol = "b"
file = "src/b.rs"
dormant = false
why = "short"
"#,
        )
        .expect("parses");
        assert_eq!(controls.len(), 2, "both entries survive the block scalar");
        assert!(
            controls[0].why.contains("second line"),
            "{:?}",
            controls[0].why
        );
        assert_eq!(controls[1].symbol, "b");
        assert!(!controls[1].dormant);
    }

    /// The whole point: a symbol used only by its own tests is dormant.
    #[test]
    fn test_only_usage_does_not_count_as_a_caller() {
        let src = r#"
fn production() { let _ = 1; }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() { the_control(); }
}
"#;
        let stripped = strip_test_modules(src);
        assert!(
            !stripped.contains("the_control"),
            "a test-only call must not read as reachable: {stripped}"
        );
        assert!(stripped.contains("production"), "real code survives");
    }

    #[test]
    fn a_nested_brace_inside_a_test_module_does_not_end_the_strip_early() {
        let src = r#"
#[cfg(test)]
mod tests {
    fn helper() { if true { the_control(); } }
}
after_the_module();
"#;
        let stripped = strip_test_modules(src);
        assert!(!stripped.contains("the_control"), "{stripped}");
        assert!(stripped.contains("after_the_module"), "{stripped}");
    }

    /// The gate must pass on the tree as it stands, or it is not a gate.
    #[test]
    fn the_declared_controls_match_the_tree() {
        run(&crate::workspace_root()).expect("declared controls agree with the tree");
    }
}
