//! Strip build-time framework constructs from the bundled Python source.
//!
//! The `@mvm.app(...)` decorator is compile-time metadata — `compile`
//! has already lowered it to IR by the time we bundle — and the decorator
//! returns the wrapped function unchanged. So the guest runtime must NOT
//! need the `mvm` SDK: the wrapper imports the user module to dispatch the
//! function, and a stray `import mvm` would fail in a rootfs that
//! deliberately doesn't ship the SDK. Removing `import mvm` and every
//! `@mvm.*` decorator from the bundled tree keeps the SDK out of the guest
//! entirely (authoring still uses the published SDK on the host).
//!
//! Tree-sitter only — no Python is executed. Unparseable files are left
//! untouched (the reachability/presence passes already ran on them).

use std::fs;
use std::path::Path;

use tree_sitter::{Node, Parser};

/// Walk every `.py` file under `bundle_dir` and rewrite it without
/// `mvm` imports / `@mvm.*` decorators. Idempotent; only writes files
/// that actually change.
pub fn strip_python(bundle_dir: &Path) -> std::io::Result<()> {
    let mut stack = vec![bundle_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "py") {
                let src = fs::read(&path)?;
                if let Some(rewritten) = strip_source(&src) {
                    fs::write(&path, rewritten)?;
                }
            }
        }
    }
    Ok(())
}

/// Return the source with `mvm` imports + `@mvm.*` decorators removed,
/// or `None` if nothing matched / the file didn't parse cleanly.
fn strip_source(source: &[u8]) -> Option<Vec<u8>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None; // don't risk mangling a file we can't parse
    }

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    collect_ranges(root, source, &mut ranges);
    if ranges.is_empty() {
        return None;
    }

    // Remove whole lines, last-first so earlier byte offsets stay valid.
    ranges.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out = source.to_vec();
    for (start, end) in ranges {
        // Expand to the start of the line (decorators/imports sit at
        // column 0 at module scope, but be defensive about indentation).
        let mut line_start = start;
        while line_start > 0 && out[line_start - 1] != b'\n' {
            line_start -= 1;
        }
        // Expand past the node's last line, including its trailing newline.
        let mut line_end = end;
        while line_end < out.len() && out[line_end] != b'\n' {
            line_end += 1;
        }
        if line_end < out.len() {
            line_end += 1; // consume the newline
        }
        out.drain(line_start..line_end);
    }
    Some(out)
}

/// Collect byte ranges of nodes to delete: `import mvm` /
/// `from mvm import …` statements and `@mvm.*` decorators.
fn collect_ranges(node: Node, source: &[u8], ranges: &mut Vec<(usize, usize)>) {
    match node.kind() {
        "import_statement" | "import_from_statement" => {
            if imports_mvm(node, source) {
                ranges.push((node.start_byte(), node.end_byte()));
                return;
            }
        }
        "decorator" => {
            if decorator_is_mvm(node, source) {
                ranges.push((node.start_byte(), node.end_byte()));
                return;
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_ranges(child, source, ranges);
    }
}

/// True if the import statement brings in the top-level `mvm` module —
/// `import mvm`, `import mvm as m`, or `from mvm[.x] import …`. A module
/// merely *prefixed* `mvm` (e.g. `mvmfoo`) is left alone.
fn imports_mvm(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // `import mvm` / `import mvm as m`: dotted_name or aliased_import.
            "dotted_name" => {
                if dotted_root_is_mvm(child, source) {
                    return true;
                }
            }
            "aliased_import" => {
                if let Some(name) = child.child_by_field_name("name")
                    && dotted_root_is_mvm(name, source)
                {
                    return true;
                }
            }
            // `from mvm import …`: the module name is the field `module_name`.
            _ => {
                if child.kind() == "dotted_name" || node.kind() == "import_from_statement" {
                    if let Some(m) = node.child_by_field_name("module_name")
                        && dotted_root_is_mvm(m, source)
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// First dotted segment equals `mvm` exactly.
fn dotted_root_is_mvm(node: Node, source: &[u8]) -> bool {
    node.utf8_text(source)
        .map(|t| t == "mvm" || t.starts_with("mvm."))
        .unwrap_or(false)
}

/// True for `@mvm`, `@mvm.app`, `@mvm.anything(...)`.
fn decorator_is_mvm(node: Node, source: &[u8]) -> bool {
    // Decorator text is `@<expr>`; strip the `@` and check the callee root.
    node.utf8_text(source)
        .map(|t| {
            let body = t.trim_start_matches('@').trim_start();
            body == "mvm" || body.starts_with("mvm.") || body.starts_with("mvm(")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(s: &str) -> String {
        String::from_utf8(strip_source(s.as_bytes()).unwrap_or_else(|| s.as_bytes().to_vec()))
            .unwrap()
    }

    #[test]
    fn strips_import_and_decorator_keeps_function() {
        let src = "import mvm\n\n\n@mvm.app(image=mvm.python_image(python=\"3.12\"))\ndef greet(name):\n    return f\"hello {name}\"\n";
        let out = strip(src);
        assert!(!out.contains("import mvm"));
        assert!(!out.contains("@mvm.app"));
        assert!(out.contains("def greet(name):"));
        assert!(out.contains("return f\"hello {name}\""));
    }

    #[test]
    fn strips_from_import() {
        let out = strip("from mvm import app\ndef f():\n    return 1\n");
        assert!(!out.contains("from mvm"));
        assert!(out.contains("def f():"));
    }

    #[test]
    fn leaves_unrelated_imports_and_lookalikes() {
        let src = "import os\nimport mvmfoo\ndef f():\n    return os.getpid()\n";
        // Nothing to strip → None → unchanged.
        assert!(strip_source(src.as_bytes()).is_none());
    }

    #[test]
    fn strips_multiline_decorator() {
        let src = "import mvm\n@mvm.app(\n    image=mvm.python_image(python=\"3.12\"),\n    resources=mvm.resources(cpu=1, memory_mb=256),\n)\ndef greet(name: str) -> str:\n    return f\"hello {name}\"\n";
        let out = strip(src);
        assert!(!out.contains("mvm"));
        assert!(out.contains("def greet(name: str) -> str:"));
    }
}
