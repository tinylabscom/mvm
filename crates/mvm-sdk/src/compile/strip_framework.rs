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
    ranges.sort_by_key(|&(start, _)| std::cmp::Reverse(start));
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
        "import_statement" | "import_from_statement" if imports_mvm(node, source) => {
            ranges.push((node.start_byte(), node.end_byte()));
            return;
        }
        "decorator" if decorator_is_mvm(node, source) => {
            ranges.push((node.start_byte(), node.end_byte()));
            return;
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
    // `from mvm import …` carries the module on the `module_name` field.
    if let Some(m) = node.child_by_field_name("module_name") {
        return dotted_root_is_mvm(m, source);
    }
    // `import mvm`, `import mvm as m`, `import a, mvm` → scan the name
    // children (`dotted_name` / `aliased_import`).
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| match child.kind() {
        "dotted_name" => dotted_root_is_mvm(child, source),
        "aliased_import" => child
            .child_by_field_name("name")
            .is_some_and(|n| dotted_root_is_mvm(n, source)),
        _ => false,
    })
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

// ---------- TypeScript / Node ----------------------------------------------
//
// Same goal as `strip_python` (keep the `mvm` SDK out of the guest), but TS
// uses the higher-order form `export const NAME = mvm.app({...})(FN)` rather
// than a `@decorator`. The function we want to keep is *embedded* inside the
// call, so a whole-line delete won't do — we unwrap the call down to `FN`.

/// Node-kinds the unwrap accepts as the wrapped function.
const FN_KINDS: [&str; 2] = ["arrow_function", "function_expression"];

/// Walk every Node/TS source file under `bundle_dir` and rewrite it without
/// `mvm-sdk` imports, with each `mvm.app({...})(FN)` unwrapped to `FN`.
/// Idempotent; only writes files that change. The TypeScript grammar is a
/// superset of JS, so one parser covers ts/tsx/mts/cts/js/mjs/cjs.
pub fn strip_typescript(bundle_dir: &Path) -> std::io::Result<()> {
    let mut stack = vec![bundle_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| matches!(e, "ts" | "tsx" | "mts" | "cts" | "js" | "mjs" | "cjs"))
            {
                let src = fs::read(&path)?;
                if let Some(rewritten) = strip_ts_source(&src) {
                    fs::write(&path, rewritten)?;
                }
            }
        }
    }
    Ok(())
}

/// One rewrite to apply to the source buffer.
enum TsEdit {
    /// `import … from "mvm-sdk"` — delete the whole line(s).
    DeleteLines(usize, usize),
    /// Replace `mvm.app({...})(FN)` (byte range) with `FN`'s text.
    Replace(usize, usize, Vec<u8>),
}

/// Return the rewritten source, or `None` if nothing matched / the file
/// didn't parse cleanly (we never risk mangling an unparseable file).
fn strip_ts_source(source: &[u8]) -> Option<Vec<u8>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut edits: Vec<TsEdit> = Vec::new();
    collect_ts_edits(root, source, &mut edits);
    if edits.is_empty() {
        return None;
    }

    // Apply highest-offset-first so earlier byte offsets stay valid.
    edits.sort_by_key(|e| match e {
        TsEdit::DeleteLines(start, _) | TsEdit::Replace(start, _, _) => std::cmp::Reverse(*start),
    });
    let mut out = source.to_vec();
    for edit in edits {
        match edit {
            TsEdit::DeleteLines(start, end) => {
                let mut line_start = start;
                while line_start > 0 && out[line_start - 1] != b'\n' {
                    line_start -= 1;
                }
                let mut line_end = end;
                while line_end < out.len() && out[line_end] != b'\n' {
                    line_end += 1;
                }
                if line_end < out.len() {
                    line_end += 1; // consume the newline
                }
                out.drain(line_start..line_end);
            }
            TsEdit::Replace(start, end, repl) => {
                out.splice(start..end, repl);
            }
        }
    }
    Some(out)
}

/// Scan module-scope statements for the two edit kinds. `mvm.app(...)` sites
/// live on the RHS of a top-level `const`, optionally `export`ed.
fn collect_ts_edits(root: Node, source: &[u8], edits: &mut Vec<TsEdit>) {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "import_statement" if import_is_mvm_sdk(child, source) => {
                edits.push(TsEdit::DeleteLines(child.start_byte(), child.end_byte()));
            }
            "export_statement" => {
                if let Some(lex) = ts_first_named_descendant(child, "lexical_declaration") {
                    collect_unwrap_in_lexical(lex, source, edits);
                }
            }
            "lexical_declaration" => collect_unwrap_in_lexical(child, source, edits),
            _ => {}
        }
    }
}

/// True for `import … from "mvm-sdk"` / `import "mvm-sdk"`. The module
/// specifier is the `source` field on the import statement.
fn import_is_mvm_sdk(node: Node, source: &[u8]) -> bool {
    node.child_by_field_name("source")
        .and_then(|s| s.utf8_text(source).ok())
        .map(|t| t.trim_matches(['"', '\'', '`']) == "mvm-sdk")
        .unwrap_or(false)
}

/// For each `NAME = mvm.app({...})(FN)` declarator in this `const`, queue a
/// replacement of the RHS with `FN` so `NAME` resolves to the bare function.
fn collect_unwrap_in_lexical(lex: Node, source: &[u8], edits: &mut Vec<TsEdit>) {
    let mut walk = lex.walk();
    for decl in lex.named_children(&mut walk) {
        if decl.kind() != "variable_declarator" {
            continue;
        }
        let Some(value) = decl.child_by_field_name("value") else {
            continue;
        };
        if let Some(fn_node) = match_app_unwrap(value, source)
            && let Ok(fn_text) = fn_node.utf8_text(source)
        {
            // Replace only the declarator's value, preserving the
            // `export const NAME = ` prefix and the trailing `;`.
            edits.push(TsEdit::Replace(
                value.start_byte(),
                value.end_byte(),
                fn_text.as_bytes().to_vec(),
            ));
        }
    }
}

/// Match `app({...})(FN)` / `mvm.app({...})(FN)`; return the `FN` node
/// (arrow or function expression). Mirrors
/// `decorator::typescript::match_app_higher_order`, but returns `FN` (the
/// outer call's argument) instead of the options object.
fn match_app_unwrap<'tree>(value: Node<'tree>, source: &[u8]) -> Option<Node<'tree>> {
    if value.kind() != "call_expression" {
        return None;
    }
    let inner_callee = value.child_by_field_name("function")?;
    if inner_callee.kind() != "call_expression" {
        return None;
    }
    let app_callee = inner_callee.child_by_field_name("function")?;
    let callee_text = app_callee.utf8_text(source).ok()?;
    if callee_text != "app" && callee_text != "mvm.app" {
        return None;
    }
    let args = value.child_by_field_name("arguments")?;
    let mut args_walk = args.walk();
    args.named_children(&mut args_walk)
        .find(|c| FN_KINDS.contains(&c.kind()))
}

fn ts_first_named_descendant<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut walk = node.walk();
    node.named_children(&mut walk).find(|c| c.kind() == kind)
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

    fn strip_ts(s: &str) -> String {
        String::from_utf8(strip_ts_source(s.as_bytes()).unwrap_or_else(|| s.as_bytes().to_vec()))
            .unwrap()
    }

    #[test]
    fn ts_unwraps_arrow_and_drops_import() {
        let src = "import * as mvm from \"mvm-sdk\";\n\nexport const greet = mvm.app({\n  image: mvm.node_image({ node: \"22\" }),\n})((name: string): string => `hello ${name}`);\n";
        let out = strip_ts(src);
        assert!(
            !out.contains("mvm"),
            "no mvm reference should remain: {out}"
        );
        assert!(out.contains("export const greet = (name: string): string => `hello ${name}`"));
    }

    #[test]
    fn ts_unwraps_function_expression() {
        let src = "import * as mvm from \"mvm-sdk\";\nexport const greet = mvm.app({})(function (name) { return name; });\n";
        let out = strip_ts(src);
        assert!(!out.contains("mvm"));
        assert!(out.contains("export const greet = function (name) { return name; };"));
    }

    #[test]
    fn ts_handles_bare_named_import() {
        // `import { app } from "mvm-sdk"` → callee is bare `app(...)`.
        let src = "import { app } from \"mvm-sdk\";\nexport const f = app({})(() => 1);\n";
        let out = strip_ts(src);
        assert!(!out.contains("mvm-sdk"));
        assert!(out.contains("export const f = () => 1;"));
    }

    #[test]
    fn ts_leaves_unrelated_files_untouched() {
        // No mvm-sdk import and no app() site → nothing to do.
        assert!(
            strip_ts_source(b"export const x = 1;\nimport { z } from \"./other.js\";\n").is_none()
        );
    }

    #[test]
    fn ts_strip_is_idempotent() {
        let src =
            "import * as mvm from \"mvm-sdk\";\nexport const greet = mvm.app({})((n) => n);\n";
        let once = strip_ts_source(src.as_bytes()).expect("first pass rewrites");
        // Second pass over the already-stripped output finds nothing.
        assert!(strip_ts_source(&once).is_none());
    }
}
