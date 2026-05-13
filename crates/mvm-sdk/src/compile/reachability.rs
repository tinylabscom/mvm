//! Bundler reachability scoping for function-entrypoint workloads
//! (plan-0007 §Phase 2 + ADR-0014 "Static analysis posture").
//!
//! After the full source tree is bundled, this module walks the
//! reachable Python (and Node / TypeScript) module graph starting
//! from the workload's entry module. The result is a relative-path
//! set fed back into the bundler so unreachable files get pruned
//! from the staged artifact.
//!
//! ## Implementation
//!
//! All language analysis runs through `tree-sitter` parsers owned in
//! Rust — no shell-outs, no language-specific scripting runtimes,
//! no regex walkers. Per-language grammar crates
//! (`tree-sitter-python`, `tree-sitter-javascript`,
//! `tree-sitter-typescript`) provide real ASTs; we run
//! tree-sitter `Query`s to find import nodes and resolve them
//! against the bundled file tree.
//!
//! Adding a new language to reachability scoping is:
//!   1. Add the `tree-sitter-<lang>` grammar crate.
//!   2. Implement an `ImportExtractor` for it (the per-language
//!      query + node-text → module-spec mapping).
//!   3. Add a new `Language` variant.
//!
//! No Python / Node interpreter is required at host-build time.

use crate::compile::data::parse_lines;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use tree_sitter::{Language as TsLanguage, Parser, Query, QueryCursor, StreamingIterator};

/// File extensions of "language source" files that get pruned by
/// reachability scoping. Other extensions (configs, lockfiles, data
/// files, etc.) are passed through unchanged. Curated lists live in
/// `data/python_extensions.txt` and `data/node_extensions.txt`.
pub static PYTHON_EXTS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| parse_lines(include_str!("../../data/python_extensions.txt")));
pub static NODE_EXTS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| parse_lines(include_str!("../../data/node_extensions.txt")));

/// Which language's scoping to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Python,
    Node,
}

impl Language {
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Python => PYTHON_EXTS.as_slice(),
            Self::Node => NODE_EXTS.as_slice(),
        }
    }
}

#[derive(Debug)]
pub enum ReachabilityError {
    /// `src_root` doesn't exist or isn't a directory.
    SrcRootInvalid(PathBuf),
    /// `entry_module` was empty.
    EmptyEntry,
    /// I/O error reading a source file during the walk.
    Io(PathBuf, std::io::Error),
    /// Tree-sitter parser setup failure (grammar mismatch, query
    /// compile error). Compile-time bug; not a user-facing
    /// condition under normal use.
    ParserSetup(String),
}

impl std::fmt::Display for ReachabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SrcRootInvalid(p) => {
                write!(f, "reachability src_root not a directory: {}", p.display())
            }
            Self::EmptyEntry => write!(f, "reachability entry_module is required"),
            Self::Io(p, e) => write!(f, "reading {}: {}", p.display(), e),
            Self::ParserSetup(s) => write!(f, "tree-sitter setup: {s}"),
        }
    }
}

impl std::error::Error for ReachabilityError {}

/// Discover Python module files reachable from ``entry_module``,
/// rooted at ``src_root``. Returns paths POSIX-relative to
/// ``src_root``, including every `__init__.py` along the way for
/// any reached package.
pub fn discover_python_reachable(
    src_root: &Path,
    entry_module: &str,
    extra_imports: &[String],
) -> Result<HashSet<String>, ReachabilityError> {
    if !src_root.is_dir() {
        return Err(ReachabilityError::SrcRootInvalid(src_root.to_path_buf()));
    }
    if entry_module.is_empty() {
        return Err(ReachabilityError::EmptyEntry);
    }
    let extractor = PythonExtractor::new()?;
    walk_python(src_root, entry_module, extra_imports, &extractor)
}

/// Discover TS/JS source files reachable from ``entry_module``,
/// rooted at ``src_root``. Same return shape as
/// :func:`discover_python_reachable`. Static `import` and
/// `export-from` clauses are followed; bare-specifier imports
/// (npm packages) are skipped (out-of-tree).
pub fn discover_node_reachable(
    src_root: &Path,
    entry_module: &str,
    extra_imports: &[String],
) -> Result<HashSet<String>, ReachabilityError> {
    if !src_root.is_dir() {
        return Err(ReachabilityError::SrcRootInvalid(src_root.to_path_buf()));
    }
    if entry_module.is_empty() {
        return Err(ReachabilityError::EmptyEntry);
    }
    let extractor = NodeExtractor::new()?;
    walk_node(src_root, entry_module, extra_imports, &extractor)
}

// ---------- Python walker -----------------------------------------------

struct PythonExtractor {
    parser_lang: TsLanguage,
    query: Query,
}

impl PythonExtractor {
    fn new() -> Result<Self, ReachabilityError> {
        let lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
        // `import a.b.c` and `import a.b as x` → import_statement
        //   children: dotted_name (or aliased_import wrapping a
        //   dotted_name).
        // `from a.b import c, d` → import_from_statement; `module_name`
        //   child is a dotted_name (or relative_import for `.` / `..`).
        let src = r#"
(import_statement
  name: [
    (dotted_name) @import.module
    (aliased_import name: (dotted_name) @import.module)
  ])

(import_from_statement
  module_name: [
    (dotted_name) @from.module
    (relative_import) @from.relative
  ])
"#;
        let query = Query::new(&lang, src)
            .map_err(|e| ReachabilityError::ParserSetup(format!("python query: {e}")))?;
        Ok(Self {
            parser_lang: lang,
            query,
        })
    }
}

fn parse_with(lang: &TsLanguage, source: &[u8]) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser.set_language(lang).ok()?;
    parser.parse(source, None)
}

/// Compute a file's package context for resolving relative imports.
/// `src_root/pkg/sub/mod.py` → `("pkg", "sub")`.
/// `src_root/pkg/__init__.py` → `("pkg",)`.
fn package_for_file(src_root: &Path, file: &Path) -> Vec<String> {
    let rel = match file.strip_prefix(src_root) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    // Drop the trailing file segment (whether `__init__.py` or
    // a module file); leaves the package path for sibling lookup.
    if !parts.is_empty() {
        parts.pop();
    }
    parts
}

fn find_python_module_path(src_root: &Path, mod_dotted: &str) -> Option<PathBuf> {
    let parts: Vec<&str> = mod_dotted.split('.').collect();
    let mut pkg_init = src_root.to_path_buf();
    for part in &parts {
        pkg_init.push(part);
    }
    pkg_init.push("__init__.py");
    if pkg_init.is_file() {
        return Some(pkg_init);
    }
    let mut mod_file = src_root.to_path_buf();
    for part in &parts {
        mod_file.push(part);
    }
    mod_file.set_extension("py");
    if mod_file.is_file() {
        return Some(mod_file);
    }
    None
}

fn walk_python(
    src_root: &Path,
    entry_module: &str,
    extras: &[String],
    extractor: &PythonExtractor,
) -> Result<HashSet<String>, ReachabilityError> {
    let mut seen_modules: HashSet<String> = HashSet::new();
    let mut files: HashSet<PathBuf> = HashSet::new();
    let mut queue: Vec<String> = std::iter::once(entry_module.to_string())
        .chain(extras.iter().cloned())
        .collect();

    while let Some(module) = queue.pop() {
        if !seen_modules.insert(module.clone()) {
            continue;
        }
        let Some(path) = find_python_module_path(src_root, &module) else {
            continue;
        };
        files.insert(path.clone());

        // Pull in every `__init__.py` up the package chain — Python
        // needs them on disk to import the descendant.
        let parts: Vec<&str> = module.split('.').collect();
        for i in 1..parts.len() {
            let mut anc = src_root.to_path_buf();
            for p in &parts[..i] {
                anc.push(p);
            }
            anc.push("__init__.py");
            if anc.is_file() {
                let anc_dotted = parts[..i].join(".");
                if seen_modules.insert(anc_dotted) {
                    files.insert(anc);
                }
            }
        }

        let source = std::fs::read(&path).map_err(|e| ReachabilityError::Io(path.clone(), e))?;
        let tree = match parse_with(&extractor.parser_lang, &source) {
            Some(t) => t,
            None => continue, // unparseable; skip
        };
        let pkg = package_for_file(src_root, &path);
        let imports = python_imports_in(&tree, &source, &pkg, &extractor.query);
        for imp in imports {
            if !seen_modules.contains(&imp) {
                queue.push(imp);
            }
        }
    }

    Ok(files
        .into_iter()
        .filter_map(|p| {
            p.strip_prefix(src_root)
                .ok()
                .map(|r| r.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
        })
        .collect())
}

fn python_imports_in(
    tree: &tree_sitter::Tree,
    source: &[u8],
    current_pkg: &[String],
    query: &Query,
) -> Vec<String> {
    let mut cursor = QueryCursor::new();
    let mut out = Vec::new();
    let mut iter = cursor.matches(query, tree.root_node(), source);
    let cap_names = query.capture_names();
    while let Some(m) = iter.next() {
        for cap in m.captures {
            let name = cap_names[cap.index as usize];
            let text = match cap.node.utf8_text(source) {
                Ok(t) => t,
                Err(_) => continue,
            };
            match name {
                "import.module" | "from.module" => {
                    out.push(text.trim().to_string());
                }
                "from.relative" => {
                    // `relative_import` is the dot-prefixed form
                    // (`.`, `..mod`). We need to split into the
                    // leading dots and the trailing module path,
                    // then resolve against `current_pkg`.
                    let resolved = resolve_relative_import(text, current_pkg);
                    if let Some(r) = resolved {
                        out.push(r);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn resolve_relative_import(text: &str, current_pkg: &[String]) -> Option<String> {
    let dots = text.chars().take_while(|c| *c == '.').count();
    let tail = &text[dots..];
    if dots == 0 {
        return None; // Not actually relative.
    }
    if dots > current_pkg.len() {
        return None; // Reaches above the bundled tree.
    }
    let base_len = current_pkg.len() - (dots - 1);
    let base: Vec<&str> = current_pkg[..base_len].iter().map(String::as_str).collect();
    let tail_parts: Vec<&str> = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split('.').filter(|s| !s.is_empty()).collect()
    };
    let combined: Vec<&str> = base
        .iter()
        .copied()
        .chain(tail_parts.iter().copied())
        .collect();
    if combined.is_empty() {
        return None;
    }
    Some(combined.join("."))
}

// ---------- Node / TypeScript walker ------------------------------------

struct NodeExtractor {
    js_lang: TsLanguage,
    ts_lang: TsLanguage,
    tsx_lang: TsLanguage,
    js_query: Query,
    ts_query: Query,
    tsx_query: Query,
}

impl NodeExtractor {
    fn new() -> Result<Self, ReachabilityError> {
        let js_lang: TsLanguage = tree_sitter_javascript::LANGUAGE.into();
        let ts_lang: TsLanguage = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        let tsx_lang: TsLanguage = tree_sitter_typescript::LANGUAGE_TSX.into();
        // Node grammar: `import_statement`, `export_statement`
        // (re-export-from), and dynamic `import("...")` / `require("...")`
        // calls. Capture the string literal used as the source.
        let src = r#"
(import_statement source: (string) @import.source)
(export_statement source: (string) @import.source)
(call_expression
  function: [(import) (identifier) @fn]
  arguments: (arguments (string) @import.source)
  (#match? @fn "^(require|import)$"))
"#;
        let js_query = Query::new(&js_lang, src)
            .map_err(|e| ReachabilityError::ParserSetup(format!("js query: {e}")))?;
        let ts_query = Query::new(&ts_lang, src)
            .map_err(|e| ReachabilityError::ParserSetup(format!("ts query: {e}")))?;
        let tsx_query = Query::new(&tsx_lang, src)
            .map_err(|e| ReachabilityError::ParserSetup(format!("tsx query: {e}")))?;
        Ok(Self {
            js_lang,
            ts_lang,
            tsx_lang,
            js_query,
            ts_query,
            tsx_query,
        })
    }

    fn for_path<'a>(&'a self, path: &Path) -> (&'a TsLanguage, &'a Query) {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        match ext {
            "ts" | "mts" | "cts" => (&self.ts_lang, &self.ts_query),
            "tsx" | "jsx" => (&self.tsx_lang, &self.tsx_query),
            _ => (&self.js_lang, &self.js_query),
        }
    }
}

fn resolve_node_module_path(src_root: &Path, mod_dotted: &str) -> Option<PathBuf> {
    let parts: Vec<&str> = mod_dotted.split('.').collect();
    let mut stem = src_root.to_path_buf();
    for p in &parts {
        stem.push(p);
    }
    for ext in NODE_EXTS.iter() {
        let candidate = stem.with_extension(ext);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for ext in NODE_EXTS.iter() {
        let candidate = stem.join(format!("index.{ext}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_node_relative(from_file: &Path, spec: &str) -> Option<PathBuf> {
    let from_dir = from_file.parent()?;
    // Strip trailing `.js` / `.mjs` / `.cjs` — TS source often imports
    // `./foo.js` referring to `./foo.ts`.
    let bare = spec
        .strip_suffix(".js")
        .or_else(|| spec.strip_suffix(".mjs"))
        .or_else(|| spec.strip_suffix(".cjs"))
        .unwrap_or(spec);
    let mut base = from_dir.to_path_buf();
    base.push(bare);
    // First try as a file with each extension.
    if base.extension().is_some() && base.is_file() {
        return Some(base);
    }
    let parent = base.parent()?.to_path_buf();
    let stem = base.file_name()?.to_string_lossy().into_owned();
    for ext in NODE_EXTS.iter() {
        let candidate = parent.join(format!("{stem}.{ext}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // Fall back to <base>/index.<ext>.
    if base.is_dir() {
        for ext in NODE_EXTS.iter() {
            let candidate = base.join(format!("index.{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn walk_node(
    src_root: &Path,
    entry_module: &str,
    extras: &[String],
    extractor: &NodeExtractor,
) -> Result<HashSet<String>, ReachabilityError> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut queue: Vec<PathBuf> = Vec::new();
    if let Some(p) = resolve_node_module_path(src_root, entry_module) {
        queue.push(p);
    }
    for extra in extras {
        if let Some(p) = resolve_node_module_path(src_root, extra) {
            queue.push(p);
        }
    }

    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let source = std::fs::read(&file).map_err(|e| ReachabilityError::Io(file.clone(), e))?;
        let (lang, query) = extractor.for_path(&file);
        let tree = match parse_with(lang, &source) {
            Some(t) => t,
            None => continue,
        };
        for spec in node_imports_in(&tree, &source, query) {
            if !spec.starts_with('.') && !spec.starts_with('/') {
                continue; // bare specifier — out of tree
            }
            let resolved = if let Some(rest) = spec.strip_prefix('/') {
                let mut p = src_root.to_path_buf();
                p.push(rest);
                if p.is_file() { Some(p) } else { None }
            } else {
                resolve_node_relative(&file, &spec)
            };
            if let Some(p) = resolved
                && p.starts_with(src_root)
                && !seen.contains(&p)
            {
                queue.push(p);
            }
        }
    }

    Ok(seen
        .into_iter()
        .filter_map(|p| {
            p.strip_prefix(src_root)
                .ok()
                .map(|r| r.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
        })
        .collect())
}

fn node_imports_in(tree: &tree_sitter::Tree, source: &[u8], query: &Query) -> Vec<String> {
    let mut cursor = QueryCursor::new();
    let mut out = Vec::new();
    let mut iter = cursor.matches(query, tree.root_node(), source);
    let cap_names = query.capture_names();
    while let Some(m) = iter.next() {
        for cap in m.captures {
            if cap_names[cap.index as usize] != "import.source" {
                continue;
            }
            // Strip surrounding quote characters from the string node.
            let raw = match cap.node.utf8_text(source) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let stripped = raw
                .trim()
                .trim_start_matches(['"', '\'', '`'])
                .trim_end_matches(['"', '\'', '`']);
            if !stripped.is_empty() {
                out.push(stripped.to_string());
            }
        }
    }
    out
}

// ---------- Language detection ------------------------------------------

/// Detect which language's scoping to apply for a function workload
/// by probing the bundled tree for the entry-module file. Returns
/// `None` if no language-specific entry module file is found —
/// scoping is then skipped.
pub fn detect_language(bundle_dir: &Path, entry_module: &str) -> Option<Language> {
    let stem_parts: Vec<&str> = entry_module.split('.').collect();
    let stem: PathBuf = stem_parts.iter().collect();
    for ext in PYTHON_EXTS.iter() {
        let p = bundle_dir.join(&stem).with_extension(ext);
        if p.is_file() {
            return Some(Language::Python);
        }
        let init = bundle_dir.join(&stem).join(format!("__init__.{ext}"));
        if init.is_file() {
            return Some(Language::Python);
        }
    }
    for ext in NODE_EXTS.iter() {
        let p = bundle_dir.join(&stem).with_extension(ext);
        if p.is_file() {
            return Some(Language::Node);
        }
        let idx = bundle_dir.join(&stem).join(format!("index.{ext}"));
        if idx.is_file() {
            return Some(Language::Node);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    // ---------- Python ---------------------------------------------------

    #[test]
    fn python_walks_simple_imports() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(&root.join("app.py"), "from helpers import combine\n");
        write(
            &root.join("helpers.py"),
            "def combine(a, b): return a + b\n",
        );
        write(&root.join("unused.py"), "x = 1\n");
        let reachable = discover_python_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("app.py"));
        assert!(reachable.contains("helpers.py"));
        assert!(!reachable.contains("unused.py"));
    }

    #[test]
    fn python_walks_relative_imports() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(&root.join("pkg/__init__.py"), "");
        write(&root.join("pkg/app.py"), "from .util import helper\n");
        write(&root.join("pkg/util.py"), "def helper(): pass\n");
        let reachable = discover_python_reachable(root, "pkg.app", &[]).unwrap();
        assert!(reachable.contains("pkg/app.py"));
        assert!(reachable.contains("pkg/util.py"));
        assert!(reachable.contains("pkg/__init__.py"));
    }

    #[test]
    fn python_walks_deep_relative_imports() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(&root.join("pkg/__init__.py"), "");
        write(&root.join("pkg/sub/__init__.py"), "");
        write(&root.join("pkg/sub/app.py"), "from ..util import helper\n");
        write(&root.join("pkg/util.py"), "def helper(): pass\n");
        let reachable = discover_python_reachable(root, "pkg.sub.app", &[]).unwrap();
        assert!(reachable.contains("pkg/sub/app.py"));
        assert!(reachable.contains("pkg/util.py"));
        assert!(reachable.contains("pkg/__init__.py"));
        assert!(reachable.contains("pkg/sub/__init__.py"));
    }

    #[test]
    fn python_extra_imports_are_followed() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(&root.join("app.py"), "x = 1\n");
        write(&root.join("plugin.py"), "y = 2\n"); // not statically imported
        let reachable = discover_python_reachable(root, "app", &["plugin".to_string()]).unwrap();
        assert!(reachable.contains("plugin.py"));
    }

    // ---------- Node / TypeScript ---------------------------------------

    #[test]
    fn node_walks_static_imports() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.ts"),
            r#"import { combine } from "./helpers.ts";
export function add(a: number, b: number): number { return combine(a, b); }
"#,
        );
        write(
            &root.join("helpers.ts"),
            "export function combine(a: number, b: number): number { return a + b; }\n",
        );
        write(&root.join("unused.ts"), "export const x = 1;\n");
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("app.ts"));
        assert!(reachable.contains("helpers.ts"));
        assert!(!reachable.contains("unused.ts"));
    }

    #[test]
    fn node_resolves_dot_js_to_dot_ts_source() {
        // Common TS pattern: import paths use `.js` even though the
        // source is `.ts`. The regex-based walker handled this; the
        // tree-sitter walker must too.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.ts"),
            r#"import { combine } from "./helpers.js";
export const v = combine(1, 2);
"#,
        );
        write(
            &root.join("helpers.ts"),
            "export const combine = (a: number, b: number) => a + b;\n",
        );
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("helpers.ts"));
    }

    #[test]
    fn node_walks_dynamic_import_call_expression() {
        // The regex walker missed this — tree-sitter sees the
        // `import("...")` call expression as a normal AST node.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.ts"),
            r#"export async function load() {
  const mod = await import("./plugin.ts");
  return mod;
}
"#,
        );
        write(&root.join("plugin.ts"), "export const x = 42;\n");
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("plugin.ts"));
    }

    #[test]
    fn node_walks_require_call_expression() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.cjs"),
            r#"const helpers = require("./helpers.cjs");
module.exports = helpers;
"#,
        );
        write(&root.join("helpers.cjs"), "module.exports = { x: 1 };\n");
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("helpers.cjs"));
    }

    #[test]
    fn node_walks_export_from_re_exports() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.ts"),
            r#"export { combine } from "./helpers.ts";
"#,
        );
        write(
            &root.join("helpers.ts"),
            "export const combine = (a: number, b: number) => a + b;\n",
        );
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("helpers.ts"));
    }

    #[test]
    fn node_skips_bare_specifiers() {
        // npm packages aren't in the bundled tree.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.ts"),
            r#"import { something } from "external-pkg";
import { local } from "./local.ts";
"#,
        );
        write(&root.join("local.ts"), "export const local = 1;\n");
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("local.ts"));
        // No `external-pkg` resolution attempted; nothing in reachable
        // for it (and importantly no error).
    }

    #[test]
    fn node_handles_tsx_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            &root.join("app.tsx"),
            r#"import { Button } from "./button.tsx";
export const App = () => <Button />;
"#,
        );
        write(
            &root.join("button.tsx"),
            "export const Button = () => <button>x</button>;\n",
        );
        let reachable = discover_node_reachable(root, "app", &[]).unwrap();
        assert!(reachable.contains("app.tsx"));
        assert!(reachable.contains("button.tsx"));
    }
}
