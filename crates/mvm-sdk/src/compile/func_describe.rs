//! Function-presence + arity introspection from source via tree-sitter.
//!
//! ADR-0015 Phase 2: extend the tree-sitter substrate from
//! reachability (PR #25) to a second job — confirming that the
//! `module:function` pair declared in `Entrypoint::Function` actually
//! resolves to a top-level function in the bundled source. Catches
//! typos at `mvmforge compile` time rather than runtime.
//!
//! Per the ADR's layering: this module handles **syntax-level**
//! introspection only. Semantic checks (type-hint → JSON Schema
//! generation, generic resolution) stay in the per-SDK runtime layer.
//! What we capture per function:
//!
//!   - whether the named function is declared at module scope
//!   - whether it's `async`
//!   - parameter count: `min` (required) and `max` (`usize::MAX` if
//!     the function takes `*args`/`**kwargs`/rest params)
//!
//! Today this is used only for presence checks. Phase 2.5 will gate
//! arity against an `args_schema`'s expected shape; the signature is
//! already captured for that purpose.

use std::path::Path;

use tree_sitter::{Language as TsLanguage, Parser, Query, QueryCursor, StreamingIterator};

use crate::compile::reachability::Language;

/// What we know about a top-level function after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
    pub name: String,
    pub is_async: bool,
    /// Minimum number of positional parameters a caller must supply.
    pub min_params: usize,
    /// Maximum positional parameters. `usize::MAX` if the function
    /// takes `*args`/`**kwargs`/rest — i.e. is variadic.
    pub max_params: usize,
    /// Names of declared positional / keyword parameters, in source
    /// order. Excludes `*args`, `**kwargs`, JS rest patterns, and
    /// PEP-570 separators. Phase 2.5: cross-checked against
    /// `args_schema.required[]` to surface mismatches at compile time.
    pub param_names: Vec<String>,
    /// True if the function accepts arbitrary named arguments —
    /// Python `**kwargs` (specifically the `dictionary_splat_pattern`).
    /// When true, any `args_schema.required` name is acceptable
    /// because the caller can hand the wrapper a dict and let it
    /// flow through.
    pub accepts_kwargs: bool,
}

/// Errors from the describe step.
#[derive(Debug)]
pub enum FuncDescribeError {
    /// I/O error reading the source file at `path`.
    Io(std::path::PathBuf, std::io::Error),
    /// Tree-sitter parser setup failure (grammar mismatch, query
    /// compile error). Compile-time bug, not user-visible.
    ParserSetup(String),
    /// Source file parsed but the named function is not defined at
    /// module scope.
    FunctionNotFound {
        path: std::path::PathBuf,
        function: String,
    },
}

impl std::fmt::Display for FuncDescribeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "reading {}: {}", p.display(), e),
            Self::ParserSetup(s) => write!(f, "tree-sitter setup: {s}"),
            Self::FunctionNotFound { path, function } => {
                write!(
                    f,
                    "function {function:?} not found at module scope in {}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for FuncDescribeError {}

/// Resolve `entry_module` against `bundle_dir` to a single source file
/// path. Mirrors the language detection in `reachability::detect_language`,
/// but returns the path so callers can read its source.
pub fn resolve_module_path(
    bundle_dir: &Path,
    language: Language,
    entry_module: &str,
) -> Option<std::path::PathBuf> {
    let stem_parts: Vec<&str> = entry_module.split('.').collect();
    let stem: std::path::PathBuf = stem_parts.iter().collect();
    let exts: &[&str] = language.extensions();
    for ext in exts {
        let p = bundle_dir.join(&stem).with_extension(ext);
        if p.is_file() {
            return Some(p);
        }
    }
    if matches!(language, Language::Python) {
        for ext in exts {
            let p = bundle_dir.join(&stem).join(format!("__init__.{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    } else {
        for ext in exts {
            let p = bundle_dir.join(&stem).join(format!("index.{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Describe a top-level function in `source` (raw bytes of a Python
/// or Node/TS module). Returns `Some(FunctionSignature)` if the
/// named function is defined at module scope; `None` otherwise.
pub fn describe_function(
    language: Language,
    source: &[u8],
    function_name: &str,
) -> Result<Option<FunctionSignature>, FuncDescribeError> {
    match language {
        Language::Python => describe_python(source, function_name),
        Language::Node => describe_node(source, function_name),
    }
}

// ---------- Python -------------------------------------------------------

fn describe_python(
    source: &[u8],
    function_name: &str,
) -> Result<Option<FunctionSignature>, FuncDescribeError> {
    let lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
    // Top-level `def` and `async def` (also when wrapped in a
    // decorator). Tree-sitter-python represents both via
    // `function_definition`; we anchor to direct children of the
    // `module` root in code, since query anchoring across decorators
    // gets verbose.
    let src = r#"
(function_definition
  name: (identifier) @name
  parameters: (parameters) @params) @fn
"#;
    let query = Query::new(&lang, src)
        .map_err(|e| FuncDescribeError::ParserSetup(format!("python query: {e}")))?;
    let tree = parse(&lang, source).ok_or_else(|| {
        FuncDescribeError::ParserSetup("python parse returned no tree".to_string())
    })?;

    let mut cursor = QueryCursor::new();
    let cap_names = query.capture_names();
    let mut iter = cursor.matches(&query, tree.root_node(), source);
    while let Some(m) = iter.next() {
        // Capture indices: 0 = "name", 1 = "params", 2 = "fn".
        let mut name_text: Option<&str> = None;
        let mut params_node: Option<tree_sitter::Node> = None;
        let mut fn_node: Option<tree_sitter::Node> = None;
        for cap in m.captures {
            let cap_name = cap_names[cap.index as usize];
            match cap_name {
                "name" => {
                    name_text = cap.node.utf8_text(source).ok();
                }
                "params" => {
                    params_node = Some(cap.node);
                }
                "fn" => {
                    fn_node = Some(cap.node);
                }
                _ => {}
            }
        }
        let (Some(name), Some(params), Some(fn_n)) = (name_text, params_node, fn_node) else {
            continue;
        };
        if name != function_name {
            continue;
        }
        if !is_python_module_scope(fn_n) {
            // Nested fn or method on a class — not importable as `module.function`.
            continue;
        }
        let info = python_param_info(params, source);
        let is_async = python_is_async(fn_n, source);
        return Ok(Some(FunctionSignature {
            name: name.to_string(),
            is_async,
            min_params: info.min_params,
            max_params: info.max_params,
            param_names: info.names,
            accepts_kwargs: info.accepts_kwargs,
        }));
    }
    Ok(None)
}

/// Walk up from `fn_node` past any `decorated_definition` wrappers and
/// confirm the parent is the `module` root. Filters out nested fns and
/// methods.
fn is_python_module_scope(fn_node: tree_sitter::Node) -> bool {
    let mut node = fn_node;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "decorated_definition" => {
                node = parent;
                continue;
            }
            "module" => return true,
            _ => return false,
        }
    }
    false
}

fn python_is_async(fn_node: tree_sitter::Node, source: &[u8]) -> bool {
    // The leading keyword is the first child token; `async def`
    // produces an `async` child before the `def` keyword.
    let mut cursor = fn_node.walk();
    for child in fn_node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        if child.utf8_text(source).map(str::trim) == Ok("async") {
            return true;
        }
        // First non-named child is typically `def` / `async`.
        break;
    }
    false
}

struct PythonParamInfo {
    min_params: usize,
    max_params: usize,
    names: Vec<String>,
    accepts_kwargs: bool,
}

fn python_param_info(params: tree_sitter::Node, source: &[u8]) -> PythonParamInfo {
    let mut min_p = 0usize;
    let mut max_p = 0usize;
    let mut variadic = false;
    let mut accepts_kwargs = false;
    let mut names: Vec<String> = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        match child.kind() {
            "identifier" => {
                min_p += 1;
                max_p += 1;
                if let Ok(name) = child.utf8_text(source) {
                    names.push(name.to_string());
                }
            }
            "typed_parameter" => {
                min_p += 1;
                max_p += 1;
                if let Some(ident) = first_named_descendant(child, "identifier")
                    && let Ok(name) = ident.utf8_text(source)
                {
                    names.push(name.to_string());
                }
            }
            "default_parameter" | "typed_default_parameter" => {
                max_p += 1;
                if let Some(ident) = first_named_descendant(child, "identifier")
                    && let Ok(name) = ident.utf8_text(source)
                {
                    names.push(name.to_string());
                }
            }
            "list_splat_pattern" => {
                // `*args` — variadic positional, not named-kwarg-bag.
                variadic = true;
            }
            "dictionary_splat_pattern" => {
                // `**kwargs` — accepts arbitrary named arguments.
                variadic = true;
                accepts_kwargs = true;
            }
            "keyword_separator" | "positional_separator" => {
                // PEP 570 / PEP 3102 markers — not parameters.
            }
            _ => {
                // `tuple_pattern`, `list_pattern`, etc. (rare). Treat
                // as a single parameter; can't extract a name.
                min_p += 1;
                max_p += 1;
            }
        }
    }
    if variadic {
        max_p = usize::MAX;
    }
    PythonParamInfo {
        min_params: min_p,
        max_params: max_p,
        names,
        accepts_kwargs,
    }
}

/// Find the first named descendant of `node` whose kind matches `kind`,
/// using a simple recursive walk. Returns the node itself if it matches.
fn first_named_descendant<'a>(
    node: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_named_descendant(child, kind) {
            return Some(found);
        }
    }
    None
}

// ---------- Node / TypeScript --------------------------------------------

fn describe_node(
    source: &[u8],
    function_name: &str,
) -> Result<Option<FunctionSignature>, FuncDescribeError> {
    // Try TS, TSX, JS in that order. We don't know the file extension
    // at this layer, but TS/TSX grammars are supersets of JS for our
    // queries, so trying TS first works for `.ts`/`.tsx`/`.mts`/`.cts`
    // and JS fallback covers `.js`/`.mjs`/`.cjs`.
    let langs: &[TsLanguage] = &[
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        tree_sitter_typescript::LANGUAGE_TSX.into(),
        tree_sitter_javascript::LANGUAGE.into(),
    ];
    let query_src = r#"
; function add(a, b) { ... }   /  async function add(a, b) { ... }
(function_declaration
  name: (identifier) @name
  parameters: (formal_parameters) @params) @fn

; export function add(a, b) { ... } / export async function ...
(export_statement
  declaration: (function_declaration
    name: (identifier) @name
    parameters: (formal_parameters) @params) @fn)

; const add = (a, b) => ...   /  const add = function (a, b) { ... }
(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: [
      (arrow_function parameters: (formal_parameters) @params) @fn
      (function_expression parameters: (formal_parameters) @params) @fn
    ]))

; export const add = (a, b) => ...
(export_statement
  declaration: (lexical_declaration
    (variable_declarator
      name: (identifier) @name
      value: [
        (arrow_function parameters: (formal_parameters) @params) @fn
        (function_expression parameters: (formal_parameters) @params) @fn
      ])))

; const add = func({...})(function (a, b) { ... })
;   — ADR-0014 / Plan-0010 curried `func({...})(fn)` authoring shape,
;     the canonical TS form. Variable's value is a `call_expression`
;     whose argument list contains the callable; the variable's name
;     carries the entrypoint name.
(lexical_declaration
  (variable_declarator
    name: (identifier) @name
    value: (call_expression
      arguments: (arguments
        [
          (arrow_function parameters: (formal_parameters) @params) @fn
          (function_expression parameters: (formal_parameters) @params) @fn
        ]))))

; export const add = func({...})(function (a, b) { ... })
(export_statement
  declaration: (lexical_declaration
    (variable_declarator
      name: (identifier) @name
      value: (call_expression
        arguments: (arguments
          [
            (arrow_function parameters: (formal_parameters) @params) @fn
            (function_expression parameters: (formal_parameters) @params) @fn
          ])))))
"#;
    for lang in langs {
        let query = match Query::new(lang, query_src) {
            Ok(q) => q,
            Err(e) => return Err(FuncDescribeError::ParserSetup(format!("node query: {e}"))),
        };
        let Some(tree) = parse(lang, source) else {
            continue;
        };
        let mut cursor = QueryCursor::new();
        let cap_names = query.capture_names();
        let mut iter = cursor.matches(&query, tree.root_node(), source);
        while let Some(m) = iter.next() {
            let mut name_text: Option<&str> = None;
            let mut params_node: Option<tree_sitter::Node> = None;
            let mut fn_node: Option<tree_sitter::Node> = None;
            for cap in m.captures {
                match cap_names[cap.index as usize] {
                    "name" => name_text = cap.node.utf8_text(source).ok(),
                    "params" => params_node = Some(cap.node),
                    "fn" => fn_node = Some(cap.node),
                    _ => {}
                }
            }
            let (Some(name), Some(params), Some(fn_n)) = (name_text, params_node, fn_node) else {
                continue;
            };
            if name != function_name {
                continue;
            }
            // Top-level only — accept module-scope or wrapped in an
            // `export_statement` whose parent is the program root.
            if !is_node_module_scope(fn_n) {
                continue;
            }
            let info = node_param_info(params, source);
            let is_async = node_is_async(fn_n, source);
            return Ok(Some(FunctionSignature {
                name: name.to_string(),
                is_async,
                min_params: info.min_params,
                max_params: info.max_params,
                param_names: info.names,
                accepts_kwargs: info.accepts_kwargs,
            }));
        }
    }
    Ok(None)
}

fn is_node_module_scope(fn_node: tree_sitter::Node) -> bool {
    // Walk up: fn_node may be inside an export_statement, a
    // lexical_declaration / variable_declarator, or transparently
    // wrapped by a call expression (the curried `func({...})(fn)`
    // form from ADR-0014 / Plan-0010). Climb until we hit the
    // program root or a container that disqualifies it (function
    // body, class body, etc.).
    let mut node = fn_node;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "program" => return true,
            "export_statement"
            | "lexical_declaration"
            | "variable_declarator"
            | "variable_declaration" => {
                node = parent;
                continue;
            }
            // The curried `func({...})(fn)` shape: the inner callable
            // sits inside `arguments` of a `call_expression`, which
            // itself is the variable's value. Both are transparent
            // for module-scope purposes.
            "arguments" | "call_expression" => {
                node = parent;
                continue;
            }
            // Anything else (function bodies, classes, blocks) means
            // we're not at module scope.
            _ => return false,
        }
    }
    false
}

fn node_is_async(fn_node: tree_sitter::Node, source: &[u8]) -> bool {
    // For function_declaration / arrow_function the `async` keyword
    // is a non-named child. For arrow functions it can also be a
    // child of `function`-like nodes. Easiest: check if any of the
    // first few non-named children is the literal "async".
    let mut cursor = fn_node.walk();
    for child in fn_node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        if child.utf8_text(source).map(str::trim) == Ok("async") {
            return true;
        }
    }
    false
}

struct NodeParamInfo {
    min_params: usize,
    max_params: usize,
    names: Vec<String>,
    accepts_kwargs: bool,
}

fn node_param_info(params: tree_sitter::Node, source: &[u8]) -> NodeParamInfo {
    let mut min_p = 0usize;
    let mut max_p = 0usize;
    let mut variadic = false;
    let mut accepts_kwargs = false;
    let mut names: Vec<String> = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        // Rest params surface as `required_parameter` whose `pattern`
        // child is a `rest_pattern`. Detect rest by scanning
        // descendants before bucketing the param.
        if param_is_rest(child) {
            variadic = true;
            // Treat rest as kwargs-accepting in JS/TS — when the
            // wrapper at runtime spreads kwargs, the rest param can
            // absorb them via positional ordering.
            accepts_kwargs = true;
            continue;
        }
        match child.kind() {
            "identifier" => {
                min_p += 1;
                max_p += 1;
                if let Ok(name) = child.utf8_text(source) {
                    names.push(name.to_string());
                }
            }
            "required_parameter" => {
                min_p += 1;
                max_p += 1;
                if let Some(ident) = first_named_descendant(child, "identifier")
                    && let Ok(name) = ident.utf8_text(source)
                {
                    names.push(name.to_string());
                }
            }
            "assignment_pattern" | "optional_parameter" => {
                max_p += 1;
                if let Some(ident) = first_named_descendant(child, "identifier")
                    && let Ok(name) = ident.utf8_text(source)
                {
                    names.push(name.to_string());
                }
            }
            "rest_pattern" | "rest_parameter" => {
                variadic = true;
                accepts_kwargs = true;
            }
            "object_pattern" | "array_pattern" => {
                // Destructured single parameter — count as one slot;
                // we can't sensibly extract a "name" here. The wrapper
                // dispatches positionally so this is fine.
                min_p += 1;
                max_p += 1;
            }
            _ => {
                min_p += 1;
                max_p += 1;
            }
        }
    }
    if variadic {
        max_p = usize::MAX;
    }
    NodeParamInfo {
        min_params: min_p,
        max_params: max_p,
        names,
        accepts_kwargs,
    }
}

/// Return true if `param` (a child of `formal_parameters`) is a rest
/// parameter — covers grammar variations where rest is the param node
/// itself, or wrapped in a `required_parameter` whose pattern child
/// is a `rest_pattern`.
fn param_is_rest(param: tree_sitter::Node) -> bool {
    if matches!(param.kind(), "rest_pattern" | "rest_parameter") {
        return true;
    }
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        if matches!(child.kind(), "rest_pattern" | "rest_parameter") {
            return true;
        }
    }
    false
}

// ---------- shared --------------------------------------------------------

fn parse(lang: &TsLanguage, source: &[u8]) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser.set_language(lang).ok()?;
    parser.parse(source, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py(src: &str, name: &str) -> Option<FunctionSignature> {
        describe_function(Language::Python, src.as_bytes(), name).unwrap()
    }

    fn ts(src: &str, name: &str) -> Option<FunctionSignature> {
        describe_function(Language::Node, src.as_bytes(), name).unwrap()
    }

    // ---------- Python ---------------------------------------------------

    #[test]
    fn python_finds_simple_def() {
        let sig = py("def add(a, b): return a + b\n", "add").unwrap();
        assert_eq!(sig.name, "add");
        assert!(!sig.is_async);
        assert_eq!(sig.min_params, 2);
        assert_eq!(sig.max_params, 2);
    }

    #[test]
    fn python_finds_async_def() {
        let sig = py("async def fetch(url): return url\n", "fetch").unwrap();
        assert!(sig.is_async);
        assert_eq!(sig.min_params, 1);
    }

    #[test]
    fn python_distinguishes_required_vs_optional_params() {
        let sig = py("def f(a, b, c=3, d=4): return None\n", "f").unwrap();
        assert_eq!(sig.min_params, 2);
        assert_eq!(sig.max_params, 4);
    }

    #[test]
    fn python_detects_variadic_via_args() {
        let sig = py("def f(a, *args): pass\n", "f").unwrap();
        assert_eq!(sig.min_params, 1);
        assert_eq!(sig.max_params, usize::MAX);
    }

    #[test]
    fn python_detects_variadic_via_kwargs() {
        let sig = py("def f(a, **kwargs): pass\n", "f").unwrap();
        assert_eq!(sig.min_params, 1);
        assert_eq!(sig.max_params, usize::MAX);
    }

    #[test]
    fn python_handles_typed_params() {
        let sig = py("def add(a: int, b: int) -> int: return a + b\n", "add").unwrap();
        assert_eq!(sig.min_params, 2);
        assert_eq!(sig.max_params, 2);
    }

    #[test]
    fn python_skips_methods_inside_classes() {
        let src = "class C:\n    def add(self, a, b): return a + b\n";
        assert!(py(src, "add").is_none());
    }

    #[test]
    fn python_skips_nested_functions() {
        let src = "def outer():\n    def add(a, b): return a + b\n    return add\n";
        // "outer" should match; "add" should not.
        assert!(py(src, "outer").is_some());
        assert!(py(src, "add").is_none());
    }

    #[test]
    fn python_finds_decorated_function() {
        let src = "import functools\n@functools.lru_cache\ndef cached(a): return a\n";
        let sig = py(src, "cached").unwrap();
        assert_eq!(sig.name, "cached");
        assert_eq!(sig.min_params, 1);
    }

    #[test]
    fn python_returns_none_for_typo() {
        let src = "def add(a, b): return a + b\n";
        assert!(py(src, "ad").is_none());
        assert!(py(src, "Add").is_none()); // case-sensitive
    }

    // ---------- Node / TypeScript ---------------------------------------

    #[test]
    fn ts_finds_function_declaration() {
        let src = "function add(a: number, b: number): number { return a + b; }\n";
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.name, "add");
        assert!(!sig.is_async);
        assert_eq!(sig.min_params, 2);
    }

    #[test]
    fn ts_finds_exported_function() {
        let src = "export function add(a: number, b: number) { return a + b; }\n";
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.name, "add");
        assert_eq!(sig.min_params, 2);
    }

    #[test]
    fn ts_finds_async_function() {
        let src = "async function fetchUrl(u: string) { return u; }\n";
        let sig = ts(src, "fetchUrl").unwrap();
        assert!(sig.is_async);
    }

    #[test]
    fn ts_finds_const_arrow_function() {
        let src = "export const add = (a: number, b: number) => a + b;\n";
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.min_params, 2);
    }

    #[test]
    fn ts_finds_curried_func_form() {
        // ADR-0014 / Plan-0010 canonical authoring shape:
        // `func({...})(fn)` wraps the user's callable. The
        // entrypoint name lives on the variable; the params live
        // on the inner function.
        let src = r#"
import { func } from "mvm-sdk";
export const add = func({ name: "x" })(
  function add(a: number, b: number): number { return a + b; }
);
"#;
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.min_params, 2);
        assert_eq!(sig.max_params, 2);
    }

    #[test]
    fn ts_finds_curried_func_form_arrow() {
        let src = r#"
import { func } from "mvm-sdk";
export const greet = func({ name: "g" })((name: string) => `hi ${name}`);
"#;
        let sig = ts(src, "greet").unwrap();
        assert_eq!(sig.min_params, 1);
    }

    #[test]
    fn ts_detects_optional_param() {
        let src = "export function f(a: number, b?: number) { return a; }\n";
        let sig = ts(src, "f").unwrap();
        assert_eq!(sig.min_params, 1);
        assert_eq!(sig.max_params, 2);
    }

    #[test]
    fn ts_detects_rest_param() {
        let src = "export function f(a: number, ...rest: number[]) { return a; }\n";
        let sig = ts(src, "f").unwrap();
        assert_eq!(sig.min_params, 1);
        assert_eq!(sig.max_params, usize::MAX);
    }

    #[test]
    fn ts_returns_none_for_method_on_class() {
        let src = "export class C {\n  add(a: number, b: number) { return a + b; }\n}\n";
        assert!(ts(src, "add").is_none());
    }

    #[test]
    fn ts_returns_none_for_typo() {
        let src = "export function add(a: number, b: number) { return a + b; }\n";
        assert!(ts(src, "ad").is_none());
    }

    #[test]
    fn js_finds_module_exports_function() {
        let src = "function add(a, b) { return a + b; }\nmodule.exports = { add };\n";
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.min_params, 2);
    }

    // ---------- Phase 2.5: parameter-name extraction --------------------

    #[test]
    fn python_extracts_param_names_simple() {
        let sig = py("def add(first, second): return first + second\n", "add").unwrap();
        assert_eq!(sig.param_names, vec!["first", "second"]);
        assert!(!sig.accepts_kwargs);
    }

    #[test]
    fn python_extracts_param_names_typed_and_default() {
        let src = "def f(a: int, b: str = \"hi\", c: int = 0) -> None: pass\n";
        let sig = py(src, "f").unwrap();
        assert_eq!(sig.param_names, vec!["a", "b", "c"]);
    }

    #[test]
    fn python_args_does_not_set_accepts_kwargs() {
        // *args is variadic positional, NOT a kwargs sink.
        let sig = py("def f(a, *args): pass\n", "f").unwrap();
        assert_eq!(sig.param_names, vec!["a"]);
        assert!(!sig.accepts_kwargs);
        assert_eq!(sig.max_params, usize::MAX);
    }

    #[test]
    fn python_kwargs_sets_accepts_kwargs() {
        let sig = py("def f(a, **opts): pass\n", "f").unwrap();
        assert_eq!(sig.param_names, vec!["a"]);
        assert!(sig.accepts_kwargs);
    }

    #[test]
    fn ts_extracts_param_names_simple() {
        let src = "export function add(first: number, second: number) { return first + second; }\n";
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.param_names, vec!["first", "second"]);
    }

    #[test]
    fn ts_extracts_param_names_arrow() {
        let src = "export const add = (first: number, second: number) => first + second;\n";
        let sig = ts(src, "add").unwrap();
        assert_eq!(sig.param_names, vec!["first", "second"]);
    }

    #[test]
    fn ts_rest_sets_accepts_kwargs() {
        let src = "export function f(a: number, ...rest: number[]) { return a; }\n";
        let sig = ts(src, "f").unwrap();
        assert_eq!(sig.param_names, vec!["a"]);
        assert!(sig.accepts_kwargs);
    }
}
