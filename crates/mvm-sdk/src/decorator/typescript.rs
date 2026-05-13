//! TypeScript decorator parser (`mvm.app({...})(fn)` higher-order form).
//!
//! Mirror of [`super::python`]: walks a TypeScript source via
//! tree-sitter-typescript and extracts the literal kwargs from the
//! single `mvm.app({...})(fn)` site at module scope. Both parsers
//! produce a `BTreeMap<String, super::value::Value>` and hand it to
//! [`super::value::lower_to_workload`] for the IR.
//!
//! Surface for v1:
//!
//! ```ts
//! import * as mvm from "mvm-sdk";
//!
//! export const greet = mvm.app({
//!     image: mvm.python_image({ python: "3.12" }),
//!     resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
//! })((name: string): string => `hello ${name}`);
//! ```
//!
//! The const name (`greet` above) is the function name. The arrow
//! body is the function's code. Both named-export (`export const`) and
//! bare top-level (`const`) forms are accepted; the latter is rare
//! but useful for tests.
//!
//! Allowlist callees may be written either dotted (`mvm.app`) or
//! bare (`app`, requires `import { app, ... } from "mvm-sdk"`). The
//! parser normalizes to the dotted form before lookup so the
//! [`super::value::HELPER_ALLOWLIST`] is one source of truth.

use std::collections::BTreeMap;
use std::path::Path;

use mvm_ir::Workload;
use tree_sitter::{Node, Parser};

use super::value::{HELPER_ALLOWLIST, Value, lower_to_workload, non_literal_at};
use super::{DecoratorManifest, ParseError};

/// Parse a TypeScript source file containing exactly one
/// `mvm.app({...})(fn)` site at module scope and return a `Workload`
/// IR plus the extracted manifest. The `path` argument is used only
/// for diagnostics; it is not read again.
pub fn parse_typescript(
    source: &[u8],
    path: &Path,
) -> Result<(Workload, DecoratorManifest), ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .map_err(|e| ParseError::ParserSetup(format!("set TypeScript language: {e}")))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        ParseError::ParserSetup("tree-sitter-typescript returned no parse tree".to_string())
    })?;
    let root = tree.root_node();
    if root.has_error() {
        let (line, column, snippet) = first_error_location(root, source);
        return Err(ParseError::SyntaxError {
            path: path.to_path_buf(),
            line,
            column,
            snippet,
        });
    }

    let mut sites: Vec<DecorationSite> = Vec::new();
    collect_decoration_sites(root, source, &mut sites);
    match sites.len() {
        0 => {
            return Err(ParseError::NoDecoratedFunction {
                path: path.to_path_buf(),
            });
        }
        1 => {}
        _ => {
            return Err(ParseError::MultipleDecoratedFunctions {
                path: path.to_path_buf(),
                first_line: sites[0].line,
                second_line: sites[1].line,
            });
        }
    }
    let site = sites.into_iter().next().unwrap();

    let kwargs = extract_object_kwargs(site.options_object, source, path)?;
    let module = module_stem(path);
    let workload = lower_to_workload(
        kwargs,
        path,
        site.line,
        site.function_name.clone(),
        module.clone(),
        "node",
    )?;
    let manifest = DecoratorManifest {
        workload_id: workload.id.clone(),
        function_name: site.function_name,
        module,
        decorator_line: site.line,
    };
    Ok((workload, manifest))
}

// ---------- Decoration-site discovery ---------------------------------------

/// A located `mvm.app({...})(fn)` site at module scope.
#[derive(Debug, Clone)]
struct DecorationSite<'tree> {
    /// 1-based source line of the outer `app(...)` call.
    line: usize,
    /// The object literal passed to `mvm.app`. Tree-sitter-typescript
    /// represents it as an `object` node.
    options_object: Node<'tree>,
    /// Const name on the LHS of the declaration. For `export const
    /// greet = mvm.app({...})(...);` this is `"greet"`.
    function_name: String,
}

fn collect_decoration_sites<'tree>(
    root: Node<'tree>,
    source: &[u8],
    out: &mut Vec<DecorationSite<'tree>>,
) {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        // `export const X = ...` is an `export_statement` wrapping a
        // `lexical_declaration`. Plain `const X = ...` is just the
        // `lexical_declaration`. Both shapes are accepted.
        let lex = match child.kind() {
            "export_statement" => first_named_descendant_kind(child, "lexical_declaration"),
            "lexical_declaration" => Some(child),
            _ => None,
        };
        let Some(lex) = lex else {
            continue;
        };
        let mut inner = lex.walk();
        for decl in lex.named_children(&mut inner) {
            if decl.kind() != "variable_declarator" {
                continue;
            }
            // The declarator's name. Accept only plain identifiers; a
            // destructuring or tuple pattern isn't a valid decorator
            // target.
            let name_node = match decl.child_by_field_name("name") {
                Some(n) if n.kind() == "identifier" => n,
                _ => continue,
            };
            let function_name = match name_node.utf8_text(source) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let value = match decl.child_by_field_name("value") {
                Some(v) => v,
                None => continue,
            };
            if let Some(options) = match_app_higher_order(value, source) {
                out.push(DecorationSite {
                    line: value.start_position().row + 1,
                    options_object: options,
                    function_name,
                });
            }
        }
    }
}

/// Match `app({...})(fn)` (or `mvm.app({...})(fn)`). Returns the
/// `object` node from the outer call's argument when matched.
fn match_app_higher_order<'tree>(value: Node<'tree>, source: &[u8]) -> Option<Node<'tree>> {
    if value.kind() != "call_expression" {
        return None;
    }
    let inner_callee = value.child_by_field_name("function")?;
    // `inner_callee` must itself be a call_expression whose function
    // is `app` or `mvm.app`.
    if inner_callee.kind() != "call_expression" {
        return None;
    }
    let app_callee = inner_callee.child_by_field_name("function")?;
    let callee_text = app_callee.utf8_text(source).ok()?;
    if callee_text != "app" && callee_text != "mvm.app" {
        return None;
    }
    // The inner `app(...)` call must take one argument: an object literal.
    let args = inner_callee.child_by_field_name("arguments")?;
    let mut args_walk = args.walk();
    let object = args
        .named_children(&mut args_walk)
        .find(|c| c.kind() == "object")?;
    Some(object)
}

fn first_named_descendant_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut walker = node.walk();
    node.named_children(&mut walker).find(|c| c.kind() == kind)
}

fn module_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app")
        .to_string()
}

// ---------- Object-literal kwarg extraction ---------------------------------

/// Walk an `object` literal and return its `{ key: value, ... }`
/// pairs as a kwarg map. Shorthand properties (`{x}` ≡ `{x: x}`) are
/// rejected — they reference a name binding, which is non-literal.
fn extract_object_kwargs(
    object: Node,
    source: &[u8],
    path: &Path,
) -> Result<BTreeMap<String, Value>, ParseError> {
    let mut kwargs = BTreeMap::new();
    let mut walker = object.walk();
    for prop in object.named_children(&mut walker) {
        match prop.kind() {
            "pair" => {
                let key_node = prop
                    .child_by_field_name("key")
                    .ok_or_else(|| non_literal_node(prop, path, "(pair)", "pair missing key"))?;
                let value_node = prop
                    .child_by_field_name("value")
                    .ok_or_else(|| non_literal_node(prop, path, "(pair)", "pair missing value"))?;
                let key = property_key_text(key_node, source).ok_or_else(|| {
                    non_literal_node(
                        key_node,
                        path,
                        "(pair-key)",
                        "object property key must be a string or identifier literal",
                    )
                })?;
                let value = eval_value(value_node, source, path, &key)?;
                kwargs.insert(key, value);
            }
            "shorthand_property_identifier" | "shorthand_property_identifier_pattern" => {
                return Err(non_literal_node(
                    prop,
                    path,
                    "(shorthand)",
                    "shorthand property reference (e.g. `{ image }`) is a name binding — the static parser only accepts literal `key: value` pairs",
                ));
            }
            "comment" => continue,
            other => {
                return Err(non_literal_node(
                    prop,
                    path,
                    "(object)",
                    &format!("unsupported object property kind: {other}"),
                ));
            }
        }
    }
    Ok(kwargs)
}

/// Extract the string text of an `object` property key. Accepts
/// `identifier`, `property_identifier`, and `string` keys.
fn property_key_text(key: Node, source: &[u8]) -> Option<String> {
    match key.kind() {
        "property_identifier" | "identifier" => key.utf8_text(source).ok().map(str::to_string),
        "string" => {
            let mut walker = key.walk();
            for child in key.named_children(&mut walker) {
                if child.kind() == "string_fragment"
                    && let Ok(t) = child.utf8_text(source)
                {
                    return Some(t.to_string());
                }
            }
            // Fall back to stripping the surrounding quotes.
            key.utf8_text(source)
                .ok()
                .map(|raw| raw.trim_matches(['"', '\'', '`']).to_string())
        }
        _ => None,
    }
}

// ---------- Value evaluation -------------------------------------------------

fn eval_value(node: Node, source: &[u8], path: &Path, kwarg: &str) -> Result<Value, ParseError> {
    match node.kind() {
        "string" => Ok(Value::Str(string_literal_text(node, source))),
        "template_string" => {
            // Accept only template strings with no interpolations
            // (just `template_chars`); rejection is a non-literal
            // (variable interpolation).
            let mut walker = node.walk();
            let mut out = String::new();
            for child in node.named_children(&mut walker) {
                match child.kind() {
                    "string_fragment" => {
                        if let Ok(t) = child.utf8_text(source) {
                            out.push_str(t);
                        }
                    }
                    "template_substitution" => {
                        return Err(non_literal_node(
                            node,
                            path,
                            kwarg,
                            "template string interpolation (${...}) is not a literal — inline the value",
                        ));
                    }
                    _ => {}
                }
            }
            Ok(Value::Str(out))
        }
        "number" => {
            let raw = node
                .utf8_text(source)
                .map_err(|_| non_literal_node(node, path, kwarg, "number not valid UTF-8"))?;
            if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                raw.parse::<f64>()
                    .map(Value::Float)
                    .map_err(|e| non_literal_node(node, path, kwarg, &format!("float parse: {e}")))
            } else {
                raw.replace('_', "")
                    .parse::<i64>()
                    .map(Value::Int)
                    .map_err(|e| {
                        non_literal_node(node, path, kwarg, &format!("integer parse: {e}"))
                    })
            }
        }
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        "null" | "undefined" => Ok(Value::None),
        "array" => {
            let mut items = Vec::new();
            let mut walker = node.walk();
            for child in node.named_children(&mut walker) {
                if child.kind() == "comment" {
                    continue;
                }
                items.push(eval_value(child, source, path, kwarg)?);
            }
            Ok(Value::List(items))
        }
        "object" => {
            let map = extract_object_kwargs(node, source, path)?;
            Ok(Value::Dict(map))
        }
        "call_expression" => eval_helper_call(node, source, path, kwarg),
        "parenthesized_expression" => {
            let mut walker = node.walk();
            for c in node.named_children(&mut walker) {
                if c.kind() != "comment" {
                    return eval_value(c, source, path, kwarg);
                }
            }
            Err(non_literal_node(node, path, kwarg, "empty parens"))
        }
        "unary_expression" => {
            // Accept `-1`, `-1.0` as literals (negation of a number).
            let op = node
                .child_by_field_name("operator")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            let inner = node
                .child_by_field_name("argument")
                .ok_or_else(|| non_literal_node(node, path, kwarg, "unary op without argument"))?;
            let v = eval_value(inner, source, path, kwarg)?;
            match (op, v) {
                ("-", Value::Int(n)) => Ok(Value::Int(-n)),
                ("-", Value::Float(n)) => Ok(Value::Float(-n)),
                ("+", v @ Value::Int(_)) | ("+", v @ Value::Float(_)) => Ok(v),
                (op, v) => Err(non_literal_node(
                    node,
                    path,
                    kwarg,
                    &format!("unsupported unary {op:?} on {v:?}"),
                )),
            }
        }
        other => Err(non_literal_node(
            node,
            path,
            kwarg,
            &format!("unsupported expression kind {other}"),
        )),
    }
}

fn string_literal_text(node: Node, source: &[u8]) -> String {
    let mut walker = node.walk();
    let mut out = String::new();
    for child in node.named_children(&mut walker) {
        if child.kind() == "string_fragment"
            && let Ok(t) = child.utf8_text(source)
        {
            out.push_str(t);
        }
    }
    if !out.is_empty() {
        return out;
    }
    // Fall back: strip the surrounding quotes off the raw text.
    if let Ok(raw) = node.utf8_text(source) {
        return raw.trim_matches(['"', '\'', '`']).to_string();
    }
    String::new()
}

fn eval_helper_call(
    call: Node,
    source: &[u8],
    path: &Path,
    kwarg: &str,
) -> Result<Value, ParseError> {
    let function = call
        .child_by_field_name("function")
        .ok_or_else(|| non_literal_node(call, path, kwarg, "call expression has no function"))?;
    let callee_text = function
        .utf8_text(source)
        .map_err(|_| non_literal_node(call, path, kwarg, "function name not valid UTF-8"))?;
    let normalized = normalize_callee(callee_text);
    if !HELPER_ALLOWLIST.contains(&normalized.as_str()) {
        return Err(ParseError::UnknownHelper {
            path: path.to_path_buf(),
            line: call.start_position().row + 1,
            column: call.start_position().column + 1,
            helper: normalized,
        });
    }

    let args = call
        .child_by_field_name("arguments")
        .ok_or_else(|| non_literal_node(call, path, kwarg, "helper call missing argument list"))?;

    // TypeScript helper calls take one `object` literal positionally
    // (e.g. `mvm.python_image({ python: "3.12" })`). The object's
    // keys become the helper's kwargs. Multiple positional args are
    // also accepted (e.g. `mvm.secret("api-key")`); they're stored as
    // `_pos_N` keys the lowering layer doesn't see (it pops from the
    // positional vec).
    let mut kwargs = BTreeMap::new();
    let mut positional = Vec::new();
    let mut walker = args.walk();
    for arg in args.named_children(&mut walker) {
        if arg.kind() == "comment" {
            continue;
        }
        if arg.kind() == "object" {
            for (k, v) in extract_object_kwargs(arg, source, path)? {
                kwargs.insert(k, v);
            }
        } else {
            positional.push(eval_value(arg, source, path, kwarg)?);
        }
    }
    Ok(Value::Helper {
        name: normalized,
        kwargs,
        positional,
    })
}

/// Normalize a TS callee identifier to the dotted form used by
/// [`HELPER_ALLOWLIST`]. Both `python_image` (bare named import) and
/// `mvm.python_image` (namespace import) normalize to
/// `"mvm.python_image"`. Sub-namespaces (e.g. `addons.database`) keep
/// the dot.
fn normalize_callee(raw: &str) -> String {
    if raw.starts_with("mvm.") || raw.starts_with("mvm[") {
        return raw.to_string();
    }
    // Bare identifier (`python_image`, `resources`, `app`,
    // `addons.database`, ...): prefix with `mvm.` if it matches an
    // allowlist tail. Otherwise return as-is and the caller will
    // surface UnknownHelper with a clear diagnostic.
    for entry in HELPER_ALLOWLIST {
        let suffix = entry.trim_start_matches("mvm.");
        if suffix == raw {
            return entry.to_string();
        }
    }
    // Special-case `app`: not in the allowlist (it's the decorator
    // itself, handled separately), but bare-import users will name it
    // `app` from the SDK. We don't normalize it; the caller decides.
    raw.to_string()
}

// ---------- Diagnostics ------------------------------------------------------

fn non_literal_node(node: Node, path: &Path, kwarg: &str, detail: &str) -> ParseError {
    let pos = node.start_position();
    non_literal_at(path, pos.row + 1, pos.column + 1, kwarg, detail)
}

fn first_error_location(root: Node, source: &[u8]) -> (usize, usize, String) {
    fn walk(node: Node, source: &[u8]) -> Option<(usize, usize, String)> {
        if node.is_error() || node.is_missing() {
            let snippet = node
                .utf8_text(source)
                .unwrap_or("")
                .chars()
                .take(40)
                .collect::<String>();
            return Some((
                node.start_position().row + 1,
                node.start_position().column + 1,
                snippet,
            ));
        }
        let mut cursor = node.walk();
        for c in node.children(&mut cursor) {
            if let Some(found) = walk(c, source) {
                return Some(found);
            }
        }
        None
    }
    walk(root, source).unwrap_or((1, 1, String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_ir::{Entrypoint, EnvValue, HookCmd, Image, NetworkMode, SecretMount};
    use std::path::PathBuf;

    fn parse_str(src: &str) -> Result<(Workload, DecoratorManifest), ParseError> {
        parse_typescript(src.as_bytes(), &PathBuf::from("app.ts"))
    }

    #[test]
    fn extracts_minimal_decorator() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
})((name: string): string => `hello ${name}`);
"#;
        let (w, m) = parse_str(src).expect("parse");
        assert_eq!(w.id, "greet");
        assert_eq!(m.function_name, "greet");
        assert_eq!(m.module, "app");
        assert!(
            matches!(&w.apps[0].image, Image::NixPackages { packages } if packages == &vec!["python312".to_string()])
        );
        match &w.apps[0].entrypoints[0] {
            Entrypoint::Function {
                language,
                module,
                function,
                primary,
                ..
            } => {
                assert_eq!(language, "node");
                assert_eq!(module, "app");
                assert_eq!(function, "greet");
                assert!(*primary);
            }
            other => panic!("expected Function entrypoint, got {other:?}"),
        }
    }

    #[test]
    fn name_kwarg_overrides_const_name() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  name: "hello-app",
  image: mvm.python_image({ python: "3.12" }),
})((name: string) => name);
"#;
        let (w, _) = parse_str(src).expect("parse");
        assert_eq!(w.id, "hello-app");
        assert_eq!(w.apps[0].name, "hello-app");
    }

    #[test]
    fn bare_named_imports_normalize_to_mvm_dot() {
        // `import { app, python_image } from "mvm-sdk"` form. The
        // parser normalizes `python_image` to `mvm.python_image`
        // before allowlist lookup so users don't have to namespace.
        let src = r#"
import { app, python_image } from "mvm-sdk";

export const greet = app({
  image: python_image({ python: "3.12" }),
})(() => "x");
"#;
        let (w, _) = parse_str(src).expect("parse");
        assert!(matches!(&w.apps[0].image, Image::NixPackages { .. }));
    }

    #[test]
    fn missing_image_rejected() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({})((name: string) => name);
"#;
        let err = parse_str(src).unwrap_err();
        assert!(
            matches!(&err, ParseError::MissingRequiredKwarg { kwarg, .. } if *kwarg == "image"),
            "got: {err}"
        );
    }

    #[test]
    fn no_decorator_rejected() {
        let src = r#"
export const greet = (name: string) => name;
"#;
        let err = parse_str(src).unwrap_err();
        assert!(matches!(err, ParseError::NoDecoratedFunction { .. }));
    }

    #[test]
    fn two_decorators_rejected() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({ image: mvm.python_image({ python: "3.12" }) })(() => "a");
export const farewell = mvm.app({ image: mvm.python_image({ python: "3.12" }) })(() => "b");
"#;
        let err = parse_str(src).unwrap_err();
        assert!(matches!(err, ParseError::MultipleDecoratedFunctions { .. }));
    }

    #[test]
    fn computed_kwarg_rejected() {
        // A name binding in kwarg-value position is non-literal.
        let src = r#"
import * as mvm from "mvm-sdk";

const IMAGE = mvm.python_image({ python: "3.12" });

export const greet = mvm.app({ image: IMAGE })(() => "x");
"#;
        let err = parse_str(src).unwrap_err();
        assert!(
            matches!(&err, ParseError::NonLiteralKwarg { kwarg, .. } if kwarg == "image"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_helper_rejected() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  resources: mvm.totally_invented({ cpu: 1 }),
})(() => "x");
"#;
        let err = parse_str(src).unwrap_err();
        assert!(
            matches!(&err, ParseError::UnknownHelper { helper, .. } if helper == "mvm.totally_invented"),
            "got: {err}"
        );
    }

    #[test]
    fn resources_helper_lowers() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  resources: mvm.resources({ cpu: 2, memory_mb: 512, rootfs_size_mb: 1024 }),
})(() => "x");
"#;
        let (w, _) = parse_str(src).expect("parse");
        let r = &w.apps[0].resources;
        assert_eq!(r.cpu_cores, 2);
        assert_eq!(r.memory_mb, 512);
        assert_eq!(r.rootfs_size_mb, 1024);
    }

    #[test]
    fn env_with_literal_and_secret() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  env: {
    "MODEL_PATH": "/data/model.pt",
    "API_KEY": mvm.secret("api-key"),
  },
})(() => "x");
"#;
        let (w, _) = parse_str(src).expect("parse");
        let env = &w.apps[0].env;
        match env.get("MODEL_PATH") {
            Some(EnvValue::Literal { value }) => assert_eq!(value, "/data/model.pt"),
            other => panic!("expected literal MODEL_PATH, got {other:?}"),
        }
        match env.get("API_KEY") {
            Some(EnvValue::SecretRef { reference }) => {
                assert_eq!(reference.name, "api-key");
                match &reference.mount {
                    SecretMount::Env { var } => assert_eq!(var, "api-key"),
                    other => panic!("expected Env mount, got {other:?}"),
                }
            }
            other => panic!("expected secret API_KEY, got {other:?}"),
        }
    }

    #[test]
    fn hooks_accept_string_and_array() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  before_start: "export FOO=1",
  before_stop: ["python", "-m", "shutdown"],
})(() => "x");
"#;
        let (w, _) = parse_str(src).expect("parse");
        let h = &w.apps[0].hooks;
        assert_eq!(h.before_start.len(), 1);
        match &h.before_start[0] {
            HookCmd::Shell { line } => assert_eq!(line, "export FOO=1"),
            other => panic!("expected Shell, got {other:?}"),
        }
        assert_eq!(h.before_stop.len(), 1);
        match &h.before_stop[0] {
            HookCmd::Argv { argv } => assert_eq!(argv[0], "python"),
            other => panic!("expected Argv, got {other:?}"),
        }
    }

    #[test]
    fn network_helper_lowers() {
        let src = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  network: mvm.network({
    mode: "bridge",
    ports: [{ guest: 8080, host: 8080, proto: "tcp" }],
  }),
})(() => "x");
"#;
        let (w, _) = parse_str(src).expect("parse");
        let n = w.apps[0].network.as_ref().expect("network present");
        assert!(matches!(n.mode, NetworkMode::Bridge));
        assert_eq!(n.ports.len(), 1);
        assert_eq!(n.ports[0].guest, 8080);
    }

    #[test]
    fn template_with_interpolation_rejected() {
        let src = r#"
import * as mvm from "mvm-sdk";

const v = "3.12";
export const greet = mvm.app({
  image: mvm.python_image({ python: `${v}` }),
})(() => "x");
"#;
        let err = parse_str(src).unwrap_err();
        assert!(
            matches!(&err, ParseError::NonLiteralKwarg { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn shorthand_property_rejected() {
        let src = r#"
import * as mvm from "mvm-sdk";

const image = mvm.python_image({ python: "3.12" });
export const greet = mvm.app({ image })(() => "x");
"#;
        let err = parse_str(src).unwrap_err();
        assert!(
            matches!(&err, ParseError::NonLiteralKwarg { .. }),
            "got: {err}"
        );
    }
}
