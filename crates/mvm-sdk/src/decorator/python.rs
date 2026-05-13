//! Python decorator parser (`@mvm.app(...)`).
//!
//! Walks a Python source file via tree-sitter and extracts the
//! literal kwargs from the single `@mvm.app(...)` decorator at module
//! scope. Calls into the `mvm.*` helper allowlist are evaluated by
//! the parser itself (it knows their semantics); anything else in
//! literal position is rejected with [`super::ParseError::NonLiteralKwarg`].
//!
//! The parser never imports the user's source or runs any Python — it
//! is a pure read of the AST. The decorated function becomes the
//! microVM's primary entrypoint; the bundled source tree (everything
//! under the script's directory, scoped by the existing reachability
//! walker in [`crate::compile::reachability`]) ships as
//! `app.source = LocalPath`.

use std::collections::BTreeMap;
use std::path::Path;

use mvm_ir::Workload;
use tree_sitter::{Node, Parser};

use super::value::{HELPER_ALLOWLIST, Value, lower_to_workload, non_literal_at};
use super::{DecoratorManifest, ParseError};

/// Local wrapper so the per-language eval functions can pass a
/// tree-sitter [`Node`] (which carries line/column) without each
/// caller computing the position. Delegates to
/// [`super::value::non_literal_at`] for the actual error build.
fn non_literal(node: Node, path: &Path, kwarg: &str, detail: &str) -> ParseError {
    let pos = node.start_position();
    non_literal_at(path, pos.row + 1, pos.column + 1, kwarg, detail)
}

/// Parse a Python source file containing exactly one `@mvm.app(...)`
/// decorator at module scope and return a `Workload` IR plus the
/// extracted manifest. The `path` argument is used only for
/// diagnostics; it is not read again.
pub fn parse_python(
    source: &[u8],
    path: &Path,
) -> Result<(Workload, DecoratorManifest), ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|e| ParseError::ParserSetup(format!("set Python language: {e}")))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        ParseError::ParserSetup("tree-sitter-python returned no parse tree".to_string())
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

    let mut decorated: Vec<(Node, Node)> = Vec::new();
    collect_decorated_functions(root, source, &mut decorated);
    match decorated.len() {
        0 => {
            return Err(ParseError::NoDecoratedFunction {
                path: path.to_path_buf(),
            });
        }
        1 => {}
        _ => {
            return Err(ParseError::MultipleDecoratedFunctions {
                path: path.to_path_buf(),
                first_line: decorated[0].0.start_position().row + 1,
                second_line: decorated[1].0.start_position().row + 1,
            });
        }
    }
    let (decorator_node, fn_node) = decorated[0];

    let function_name =
        function_name_of(fn_node, source).ok_or_else(|| ParseError::DecoratorTarget {
            path: path.to_path_buf(),
            line: fn_node.start_position().row + 1,
            target_kind: format!("{:?} (couldn't read function name)", fn_node.kind()),
        })?;

    let module = module_stem(path);
    let decorator_line = decorator_node.start_position().row + 1;

    let kwargs = extract_call_kwargs(decorator_node, source, path, "mvm.app")?;

    let workload = lower_to_workload(
        kwargs,
        path,
        decorator_line,
        function_name.clone(),
        module.clone(),
        "python",
    )?;
    let manifest = DecoratorManifest {
        workload_id: workload.id.clone(),
        function_name,
        module,
        decorator_line,
    };
    Ok((workload, manifest))
}

// ---------- Decorated-function discovery ------------------------------------

/// Walk top-level statements and collect `(decorator_node, function_def_node)`
/// pairs where the decorator's callable is exactly `mvm.app`.
fn collect_decorated_functions<'tree>(
    root: Node<'tree>,
    source: &[u8],
    out: &mut Vec<(Node<'tree>, Node<'tree>)>,
) {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == "decorated_definition" {
            let mut inner = child.walk();
            let decorators: Vec<Node> = child
                .named_children(&mut inner)
                .filter(|c| c.kind() == "decorator")
                .collect();
            let definition = child.child_by_field_name("definition").or_else(|| {
                let mut last = None;
                let mut inner2 = child.walk();
                for c in child.named_children(&mut inner2) {
                    if c.kind() == "function_definition" {
                        last = Some(c);
                    }
                }
                last
            });
            if let Some(def) = definition
                && def.kind() == "function_definition"
            {
                for dec in decorators {
                    if decorator_is_mvm_app(dec, source) {
                        out.push((dec, def));
                        break;
                    }
                }
            }
        }
    }
}

/// True iff `decorator_node` is the form `@mvm.app(...)` (with parens;
/// the parser rejects bare `@mvm.app` so an unparameterized decoration
/// is a syntax error rather than a silent fallthrough).
fn decorator_is_mvm_app(decorator: Node, source: &[u8]) -> bool {
    // Tree-sitter-python represents `@mvm.app(...)` as a `decorator`
    // node whose only named child is a `call` node, whose `function`
    // is an `attribute` (`mvm.app`). The bare `@mvm.app` form (no
    // call) has an `attribute` directly under `decorator`; we treat
    // that as not-our-decorator so the user sees a clear error if
    // they forget the parens.
    let mut walker = decorator.walk();
    for c in decorator.named_children(&mut walker) {
        if c.kind() == "call"
            && let Some(function) = c.child_by_field_name("function")
            && let Ok(text) = function.utf8_text(source)
            && text == "mvm.app"
        {
            return true;
        }
    }
    false
}

fn function_name_of(def: Node, source: &[u8]) -> Option<String> {
    def.child_by_field_name("name")
        .and_then(|n| n.utf8_text(source).ok())
        .map(str::to_string)
}

/// Derive the entrypoint module name from a script path: `app.py` →
/// `"app"`. Multi-segment directory paths are flattened to the leaf
/// stem; users with a package layout (`pkg/app.py`) point at the
/// script and the bundler ships the rest of the package alongside.
fn module_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app")
        .to_string()
}

// ---------- Call-kwarg extraction -------------------------------------------

/// Walk a `call`-node's `arguments` and return its keyword arguments.
/// Positional args are accepted but recorded as `_pos_0`, `_pos_1`,
/// etc. — the caller decides whether they're valid in context.
fn extract_call_kwargs(
    call_or_decorator: Node,
    source: &[u8],
    path: &Path,
    call_label: &str,
) -> Result<BTreeMap<String, Value>, ParseError> {
    let call = find_call_node(call_or_decorator).ok_or_else(|| ParseError::DecoratorTarget {
        path: path.to_path_buf(),
        line: call_or_decorator.start_position().row + 1,
        target_kind: format!("`{call_label}` requires a call form like `@mvm.app(...)`"),
    })?;
    let args =
        call.child_by_field_name("arguments")
            .ok_or_else(|| ParseError::NonLiteralKwarg {
                path: path.to_path_buf(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                kwarg: call_label.to_string(),
                detail: "missing argument list".to_string(),
            })?;

    let mut kwargs = BTreeMap::new();
    let mut pos_idx = 0usize;
    let mut walker = args.walk();
    for arg in args.named_children(&mut walker) {
        match arg.kind() {
            "keyword_argument" => {
                let name_node =
                    arg.child_by_field_name("name")
                        .ok_or_else(|| ParseError::NonLiteralKwarg {
                            path: path.to_path_buf(),
                            line: arg.start_position().row + 1,
                            column: arg.start_position().column + 1,
                            kwarg: call_label.to_string(),
                            detail: "keyword argument has no name".to_string(),
                        })?;
                let name = name_node
                    .utf8_text(source)
                    .map_err(|_| ParseError::NonLiteralKwarg {
                        path: path.to_path_buf(),
                        line: arg.start_position().row + 1,
                        column: arg.start_position().column + 1,
                        kwarg: call_label.to_string(),
                        detail: "keyword name is not valid UTF-8".to_string(),
                    })?
                    .to_string();
                let value_node = arg.child_by_field_name("value").ok_or_else(|| {
                    ParseError::NonLiteralKwarg {
                        path: path.to_path_buf(),
                        line: arg.start_position().row + 1,
                        column: arg.start_position().column + 1,
                        kwarg: name.clone(),
                        detail: "keyword argument has no value".to_string(),
                    }
                })?;
                let value = eval_value(value_node, source, path, &name)?;
                kwargs.insert(name, value);
            }
            // Skip comment nodes; tree-sitter-python emits them as
            // named children of `argument_list` when they sit between
            // arguments.
            "comment" => continue,
            _ => {
                let value = eval_value(arg, source, path, &format!("(positional #{pos_idx})"))?;
                kwargs.insert(format!("_pos_{pos_idx}"), value);
                pos_idx += 1;
            }
        }
    }
    Ok(kwargs)
}

fn find_call_node(start: Node) -> Option<Node> {
    if start.kind() == "call" {
        return Some(start);
    }
    let mut walker = start.walk();
    start
        .named_children(&mut walker)
        .find(|c| c.kind() == "call")
}

// ---------- Value evaluation -------------------------------------------------

fn eval_value(node: Node, source: &[u8], path: &Path, kwarg: &str) -> Result<Value, ParseError> {
    match node.kind() {
        "string" => {
            // tree-sitter-python `string` includes the surrounding
            // quotes and may contain `string_start`, `string_content`,
            // and `string_end` children. The text without quotes is
            // the concatenation of every `string_content` child.
            let mut out = String::new();
            let mut walker = node.walk();
            for child in node.named_children(&mut walker) {
                if child.kind() == "string_content"
                    && let Ok(t) = child.utf8_text(source)
                {
                    out.push_str(t);
                }
            }
            if out.is_empty()
                && let Ok(raw) = node.utf8_text(source)
            {
                let trimmed = raw
                    .trim_start_matches(['b', 'B', 'r', 'R', 'f', 'F'])
                    .trim_start_matches(['"', '\''])
                    .trim_end_matches(['"', '\'']);
                out.push_str(trimmed);
            }
            Ok(Value::Str(out))
        }
        "integer" => {
            let raw = node
                .utf8_text(source)
                .map_err(|_| non_literal(node, path, kwarg, "integer not valid UTF-8"))?;
            let parsed = raw
                .replace('_', "")
                .parse::<i64>()
                .map_err(|e| non_literal(node, path, kwarg, &format!("integer parse: {e}")))?;
            Ok(Value::Int(parsed))
        }
        "float" => {
            let raw = node
                .utf8_text(source)
                .map_err(|_| non_literal(node, path, kwarg, "float not valid UTF-8"))?;
            let parsed = raw
                .replace('_', "")
                .parse::<f64>()
                .map_err(|e| non_literal(node, path, kwarg, &format!("float parse: {e}")))?;
            Ok(Value::Float(parsed))
        }
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        "none" => Ok(Value::None),
        "list" => {
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
        "dictionary" => {
            let mut map = BTreeMap::new();
            let mut walker = node.walk();
            for child in node.named_children(&mut walker) {
                if child.kind() != "pair" {
                    continue;
                }
                let key_node = child
                    .child_by_field_name("key")
                    .ok_or_else(|| non_literal(child, path, kwarg, "dict pair has no key"))?;
                let value_node = child
                    .child_by_field_name("value")
                    .ok_or_else(|| non_literal(child, path, kwarg, "dict pair has no value"))?;
                let key = match eval_value(key_node, source, path, kwarg)? {
                    Value::Str(s) => s,
                    other => {
                        return Err(non_literal(
                            key_node,
                            path,
                            kwarg,
                            &format!("dict key must be a string literal, got {other:?}"),
                        ));
                    }
                };
                let value = eval_value(value_node, source, path, kwarg)?;
                map.insert(key, value);
            }
            Ok(Value::Dict(map))
        }
        "call" => eval_helper_call(node, source, path, kwarg),
        "parenthesized_expression" => {
            // Pass through `(value)`. tree-sitter-python wraps these
            // around any expression in parens.
            let mut walker = node.walk();
            for c in node.named_children(&mut walker) {
                if c.kind() != "comment" {
                    return eval_value(c, source, path, kwarg);
                }
            }
            Err(non_literal(node, path, kwarg, "empty parens"))
        }
        "unary_operator" => {
            // Accept `-1`, `-1.0` as integer/float literals (Python
            // grammar emits these as unary_operator nodes).
            let op = node
                .child_by_field_name("operator")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            let inner = node
                .child_by_field_name("argument")
                .ok_or_else(|| non_literal(node, path, kwarg, "unary op without argument"))?;
            let v = eval_value(inner, source, path, kwarg)?;
            match (op, v) {
                ("-", Value::Int(n)) => Ok(Value::Int(-n)),
                ("-", Value::Float(n)) => Ok(Value::Float(-n)),
                ("+", v @ Value::Int(_)) | ("+", v @ Value::Float(_)) => Ok(v),
                (op, v) => Err(non_literal(
                    node,
                    path,
                    kwarg,
                    &format!("unsupported unary {op:?} on {v:?}"),
                )),
            }
        }
        other => Err(non_literal(
            node,
            path,
            kwarg,
            &format!("unsupported expression kind {other}"),
        )),
    }
}

fn eval_helper_call(
    call: Node,
    source: &[u8],
    path: &Path,
    kwarg: &str,
) -> Result<Value, ParseError> {
    let function = call
        .child_by_field_name("function")
        .ok_or_else(|| non_literal(call, path, kwarg, "call expression has no function"))?;
    let name = function
        .utf8_text(source)
        .map_err(|_| non_literal(call, path, kwarg, "function name not valid UTF-8"))?
        .to_string();
    if !HELPER_ALLOWLIST.contains(&name.as_str()) {
        return Err(ParseError::UnknownHelper {
            path: path.to_path_buf(),
            line: call.start_position().row + 1,
            column: call.start_position().column + 1,
            helper: name,
        });
    }

    let args = call
        .child_by_field_name("arguments")
        .ok_or_else(|| non_literal(call, path, kwarg, "helper call missing argument list"))?;

    let mut kwargs = BTreeMap::new();
    let mut positional = Vec::new();
    let mut walker = args.walk();
    for arg in args.named_children(&mut walker) {
        if arg.kind() == "comment" {
            continue;
        }
        if arg.kind() == "keyword_argument" {
            let key_node = arg
                .child_by_field_name("name")
                .ok_or_else(|| non_literal(arg, path, kwarg, "helper kwarg has no name"))?;
            let value_node = arg
                .child_by_field_name("value")
                .ok_or_else(|| non_literal(arg, path, kwarg, "helper kwarg has no value"))?;
            let key = key_node
                .utf8_text(source)
                .map_err(|_| non_literal(arg, path, kwarg, "helper kwarg name not valid UTF-8"))?
                .to_string();
            kwargs.insert(key.clone(), eval_value(value_node, source, path, &key)?);
        } else {
            positional.push(eval_value(arg, source, path, kwarg)?);
        }
    }
    Ok(Value::Helper {
        name,
        kwargs,
        positional,
    })
}

// ---------- Diagnostics helpers ----------------------------------------------

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
        parse_python(src.as_bytes(), &PathBuf::from("app.py"))
    }

    #[test]
    fn extracts_minimal_decorator() {
        let src = r#"
import mvm

@mvm.app(image=mvm.python_image(python="3.12"))
def greet(name: str) -> str:
    return f"hello {name}"
"#;
        let (w, m) = parse_str(src).expect("parse");
        assert_eq!(w.id, "greet");
        assert_eq!(w.apps.len(), 1);
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
                assert_eq!(language, "python");
                assert_eq!(module, "app");
                assert_eq!(function, "greet");
                assert!(*primary);
            }
            other => panic!("expected Function entrypoint, got {other:?}"),
        }
    }

    #[test]
    fn name_kwarg_overrides_function_name() {
        let src = r#"
import mvm

@mvm.app(name="hello-app", image=mvm.python_image(python="3.12"))
def greet(name: str) -> str:
    return name
"#;
        let (w, m) = parse_str(src).expect("parse");
        assert_eq!(w.id, "hello-app");
        assert_eq!(w.apps[0].name, "hello-app");
        assert_eq!(m.workload_id, "hello-app");
    }

    #[test]
    fn missing_image_rejected() {
        let src = r#"
import mvm

@mvm.app()
def greet():
    pass
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
def greet():
    pass
"#;
        let err = parse_str(src).unwrap_err();
        assert!(matches!(err, ParseError::NoDecoratedFunction { .. }));
    }

    #[test]
    fn two_decorators_rejected() {
        let src = r#"
import mvm

@mvm.app(image=mvm.python_image(python="3.12"))
def greet(): pass

@mvm.app(image=mvm.python_image(python="3.12"))
def farewell(): pass
"#;
        let err = parse_str(src).unwrap_err();
        assert!(matches!(err, ParseError::MultipleDecoratedFunctions { .. }));
    }

    #[test]
    fn computed_kwarg_rejected() {
        // A name binding in kwarg-value position is the canonical
        // example of a non-literal value the static parser must
        // refuse. The user has to inline the value or use a
        // documented helper.
        let src = r#"
import mvm

IMAGE = mvm.python_image(python="3.12")

@mvm.app(image=IMAGE)
def greet(): pass
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
import mvm

@mvm.app(image=mvm.python_image(python="3.12"), resources=mvm.totally_invented(cpu=1))
def greet(): pass
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
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=2, memory_mb=512, rootfs_size_mb=1024),
)
def greet(): pass
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
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    env={
        "MODEL_PATH": "/data/model.pt",
        "API_KEY": mvm.secret("api-key"),
    },
)
def greet(): pass
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
    fn hooks_accept_string_list_and_helper() {
        let src = r#"
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    before_start="export FOO=1",
    after_start=mvm.hook(["curl", "-fsS", "http://127.0.0.1/h"]),
    before_stop=["python", "-m", "shutdown"],
)
def greet(): pass
"#;
        let (w, _) = parse_str(src).expect("parse");
        let h = &w.apps[0].hooks;
        assert_eq!(h.before_start.len(), 1);
        match &h.before_start[0] {
            HookCmd::Shell { line } => assert_eq!(line, "export FOO=1"),
            other => panic!("expected Shell, got {other:?}"),
        }
        assert_eq!(h.after_start.len(), 1);
        match &h.after_start[0] {
            HookCmd::Argv { argv } => assert_eq!(argv.len(), 3),
            other => panic!("expected Argv, got {other:?}"),
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
import mvm

@mvm.app(
    image=mvm.python_image(python="3.12"),
    network=mvm.network(
        mode="bridge",
        ports=[{"guest": 8080, "host": 8080, "proto": "tcp"}],
    ),
)
def greet(): pass
"#;
        let (w, _) = parse_str(src).expect("parse");
        let n = w.apps[0].network.as_ref().expect("network present");
        assert!(matches!(n.mode, NetworkMode::Bridge));
        assert_eq!(n.ports.len(), 1);
        assert_eq!(n.ports[0].guest, 8080);
    }

    #[test]
    fn decorator_on_class_rejected_via_no_decorated_function() {
        // We only collect decorators on `function_definition` nodes, so
        // a class-decorated app is reported as "no @mvm.app function".
        let src = r#"
import mvm

@mvm.app(image=mvm.python_image(python="3.12"))
class Greeter:
    pass
"#;
        let err = parse_str(src).unwrap_err();
        assert!(matches!(err, ParseError::NoDecoratedFunction { .. }));
    }

    #[test]
    fn bare_decorator_without_parens_rejected() {
        // `@mvm.app` (no call) is intentionally treated as not-our-decorator.
        // Surface: "no @mvm.app function" → user adds `(...)`.
        let src = r#"
import mvm

@mvm.app
def greet(): pass
"#;
        let err = parse_str(src).unwrap_err();
        assert!(matches!(err, ParseError::NoDecoratedFunction { .. }));
    }

    #[test]
    fn syntax_error_is_reported_with_line() {
        let src = "@mvm.app(\ndef oops\n";
        let err = parse_str(src).unwrap_err();
        match err {
            ParseError::SyntaxError { line, .. } => assert!(line >= 1),
            other => panic!("expected SyntaxError, got {other:?}"),
        }
    }
}
