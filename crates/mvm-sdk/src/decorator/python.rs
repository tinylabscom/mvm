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

use mvm_ir::{
    App, Dependencies, Entrypoint, EnvValue, Format, HookCmd, Hooks, Image, Mount, Network,
    NetworkEgress, NetworkMode, PortForward, PortProto, Resources, SecretMount, SecretRef, Source,
    Workload,
};
use tree_sitter::{Node, Parser};

use super::{DecoratorManifest, ParseError};

/// Closed allowlist of `mvm.*` helper calls accepted in decorator
/// kwarg-value position. Anything outside this set is rejected with
/// [`ParseError::UnknownHelper`].
///
/// Documented surface: `mvm.python_image`, `mvm.node_image`,
/// `mvm.nix_packages`, `mvm.resources`, `mvm.network`, `mvm.secret`,
/// `mvm.literal`, `mvm.hook`, `mvm.addons.database`,
/// `mvm.addons.service`. The list lives in code so adding a helper
/// is a reviewed code change rather than a config update.
pub const HELPER_ALLOWLIST: &[&str] = &[
    "mvm.python_image",
    "mvm.node_image",
    "mvm.nix_packages",
    "mvm.resources",
    "mvm.network",
    "mvm.secret",
    "mvm.literal",
    "mvm.hook",
    "mvm.addons.database",
    "mvm.addons.service",
];

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

/// The parsed shape of a kwarg's value. Lowered to IR types by
/// [`lower_to_workload`].
///
/// `Bool`/`Float` are accepted at the parser level so future helpers
/// can take them (e.g. a `mvm.resources(disabled=True)` toggle, or
/// fractional cpu shares); v1 lowering doesn't consume them but the
/// shape is reserved so adding a helper that does isn't a parser
/// change. dead_code allow covers that future-proofing window.
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    None,
    List(Vec<Value>),
    Dict(BTreeMap<String, Value>),
    /// A call into the `mvm.*` allowlist. The pair carries the
    /// dotted callable name (e.g. `mvm.python_image`) and its
    /// already-extracted kwargs.
    Helper {
        name: String,
        kwargs: BTreeMap<String, Value>,
        positional: Vec<Value>,
    },
}

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

fn non_literal(node: Node, path: &Path, kwarg: &str, detail: &str) -> ParseError {
    ParseError::NonLiteralKwarg {
        path: path.to_path_buf(),
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
        kwarg: kwarg.to_string(),
        detail: detail.to_string(),
    }
}

// ---------- Workload lowering ------------------------------------------------

/// Turn the extracted kwarg map into a `Workload` IR. Required:
/// `image`. Optional with sensible defaults: `resources`, `network`,
/// `env`, `addons`, `include`, the four hook fields, `name`, `format`.
fn lower_to_workload(
    mut kwargs: BTreeMap<String, Value>,
    path: &Path,
    decorator_line: usize,
    function_name: String,
    module: String,
) -> Result<Workload, ParseError> {
    let workload_id = match kwargs.remove("name") {
        Some(Value::Str(s)) => s,
        Some(other) => {
            return Err(ParseError::HelperBadKwarg {
                path: path.to_path_buf(),
                line: decorator_line,
                helper: "mvm.app".to_string(),
                kwarg: "name".to_string(),
                detail: format!("expected string literal, got {other:?}"),
            });
        }
        None => function_name.clone(),
    };

    let image = match kwargs.remove("image") {
        Some(v) => helper_to_image(v, path, decorator_line)?,
        None => {
            return Err(ParseError::MissingRequiredKwarg {
                path: path.to_path_buf(),
                line: decorator_line,
                kwarg: "image",
            });
        }
    };

    let resources = match kwargs.remove("resources") {
        Some(v) => helper_to_resources(v, path, decorator_line)?,
        None => Resources {
            cpu_cores: 1,
            memory_mb: 256,
            rootfs_size_mb: 512,
        },
    };

    let network = match kwargs.remove("network") {
        Some(v) => Some(helper_to_network(v, path, decorator_line)?),
        None => None,
    };

    let env = match kwargs.remove("env") {
        Some(Value::Dict(d)) => d
            .into_iter()
            .map(|(k, v)| helper_to_env_value(v, path, decorator_line).map(|ev| (k, ev)))
            .collect::<Result<BTreeMap<String, EnvValue>, ParseError>>()?,
        Some(other) => {
            return Err(ParseError::HelperBadKwarg {
                path: path.to_path_buf(),
                line: decorator_line,
                helper: "mvm.app".to_string(),
                kwarg: "env".to_string(),
                detail: format!("expected dict literal, got {other:?}"),
            });
        }
        None => BTreeMap::new(),
    };

    let mut hooks = Hooks::default();
    for (name, phase) in [
        ("before_build", &mut hooks.before_build),
        ("before_start", &mut hooks.before_start),
        ("after_start", &mut hooks.after_start),
        ("before_stop", &mut hooks.before_stop),
    ] {
        if let Some(v) = kwargs.remove(name) {
            *phase = lower_hook_list(v, path, decorator_line, name)?;
        }
    }

    let include = match kwargs.remove("include") {
        Some(Value::List(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::Str(s) => Ok(s),
                other => Err(ParseError::HelperBadKwarg {
                    path: path.to_path_buf(),
                    line: decorator_line,
                    helper: "mvm.app".to_string(),
                    kwarg: "include".to_string(),
                    detail: format!("expected string list, got element {other:?}"),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(other) => {
            return Err(ParseError::HelperBadKwarg {
                path: path.to_path_buf(),
                line: decorator_line,
                helper: "mvm.app".to_string(),
                kwarg: "include".to_string(),
                detail: format!("expected string list, got {other:?}"),
            });
        }
        None => vec!["**".to_string()],
    };

    // `addons` lowering deferred — Phase 4 ships with the IR field
    // populated only on the empty default. Decorator users who need
    // addons can still build via the imperative `mvm-sdk::builder`
    // surface until Phase 4 follow-up wires them in.
    let _ = kwargs.remove("addons");

    if let Some((name, _)) = kwargs.into_iter().next() {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line: decorator_line,
            helper: "mvm.app".to_string(),
            kwarg: name,
            detail: "unrecognized kwarg on `@mvm.app(...)`".to_string(),
        });
    }

    let app = App {
        name: workload_id.clone(),
        source: Source::LocalPath {
            path: ".".to_string(),
            include,
            exclude: vec![],
        },
        image,
        entrypoints: vec![Entrypoint::Function {
            language: "python".to_string(),
            module,
            function: function_name,
            format: Format::Json,
            working_dir: "/app".to_string(),
            env: BTreeMap::new(),
            args_schema: None,
            return_schema: None,
            extra_imports: vec![],
            primary: true,
            concurrency: None,
        }],
        env,
        mounts: Vec::<Mount>::new(),
        network,
        resources,
        dependencies: Some(Dependencies::None),
        threat_tier: Default::default(),
        addons: vec![],
        hooks,
    };

    Ok(Workload {
        schema_version: "0.1".to_string(),
        id: workload_id,
        apps: vec![app],
        volumes: vec![],
        extensions: BTreeMap::new(),
    })
}

fn helper_to_image(v: Value, path: &Path, line: usize) -> Result<Image, ParseError> {
    let Value::Helper {
        name,
        kwargs,
        positional,
    } = v
    else {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "image".to_string(),
            detail: format!("expected one of mvm.python_image/node_image/nix_packages, got {v:?}"),
        });
    };
    match name.as_str() {
        "mvm.python_image" => {
            let python_version = pop_string_kwarg(&mut kwargs.clone(), "python")
                .unwrap_or_else(|| "3.12".to_string());
            let extra_packages = match kwargs.get("packages") {
                Some(Value::List(items)) => {
                    list_of_strings(items, path, line, "mvm.python_image", "packages")?
                }
                Some(other) => {
                    return Err(ParseError::HelperBadKwarg {
                        path: path.to_path_buf(),
                        line,
                        helper: "mvm.python_image".to_string(),
                        kwarg: "packages".to_string(),
                        detail: format!("expected string list, got {other:?}"),
                    });
                }
                None => vec![],
            };
            let mut packages = vec![format!("python{}", python_version.replace('.', ""))];
            packages.extend(extra_packages);
            Ok(Image::NixPackages { packages })
        }
        "mvm.node_image" => {
            let node_version =
                pop_string_kwarg(&mut kwargs.clone(), "node").unwrap_or_else(|| "22".to_string());
            let extra_packages = match kwargs.get("packages") {
                Some(Value::List(items)) => {
                    list_of_strings(items, path, line, "mvm.node_image", "packages")?
                }
                Some(other) => {
                    return Err(ParseError::HelperBadKwarg {
                        path: path.to_path_buf(),
                        line,
                        helper: "mvm.node_image".to_string(),
                        kwarg: "packages".to_string(),
                        detail: format!("expected string list, got {other:?}"),
                    });
                }
                None => vec![],
            };
            let mut packages = vec![format!("nodejs_{}", node_version)];
            packages.extend(extra_packages);
            Ok(Image::NixPackages { packages })
        }
        "mvm.nix_packages" => {
            let packages = match positional.as_slice() {
                [Value::List(items)] => {
                    list_of_strings(items, path, line, "mvm.nix_packages", "_pos_0")?
                }
                _ => match kwargs.get("packages") {
                    Some(Value::List(items)) => {
                        list_of_strings(items, path, line, "mvm.nix_packages", "packages")?
                    }
                    _ => {
                        return Err(ParseError::HelperMissingKwarg {
                            path: path.to_path_buf(),
                            line,
                            helper: "mvm.nix_packages".to_string(),
                            kwarg: "packages",
                        });
                    }
                },
            };
            Ok(Image::NixPackages { packages })
        }
        other => Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "image".to_string(),
            detail: format!("not an image-shaped helper: {other}"),
        }),
    }
}

fn helper_to_resources(v: Value, path: &Path, line: usize) -> Result<Resources, ParseError> {
    let Value::Helper {
        name, mut kwargs, ..
    } = v
    else {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "resources".to_string(),
            detail: format!("expected mvm.resources(...), got {v:?}"),
        });
    };
    if name != "mvm.resources" {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "resources".to_string(),
            detail: format!("expected mvm.resources(...), got {name}(...)"),
        });
    }
    let cpu = pop_int_kwarg(&mut kwargs, "cpu").unwrap_or(1) as u16;
    let memory_mb = pop_int_kwarg(&mut kwargs, "memory_mb").unwrap_or(256) as u32;
    let rootfs_size_mb = pop_int_kwarg(&mut kwargs, "rootfs_size_mb").unwrap_or(512) as u32;
    Ok(Resources {
        cpu_cores: cpu,
        memory_mb,
        rootfs_size_mb,
    })
}

fn helper_to_network(v: Value, path: &Path, line: usize) -> Result<Network, ParseError> {
    let Value::Helper {
        name, mut kwargs, ..
    } = v
    else {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "network".to_string(),
            detail: format!("expected mvm.network(...), got {v:?}"),
        });
    };
    if name != "mvm.network" {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "network".to_string(),
            detail: format!("expected mvm.network(...), got {name}(...)"),
        });
    }
    let mode_str = pop_string_kwarg(&mut kwargs, "mode").unwrap_or_else(|| "none".to_string());
    let mode = match mode_str.as_str() {
        "none" => NetworkMode::None,
        "bridge" => NetworkMode::Bridge,
        "host" => NetworkMode::Host,
        other => {
            return Err(ParseError::HelperBadKwarg {
                path: path.to_path_buf(),
                line,
                helper: "mvm.network".to_string(),
                kwarg: "mode".to_string(),
                detail: format!("unknown mode {other:?}; expected none|bridge|host"),
            });
        }
    };
    let ports = match kwargs.remove("ports") {
        Some(Value::List(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::Dict(mut d) => {
                    let guest = match d.remove("guest") {
                        Some(Value::Int(n)) => n as u16,
                        other => {
                            return Err(ParseError::HelperBadKwarg {
                                path: path.to_path_buf(),
                                line,
                                helper: "mvm.network".to_string(),
                                kwarg: "ports[].guest".to_string(),
                                detail: format!("expected integer, got {other:?}"),
                            });
                        }
                    };
                    let host = match d.remove("host") {
                        Some(Value::Int(n)) => n as u16,
                        Some(Value::None) | None => 0,
                        other => {
                            return Err(ParseError::HelperBadKwarg {
                                path: path.to_path_buf(),
                                line,
                                helper: "mvm.network".to_string(),
                                kwarg: "ports[].host".to_string(),
                                detail: format!("expected integer or None, got {other:?}"),
                            });
                        }
                    };
                    let proto = match d.remove("proto") {
                        Some(Value::Str(s)) if s == "tcp" => PortProto::Tcp,
                        Some(Value::Str(s)) if s == "udp" => PortProto::Udp,
                        None => PortProto::Tcp,
                        other => {
                            return Err(ParseError::HelperBadKwarg {
                                path: path.to_path_buf(),
                                line,
                                helper: "mvm.network".to_string(),
                                kwarg: "ports[].proto".to_string(),
                                detail: format!("expected \"tcp\"/\"udp\", got {other:?}"),
                            });
                        }
                    };
                    Ok(PortForward { guest, host, proto })
                }
                other => Err(ParseError::HelperBadKwarg {
                    path: path.to_path_buf(),
                    line,
                    helper: "mvm.network".to_string(),
                    kwarg: "ports[]".to_string(),
                    detail: format!("expected dict with guest/host/proto, got {other:?}"),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(other) => {
            return Err(ParseError::HelperBadKwarg {
                path: path.to_path_buf(),
                line,
                helper: "mvm.network".to_string(),
                kwarg: "ports".to_string(),
                detail: format!("expected list of dicts, got {other:?}"),
            });
        }
        None => vec![],
    };
    // `egress`, `peers`, `dns` left at defaults in v1; the closed
    // helper allowlist will grow them as users surface needs.
    let _ = kwargs;
    Ok(Network {
        mode,
        ports,
        egress: None::<NetworkEgress>,
        peers: vec![],
        dns: None,
    })
}

fn helper_to_env_value(v: Value, path: &Path, line: usize) -> Result<EnvValue, ParseError> {
    match v {
        Value::Str(s) => Ok(EnvValue::Literal { value: s }),
        Value::Helper {
            name,
            mut kwargs,
            mut positional,
        } if name == "mvm.literal" => {
            let value = positional
                .pop()
                .or_else(|| kwargs.remove("value"))
                .ok_or_else(|| ParseError::HelperMissingKwarg {
                    path: path.to_path_buf(),
                    line,
                    helper: "mvm.literal".to_string(),
                    kwarg: "value",
                })?;
            match value {
                Value::Str(s) => Ok(EnvValue::Literal { value: s }),
                other => Err(ParseError::HelperBadKwarg {
                    path: path.to_path_buf(),
                    line,
                    helper: "mvm.literal".to_string(),
                    kwarg: "value".to_string(),
                    detail: format!("expected string, got {other:?}"),
                }),
            }
        }
        Value::Helper {
            name,
            mut kwargs,
            mut positional,
        } if name == "mvm.secret" => {
            let secret_name = positional
                .pop()
                .or_else(|| kwargs.remove("name"))
                .ok_or_else(|| ParseError::HelperMissingKwarg {
                    path: path.to_path_buf(),
                    line,
                    helper: "mvm.secret".to_string(),
                    kwarg: "name",
                })?;
            let secret_name = match secret_name {
                Value::Str(s) => s,
                other => {
                    return Err(ParseError::HelperBadKwarg {
                        path: path.to_path_buf(),
                        line,
                        helper: "mvm.secret".to_string(),
                        kwarg: "name".to_string(),
                        detail: format!("expected string, got {other:?}"),
                    });
                }
            };
            let mount_var = pop_string_kwarg(&mut kwargs, "var");
            Ok(EnvValue::SecretRef {
                reference: SecretRef {
                    name: secret_name.clone(),
                    mount: SecretMount::Env {
                        var: mount_var.unwrap_or(secret_name),
                    },
                },
            })
        }
        other => Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: "env[]".to_string(),
            detail: format!(
                "expected string literal or mvm.literal(...)/mvm.secret(...), got {other:?}"
            ),
        }),
    }
}

fn lower_hook_list(
    v: Value,
    path: &Path,
    line: usize,
    phase: &'static str,
) -> Result<Vec<HookCmd>, ParseError> {
    // Hook-value shapes accepted in decorator kwarg position:
    //   - a string literal → length-1 vec with one `Shell`
    //   - a flat list of strings → length-1 vec with one `Argv`
    //     (interpreted as a single argv-style command)
    //   - a `mvm.hook(...)` helper call → length-1 vec
    //   - a list containing `mvm.hook(...)` helpers → one HookCmd
    //     per helper. Use this form for multiple commands in one
    //     phase. Bare strings inside such a list are also accepted
    //     and lowered as `Shell`.
    match v {
        Value::Str(line_str) => Ok(vec![HookCmd::Shell { line: line_str }]),
        Value::List(items) => {
            if items.iter().all(|i| matches!(i, Value::Str(_))) {
                let argv = list_of_strings(&items, path, line, "list", phase)?;
                Ok(vec![HookCmd::Argv { argv }])
            } else {
                items
                    .into_iter()
                    .map(|item| lower_one_hook(item, path, line, phase))
                    .collect()
            }
        }
        helper @ Value::Helper { .. } => Ok(vec![lower_one_hook(helper, path, line, phase)?]),
        other => Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: phase.to_string(),
            detail: format!("expected string, list, or mvm.hook(...); got {other:?}"),
        }),
    }
}

fn lower_one_hook(
    v: Value,
    path: &Path,
    line: usize,
    phase: &'static str,
) -> Result<HookCmd, ParseError> {
    match v {
        Value::Str(line_str) => Ok(HookCmd::Shell { line: line_str }),
        Value::List(items) => {
            let argv = list_of_strings(&items, path, line, "mvm.hook", phase)?;
            Ok(HookCmd::Argv { argv })
        }
        Value::Helper {
            name,
            mut kwargs,
            mut positional,
        } if name == "mvm.hook" => {
            let arg = positional
                .pop()
                .or_else(|| kwargs.remove("cmd"))
                .ok_or_else(|| ParseError::HelperMissingKwarg {
                    path: path.to_path_buf(),
                    line,
                    helper: "mvm.hook".to_string(),
                    kwarg: "cmd",
                })?;
            match arg {
                Value::Str(s) => Ok(HookCmd::Shell { line: s }),
                Value::List(items) => Ok(HookCmd::Argv {
                    argv: list_of_strings(&items, path, line, "mvm.hook", phase)?,
                }),
                other => Err(ParseError::HelperBadKwarg {
                    path: path.to_path_buf(),
                    line,
                    helper: "mvm.hook".to_string(),
                    kwarg: phase.to_string(),
                    detail: format!("expected string or list, got {other:?}"),
                }),
            }
        }
        other => Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line,
            helper: "mvm.app".to_string(),
            kwarg: phase.to_string(),
            detail: format!("expected string/list/mvm.hook, got {other:?}"),
        }),
    }
}

fn list_of_strings(
    items: &[Value],
    path: &Path,
    line: usize,
    helper: &str,
    kwarg: &str,
) -> Result<Vec<String>, ParseError> {
    items
        .iter()
        .map(|v| match v {
            Value::Str(s) => Ok(s.clone()),
            other => Err(ParseError::HelperBadKwarg {
                path: path.to_path_buf(),
                line,
                helper: helper.to_string(),
                kwarg: kwarg.to_string(),
                detail: format!("expected string element, got {other:?}"),
            }),
        })
        .collect()
}

fn pop_string_kwarg(map: &mut BTreeMap<String, Value>, key: &str) -> Option<String> {
    match map.remove(key) {
        Some(Value::Str(s)) => Some(s),
        _ => None,
    }
}

fn pop_int_kwarg(map: &mut BTreeMap<String, Value>, key: &str) -> Option<i64> {
    match map.remove(key) {
        Some(Value::Int(n)) => Some(n),
        _ => None,
    }
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
