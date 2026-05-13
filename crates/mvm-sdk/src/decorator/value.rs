//! Language-independent kwarg value model + IR lowering.
//!
//! Both [`super::python`] and [`super::typescript`] parsers produce a
//! `BTreeMap<String, Value>` from a `@mvm.app(...)` / `mvm.app({...})(fn)`
//! site and hand it to [`lower_to_workload`] for the final `Workload`
//! IR. Keeping the lowering in one place means a new helper or kwarg
//! lands once and is automatically supported across every language
//! parser.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mvm_ir::{
    App, Dependencies, Entrypoint, EnvValue, Format, HookCmd, Hooks, Image, Mount, Network,
    NetworkEgress, NetworkMode, PortForward, PortProto, Resources, SecretMount, SecretRef, Source,
    Workload,
};

use super::ParseError;

/// Closed allowlist of `mvm.*` helper calls accepted in decorator
/// kwarg-value position. Anything outside this set is rejected with
/// [`ParseError::UnknownHelper`].
///
/// Documented surface: `mvm.python_image`, `mvm.node_image`,
/// `mvm.nix_packages`, `mvm.resources`, `mvm.network`, `mvm.secret`,
/// `mvm.literal`, `mvm.hook`, `mvm.addons.database`,
/// `mvm.addons.service`. The list lives in code so adding a helper
/// is a reviewed code change rather than a config update.
///
/// Language parsers normalize helper callees to the dotted form (e.g.
/// a TypeScript `app({...})` import becomes `mvm.app` before lookup)
/// so the allowlist is a single source of truth.
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

/// The parsed shape of a kwarg's value. Lowered to IR types by
/// [`lower_to_workload`].
///
/// `Bool`/`Float` are accepted at the parser level so future helpers
/// can take them (e.g. fractional cpu shares); v1 lowering doesn't
/// consume them but the shape is reserved so adding a helper that
/// does isn't a parser change. `dead_code` allow covers that
/// future-proofing window.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    None,
    List(Vec<Value>),
    Dict(BTreeMap<String, Value>),
    /// A call into the `mvm.*` allowlist. The pair carries the
    /// dotted callable name (e.g. `mvm.python_image`) and its
    /// already-extracted args.
    Helper {
        name: String,
        kwargs: BTreeMap<String, Value>,
        positional: Vec<Value>,
    },
}

/// Turn the extracted kwarg map into a `Workload` IR.
///
/// Required: `image`. Optional with sensible defaults: `resources`,
/// `network`, `env`, `addons`, `include`, the four hook fields,
/// `name`. `language` is passed in by the caller (Python parsers pass
/// `"python"`; TypeScript parsers pass `"node"`).
pub fn lower_to_workload(
    mut kwargs: BTreeMap<String, Value>,
    path: &Path,
    decorator_line: usize,
    function_name: String,
    module: String,
    language: &str,
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
                detail: format!("expected dict/object literal, got {other:?}"),
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
    // surface until the follow-up wires them in.
    let _ = kwargs.remove("addons");

    if let Some((name, _)) = kwargs.into_iter().next() {
        return Err(ParseError::HelperBadKwarg {
            path: path.to_path_buf(),
            line: decorator_line,
            helper: "mvm.app".to_string(),
            kwarg: name,
            detail: "unrecognized kwarg on `@mvm.app(...)` / `mvm.app({...})(fn)`".to_string(),
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
            language: language.to_string(),
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

/// Build a `ParseError::NonLiteralKwarg` for a value the parser
/// couldn't statically evaluate. Used by per-language `eval_value`
/// implementations so they don't have to repeat the boilerplate.
pub fn non_literal_at(
    path: &Path,
    line: usize,
    column: usize,
    kwarg: &str,
    detail: &str,
) -> ParseError {
    ParseError::NonLiteralKwarg {
        path: PathBuf::from(path),
        line,
        column,
        kwarg: kwarg.to_string(),
        detail: detail.to_string(),
    }
}
