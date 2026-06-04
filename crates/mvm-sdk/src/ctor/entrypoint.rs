use std::collections::BTreeMap;

use crate::ir::{Entrypoint, EnvValue, Format};

/// Command-style entrypoint (legacy v0 shape). Working dir defaults to
/// `/app`.
pub fn entrypoint_command<I, S>(command: I) -> Entrypoint
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Entrypoint::Command {
        command: command.into_iter().map(Into::into).collect(),
        working_dir: "/app".to_string(),
        env: BTreeMap::new(),
    }
}

/// Function-call entrypoint (plan 0003 / ADR-0009). Defaults to
/// `format = json`, `working_dir = /app`, `primary = false`. Use
/// [`EntrypointExt`] chained setters to override.
pub fn entrypoint_function(
    language: impl Into<String>,
    module: impl Into<String>,
    function: impl Into<String>,
) -> Entrypoint {
    Entrypoint::Function {
        language: language.into(),
        module: module.into(),
        function: function.into(),
        format: Format::Json,
        working_dir: "/app".to_string(),
        env: BTreeMap::new(),
        args_schema: None,
        return_schema: None,
        extra_imports: Vec::new(),
        primary: false,
        concurrency: None,
    }
}

/// Chained-setter extensions on [`Entrypoint`]. Bring into scope via
/// `use mvm_sdk::*;` (the trait is re-exported from the prelude).
/// Methods that don't apply to a given variant (e.g. `with_format` on
/// a `Command` entrypoint) panic with a clear message — caller error,
/// not a runtime concern.
pub trait EntrypointExt: Sized {
    fn with_format(self, format: Format) -> Self;
    fn with_primary(self, primary: bool) -> Self;
    fn with_working_dir(self, working_dir: impl Into<String>) -> Self;
    fn with_env(self, key: impl Into<String>, value: EnvValue) -> Self;
    /// Supply an explicit JSON Schema for the function's args. Mirrors
    /// the Python SDK's `args_schema=` and the TypeScript SDK's
    /// `argsSchema:`. Pass `serde_json::Map<String, Value>` (typically
    /// constructed via `serde_json::json!({...}).as_object().cloned()`).
    ///
    /// The host's `mvm emit` step will auto-derive args/return
    /// schemas from the entry source per ADR-0016 when these fields
    /// are unset; explicit values supplied via these setters always
    /// win. SDK-layer byte-identity tests that hit corpus fixtures
    /// expecting auto-derived shapes need to set these explicitly,
    /// since the SDK's `emit_json` doesn't run signature extraction
    /// (no source-tree access in the pure-IR build path).
    fn with_args_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self;
    fn with_return_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self;
}

impl EntrypointExt for Entrypoint {
    fn with_format(self, fmt: Format) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format: fmt,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_format only applies to function-call entrypoints")
            }
        }
    }

    fn with_primary(self, p: bool) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary: p,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_primary only applies to function-call entrypoints")
            }
        }
    }

    fn with_working_dir(self, wd: impl Into<String>) -> Self {
        let wd = wd.into();
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir: wd,
                env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { command, env, .. } => Entrypoint::Command {
                command,
                working_dir: wd,
                env,
            },
        }
    }

    fn with_env(self, key: impl Into<String>, value: EnvValue) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                mut env,
                args_schema,
                return_schema,
                extra_imports,
                primary,
                concurrency,
            } => {
                env.insert(key.into(), value);
                Entrypoint::Function {
                    language,
                    module,
                    function,
                    format,
                    working_dir,
                    env,
                    args_schema,
                    return_schema,
                    extra_imports,
                    primary,
                    concurrency,
                }
            }
            Entrypoint::Command {
                command,
                working_dir,
                mut env,
            } => {
                env.insert(key.into(), value);
                Entrypoint::Command {
                    command,
                    working_dir,
                    env,
                }
            }
        }
    }

    fn with_args_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                return_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema: Some(crate::ir::JsonSchemaShape(schema)),
                return_schema,
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_args_schema only applies to function-call entrypoints")
            }
        }
    }

    fn with_return_schema(self, schema: serde_json::Map<String, serde_json::Value>) -> Self {
        match self {
            Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                extra_imports,
                primary,
                concurrency,
                ..
            } => Entrypoint::Function {
                language,
                module,
                function,
                format,
                working_dir,
                env,
                args_schema,
                return_schema: Some(crate::ir::JsonSchemaShape(schema)),
                extra_imports,
                primary,
                concurrency,
            },
            Entrypoint::Command { .. } => {
                panic!("with_return_schema only applies to function-call entrypoints")
            }
        }
    }
}
