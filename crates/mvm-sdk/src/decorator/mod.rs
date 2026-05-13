//! Static decorator parser — extracts `@mvm.app(...)` kwargs from a
//! user's source file and lowers them to a `Workload` IR.
//!
//! The decorator path **never runs user code on the host**: parsing is
//! pure tree-sitter, the allowlist of helper calls is closed and
//! hand-curated, and any computed expression in literal position is
//! rejected with `E_DECORATOR_NON_LITERAL`. The decorated function
//! becomes the microVM's `/etc/mvm/entrypoint`; the user's source tree
//! ships as `app.source.LocalPath` and the runner dispatches the
//! function at invoke time.
//!
//! Today the Python parser is implemented; the TypeScript mirror lands
//! in a follow-up slice. The two share the [`DecoratorManifest`]
//! shape and [`ParseError`] taxonomy so callers can route by file
//! extension without language-specific branches.

pub mod python;
pub mod typescript;
mod value;

pub use python::parse_python;
pub use typescript::parse_typescript;
pub use value::HELPER_ALLOWLIST;

use std::path::PathBuf;

/// Diagnostic shape for a parse failure. Errors carry the originating
/// path and a 1-based `(line, column)` so the CLI can produce a
/// rustc-style pointer.
#[derive(Debug)]
pub enum ParseError {
    /// The source could not be parsed under the language grammar.
    /// Carries a sample of the offending text for the diagnostic.
    SyntaxError {
        path: PathBuf,
        line: usize,
        column: usize,
        snippet: String,
    },
    /// No `@mvm.app(...)` decorator found at module scope.
    NoDecoratedFunction { path: PathBuf },
    /// More than one `@mvm.app(...)`-decorated function found at
    /// module scope. v1 requires exactly one (one app per microVM).
    MultipleDecoratedFunctions {
        path: PathBuf,
        first_line: usize,
        second_line: usize,
    },
    /// `@mvm.app` decorates something other than a module-level
    /// function (a class, a nested function, an expression).
    DecoratorTarget {
        path: PathBuf,
        line: usize,
        target_kind: String,
    },
    /// A decorator kwarg has a value the static parser can't evaluate
    /// — a name binding, an arithmetic expression, an unrecognized
    /// call. Tells the user which kwarg and where.
    NonLiteralKwarg {
        path: PathBuf,
        line: usize,
        column: usize,
        kwarg: String,
        detail: String,
    },
    /// A `mvm.*` helper call appears in literal position but isn't in
    /// the closed allowlist.
    UnknownHelper {
        path: PathBuf,
        line: usize,
        column: usize,
        helper: String,
    },
    /// A required kwarg is missing on `@mvm.app(...)`.
    MissingRequiredKwarg {
        path: PathBuf,
        line: usize,
        kwarg: &'static str,
    },
    /// A `mvm.*` helper call is missing a required kwarg.
    HelperMissingKwarg {
        path: PathBuf,
        line: usize,
        helper: String,
        kwarg: &'static str,
    },
    /// A helper kwarg has the wrong shape (e.g. expected a string,
    /// got a number).
    HelperBadKwarg {
        path: PathBuf,
        line: usize,
        helper: String,
        kwarg: String,
        detail: String,
    },
    /// Internal tree-sitter setup or query-compile failure. Not a
    /// user-visible condition under normal use.
    ParserSetup(String),
    /// I/O error reading the source file.
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyntaxError {
                path,
                line,
                column,
                snippet,
            } => write!(
                f,
                "{}:{line}:{column}: syntax error near {snippet:?}",
                path.display()
            ),
            Self::NoDecoratedFunction { path } => write!(
                f,
                "{}: no `@mvm.app(...)`-decorated function found at module scope",
                path.display()
            ),
            Self::MultipleDecoratedFunctions {
                path,
                first_line,
                second_line,
            } => write!(
                f,
                "{}: multiple `@mvm.app` decorators (lines {first_line} and {second_line}); v1 requires exactly one — every app is one microVM",
                path.display()
            ),
            Self::DecoratorTarget {
                path,
                line,
                target_kind,
            } => write!(
                f,
                "{}:{line}: `@mvm.app` must decorate a module-level function (got {target_kind})",
                path.display()
            ),
            Self::NonLiteralKwarg {
                path,
                line,
                column,
                kwarg,
                detail,
            } => write!(
                f,
                "{}:{line}:{column}: decorator kwarg `{kwarg}` is not a literal — {detail}. The static parser accepts string/number/bool/None/list/dict literals and calls into the `mvm.*` helper allowlist.",
                path.display()
            ),
            Self::UnknownHelper {
                path,
                line,
                column,
                helper,
            } => write!(
                f,
                "{}:{line}:{column}: `{helper}` is not in the decorator helper allowlist. See `mvm_sdk::decorator::python::HELPER_ALLOWLIST`.",
                path.display()
            ),
            Self::MissingRequiredKwarg { path, line, kwarg } => write!(
                f,
                "{}:{line}: `@mvm.app(...)` is missing required kwarg `{kwarg}`",
                path.display()
            ),
            Self::HelperMissingKwarg {
                path,
                line,
                helper,
                kwarg,
            } => write!(
                f,
                "{}:{line}: `{helper}(...)` is missing required kwarg `{kwarg}`",
                path.display()
            ),
            Self::HelperBadKwarg {
                path,
                line,
                helper,
                kwarg,
                detail,
            } => write!(
                f,
                "{}:{line}: `{helper}(...)` kwarg `{kwarg}`: {detail}",
                path.display()
            ),
            Self::ParserSetup(s) => write!(f, "tree-sitter setup: {s}"),
            Self::Io(p, e) => write!(f, "reading {}: {e}", p.display()),
        }
    }
}

impl std::error::Error for ParseError {}

/// The intent extracted from a `@mvm.app(...)` decorator. Lowered to
/// a `Workload` IR by the per-language parser.
///
/// All fields except `workload_id` and `function_name` are optional;
/// the parser fills sensible defaults so a minimal decorator
/// (`@mvm.app(image=mvm.python_image(python="3.12"))` over `def
/// greet(...)`) produces a complete Workload.
#[derive(Debug, Clone)]
pub struct DecoratorManifest {
    /// Workload id. Defaults to the decorated function name. Override
    /// via `@mvm.app(name="my-app")`.
    pub workload_id: String,
    /// Name of the decorated function (the primary entrypoint).
    pub function_name: String,
    /// Module path the runner dispatches against (e.g. `app` for
    /// `app.py`). Derived from the source-file stem; `@mvm.app` does
    /// not (yet) take an override.
    pub module: String,
    /// Source-line of the decorator itself. Used in error messages.
    pub decorator_line: usize,
}
