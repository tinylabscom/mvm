use crate::ir::{Dependencies, NodeTool, PythonTool};

/// Python lockfile dependency (`uv.lock` by default).
pub fn python_deps(lockfile: impl Into<String>) -> Dependencies {
    python_deps_with(lockfile, PythonTool::Uv)
}

pub fn python_deps_with(lockfile: impl Into<String>, tool: PythonTool) -> Dependencies {
    Dependencies::Python {
        lockfile: lockfile.into(),
        tool,
    }
}

/// Node lockfile dependency (`pnpm-lock.yaml` by default).
pub fn node_deps(lockfile: impl Into<String>) -> Dependencies {
    node_deps_with(lockfile, NodeTool::Pnpm)
}

pub fn node_deps_with(lockfile: impl Into<String>, tool: NodeTool) -> Dependencies {
    Dependencies::Node {
        lockfile: lockfile.into(),
        tool,
    }
}

/// Explicit "no runtime dependencies" — bypasses the host's lockfile
/// checks for stdlib-only workloads.
pub fn no_deps() -> Dependencies {
    Dependencies::None
}
