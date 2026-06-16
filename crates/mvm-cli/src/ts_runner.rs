//! TypeScript runner discovery — shared by `mvmctl compile` (auto-run
//! of record-mode `.ts` scripts) and `mvmctl doctor` (host-environment
//! probe). Lives in its own module so the install-hint string is one
//! source of truth between the two surfaces.
//!
//! Resolution order applied by `resolve`:
//!
//! 1. `MVM_TSX` env override — explicit user pin (handled by the
//!    caller; this module is only the post-override fallback).
//! 2. `./node_modules/.bin/tsx` — cwd-relative, pins the runner via
//!    the project's lockfile.
//! 3. `./node_modules/.bin/bun`.
//! 4. `./node_modules/.bin/deno`.
//! 5. `tsx` on `PATH`.
//! 6. `bun` on `PATH`.
//! 7. `deno` on `PATH`.
//! 8. `None` — the caller surfaces `install_hint` to the user.

use std::path::PathBuf;

/// Candidate runners, in priority order. `tsx` wins because it's the
/// canonical TypeScript-only runner and ships the smallest install
/// footprint (`npm install -g tsx`); `bun` and `deno` are full
/// toolchains that also accept `.ts` input.
pub(crate) const CANDIDATES: [&str; 3] = ["tsx", "bun", "deno"];

/// Look for a TS runner under `./node_modules/.bin/<name>`
/// (cwd-relative). `tsx` wins over `bun` wins over `deno`. Returns
/// the first existing **file** (npm/pnpm install
/// `node_modules/.bin/tsx` as a symlink, which still passes
/// `is_file()` through the symlink). Returns `None` if no runner is
/// present so the caller can fall through to a `PATH` search.
pub(crate) fn project_local() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let base = cwd.join("node_modules").join(".bin");
    if !base.is_dir() {
        return None;
    }
    for candidate in CANDIDATES {
        let p = base.join(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Search `PATH` for `tsx`, then `bun`, then `deno`. Returns the
/// first hit, or `None` if no candidate is on `PATH`.
pub(crate) fn on_path() -> Option<PathBuf> {
    for candidate in CANDIDATES {
        if let Ok(found) = which::which(candidate) {
            return Some(found);
        }
    }
    None
}

/// Resolve the runner without consulting `MVM_TSX` (the env-override
/// is the caller's responsibility — it's a single `std::env::var`
/// lookup and the caller already special-cases the empty-string
/// case). Returns the first existing candidate per the order in
/// the module docs, or `None` so the caller can `bail!` with
/// [`install_hint`].
pub(crate) fn resolve() -> Option<PathBuf> {
    project_local().or_else(on_path)
}

/// Single source of truth for the "install a TS runner" message
/// surfaced by `mvmctl compile` (on `bail!`) and `mvmctl doctor`
/// (on a WARN result). Listing every install path keeps the two
/// messages aligned and avoids users re-discovering the same
/// recipes in two places.
pub(crate) fn install_hint() -> &'static str {
    "no TypeScript runner found on PATH (tried `tsx`, `bun`, `deno`) \
     and no project-local `./node_modules/.bin/{tsx,bun,deno}`. Install one: \
     `brew install tsx` (macOS) / `npm install -g tsx` / `pnpm add -g tsx` / \
     `yarn global add tsx` — or `brew install oven-sh/bun/bun` / \
     `curl -fsSL https://bun.sh/install | bash` for bun, or \
     `brew install deno` / `curl -fsSL https://deno.land/install.sh | sh` \
     for deno. Add the runner to your `package.json` devDependencies so \
     `./node_modules/.bin/tsx` resolves without polluting global PATH, or \
     set `MVM_TSX=<path>` to an explicit binary."
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// `std::env::set_current_dir` is process-wide; this Mutex stops
    /// `cargo test`'s thread pool from racing between two cwd-mutating
    /// tests. The lock is held for the lifetime of [`CwdGuard`].
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    struct CwdGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: PathBuf,
    }

    impl CwdGuard {
        fn enter(dir: &Path) -> Self {
            let g = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::current_dir().expect("cwd");
            std::env::set_current_dir(dir).expect("chdir");
            CwdGuard { _guard: g, prev }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    #[cfg(unix)]
    fn write_exec(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn project_local_returns_none_when_no_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let _g = CwdGuard::enter(tmp.path());
        assert!(
            project_local().is_none(),
            "expected None without ./node_modules/.bin"
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_local_prefers_tsx_over_bun_and_deno() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        // Plant all three; tsx must win.
        for name in CANDIDATES {
            write_exec(&bin.join(name), "#!/bin/sh\nexit 0\n");
        }
        let _g = CwdGuard::enter(tmp.path());
        let resolved = project_local().expect("should resolve");
        assert_eq!(
            resolved.file_name().and_then(|s| s.to_str()),
            Some("tsx"),
            "tsx must win the priority order"
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_local_falls_through_to_bun_when_only_bun_present() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_exec(&bin.join("bun"), "#!/bin/sh\nexit 0\n");
        let _g = CwdGuard::enter(tmp.path());
        let resolved = project_local().expect("should resolve bun");
        assert_eq!(resolved.file_name().and_then(|s| s.to_str()), Some("bun"));
    }

    #[cfg(unix)]
    #[test]
    fn project_local_falls_through_to_deno_when_only_deno_present() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_exec(&bin.join("deno"), "#!/bin/sh\nexit 0\n");
        let _g = CwdGuard::enter(tmp.path());
        let resolved = project_local().expect("should resolve deno");
        assert_eq!(resolved.file_name().and_then(|s| s.to_str()), Some("deno"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_picks_project_local_over_path_when_both_present() {
        // Plant ./node_modules/.bin/tsx; even if PATH carries another
        // `tsx`, the project-local one must win.
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tsx = bin.join("tsx");
        write_exec(&tsx, "#!/bin/sh\nexit 0\n");

        let _g = CwdGuard::enter(tmp.path());
        let resolved = resolve().expect("project-local tsx must resolve");
        // Symlink-canonicalize to handle macOS /var → /private/var.
        let resolved = std::fs::canonicalize(&resolved).unwrap_or(resolved);
        let expected = std::fs::canonicalize(&tsx).unwrap_or(tsx);
        assert_eq!(resolved, expected);
    }

    #[test]
    fn install_hint_covers_all_runners_and_resolution_paths() {
        let hint = install_hint();
        for s in [
            "tsx",
            "bun",
            "deno",
            "brew install",
            "npm install -g tsx",
            "node_modules",
            "MVM_TSX",
        ] {
            assert!(hint.contains(s), "install_hint missing {s:?}: {hint}");
        }
    }
}
