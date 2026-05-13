//! Lifecycle-hook merger (SDK port Phase 10a).
//!
//! [`merge_hooks`] takes an `App`'s own `Hooks` plus the hooks each
//! attached addon contributes, and returns the per-phase command list
//! the workload VM should execute. The rule is uniform vector
//! concatenation — addons first (in attachment order), then the app's
//! commands. No special-cases for single vs. multiple commands per
//! phase: empty vecs concatenate to empty, length-1 vecs to length-1,
//! etc.
//!
//! Phase 10a (this module) handles the **compile-time** merge so the
//! launch.json that the Nix factory reads at flake-evaluation time
//! contains the already-merged sequence. The factory's only job is
//! to bake the resulting commands into the rootfs init at the right
//! lifecycle point — no merging in Nix, where the language is too
//! cumbersome for it.

use mvm_ir::Hooks;

/// Merge the consuming `App`'s hooks with each attached addon's
/// hooks. For every phase: `addons[0].phase ++ addons[1].phase ++ …
/// ++ app.phase`. The addons run before the app within each phase,
/// in their attachment order; the app's commands always come last so
/// the app sees a fully-set-up environment.
///
/// Returns a new `Hooks` — the inputs aren't modified. The merged
/// shape is what serializes into launch.json; the per-phase Nix
/// snippets just emit one `${pkgs.runtimeShell}`-line per `HookCmd`.
pub fn merge_hooks(app: &Hooks, addons: &[&Hooks]) -> Hooks {
    let mut out = Hooks::default();
    for addon in addons {
        out.before_build.extend(addon.before_build.iter().cloned());
        out.before_start.extend(addon.before_start.iter().cloned());
        out.after_start.extend(addon.after_start.iter().cloned());
        out.before_stop.extend(addon.before_stop.iter().cloned());
    }
    out.before_build.extend(app.before_build.iter().cloned());
    out.before_start.extend(app.before_start.iter().cloned());
    out.after_start.extend(app.after_start.iter().cloned());
    out.before_stop.extend(app.before_stop.iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_ir::HookCmd;

    fn shell(line: &str) -> HookCmd {
        HookCmd::Shell {
            line: line.to_string(),
        }
    }

    fn argv(args: &[&str]) -> HookCmd {
        HookCmd::Argv {
            argv: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn merge_app_only() {
        let app = Hooks {
            before_start: vec![shell("export FOO=1")],
            ..Hooks::default()
        };
        let merged = merge_hooks(&app, &[]);
        assert_eq!(merged.before_start, vec![shell("export FOO=1")]);
        assert!(merged.before_build.is_empty());
        assert!(merged.after_start.is_empty());
        assert!(merged.before_stop.is_empty());
    }

    #[test]
    fn merge_addon_only() {
        let addon = Hooks {
            before_start: vec![shell("create-db-user")],
            ..Hooks::default()
        };
        let merged = merge_hooks(&Hooks::default(), &[&addon]);
        assert_eq!(merged.before_start, vec![shell("create-db-user")]);
    }

    #[test]
    fn addons_run_before_app_within_each_phase() {
        let app = Hooks {
            before_start: vec![shell("APP")],
            ..Hooks::default()
        };
        let db = Hooks {
            before_start: vec![shell("create-db-user")],
            ..Hooks::default()
        };
        let authx = Hooks {
            before_start: vec![shell("start-auth-daemon")],
            ..Hooks::default()
        };
        let merged = merge_hooks(&app, &[&db, &authx]);
        assert_eq!(
            merged.before_start,
            vec![
                shell("create-db-user"),
                shell("start-auth-daemon"),
                shell("APP"),
            ]
        );
    }

    #[test]
    fn addons_preserve_attachment_order() {
        // Switching the addon order must switch the resulting phase
        // order — addons are not commutative.
        let db = Hooks {
            before_start: vec![shell("db")],
            ..Hooks::default()
        };
        let authx = Hooks {
            before_start: vec![shell("authx")],
            ..Hooks::default()
        };
        let a = merge_hooks(&Hooks::default(), &[&db, &authx]);
        let b = merge_hooks(&Hooks::default(), &[&authx, &db]);
        assert_eq!(a.before_start, vec![shell("db"), shell("authx")]);
        assert_eq!(b.before_start, vec![shell("authx"), shell("db")]);
    }

    #[test]
    fn merge_does_not_alias_phases() {
        // Each phase is merged independently — a contribution to
        // `before_start` must not bleed into `after_start`.
        let app = Hooks {
            before_build: vec![argv(&["python", "-m", "migrate"])],
            after_start: vec![shell("curl /h")],
            ..Hooks::default()
        };
        let addon = Hooks {
            before_start: vec![shell("setup")],
            before_stop: vec![shell("teardown")],
            ..Hooks::default()
        };
        let merged = merge_hooks(&app, &[&addon]);
        assert_eq!(merged.before_build.len(), 1);
        assert_eq!(merged.before_start.len(), 1);
        assert_eq!(merged.after_start.len(), 1);
        assert_eq!(merged.before_stop.len(), 1);
        assert_eq!(merged.before_build[0], argv(&["python", "-m", "migrate"]));
        assert_eq!(merged.before_start[0], shell("setup"));
        assert_eq!(merged.after_start[0], shell("curl /h"));
        assert_eq!(merged.before_stop[0], shell("teardown"));
    }

    #[test]
    fn merge_empty_app_and_empty_addons_is_empty() {
        let merged = merge_hooks(&Hooks::default(), &[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn merge_preserves_input_immutability() {
        // The inputs must not be mutated — merge_hooks takes &T.
        let app = Hooks {
            before_start: vec![shell("APP")],
            ..Hooks::default()
        };
        let addon = Hooks {
            before_start: vec![shell("ADDON")],
            ..Hooks::default()
        };
        let _ = merge_hooks(&app, &[&addon]);
        assert_eq!(app.before_start, vec![shell("APP")]);
        assert_eq!(addon.before_start, vec![shell("ADDON")]);
    }

    #[test]
    fn merge_handles_many_addons() {
        // The vec extends naturally with N addons; no arbitrary limit.
        let mut addons_owned: Vec<Hooks> = (0..8)
            .map(|i| Hooks {
                before_start: vec![shell(&format!("addon-{i}"))],
                ..Hooks::default()
            })
            .collect();
        let refs: Vec<&Hooks> = addons_owned.iter_mut().map(|h| &*h).collect();
        let app = Hooks {
            before_start: vec![shell("APP")],
            ..Hooks::default()
        };
        let merged = merge_hooks(&app, &refs);
        assert_eq!(merged.before_start.len(), 9);
        assert_eq!(merged.before_start[0], shell("addon-0"));
        assert_eq!(merged.before_start[7], shell("addon-7"));
        assert_eq!(merged.before_start[8], shell("APP"));
    }
}
