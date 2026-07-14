//! Lifecycle hook IR (SDK port Phase 1a).
//!
//! Four phases — `before_build`, `before_start`, `after_start`,
//! `before_stop` — each a `Vec<HookCmd>`. Empty vec = no hook for that
//! phase. The compiler merges hooks from every addon attached to an app
//! plus the app's own hooks by straight vector concatenation, in
//! addon-attachment order followed by the app's commands. No special
//! single-vs-sequence handling.
//!
//! Phase semantics (Phase 10 wires the consumers; Phase 1a only reserves
//! the IR field shape):
//!
//! - `before_build` — runs in the builder microVM after the dep install,
//!   before the rootfs snapshot. Use for one-off build-time setup
//!   (DB migration, seed data, cache warm).
//! - `before_start` — runs in the workload microVM before the entrypoint
//!   or warm-process pool starts. Use for run-time setup that every
//!   boot needs (env exports, fs-prep).
//! - `after_start` — readiness probe. Polled to exit-0 or timeout before
//!   the warm-process pool accepts `mvmctl invoke` requests.
//! - `before_stop` — runs at shutdown, best-effort.
//!
//! `after_stop` is intentionally omitted (the VM is gone — nothing to
//! run in). Adding `after_build` if needed is a non-breaking field
//! addition under the same `skip_serializing_if = "Vec::is_empty"`
//! discipline used here.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Per-phase lifecycle command lists for an `App` or an `AddonUse`.
///
/// Each phase is a `Vec<HookCmd>` — always. The "empty vec means no
/// hook" rule plus the `skip_serializing_if = "Vec::is_empty"` field
/// attribute on every phase keeps IR documents that don't use hooks
/// byte-identical to v0 fixtures: the JSON object simply omits the
/// `hooks` key when every phase is empty.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hooks {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before_build: Vec<HookCmd>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before_start: Vec<HookCmd>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after_start: Vec<HookCmd>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub before_stop: Vec<HookCmd>,
}

impl Hooks {
    /// True iff every phase carries an empty `Vec`. `App`'s and
    /// `AddonUse`'s `skip_serializing_if` uses this so a workload that
    /// doesn't declare hooks emits the same JSON it always did.
    pub fn is_empty(&self) -> bool {
        self.before_build.is_empty()
            && self.before_start.is_empty()
            && self.after_start.is_empty()
            && self.before_stop.is_empty()
    }
}

/// One command in a hook phase.
///
/// Two variants, internally tagged on `kind` — matches the rest of the
/// IR's enum conventions (`Source`, `Image`, `MountSource`, …) so the
/// JSON Schema and SDK generators handle the discriminant uniformly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookCmd {
    /// Single shell line, executed via `/bin/sh -c <line>`. Use for
    /// short one-liners (`export FOO=bar`, `mkdir -p /run/app`).
    Shell { line: String },
    /// Argv list, executed without a shell. Use when the command needs
    /// no shell interpretation (paths with spaces, untrusted args, no
    /// glob/var expansion). Empty argv is rejected by the validator
    /// (Phase 10 — Phase 1a just reserves the shape).
    Argv { argv: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hooks_is_empty() {
        let h = Hooks::default();
        assert!(h.is_empty());
    }

    #[test]
    fn non_empty_phase_makes_hooks_non_empty() {
        let h = Hooks {
            before_start: vec![HookCmd::Shell {
                line: "echo hi".into(),
            }],
            ..Hooks::default()
        };
        assert!(!h.is_empty());
    }

    #[test]
    fn empty_hooks_omit_all_keys_in_json() {
        let h = Hooks::default();
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, "{}", "every phase is skip_serializing_if = empty");
    }

    #[test]
    fn non_empty_hooks_round_trip() {
        let h = Hooks {
            before_build: vec![HookCmd::Argv {
                argv: vec!["python".into(), "-m".into(), "migrate".into()],
            }],
            before_start: vec![HookCmd::Shell {
                line: "export MODEL=/data/m.pt".into(),
            }],
            after_start: vec![HookCmd::Argv {
                argv: vec![
                    "curl".into(),
                    "-fsS".into(),
                    "http://127.0.0.1/health".into(),
                ],
            }],
            before_stop: vec![HookCmd::Shell {
                line: "pkill app".into(),
            }],
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: Hooks = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn hookcmd_variants_serialize_with_kind_tag() {
        let shell = HookCmd::Shell {
            line: "true".into(),
        };
        let argv = HookCmd::Argv {
            argv: vec!["true".into()],
        };
        assert_eq!(
            serde_json::to_value(&shell).unwrap(),
            serde_json::json!({"kind": "shell", "line": "true"})
        );
        assert_eq!(
            serde_json::to_value(&argv).unwrap(),
            serde_json::json!({"kind": "argv", "argv": ["true"]})
        );
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let bad = serde_json::json!({"kind": "spawn", "binary": "/bin/sh"});
        let err = serde_json::from_value::<HookCmd>(bad).unwrap_err();
        assert!(
            err.to_string().contains("spawn") || err.to_string().contains("unknown"),
            "expected an unknown-variant error, got: {err}"
        );
    }

    #[test]
    fn extra_fields_on_hooks_are_rejected() {
        // `deny_unknown_fields` on Hooks gates schema drift — a typo'd
        // phase name (e.g. `after_build` which we deliberately don't
        // ship) fails closed instead of being silently ignored.
        let bad = serde_json::json!({"after_build": [{"kind": "shell", "line": "x"}]});
        let err = serde_json::from_value::<Hooks>(bad).unwrap_err();
        assert!(err.to_string().contains("after_build"));
    }
}
