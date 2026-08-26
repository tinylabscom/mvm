//! `mvmctl trust audit posture` — security posture self-test.
//!
//! Read-only diagnostic that reports which host-hardening
//! mitigations are active on the calling host. Operators run it
//! to confirm their config without reading source; monitoring
//! systems run it as a configuration-drift check.
//!
//! ## What it reports
//!
//! - **Host signer** — does `~/.mvm/keys/host-signer.ed25519`
//!   exist? Is it mode 0600?
//! - **Audit chain** — does `~/.mvm/audit/local.jsonl` exist?
//!   Does it verify clean via [`mvm_hostd::supervisor::verify_audit_chain`]?
//! - **Web-fetch allowlist** — count of hosts in
//!   `$MVM_WEB_FETCH_ALLOWLIST`.
//! - **Web-search allowlist** — count + names of providers in
//!   `$MVM_WEB_SEARCH_ALLOWLIST`. Per provider: is its API key
//!   resolvable via direct env var or `*_FROM_SECRET`?
//! - **Tool staging dir** — `$MVM_TOOL_STAGING_DIR` (or default
//!   `~/.mvm/tool-staging/`): exists? Mode 0700?
//! - **Overlay root** — `~/.mvm/overlays/`: exists? Mode 0700?
//!   How many tenants?
//! - **Secret store** — `~/.mvm/secrets/`: exists? Mode 0700?
//! - **TLS minimum** — pinned to TLS 1.3.
//!
//! ## What it does NOT do
//!
//! - No network calls. Doesn't probe upstreams to confirm they
//!   advertise TLS 1.3; that would be a runtime cost + flake.
//! - No write side effects. Operators on production hosts can
//!   run `mvmctl trust audit posture --json` from a monitoring agent
//!   without risk of mutating state.

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PostureStatus {
    /// The check passed — the mitigation is active.
    Ok,
    /// The check passed structurally but the operator may want
    /// to act (e.g., allowlist is empty so the tool is fail-
    /// closed but inactive).
    Warn,
    /// The check failed — the mitigation is NOT active.
    Fail,
}

#[derive(Debug, Serialize)]
pub struct PostureCheck {
    pub name: &'static str,
    pub status: PostureStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct PostureReport {
    pub checks: Vec<PostureCheck>,
}

impl PostureReport {
    pub fn summary_counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.status {
                PostureStatus::Ok => ok += 1,
                PostureStatus::Warn => warn += 1,
                PostureStatus::Fail => fail += 1,
            }
        }
        (ok, warn, fail)
    }
}

pub(super) fn run(json: bool) -> Result<()> {
    let home = mvm_core::config::mvm_home_strict().ok();
    let report = build_report(home.as_deref());
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_human(&report);
    }
    // Exit non-zero if any check Fails — monitoring systems can
    // gate on this. Warns don't fail.
    let (_, _, fail) = report.summary_counts();
    if fail > 0 {
        anyhow::bail!("{fail} posture check(s) failed");
    }
    Ok(())
}

pub fn build_report(home: Option<&std::path::Path>) -> PostureReport {
    let checks = vec![
        check_host_signer(home),
        check_audit_chain(home),
        check_web_fetch_allowlist(),
        check_web_search_allowlist(),
        check_tool_staging_dir(home),
        check_overlay_root(home),
        check_secret_store(home),
        check_tls_minimum(),
    ];
    PostureReport { checks }
}

fn render_human(report: &PostureReport) {
    let (ok, warn, fail) = report.summary_counts();
    eprintln!(
        "mvmctl trust audit posture — security self-test ({} ok / {} warn / {} fail)",
        ok, warn, fail
    );
    for c in &report.checks {
        let sigil = match c.status {
            PostureStatus::Ok => "✓",
            PostureStatus::Warn => "!",
            PostureStatus::Fail => "✗",
        };
        eprintln!("  {sigil} {}: {}", c.name, c.detail);
    }
}

// ──────────────────────────────────────────────────────────────
// Individual checks
// ──────────────────────────────────────────────────────────────

fn check_host_signer(home: Option<&std::path::Path>) -> PostureCheck {
    if home.is_none() {
        return PostureCheck {
            name: "host_signer",
            status: PostureStatus::Fail,
            detail: "no home root (MVM_HOME/$HOME unset) — cannot locate the host signer key"
                .into(),
        };
    }
    let path = mvm_core::config::mvm_keys_dir().join("host-signer.ed25519");
    if !path.exists() {
        return PostureCheck {
            name: "host_signer",
            status: PostureStatus::Fail,
            detail: format!(
                "not present at {}; run any mvmctl command that signs to initialize",
                path.display()
            ),
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(&path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 {
                    return PostureCheck {
                        name: "host_signer",
                        status: PostureStatus::Fail,
                        detail: format!(
                            "{} has mode {:04o}; expected 0600. \
                             Fix with `chmod 0600 {}` or rotate.",
                            path.display(),
                            mode,
                            path.display()
                        ),
                    };
                }
            }
            Err(e) => {
                return PostureCheck {
                    name: "host_signer",
                    status: PostureStatus::Fail,
                    detail: format!("stat {}: {e}", path.display()),
                };
            }
        }
    }
    PostureCheck {
        name: "host_signer",
        status: PostureStatus::Ok,
        detail: format!("present at {} (mode 0600)", path.display()),
    }
}

fn check_audit_chain(home: Option<&std::path::Path>) -> PostureCheck {
    if home.is_none() {
        return PostureCheck {
            name: "audit_chain",
            status: PostureStatus::Fail,
            detail: "no home root (MVM_HOME/$HOME unset) — cannot locate the audit chain".into(),
        };
    }
    let path = mvm_core::config::mvm_audit_dir().join("local.jsonl");
    if !path.exists() {
        return PostureCheck {
            name: "audit_chain",
            status: PostureStatus::Warn,
            detail: format!(
                "no chain at {} yet (created on first audit-emitting command)",
                path.display()
            ),
        };
    }
    // Verifying the chain requires the host signer's verifying
    // key. Load it lazily — if it fails, surface that.
    let keys_dir = mvm_core::config::mvm_keys_dir();
    match crate::commands::vm::host_signer::load_or_init_at(&keys_dir) {
        Ok(signer) => match mvm_hostd::supervisor::verify_audit_chain(&path, &signer.verifying) {
            Ok(count) => PostureCheck {
                name: "audit_chain",
                status: PostureStatus::Ok,
                detail: format!("verified {count} entry/entries at {}", path.display()),
            },
            Err(e) => PostureCheck {
                name: "audit_chain",
                status: PostureStatus::Fail,
                detail: format!("verify_audit_chain refused {}: {e}", path.display()),
            },
        },
        Err(e) => PostureCheck {
            name: "audit_chain",
            status: PostureStatus::Fail,
            detail: format!("can't load host signer to verify chain: {e}"),
        },
    }
}

fn check_web_fetch_allowlist() -> PostureCheck {
    let raw = std::env::var(mvm_hostd::supervisor::tools::web_fetch::ALLOWLIST_ENV_VAR)
        .unwrap_or_default();
    let count = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .count();
    if count == 0 {
        return PostureCheck {
            name: "web_fetch_allowlist",
            status: PostureStatus::Warn,
            detail: format!(
                "${} unset or empty — mvm.web_fetch is fail-closed (no host reachable)",
                mvm_hostd::supervisor::tools::web_fetch::ALLOWLIST_ENV_VAR
            ),
        };
    }
    PostureCheck {
        name: "web_fetch_allowlist",
        status: PostureStatus::Ok,
        detail: format!(
            "{count} host(s) allowlisted via ${}",
            mvm_hostd::supervisor::tools::web_fetch::ALLOWLIST_ENV_VAR
        ),
    }
}

fn check_web_search_allowlist() -> PostureCheck {
    let raw = std::env::var(mvm_hostd::supervisor::tools::web_search::ALLOWLIST_ENV_VAR)
        .unwrap_or_default();
    let providers: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if providers.is_empty() {
        return PostureCheck {
            name: "web_search_allowlist",
            status: PostureStatus::Warn,
            detail: format!(
                "${} unset or empty — mvm.web_search is fail-closed (no provider reachable)",
                mvm_hostd::supervisor::tools::web_search::ALLOWLIST_ENV_VAR
            ),
        };
    }
    // Inspect per-provider credential reachability via env var.
    // (We don't peek into the secret_store here — that would
    // require building one, which has side effects. Operators
    // running --json against a monitoring agent expect a no-IO
    // posture check.)
    let mut details = Vec::new();
    for p in &providers {
        let configured = match p.as_str() {
            "brave" => {
                std::env::var(mvm_hostd::supervisor::tools::web_search::BRAVE_API_KEY_ENV_VAR)
                    .is_ok()
                    || std::env::var("BRAVE_API_KEY_FROM_SECRET").is_ok()
            }
            "tavily" => {
                std::env::var(mvm_hostd::supervisor::tools::web_search::TAVILY_API_KEY_ENV_VAR)
                    .is_ok()
                    || std::env::var("TAVILY_API_KEY_FROM_SECRET").is_ok()
            }
            "google" => {
                (std::env::var(mvm_hostd::supervisor::tools::web_search::GOOGLE_API_KEY_ENV_VAR)
                    .is_ok()
                    || std::env::var("GOOGLE_API_KEY_FROM_SECRET").is_ok())
                    && (std::env::var(
                        mvm_hostd::supervisor::tools::web_search::GOOGLE_CSE_ID_ENV_VAR,
                    )
                    .is_ok()
                        || std::env::var("GOOGLE_CSE_ID_FROM_SECRET").is_ok())
            }
            _ => false,
        };
        details.push(format!(
            "{}={}",
            p,
            if configured {
                "configured"
            } else {
                "missing-key"
            }
        ));
    }
    let any_missing = details.iter().any(|d| d.ends_with("missing-key"));
    PostureCheck {
        name: "web_search_allowlist",
        status: if any_missing {
            PostureStatus::Warn
        } else {
            PostureStatus::Ok
        },
        detail: details.join(", "),
    }
}

fn check_tool_staging_dir(home: Option<&std::path::Path>) -> PostureCheck {
    let path = match std::env::var_os(mvm_hostd::supervisor::tools::staging::STAGING_DIR_ENV_VAR) {
        Some(p) => std::path::PathBuf::from(p),
        None => match home {
            Some(_) => std::path::PathBuf::from(mvm_core::config::mvm_home()).join("tool-staging"),
            None => {
                return PostureCheck {
                    name: "tool_staging_dir",
                    status: PostureStatus::Fail,
                    detail: "no home root (MVM_HOME/$HOME unset) and $MVM_TOOL_STAGING_DIR not set"
                        .into(),
                };
            }
        },
    };
    if !path.exists() {
        return PostureCheck {
            name: "tool_staging_dir",
            status: PostureStatus::Warn,
            detail: format!(
                "{} does not exist yet (created on first upload/download call)",
                path.display()
            ),
        };
    }
    check_dir_mode_0700(&path, "tool_staging_dir")
}

fn check_overlay_root(home: Option<&std::path::Path>) -> PostureCheck {
    if home.is_none() {
        return PostureCheck {
            name: "overlay_root",
            status: PostureStatus::Fail,
            detail: "no home root (MVM_HOME/$HOME unset)".into(),
        };
    }
    let path = mvm_core::config::mvm_overlays_dir();
    if !path.exists() {
        return PostureCheck {
            name: "overlay_root",
            status: PostureStatus::Warn,
            detail: format!(
                "{} does not exist yet (created on first overlay create)",
                path.display()
            ),
        };
    }
    let mut check = check_dir_mode_0700(&path, "overlay_root");
    // Tack on tenant count to the detail string.
    if let Ok(entries) = std::fs::read_dir(&path) {
        let tenant_count = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .count();
        check.detail = format!("{} ({tenant_count} tenant(s))", check.detail);
    }
    check
}

fn check_secret_store(home: Option<&std::path::Path>) -> PostureCheck {
    if home.is_none() {
        return PostureCheck {
            name: "secret_store",
            status: PostureStatus::Fail,
            detail: "no home root (MVM_HOME/$HOME unset)".into(),
        };
    }
    let path = mvm_core::config::mvm_secrets_dir();
    if !path.exists() {
        return PostureCheck {
            name: "secret_store",
            status: PostureStatus::Warn,
            detail: format!(
                "{} does not exist (no secrets stored yet via mvmctl secret put)",
                path.display()
            ),
        };
    }
    check_dir_mode_0700(&path, "secret_store")
}

fn check_tls_minimum() -> PostureCheck {
    // The constant is compile-time-pinned at TLS 1.3. This check is
    // a "config did not regress" signal — the
    // unit test `w7_min_tls_version_is_pinned_at_1_3` would have
    // caught a regression at compile time, but the operator-
    // visible report mentioning it adds confidence.
    let v = mvm_hostd::supervisor::tools::http_hardening::MIN_TLS_VERSION;
    let detail = format!("pinned to {v:?} (plan 65 W7)");
    if v == mvm_http::TlsVersion::Tls13 {
        PostureCheck {
            name: "tls_minimum",
            status: PostureStatus::Ok,
            detail,
        }
    } else {
        PostureCheck {
            name: "tls_minimum",
            status: PostureStatus::Fail,
            detail: format!("{detail} — expected Tls13, hardening regressed"),
        }
    }
}

fn check_dir_mode_0700(path: &std::path::Path, name: &'static str) -> PostureCheck {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o700 {
                    PostureCheck {
                        name,
                        status: PostureStatus::Ok,
                        detail: format!("{} mode 0700", path.display()),
                    }
                } else {
                    PostureCheck {
                        name,
                        status: PostureStatus::Fail,
                        detail: format!(
                            "{} has mode {:04o}; expected 0700. Fix with `chmod 0700 {}`.",
                            path.display(),
                            mode,
                            path.display()
                        ),
                    }
                }
            }
            Err(e) => PostureCheck {
                name,
                status: PostureStatus::Fail,
                detail: format!("stat {}: {e}", path.display()),
            },
        }
    }
    #[cfg(not(unix))]
    {
        PostureCheck {
            name,
            status: PostureStatus::Ok,
            detail: format!("{} present (Unix-mode check skipped)", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn build_fake_home() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("keys")).unwrap();
        dir
    }

    // Production paths resolve via mvm_core::config::mvm_home()
    // (MVM_HOME first, then $HOME). Point MVM_HOME at the tempdir so the
    // helper-built paths land in the temp tree the test populates.
    // Restored on drop by the shared process-env guard.

    struct DataDirGuard {
        _env: mvm_core::util::test_env::TestEnv,
    }

    impl DataDirGuard {
        fn new(home: &std::path::Path) -> Self {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.set("MVM_HOME", home);
            Self { _env: env }
        }
    }

    fn write_mode(path: &std::path::Path, content: &[u8], mode: u32) {
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    // ──────────────────────────────────────────────────────────
    // Host signer
    // ──────────────────────────────────────────────────────────

    #[test]
    fn host_signer_check_fails_when_missing() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let check = check_host_signer(Some(dir.path()));
        assert_eq!(check.status, PostureStatus::Fail);
        assert!(check.detail.contains("not present"), "{}", check.detail);
    }

    #[cfg(unix)]
    #[test]
    fn host_signer_check_fails_when_mode_loose() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let signer = dir.path().join("keys").join("host-signer.ed25519");
        write_mode(&signer, &[0u8; 32], 0o644);
        let check = check_host_signer(Some(dir.path()));
        assert_eq!(check.status, PostureStatus::Fail);
        assert!(check.detail.contains("0644"), "{}", check.detail);
    }

    #[cfg(unix)]
    #[test]
    fn host_signer_check_passes_at_0600() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let signer = dir.path().join("keys").join("host-signer.ed25519");
        write_mode(&signer, &[0u8; 32], 0o600);
        let check = check_host_signer(Some(dir.path()));
        assert_eq!(check.status, PostureStatus::Ok);
    }

    // ──────────────────────────────────────────────────────────
    // Overlay root
    // ──────────────────────────────────────────────────────────

    #[test]
    fn overlay_root_check_warns_when_missing() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let check = check_overlay_root(Some(dir.path()));
        assert_eq!(check.status, PostureStatus::Warn);
    }

    #[cfg(unix)]
    #[test]
    fn overlay_root_check_passes_at_0700_with_tenant_count() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let overlay = dir.path().join("overlays");
        std::fs::create_dir_all(&overlay).unwrap();
        std::fs::create_dir_all(overlay.join("acme")).unwrap();
        std::fs::create_dir_all(overlay.join("beta")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&overlay, std::fs::Permissions::from_mode(0o700)).unwrap();
        let check = check_overlay_root(Some(dir.path()));
        assert_eq!(check.status, PostureStatus::Ok);
        assert!(check.detail.contains("2 tenant"), "{}", check.detail);
    }

    #[cfg(unix)]
    #[test]
    fn overlay_root_check_fails_at_0755() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let overlay = dir.path().join("overlays");
        std::fs::create_dir_all(&overlay).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&overlay, std::fs::Permissions::from_mode(0o755)).unwrap();
        let check = check_overlay_root(Some(dir.path()));
        assert_eq!(check.status, PostureStatus::Fail);
        assert!(check.detail.contains("0755"), "{}", check.detail);
    }

    // ──────────────────────────────────────────────────────────
    // TLS minimum
    // ──────────────────────────────────────────────────────────

    #[test]
    fn tls_minimum_check_passes_when_pinned_at_1_3() {
        let check = check_tls_minimum();
        assert_eq!(check.status, PostureStatus::Ok);
        // `mvm_http::TlsVersion`'s Debug renders as `Tls13`.
        assert!(check.detail.contains("Tls13"), "{}", check.detail);
        assert!(check.detail.contains("W7"), "{}", check.detail);
    }

    // ──────────────────────────────────────────────────────────
    // Report summary
    // ──────────────────────────────────────────────────────────

    #[test]
    fn report_summary_counts_ok_warn_fail() {
        let report = PostureReport {
            checks: vec![
                PostureCheck {
                    name: "a",
                    status: PostureStatus::Ok,
                    detail: String::new(),
                },
                PostureCheck {
                    name: "b",
                    status: PostureStatus::Warn,
                    detail: String::new(),
                },
                PostureCheck {
                    name: "c",
                    status: PostureStatus::Fail,
                    detail: String::new(),
                },
                PostureCheck {
                    name: "d",
                    status: PostureStatus::Ok,
                    detail: String::new(),
                },
            ],
        };
        assert_eq!(report.summary_counts(), (2, 1, 1));
    }

    #[test]
    fn build_report_emits_all_checks() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let report = build_report(Some(dir.path()));
        // The list of check names is stable; pin the count so a
        // future addition is a deliberate update.
        let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            vec![
                "host_signer",
                "audit_chain",
                "web_fetch_allowlist",
                "web_search_allowlist",
                "tool_staging_dir",
                "overlay_root",
                "secret_store",
                "tls_minimum",
            ]
        );
    }

    #[test]
    fn report_serializes_to_stable_json_keys() {
        let dir = build_fake_home();
        let _g = DataDirGuard::new(dir.path());
        let report = build_report(Some(dir.path()));
        let json = serde_json::to_string(&report).unwrap();
        // The check names + the lowercase status enum are part of
        // the wire contract that operators script against.
        assert!(json.contains("\"host_signer\""), "{json}");
        assert!(json.contains("\"tls_minimum\""), "{json}");
        // Status enum uses lowercase via #[serde(rename_all)].
        assert!(json.contains("\"ok\"") || json.contains("\"warn\"") || json.contains("\"fail\""));
    }
}
