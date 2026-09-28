//! Runtime approvals, answered by the `mvmctl` that launched the run.
//!
//! A route rule or a secret binding whose decision is `ask` makes the VM's
//! network endpoint hold the flow and put the question to the approval socket
//! in the VM's socket directory. This module binds that socket for the life
//! of a foreground run and answers with the backends the launch chose:
//!
//! - `--approval tty|deny|webhook=URL` (repeatable) on the command line, else
//! - `[approval] backends = [...]` in the project's `mvm.toml`, else
//! - the terminal when an operator is at one, and deny otherwise.
//!
//! Several backends combine under `--approval-mode all|any` (or
//! `[approval] mode`), `all` by default. Nothing here decides anything on its
//! own: the endpoint enforces the timeout, rate limit and session ledger, and
//! audits every step. A run with no broker — a detached machine, a failed bind
//! — gets no answer, which the endpoint turns into a denial.

pub mod tty;

use std::io::IsTerminal;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use mvm_client::approval_broker::{
    ApprovalBackend, ApprovalServer, ChainBackend, ChainMode, DenyBackend, WebhookBackend,
};
use mvm_core::manifest::{ApprovalChainMode, ManifestApproval};

/// One approval backend, as `--approval` and `[approval] backends` spell it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSpec {
    /// Ask on the controlling terminal.
    Tty,
    /// Refuse every request.
    Deny,
    /// POST the question to a URL (`https://`, or `http://` to loopback).
    Webhook(String),
}

impl FromStr for ApprovalSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "tty" => Ok(Self::Tty),
            "deny" => Ok(Self::Deny),
            other => match other.strip_prefix("webhook=") {
                Some(url) => {
                    WebhookBackend::new(url)?;
                    Ok(Self::Webhook(url.to_string()))
                }
                None => anyhow::bail!(
                    "unknown approval backend {other:?}: expected tty, deny, or webhook=URL"
                ),
            },
        }
    }
}

/// Parse `--approval-mode`.
///
/// # Errors
///
/// Anything but `all` or `any`.
pub fn parse_mode(s: &str) -> Result<ApprovalChainMode> {
    match s {
        "all" => Ok(ApprovalChainMode::All),
        "any" => Ok(ApprovalChainMode::Any),
        other => anyhow::bail!("unknown approval mode {other:?}: expected all or any"),
    }
}

/// The backends a launch answers approvals with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalChoice {
    backends: Vec<ApprovalSpec>,
    mode: ApprovalChainMode,
}

/// What a launch was given to choose from.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalInputs<'a> {
    /// `--approval`, in order.
    pub flags: &'a [ApprovalSpec],
    /// `--approval-mode`.
    pub flag_mode: Option<ApprovalChainMode>,
    /// The project manifest's `[approval]`, if it has one.
    pub manifest: Option<&'a ManifestApproval>,
    /// Whether an operator is at a terminal to ask.
    pub operator_at_terminal: bool,
}

impl ApprovalChoice {
    /// Resolve a launch's choice: flags over the manifest over the default.
    ///
    /// # Errors
    ///
    /// A manifest backend that does not parse.
    pub fn resolve(inputs: ApprovalInputs<'_>) -> Result<Self> {
        let manifest = inputs.manifest.cloned().unwrap_or_default();
        let backends = if !inputs.flags.is_empty() {
            inputs.flags.to_vec()
        } else if !manifest.backends.is_empty() {
            manifest
                .backends
                .iter()
                .map(|b| b.parse())
                .collect::<Result<Vec<_>>>()
                .context("invalid `[approval] backends` in mvm.toml")?
        } else {
            vec![Self::default_backend(inputs.operator_at_terminal)]
        };
        Ok(Self {
            backends,
            mode: inputs.flag_mode.or(manifest.mode).unwrap_or_default(),
        })
    }

    /// The choice with nothing configured.
    #[must_use]
    pub fn default_for(operator_at_terminal: bool) -> Self {
        Self {
            backends: vec![Self::default_backend(operator_at_terminal)],
            mode: ApprovalChainMode::All,
        }
    }

    fn default_backend(operator_at_terminal: bool) -> ApprovalSpec {
        if operator_at_terminal {
            ApprovalSpec::Tty
        } else {
            ApprovalSpec::Deny
        }
    }

    /// The backends, in the order they are asked.
    #[must_use]
    pub fn backends(&self) -> &[ApprovalSpec] {
        &self.backends
    }

    /// The backend that answers. `interactive_run` is whether the run itself
    /// reads the terminal (`-it`), which the terminal backend must not race.
    ///
    /// # Errors
    ///
    /// A webhook URL that does not parse (already refused at resolution).
    pub fn backend(&self, interactive_run: bool) -> Result<Arc<dyn ApprovalBackend>> {
        let mut members = self
            .backends
            .iter()
            .map(|spec| member(spec, interactive_run))
            .collect::<Result<Vec<_>>>()?;
        if members.len() == 1 {
            return Ok(Arc::from(members.remove(0)));
        }
        let mode = match self.mode {
            ApprovalChainMode::All => ChainMode::All,
            ApprovalChainMode::Any => ChainMode::Any,
        };
        Ok(Arc::new(ChainBackend::new(mode, members)))
    }
}

fn member(spec: &ApprovalSpec, interactive_run: bool) -> Result<Box<dyn ApprovalBackend>> {
    Ok(match spec {
        ApprovalSpec::Tty => Box::new(tty::TerminalBackend::controlling(interactive_run)),
        ApprovalSpec::Deny => Box::new(DenyBackend),
        ApprovalSpec::Webhook(url) => Box::new(WebhookBackend::new(url)?),
    })
}

/// Whether an operator is at a terminal this process can ask on: standard
/// error is a terminal, and there is a controlling terminal to open.
#[must_use]
pub fn operator_at_terminal() -> bool {
    std::io::stderr().is_terminal() && std::fs::File::open("/dev/tty").is_ok()
}

static CHOICE: Mutex<Option<ApprovalChoice>> = Mutex::new(None);

/// Record the choice this process's launches answer approvals with.
pub fn configure(choice: ApprovalChoice) {
    *CHOICE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(choice);
}

fn configured() -> ApprovalChoice {
    CHOICE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| ApprovalChoice::default_for(operator_at_terminal()))
}

/// Bind the approval broker for the booted VM `vm_name`, answering with the
/// configured choice. Held for the run and dropped at teardown.
///
/// A broker that cannot be bound is reported and skipped: the endpoint then
/// gets no answer and denies, which is the safe failure.
#[must_use]
pub fn serve_for(vm_name: &str, interactive_run: bool) -> Option<ApprovalServer> {
    let path = mvm_core::config::vm_approval_socket(vm_name);
    let served = configured()
        .backend(interactive_run)
        .and_then(|backend| ApprovalServer::bind(&path, backend));
    match served {
        Ok(server) => Some(server),
        Err(e) => {
            tracing::warn!(
                vm = vm_name,
                error = %format!("{e:#}"),
                "approval broker not started; requests that ask will be denied"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::approval_broker::{ApprovalPrompt, ApprovalSubject};
    use mvm_contract::policy::approval::{ApprovalOutcome, ApprovalRequestId};

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse("apr-1").unwrap(),
            subject: ApprovalSubject::ToolCall {
                tool: "shell".into(),
            },
            expires_in_ms: 5_000,
        }
    }

    #[test]
    fn specs_parse_and_a_plain_http_webhook_is_refused() {
        assert_eq!("tty".parse::<ApprovalSpec>().unwrap(), ApprovalSpec::Tty);
        assert_eq!("deny".parse::<ApprovalSpec>().unwrap(), ApprovalSpec::Deny);
        assert_eq!(
            "webhook=https://a.example/h"
                .parse::<ApprovalSpec>()
                .unwrap(),
            ApprovalSpec::Webhook("https://a.example/h".into())
        );
        assert!(
            "webhook=http://127.0.0.1:9/h"
                .parse::<ApprovalSpec>()
                .is_ok()
        );
        for bad in ["webhook=http://a.example/h", "webhook=ftp://x", "ask", ""] {
            assert!(bad.parse::<ApprovalSpec>().is_err(), "{bad}");
        }
        assert_eq!(parse_mode("any").unwrap(), ApprovalChainMode::Any);
        assert!(parse_mode("most").is_err());
    }

    #[test]
    fn the_default_asks_an_operator_at_a_terminal_and_denies_otherwise() {
        let inputs = |at_terminal| ApprovalInputs {
            flags: &[],
            flag_mode: None,
            manifest: None,
            operator_at_terminal: at_terminal,
        };
        assert_eq!(
            ApprovalChoice::resolve(inputs(true)).unwrap().backends(),
            [ApprovalSpec::Tty]
        );
        assert_eq!(
            ApprovalChoice::resolve(inputs(false)).unwrap().backends(),
            [ApprovalSpec::Deny]
        );
    }

    #[test]
    fn flags_replace_the_manifest_and_the_manifest_replaces_the_default() {
        let manifest = ManifestApproval {
            backends: vec!["webhook=https://a.example/h".into()],
            mode: Some(ApprovalChainMode::Any),
        };
        let from_manifest = ApprovalChoice::resolve(ApprovalInputs {
            flags: &[],
            flag_mode: None,
            manifest: Some(&manifest),
            operator_at_terminal: true,
        })
        .unwrap();
        assert_eq!(
            from_manifest.backends(),
            [ApprovalSpec::Webhook("https://a.example/h".into())]
        );
        assert_eq!(from_manifest.mode, ApprovalChainMode::Any);

        let from_flags = ApprovalChoice::resolve(ApprovalInputs {
            flags: &[ApprovalSpec::Deny],
            flag_mode: Some(ApprovalChainMode::All),
            manifest: Some(&manifest),
            operator_at_terminal: true,
        })
        .unwrap();
        assert_eq!(from_flags.backends(), [ApprovalSpec::Deny]);
        assert_eq!(from_flags.mode, ApprovalChainMode::All);

        let broken = ManifestApproval {
            backends: vec!["webhook=http://a.example/h".into()],
            mode: None,
        };
        assert!(
            ApprovalChoice::resolve(ApprovalInputs {
                flags: &[],
                flag_mode: None,
                manifest: Some(&broken),
                operator_at_terminal: false,
            })
            .is_err()
        );
    }

    #[test]
    fn a_chain_combines_under_its_mode() {
        let chain = |mode| ApprovalChoice {
            backends: vec![ApprovalSpec::Deny, ApprovalSpec::Tty],
            mode,
        };
        // The terminal member is busy (an `-it` run), so it denies too: both
        // modes refuse, and neither reaches a real terminal.
        for mode in [ApprovalChainMode::All, ApprovalChainMode::Any] {
            let answer = chain(mode).backend(true).unwrap().decide(&prompt());
            assert_eq!(answer.outcome, ApprovalOutcome::Denied, "{mode:?}");
        }
    }

    #[test]
    fn a_broker_serves_the_vm_socket_and_removes_it_when_dropped() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let vm = "approval-serve-test";
        let path = mvm_core::config::vm_approval_socket(vm);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        configure(ApprovalChoice {
            backends: vec![ApprovalSpec::Deny],
            mode: ApprovalChainMode::All,
        });
        let server = serve_for(vm, false).expect("bound");
        assert_eq!(server.path(), path);
        assert!(path.exists());
        drop(server);
        assert!(!path.exists());
        drop(env);
    }
}
