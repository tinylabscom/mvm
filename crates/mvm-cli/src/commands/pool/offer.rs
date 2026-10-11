//! The offer an interactive run makes when strict startup refuses it.
//!
//! An unnamed run that a shared standby could serve must claim one. When there
//! is none it is refused, and the refusal names the fix. On a terminal, with a
//! person at it, the run also offers to apply that fix: prepare a standby of
//! the same image and sizing, then retry the launch once.
//!
//! The offer is never made where nobody can answer it. A run under CI, with
//! `--json`, or with any of stdin, stdout or stderr redirected returns the
//! refusal exactly as it always has. Stdout is included because the
//! confirmation helper writes its question there; a prompt nobody sees would
//! leave the run waiting on input nobody knows to give.
//!
//! Residency is respected rather than changed. An operator who set
//! `MVM_RESIDENCY` to `parked` or `cold` chose not to hold standbys, so that
//! refusal stands. On a host whose *default* is `parked` (Linux), the retried
//! launch claims with a warm target of one — exactly what `MVM_RESIDENCY=warm`
//! gives a single run — and the offer says to export it so later runs claim
//! too. Nothing is written to the host's configuration.

use anyhow::Result;
use mvm_core::residency::{ResidencyKind, ResidencySource};
use mvm_core::vm_backend::WarmClaimRefusal;

use super::{StrictStartupNeedsWarmTarget, WarmRequest};
use crate::commands::vm::exec::RunArgs;

/// The image and sizing a refused run would have claimed, in the form
/// `pool warm` prepares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct WarmOffer {
    /// The `--image` the run named, or `None` for the default image.
    image: Option<String>,
    cpus: u32,
    /// `--memory` exactly as the run was given it, for the printed command.
    memory: String,
    memory_mib: u32,
}

impl WarmOffer {
    /// The offer for `args`, or `None` when `pool warm` cannot prepare what
    /// the run boots. It prepares an OCI image or the default image on the
    /// auto-selected backend; a manifest, flake, deployment, runtime, plan or
    /// named hypervisor selects something else, so offering to warm would
    /// warm a standby the retry still could not claim.
    pub(in crate::commands) fn for_run(args: &RunArgs, has_source_override: bool) -> Option<Self> {
        let other_source = has_source_override
            || args.manifest.is_some()
            || args.flake.is_some()
            || args.deployment.is_some()
            || args.runtime_pack
            || args.runtime.is_some()
            || args.source.is_some()
            || args.registry_pack_image.is_some()
            || args.launch_plan.is_some()
            || args.from_workload_ir.is_some()
            || args.plan.is_some();
        let other_backend = args.hypervisor.is_some() || args.policy_backend.is_some();
        if other_source || other_backend || args.vm_name.is_some() {
            return None;
        }
        let memory_mib = mvm_core::util::parse_human_size(&args.memory).ok()?;
        Some(Self {
            image: args.image.clone(),
            cpus: args.cpus,
            memory: args.memory.clone(),
            memory_mib,
        })
    }

    fn label(&self) -> &str {
        self.image.as_deref().unwrap_or("the default image")
    }

    /// The command that prepares this standby by hand.
    fn command(&self) -> String {
        let image = match &self.image {
            Some(image) => format!("--image {image}"),
            None => "--default".to_string(),
        };
        format!(
            "mvmctl pool warm {image} --cpus {} --memory {}",
            self.cpus, self.memory
        )
    }

    fn request(&self) -> WarmRequest {
        WarmRequest {
            image: self.image.clone(),
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            target: 1,
        }
    }
}

/// Whether a person can answer a prompt here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) struct RefusalTerminal {
    pub(in crate::commands) stdin_tty: bool,
    pub(in crate::commands) stdout_tty: bool,
    pub(in crate::commands) stderr_tty: bool,
    pub(in crate::commands) ci: bool,
    pub(in crate::commands) json: bool,
}

impl RefusalTerminal {
    /// This process's terminal, for a run that was or was not given `--json`.
    pub(in crate::commands) fn detect(json: bool) -> Self {
        use std::io::IsTerminal as _;
        Self {
            stdin_tty: std::io::stdin().is_terminal(),
            stdout_tty: std::io::stdout().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
            ci: std::env::var_os("CI").is_some(),
            json,
        }
    }

    /// Whether the offer may prompt: every stream a terminal, not CI, not
    /// `--json`.
    pub(in crate::commands) fn can_prompt(&self) -> bool {
        self.stdin_tty && self.stdout_tty && self.stderr_tty && !self.ci && !self.json
    }
}

/// Which strict-startup refusal an error is, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupRefusal {
    /// The host's residency holds no warm target.
    NoWarmTarget,
    /// A warm target is held, but no standby matches this launch.
    NoCompatibleStandby,
}

fn classify(err: &anyhow::Error) -> Option<StartupRefusal> {
    err.chain().find_map(|cause| {
        if cause.is::<StrictStartupNeedsWarmTarget>() {
            return Some(StartupRefusal::NoWarmTarget);
        }
        match cause.downcast_ref::<WarmClaimRefusal>() {
            Some(WarmClaimRefusal::NoCompatibleParent) => Some(StartupRefusal::NoCompatibleStandby),
            _ => None,
        }
    })
}

/// What the offer does on the terminal and to the pool. A trait so the
/// decision is testable without a terminal or a VM.
trait OfferIo {
    fn say(&mut self, line: &str);
    fn ask(&mut self, question: &str) -> bool;
    fn warm(&mut self, req: &WarmRequest) -> Result<()>;
}

struct ProcessIo;

impl OfferIo for ProcessIo {
    fn say(&mut self, line: &str) {
        eprintln!("{line}");
    }
    fn ask(&mut self, question: &str) -> bool {
        crate::ui::confirm(question)
    }
    fn warm(&mut self, req: &WarmRequest) -> Result<()> {
        super::warm_request(req)
    }
}

/// Run `launch` and, if strict startup refuses it on an interactive terminal,
/// offer to prepare the standby and retry once.
///
/// `launch` receives the warm target the attempt claims with: `None` keeps
/// the one the run resolved, `Some(1)` stands in for `MVM_RESIDENCY=warm` on
/// a retry where the host default holds no target.
pub(in crate::commands) fn launch_with_warm_offer(
    offer: Option<WarmOffer>,
    terminal: RefusalTerminal,
    mut launch: impl FnMut(Option<u32>) -> Result<()>,
) -> Result<()> {
    let Err(err) = launch(None) else {
        return Ok(());
    };
    // Settle the cases with no offer before resolving residency, which can
    // itself write to stderr: a refusal nobody is offered a fix for leaves
    // exactly as it always has.
    if offer.is_none() || !terminal.can_prompt() || classify(&err).is_none() {
        return Err(err);
    }
    let (policy, source) = mvm_core::residency::resolve_residency();
    offer_after_refusal(
        err,
        offer.as_ref(),
        terminal,
        (policy.kind(), source),
        &mut ProcessIo,
        launch,
    )
}

fn offer_after_refusal(
    err: anyhow::Error,
    offer: Option<&WarmOffer>,
    terminal: RefusalTerminal,
    residency: (ResidencyKind, ResidencySource),
    io: &mut dyn OfferIo,
    retry: impl FnOnce(Option<u32>) -> Result<()>,
) -> Result<()> {
    let (Some(refusal), Some(offer)) = (classify(&err), offer) else {
        return Err(err);
    };
    if !terminal.can_prompt() {
        return Err(err);
    }
    let holds_warm = matches!(residency.0, ResidencyKind::Warm);
    if !holds_warm && matches!(residency.1, ResidencySource::EnvOverride) {
        // MVM_RESIDENCY was set to hold no standbys; that choice stands.
        return Err(err);
    }
    io.say(&format!("{err:#}"));
    io.say(&match refusal {
        StartupRefusal::NoWarmTarget => {
            "This host holds no warm standbys by default (residency: parked).".to_string()
        }
        StartupRefusal::NoCompatibleStandby => {
            format!(
                "No warm standby of {} at this sizing is prepared.",
                offer.label()
            )
        }
    });
    io.say(&format!("To prepare one: {}", offer.command()));
    if !holds_warm {
        io.say("To let later unnamed runs claim it: export MVM_RESIDENCY=warm");
    }
    if !io.ask(&format!(
        "Prepare a standby for {} now? [y/N]",
        offer.label()
    )) {
        return Err(err);
    }
    io.warm(&offer.request())?;
    retry((!holds_warm).then_some(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERACTIVE: RefusalTerminal = RefusalTerminal {
        stdin_tty: true,
        stdout_tty: true,
        stderr_tty: true,
        ci: false,
        json: false,
    };
    const AUTO_PARKED: (ResidencyKind, ResidencySource) =
        (ResidencyKind::Parked, ResidencySource::AutoDetect);
    const AUTO_WARM: (ResidencyKind, ResidencySource) =
        (ResidencyKind::Warm, ResidencySource::AutoDetect);

    #[derive(Default)]
    struct Recorder {
        said: Vec<String>,
        asked: Vec<String>,
        answer: bool,
        warmed: Vec<WarmRequest>,
    }

    impl OfferIo for Recorder {
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
        fn ask(&mut self, question: &str) -> bool {
            self.asked.push(question.to_string());
            self.answer
        }
        fn warm(&mut self, req: &WarmRequest) -> Result<()> {
            self.warmed.push(req.clone());
            Ok(())
        }
    }

    fn alpine() -> WarmOffer {
        WarmOffer {
            image: Some("alpine".to_string()),
            cpus: 2,
            memory: "512M".to_string(),
            memory_mib: 512,
        }
    }

    fn zero_pool_refusal() -> anyhow::Error {
        anyhow::Error::new(StrictStartupNeedsWarmTarget).context("claiming configured warm standby")
    }

    /// Runs the offer and returns the recorder, the retry's warm target when
    /// it ran, and the result.
    fn offer(
        err: anyhow::Error,
        terminal: RefusalTerminal,
        residency: (ResidencyKind, ResidencySource),
        answer: bool,
    ) -> (Recorder, Option<Option<u32>>, Result<()>) {
        let mut io = Recorder {
            answer,
            ..Recorder::default()
        };
        let mut retried = None;
        let result = offer_after_refusal(
            err,
            Some(&alpine()),
            terminal,
            residency,
            &mut io,
            |target| {
                retried = Some(target);
                Ok(())
            },
        );
        (io, retried, result)
    }

    #[test]
    fn a_non_interactive_refusal_is_returned_untouched_without_a_prompt() {
        let expected = format!("{:#}", zero_pool_refusal());
        for terminal in [
            RefusalTerminal {
                stdin_tty: false,
                ..INTERACTIVE
            },
            RefusalTerminal {
                stdout_tty: false,
                ..INTERACTIVE
            },
            RefusalTerminal {
                stderr_tty: false,
                ..INTERACTIVE
            },
            RefusalTerminal {
                ci: true,
                ..INTERACTIVE
            },
            RefusalTerminal {
                json: true,
                ..INTERACTIVE
            },
        ] {
            let (io, retried, result) = offer(zero_pool_refusal(), terminal, AUTO_PARKED, true);
            assert!(io.said.is_empty() && io.asked.is_empty(), "{terminal:?}");
            assert!(io.warmed.is_empty() && retried.is_none(), "{terminal:?}");
            assert_eq!(format!("{:#}", result.unwrap_err()), expected);
        }
    }

    #[test]
    fn the_prompt_names_the_image_and_defaults_to_no() {
        let (io, retried, result) = offer(zero_pool_refusal(), INTERACTIVE, AUTO_PARKED, false);
        assert_eq!(io.asked, ["Prepare a standby for alpine now? [y/N]"]);
        assert!(io.warmed.is_empty(), "declining must not warm");
        assert!(retried.is_none(), "declining must not retry");
        assert_eq!(
            format!("{:#}", result.unwrap_err()),
            format!("{:#}", zero_pool_refusal())
        );
        assert!(
            io.said
                .iter()
                .any(|l| l
                    == "To prepare one: mvmctl pool warm --image alpine --cpus 2 --memory 512M"),
            "{:?}",
            io.said
        );
    }

    #[test]
    fn yes_on_a_parked_default_warms_once_and_retries_with_a_warm_target() {
        let (io, retried, result) = offer(zero_pool_refusal(), INTERACTIVE, AUTO_PARKED, true);
        result.unwrap();
        assert_eq!(io.warmed, [alpine().request()]);
        assert_eq!(retried, Some(Some(1)));
        assert!(
            io.said
                .iter()
                .any(|l| l.contains("export MVM_RESIDENCY=warm")),
            "{:?}",
            io.said
        );
    }

    #[test]
    fn yes_under_warm_residency_retries_with_the_resolved_target() {
        let err = anyhow::Error::new(WarmClaimRefusal::NoCompatibleParent);
        let (io, retried, result) = offer(err, INTERACTIVE, AUTO_WARM, true);
        result.unwrap();
        assert_eq!(io.warmed.len(), 1);
        assert_eq!(retried, Some(None));
        assert!(!io.said.iter().any(|l| l.contains("export MVM_RESIDENCY")));
    }

    #[test]
    fn an_operator_chosen_parked_residency_is_not_overridden() {
        let (io, retried, result) = offer(
            zero_pool_refusal(),
            INTERACTIVE,
            (ResidencyKind::Parked, ResidencySource::EnvOverride),
            true,
        );
        assert!(io.asked.is_empty() && retried.is_none());
        assert!(result.is_err());
    }

    #[test]
    fn other_errors_and_other_refusals_get_no_offer() {
        for err in [
            anyhow::anyhow!("kernel not found"),
            anyhow::Error::new(WarmClaimRefusal::BackendUnsupported {
                backend: "wasm".to_string(),
            }),
        ] {
            let (io, retried, result) = offer(err, INTERACTIVE, AUTO_WARM, true);
            assert!(io.asked.is_empty() && retried.is_none());
            assert!(result.is_err());
        }
    }

    #[test]
    fn a_failed_warm_is_returned_without_a_retry() {
        struct FailingWarm(Recorder);
        impl OfferIo for FailingWarm {
            fn say(&mut self, line: &str) {
                self.0.say(line);
            }
            fn ask(&mut self, question: &str) -> bool {
                self.0.ask(question)
            }
            fn warm(&mut self, _: &WarmRequest) -> Result<()> {
                anyhow::bail!("pool warm: 0/1 standby(s) warmed")
            }
        }
        let mut io = FailingWarm(Recorder {
            answer: true,
            ..Recorder::default()
        });
        let mut retried = false;
        let result = offer_after_refusal(
            zero_pool_refusal(),
            Some(&alpine()),
            INTERACTIVE,
            AUTO_PARKED,
            &mut io,
            |_| {
                retried = true;
                Ok(())
            },
        );
        assert!(!retried);
        assert!(result.unwrap_err().to_string().contains("0/1"));
    }

    #[test]
    fn the_default_image_is_offered_through_pool_warm_default() {
        let offer = WarmOffer {
            image: None,
            ..alpine()
        };
        assert_eq!(offer.label(), "the default image");
        assert_eq!(
            offer.command(),
            "mvmctl pool warm --default --cpus 2 --memory 512M"
        );
    }

    #[test]
    fn a_run_of_another_source_or_backend_gets_no_offer() {
        let image_run = RunArgs {
            image: Some("alpine".to_string()),
            cpus: 2,
            memory: "512M".to_string(),
            ..RunArgs::default()
        };
        assert_eq!(WarmOffer::for_run(&image_run, false), Some(alpine()));
        assert_eq!(WarmOffer::for_run(&image_run, true), None);
        let manifest_run = RunArgs {
            manifest: Some("./mvm.toml".to_string()),
            ..image_run.clone()
        };
        assert_eq!(WarmOffer::for_run(&manifest_run, false), None);
        let libkrun_run = RunArgs {
            hypervisor: Some("libkrun".to_string()),
            ..image_run.clone()
        };
        assert_eq!(WarmOffer::for_run(&libkrun_run, false), None);
        let named_run = RunArgs {
            vm_name: Some("web".to_string()),
            ..image_run
        };
        assert_eq!(WarmOffer::for_run(&named_run, false), None);
    }
}
