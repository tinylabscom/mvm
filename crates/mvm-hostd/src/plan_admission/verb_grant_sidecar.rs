//! Persist the signed agent and drive authority consumed at guest boot.

use super::write_secret_file;
use anyhow::{Context, Result};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan, VerbId};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use std::path::Path;

/// Mint a signed `VerbGrantEnvelope` when the plan carries agent, drive,
/// or application-terminal authority and write it to `<state_dir>/verb-grant.json` at mode 0600.
///
/// The sidecar is consumed by the backend's `verb_grant_cmdline_token` at
/// launch time and carried to the guest on the kernel command line.
pub(super) fn mint_verb_grant_sidecar(
    plan_json: &str,
    vm_name: &str,
    state_dir: &Path,
) -> Result<Option<VerbGrantEnvelope>> {
    let sidecar_path = state_dir.join("verb-grant.json");
    match std::fs::remove_file(&sidecar_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(anyhow::Error::from(error)).with_context(|| {
                format!("remove stale verb-grant sidecar {}", sidecar_path.display())
            });
        }
    }

    let Ok(signed) = serde_json::from_str::<SignedExecutionPlan>(plan_json) else {
        return Ok(None);
    };
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)
        .context("decode admitted plan for guest grant")?;

    // The grant expires with the plan's validity window. Minting one that is
    // already dead guarantees the guest refuses activation, and the guest can
    // only say `VerbNotAuthorized`; refusing here says what actually expired.
    refuse_expired_plan(&plan, chrono::Utc::now())?;
    let drive = plan.grants.as_ref().and_then(|grants| grants.drive.clone());
    let application_terminal = plan
        .grants
        .as_ref()
        .and_then(|grants| grants.application_terminal.as_ref())
        .map(mvm_contract::grants::ApplicationTerminalBinding::from);
    let other_authority = drive.is_some() || application_terminal.is_some();
    let Some(verbs) = granted_verbs(&plan, other_authority) else {
        return Ok(None);
    };

    let keys_dir = mvm_core::config::mvm_keys_dir();
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir)
        .context("load host signer for verb-grant mint")?;
    let keystore = crate::host_signer::keystore::Keystore::load_from_file(&signer.secret_path)
        .context("load Keystore from host-signer key file")?;
    let grant = crate::host_signer::mint_verb_grant(
        &keystore,
        vm_name,
        &plan.nonce,
        plan.valid_until,
        verbs,
        crate::host_signer::VerbGrantAuthority {
            drive,
            application_terminal,
        },
    )
    .context("mint verb grant")?;

    let envelope = VerbGrantEnvelope {
        pubkey_hex: keystore
            .pub_key()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        plan_nonce_hex: plan.nonce.as_hex().to_string(),
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant,
    };
    let envelope_json = serde_json::to_vec(&envelope).context("serialize VerbGrantEnvelope")?;
    write_secret_file(&sidecar_path, &envelope_json)?;
    Ok(Some(envelope))
}

/// The verbs a minted grant carries, or `None` when the plan needs no grant.
///
/// The display verbs ride along on a grant that is being minted anyway, and
/// never cause one: a minted grant is a closed verb list for the guest agent,
/// so minting one for display alone would take every unlisted verb away from a
/// plan that never asked for that.
fn granted_verbs(plan: &ExecutionPlan, other_authority: bool) -> Option<Vec<VerbId>> {
    if plan.agent_verbs.is_none() && !other_authority {
        return None;
    }
    let mut verbs = plan.agent_verbs.clone().unwrap_or_default();
    for verb in mvm_contract::stream::display_verbs(plan) {
        if !verbs.contains(&verb) {
            verbs.push(verb);
        }
    }
    Some(verbs)
}

/// Refuse to mint a grant from a plan whose validity window has closed.
fn refuse_expired_plan(plan: &ExecutionPlan, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    if now < plan.valid_until {
        return Ok(());
    }
    let window = (plan.valid_until - plan.valid_from).num_seconds();
    let since_admission = (now - plan.valid_from).num_seconds();
    anyhow::bail!(
        "the admitted plan's validity window closed at {} ({window}s after admission at {}), \
         {since_admission}s ago counting from admission; a verb grant minted from it would \
         already be expired, so the guest would refuse to activate. Something between admission \
         and boot took longer than the window. Start again: prepared artifacts are cached.",
        plan.valid_until,
        plan.valid_from
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_valid(from_secs_ago: i64, window_secs: i64) -> ExecutionPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.valid_from = chrono::Utc::now() - chrono::Duration::seconds(from_secs_ago);
        plan.valid_until = plan.valid_from + chrono::Duration::seconds(window_secs);
        plan
    }

    #[test]
    fn a_plan_whose_window_closed_is_refused_with_both_times() {
        let plan = plan_valid(700, 600);
        let err = refuse_expired_plan(&plan, chrono::Utc::now())
            .unwrap_err()
            .to_string();
        assert!(err.contains("validity window closed"), "{err}");
        assert!(err.contains("600s after admission"), "{err}");
        assert!(err.contains(&plan.valid_until.to_string()), "{err}");
    }

    #[test]
    fn a_plan_still_in_its_window_mints() {
        assert!(refuse_expired_plan(&plan_valid(5, 600), chrono::Utc::now()).is_ok());
    }

    #[test]
    fn explicit_empty_verbs_mint_a_signed_closed_grant() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("isolated home");
        env.isolate_mvm_home(home.path());
        let state_dir = home.path().join("empty-verbs");
        std::fs::create_dir_all(&state_dir).expect("state dir");

        let mut plan = plan_valid(5, 600);
        plan.agent_verbs = Some(Vec::new());
        let signed = serde_json::to_string(&SignedExecutionPlan(
            mvm_core::protocol::signing::SignedPayload {
                payload: serde_json::to_vec(&plan).expect("plan payload"),
                signature: vec![],
                signer_id: "test".into(),
            },
        ))
        .expect("signed plan envelope");

        let envelope = mint_verb_grant_sidecar(&signed, "empty-verbs", &state_dir)
            .expect("empty allowlist plan")
            .expect("explicit empty allowlist requires a grant");
        assert!(state_dir.join("verb-grant.json").is_file());
        assert!(envelope.grant.verbs.is_empty());
        assert!(envelope.grant.permits("ping"));
        assert!(!envelope.grant.permits("worker-status"));
        let key = crate::audit::host_keypair::load_or_init_at(&mvm_core::config::mvm_keys_dir())
            .expect("host signer");
        envelope
            .grant
            .verify(
                &key.verifying,
                "empty-verbs",
                &plan.nonce,
                chrono::Utc::now(),
            )
            .expect("empty grant is signed and bound to the plan");
    }

    #[test]
    fn display_verbs_join_a_grant_but_never_cause_one() {
        let mut plan = plan_valid(5, 600);
        plan.services = vec![
            mvm_contract::protocol::broker::ServiceId::parse(
                mvm_contract::stream::DISPLAY_VIEW_GRANT_SERVICE,
            )
            .unwrap(),
        ];
        plan.grants = Some(mvm_contract::grants::Grants {
            display_input: Some(mvm_contract::grants::DisplayInputGrant::default()),
            ..Default::default()
        });
        assert_eq!(
            granted_verbs(&plan, false),
            None,
            "a display-only plan must not narrow the agent to a verb list"
        );

        plan.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
        let verbs: Vec<String> = granted_verbs(&plan, false)
            .unwrap()
            .iter()
            .map(|verb| verb.as_str().to_string())
            .collect();
        assert_eq!(
            verbs,
            vec![
                "run-entrypoint",
                mvm_contract::stream::DISPLAY_VIEW_VERB,
                mvm_contract::stream::DISPLAY_INPUT_VERB,
            ]
        );
    }

    #[test]
    fn legacy_tool_only_plan_is_refused_without_a_guest_grant() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("isolated home");
        env.isolate_mvm_home(home.path());
        let state_dir = home.path().join("tool-guest");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let plan = plan_valid(5, 600);
        let signed = |payload: Vec<u8>| {
            serde_json::to_string(&SignedExecutionPlan(
                mvm_core::protocol::signing::SignedPayload {
                    payload,
                    signature: vec![],
                    signer_id: "test".into(),
                },
            ))
            .expect("signed plan envelope")
        };
        assert!(
            mint_verb_grant_sidecar(
                &signed(serde_json::to_vec(&plan).unwrap()),
                "tool-guest",
                &state_dir
            )
            .expect("no-tool plan")
            .is_none()
        );

        let mut legacy = serde_json::to_value(&plan).unwrap();
        legacy["tools"] = serde_json::json!({"allow": ["shell"]});
        let error = mint_verb_grant_sidecar(
            &signed(serde_json::to_vec(&legacy).unwrap()),
            "tool-guest",
            &state_dir,
        )
        .expect_err("legacy tool policy must be refused");
        assert!(error.to_string().contains("decode admitted plan"));
        assert!(!state_dir.join("verb-grant.json").exists());
    }

    #[test]
    fn an_application_terminal_plan_mints_a_grant_bound_to_its_argv() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("isolated home");
        env.isolate_mvm_home(home.path());
        let state_dir = home.path().join("terminal-guest");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let mut plan = plan_valid(5, 600);
        let terminal =
            mvm_contract::grants::ApplicationTerminalGrant::new(vec!["/usr/bin/claude".into()])
                .expect("valid argv");
        plan.grants = Some(mvm_contract::grants::Grants {
            application_terminal: Some(terminal.clone()),
            ..Default::default()
        });
        let signed = serde_json::to_string(&SignedExecutionPlan(
            mvm_core::protocol::signing::SignedPayload {
                payload: serde_json::to_vec(&plan).expect("plan payload"),
                signature: vec![],
                signer_id: "test".into(),
            },
        ))
        .expect("signed plan envelope");
        let envelope = mint_verb_grant_sidecar(&signed, "terminal-guest", &state_dir)
            .expect("terminal plan")
            .expect("an application terminal requires a grant");
        let binding = envelope
            .grant
            .application_terminal
            .as_ref()
            .expect("binding carried");
        assert_eq!(binding.argv_digest, terminal.argv_digest());
        assert!(envelope.grant.permits("console-open"));
        assert!(!envelope.grant.permits("exec"));
        let key = crate::audit::host_keypair::load_or_init_at(&mvm_core::config::mvm_keys_dir())
            .expect("host signer");
        assert!(
            envelope
                .grant
                .verify(
                    &key.verifying,
                    "terminal-guest",
                    &plan.nonce,
                    chrono::Utc::now()
                )
                .is_ok()
        );
    }
}
