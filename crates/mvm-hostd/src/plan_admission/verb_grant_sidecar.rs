//! Persist the signed agent and drive authority consumed at guest boot.

use super::write_secret_file;
use anyhow::{Context, Result};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan, ToolMediationGrant, VerbId};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use std::path::Path;

/// Mint a signed `VerbGrantEnvelope` when the plan carries agent or drive
/// authority and write it to `<state_dir>/verb-grant.json` at mode 0600.
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
    let Ok(plan) = serde_json::from_slice::<ExecutionPlan>(&signed.0.payload) else {
        return Ok(None);
    };

    // The grant expires with the plan's validity window. Minting one that is
    // already dead guarantees the guest refuses activation, and the guest can
    // only say `VerbNotAuthorized`; refusing here says what actually expired.
    refuse_expired_plan(&plan, chrono::Utc::now())?;
    let tool_mediation = tool_mediation_for(&plan)?;
    let drive = plan.grants.as_ref().and_then(|grants| grants.drive.clone());
    let Some(verbs) = granted_verbs(&plan, drive.is_some() || tool_mediation.is_some()) else {
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
        drive,
        tool_mediation,
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
    let mut verbs = plan.agent_verbs.clone().unwrap_or_default();
    if verbs.is_empty() && !other_authority {
        return None;
    }
    for verb in mvm_contract::stream::display_verbs(plan) {
        if !verbs.contains(&verb) {
            verbs.push(verb);
        }
    }
    Some(verbs)
}

fn tool_mediation_for(plan: &ExecutionPlan) -> Result<Option<ToolMediationGrant>> {
    if plan.tools.is_empty() {
        return Ok(None);
    }
    let grant = ToolMediationGrant {
        class_gate_only: plan.agent_verbs.is_none(),
        command_map_digest: ToolMediationGrant::digest_commands(&plan.tools.command_executables())
            .map_err(anyhow::Error::msg)?,
    };
    Ok(Some(grant))

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
    fn tool_rules_require_a_signed_guest_mediation_grant() {
        let mut plan = plan_valid(5, 600);
        assert!(tool_mediation_for(&plan).expect("empty plan").is_none());
        plan.tools.allow.push("shell".to_string());
        assert_eq!(
            tool_mediation_for(&plan).expect("tool plan"),
            Some(ToolMediationGrant {
                class_gate_only: true,
                command_map_digest: None,

            })
        );
        plan.agent_verbs = Some(Vec::new());
        assert_eq!(
            tool_mediation_for(&plan).expect("explicit verbs"),
            Some(ToolMediationGrant {
                class_gate_only: false,
                command_map_digest: None,

            })
        );
    }

    #[test]
    fn signed_guest_map_comes_from_plan_paths_and_refuses_ambiguous_ownership() {
        use mvm_contract::policy::tool_rules::ToolRuleDetail;

        let mut plan = plan_valid(5, 600);
        plan.tools.allow.push("shell".into());
        plan.tools.detail.insert(
            "shell".into(),
            ToolRuleDetail {
                executable: Some("/bin/sh".into()),
                ..ToolRuleDetail::default()
            },
        );
        let map = tool_mediation_for(&plan)
            .expect("valid map")
            .expect("tool grant");
        assert_eq!(
            map.command_map_digest,
            ToolMediationGrant::digest_commands(&plan.tools.command_executables())
                .expect("valid map")
        );

        plan.tools.detail.insert(
            "other".into(),
            ToolRuleDetail {
                executable: Some("/bin/sh".into()),
                ..ToolRuleDetail::default()
            },
        );
        assert!(tool_mediation_for(&plan).is_err());
        plan.tools
            .detail
            .get_mut("other")
            .expect("other detail")
            .executable = Some("relative/sh".into());
        assert!(tool_mediation_for(&plan).is_err());
    }

    #[test]
    fn tool_only_plan_mints_a_verifiable_guest_grant() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("isolated home");
        env.isolate_mvm_home(home.path());
        let state_dir = home.path().join("tool-guest");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let mut plan = plan_valid(5, 600);
        let signed = |plan: &ExecutionPlan| {
            serde_json::to_string(&SignedExecutionPlan(
                mvm_core::protocol::signing::SignedPayload {
                    payload: serde_json::to_vec(plan).expect("plan payload"),
                    signature: vec![],
                    signer_id: "test".into(),
                },
            ))
            .expect("signed plan envelope")
        };
        assert!(
            mint_verb_grant_sidecar(&signed(&plan), "tool-guest", &state_dir)
                .expect("no-tool plan")
                .is_none()
        );

        plan.tools.allow.push("shell".into());
        let envelope = mint_verb_grant_sidecar(&signed(&plan), "tool-guest", &state_dir)
            .expect("tool plan")
            .expect("tool policy requires a grant");
        assert_eq!(
            envelope.grant.tool_mediation,
            Some(ToolMediationGrant {
                class_gate_only: true,
                command_map_digest: None,

            })
        );
        let key = crate::audit::host_keypair::load_or_init_at(&mvm_core::config::mvm_keys_dir())
            .expect("host signer");
        assert!(
            envelope
                .grant
                .verify(
                    &key.verifying,
                    "tool-guest",
                    &plan.nonce,
                    chrono::Utc::now()
                )
                .is_ok()
        );
        assert!(state_dir.join("verb-grant.json").is_file());
    }
}
