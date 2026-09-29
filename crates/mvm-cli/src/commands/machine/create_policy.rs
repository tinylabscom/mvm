//! The authored policy a persistent machine is created under.
//!
//! `machine create` and `machine start --image/--manifest` build a spec that
//! later starts re-admit, so the policy is resolved once, here, the same way
//! `run` and `machine run` resolve theirs: `--policy`, the project
//! manifest's `[policy]` table and `[network] allow_hosts`, then the flags on
//! top, under the same fold. The spec then records the result.
//!
//! A spec records network and resource grants only. A policy that also binds
//! secrets, shares, env or endpoint routes is refused rather than half
//! applied: a restart would lose what the spec cannot hold.

use anyhow::{Context, Result, bail};
use mvm_client::policy_profiles::{
    LaunchFlags, Platform, PolicyBody, PolicySelection, PolicyStore, ProjectPolicy, fold, resolve,
};

/// What `build_machine_spec` asks of the policy.
pub(super) struct MachinePolicyInputs<'a> {
    /// `--policy NAME|PATH`.
    pub policy: Option<&'a str>,
    /// The manifest's contribution, when the machine is sourced from one.
    pub project: Option<&'a ProjectPolicy>,
    pub allow_host: &'a [String],
    /// `--net`, or the manifest's `net = true`.
    pub net: bool,
    pub cpu_limit: Option<u32>,
    pub timeout: Option<u64>,
    pub cpus: u32,
    pub memory_mib: u64,
}

/// The network and resource grants the spec records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MachinePolicy {
    pub allow_host: Vec<String>,
    pub cpu_limit: Option<u32>,
    pub timeout: Option<u64>,
    pub policy: Option<PolicyBody>,
}

/// Refuse a policy section a machine spec cannot record.
fn refuse_unrecordable(policy: &PolicyBody) -> Result<()> {
    for (section, present) in [
        ("secrets", !policy.secrets.is_empty()),
        ("shares", !policy.shares.is_empty()),
        ("env", !policy.env.is_empty()),
        ("tools", !policy.tools.is_empty()),
        ("network.routes", !policy.network.routes.is_empty()),
    ] {
        if present {
            bail!(
                "the policy's {section} cannot be recorded on a persistent machine's spec yet, \
                 so a restart would drop them. Run it with `mvmctl run` or `machine run`, which \
                 apply them per launch"
            );
        }
    }
    Ok(())
}

/// Resolve and fold the machine's policy.
///
/// # Errors
///
/// A policy that does not resolve, a section a spec cannot record, or a flag
/// the policy denies, blocks or bounds.
pub(super) fn machine_policy(inputs: MachinePolicyInputs<'_>) -> Result<MachinePolicy> {
    let selection = PolicySelection::for_launch(inputs.policy, inputs.project.cloned())?;
    let Some(selection) = selection else {
        return Ok(MachinePolicy {
            allow_host: inputs.allow_host.to_vec(),
            cpu_limit: inputs.cpu_limit,
            timeout: inputs.timeout,
            policy: None,
        });
    };
    let backend = mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name());
    let resolved = resolve(
        &PolicyStore::from_config(),
        &selection,
        Platform::current(Some(backend)),
    )?;
    if resolved.backend_conditioned {
        bail!(
            "a persistent machine cannot use backend-conditioned policy because a later start \
             may select a different hypervisor; use a backend-independent policy"
        );
    }
    for note in &resolved.notes {
        crate::ui::warn(&format!("policy: {note}"));
    }
    refuse_unrecordable(&resolved.policy)?;
    let folded = fold(
        &resolved.policy,
        &LaunchFlags {
            allow_host: inputs.allow_host.to_vec(),
            net: inputs.net,
            cpu_limit: inputs.cpu_limit,
            timeout: inputs.timeout,
            cpus: inputs.cpus,
            memory_mib: inputs.memory_mib,
            ..LaunchFlags::default()
        },
    )
    .context("applying the machine's policy")?;
    Ok(MachinePolicy {
        allow_host: folded.allow_host,
        cpu_limit: folded.cpu_limit,
        timeout: folded.timeout,
        policy: Some(resolved.policy),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn project(allow: &[&str]) -> ProjectPolicy {
        ProjectPolicy {
            manifest: "/p/mvm.toml".into(),
            profile: None,
            include: Vec::new(),
            allow_hosts: allow.iter().map(ToString::to_string).collect(),
        }
    }

    fn inputs<'a>(
        policy: Option<&'a str>,
        project: Option<&'a ProjectPolicy>,
        allow_host: &'a [String],
    ) -> MachinePolicyInputs<'a> {
        MachinePolicyInputs {
            policy,
            project,
            allow_host,
            net: false,
            cpu_limit: None,
            timeout: None,
            cpus: 2,
            memory_mib: 512,
        }
    }

    #[test]
    fn with_no_policy_and_no_project_the_flags_pass_through() {
        let hosts = vec!["a.test".to_string()];
        let resolved = machine_policy(inputs(None, None, &hosts)).unwrap();
        assert_eq!(resolved.allow_host, hosts);
    }

    #[test]
    fn a_projects_hosts_and_a_flags_hosts_both_apply() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let project = project(&["api.example.com"]);
        let hosts = vec!["b.test".to_string()];
        let resolved = machine_policy(inputs(None, Some(&project), &hosts)).unwrap();
        assert_eq!(resolved.allow_host, ["api.example.com:443", "b.test:443"]);
    }

    #[test]
    fn a_blocked_policy_refuses_the_manifests_net() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let err = machine_policy(MachinePolicyInputs {
            net: true,
            ..inputs(Some("offline"), None, &[])
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("blocks the network"), "{err:#}");
    }

    #[test]
    fn backend_conditioned_policy_is_refused_for_a_persistent_spec() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let profile = home.path().join("backend.toml");
        std::fs::write(
            &profile,
            "[[when]]\nbackend = \"firecracker\"\n[when.overrides.network]\nblock = true\n",
        )
        .unwrap();
        let error = machine_policy(inputs(Some(profile.to_str().unwrap()), None, &[]))
            .expect_err("a later start could pick another backend");
        assert!(format!("{error:#}").contains("backend-conditioned"));
    }

    #[test]
    fn every_policy_section_a_spec_cannot_hold_is_refused() {
        for (section, text) in [
            ("secrets", "[[secrets.bind]]\nname = \"gh\"\n"),
            ("secrets", "[secrets]\ndeny = [\"gh\"]\n"),
            (
                "shares",
                "[[shares.mount]]\nhost = \"/src\"\nguest = \"/work\"\n",
            ),
            ("shares", "[shares]\ndeny = [\"/private\"]\n"),
            ("env", "[env]\nallow = [\"MODE\"]\n"),
            ("env", "[env]\ndeny = [\"DEBUG\"]\n"),
            ("env", "[env]\nreadmit = [\"LD_PRELOAD\"]\n"),
            ("tools", "[tools]\nallow = [\"curl\"]\n"),
            ("tools", "[tools]\ndeny = [\"ssh\"]\n"),
            (
                "network.routes",
                "[[network.routes]]\nid = \"api\"\nhost = \"api.test\"\n",
            ),
        ] {
            let body: PolicyBody = toml::from_str(text).expect("policy parses");
            let error = refuse_unrecordable(&body).expect_err("section must be refused");
            assert!(error.to_string().contains(section), "{error:#}");
        }
        assert!(refuse_unrecordable(&PolicyBody::default()).is_ok());
    }
}
