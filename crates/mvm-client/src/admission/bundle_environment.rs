//! A signed bundle's environment descriptor measured against the launch.
//!
//! The verifier already held the descriptor to its own bundle: its target is
//! the bundle's architecture and every capability it requires is one the
//! bundle's posture permits. What it could not see is the launch. Admission
//! checks what only the launch can answer:
//!
//! - every required secret slot is bound through the launch's ordinary secret
//!   bindings, so the value stays on the host and is substituted at the
//!   endpoint, never carried in the bundle or the guest;
//! - the entrypoint the launch resolved from the image is the one the
//!   descriptor names, so a descriptor cannot silently stand in for the image's
//!   own entrypoint or the other way round;
//! - each required capability is permitted by every posture the launch is held
//!   to, including one the caller supplied beside the pin.
//!
//! Requirements the launcher cannot establish are refused, not silently ignored.
//!
//! The descriptor grants nothing. A launch that does not ask for a capability
//! the descriptor requires simply runs without it, under its own flags.

use mvm_core::plan::{BundleSecurityPosture, EnvironmentDescriptor, SecretBinding};

use super::entrypoint_resolve::ResolvedEntrypoint;

/// The signed environment of the installed bundle `id_or_slot` names, its
/// manifest signature checked against the trust store again. `None` when the
/// key is a template slot, names no installed bundle, or the bundle carries
/// no descriptor.
pub fn installed_bundle_environment(
    id_or_slot: &str,
) -> anyhow::Result<Option<EnvironmentDescriptor>> {
    mvm_runtime::vm::template::lifecycle::installed_bundle_environment(id_or_slot)
}

/// What the launch provides, in the terms a descriptor can check.
#[derive(Debug, Clone, Copy)]
pub struct EnvironmentRequest<'a> {
    /// The secret bindings the plan will carry.
    pub secrets: &'a [SecretBinding],
    /// What the launch worked out the image runs.
    pub entrypoint: &'a ResolvedEntrypoint,
    /// Every posture the launch is held to.
    pub postures: &'a [BundleSecurityPosture],
    /// Concrete network selected for this launch.
    pub network_policy: &'a mvm_core::network_policy::NetworkPolicy,
}

/// One way a launch does not meet its bundle's signed environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentRefusal {
    /// The launch exceeds its signed exact-destination ceiling.
    NetworkBeyondPolicy,
    /// Required secret slots the launch binds no secret to.
    UnboundSecretSlots { names: Vec<String> },
    /// The image runs something other than the declared entrypoint.
    EntrypointMismatch {
        declared: Vec<String>,
        resolved: Vec<String>,
    },
    /// An ordinary launch cannot establish the declared image entrypoint.
    EntrypointUnresolved { because: String },
    /// Required capabilities a posture the launch is held to does not permit.
    CapabilitiesBeyondPosture { capabilities: Vec<&'static str> },
    /// Requirements the launcher cannot yet establish or enforce.
    UnsupportedRequirements { fields: Vec<&'static str> },
}

impl std::fmt::Display for EnvironmentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkBeyondPolicy => write!(
                f,
                "the launch network exceeds the bundle's signed environment policy"
            ),
            Self::UnboundSecretSlots { names } => write!(
                f,
                "required secret slots {} have no binding; bind each with --secret",
                names.join(", ")
            ),
            Self::EntrypointMismatch { declared, resolved } => write!(
                f,
                "the bundle declares entrypoint {declared:?} but the image runs {resolved:?}"
            ),
            Self::EntrypointUnresolved { because } => write!(
                f,
                "the bundle's declared entrypoint cannot be verified ({because})"
            ),
            Self::CapabilitiesBeyondPosture { capabilities } => write!(
                f,
                "the bundle requires {}, which the security posture this launch is held to \
                 does not permit",
                capabilities.join(", ")
            ),
            Self::UnsupportedRequirements { fields } => write!(
                f,
                "this launcher cannot enforce the signed environment requirements {}; \
                 use an environment whose requirements this launcher supports",
                fields.join(", ")
            ),
        }
    }
}

/// Every way `request` fails `environment`, in a fixed order. Empty when the
/// launch meets it.
pub fn environment_refusals(
    environment: &EnvironmentDescriptor,
    request: &EnvironmentRequest<'_>,
) -> Vec<EnvironmentRefusal> {
    let mut refused = Vec::new();
    if !mvm_core::plan::environment_network_permitted(environment, request.network_policy) {
        refused.push(EnvironmentRefusal::NetworkBeyondPolicy);
    }
    let unsupported = mvm_core::plan::bundle::unsupported_environment_requirements(environment);
    if !unsupported.is_empty() {
        refused.push(EnvironmentRefusal::UnsupportedRequirements {
            fields: unsupported,
        });
    }
    let unbound =
        mvm_core::plan::bundle::unbound_environment_secret_slots(environment, request.secrets);
    if !unbound.is_empty() {
        refused.push(EnvironmentRefusal::UnboundSecretSlots { names: unbound });
    }
    match request.entrypoint {
        ResolvedEntrypoint::Known { argv, .. } if *argv != environment.entrypoint.argv => {
            refused.push(EnvironmentRefusal::EntrypointMismatch {
                declared: environment.entrypoint.argv.clone(),
                resolved: argv.clone(),
            });
        }
        ResolvedEntrypoint::Unresolved { because } => {
            refused.push(EnvironmentRefusal::EntrypointUnresolved {
                because: because.clone(),
            });
        }
        ResolvedEntrypoint::Known { .. } | ResolvedEntrypoint::AdHocOverride { .. } => {}
    }
    let mut beyond: Vec<&'static str> = request
        .postures
        .iter()
        .flat_map(|posture| {
            mvm_core::plan::bundle::forbidden_capabilities(environment, Some(posture))
        })
        .collect();
    beyond.sort_unstable();
    beyond.dedup();
    if !beyond.is_empty() {
        refused.push(EnvironmentRefusal::CapabilitiesBeyondPosture {
            capabilities: beyond,
        });
    }
    refused
}

/// The refusal message for a non-empty set of refusals.
pub fn refusal_message(refused: &[EnvironmentRefusal]) -> String {
    let reasons: Vec<String> = refused.iter().map(ToString::to_string).collect();
    format!(
        "the launch does not meet the bundle's signed environment: {}",
        reasons.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::security::AgentProfile;

    fn environment() -> EnvironmentDescriptor {
        serde_json::from_value(serde_json::json!({
            "descriptor_version": 1,
            "target": "x86_64-linux",
            "entrypoint": { "argv": ["/usr/bin/agent"] },
            "secret_slots": [
                { "name": "AGENT_TOKEN", "required": true },
                { "name": "OPTIONAL_KEY", "required": false },
            ],
            "capabilities": ["egress"],
        }))
        .unwrap()
    }

    fn binding(name: &str) -> SecretBinding {
        SecretBinding {
            name: name.to_string(),
            source: mvm_core::plan::SecretSource::Keystore {
                address: name.to_lowercase(),
            },
            destinations: Vec::new(),
            approval_required: false,
        }
    }

    fn posture(allows_egress: bool) -> BundleSecurityPosture {
        BundleSecurityPosture {
            profile: AgentProfile::Dev,
            verity_protected: false,
            requires_auth: true,
            allows_volumes: false,
            allows_egress,
        }
    }

    fn known(argv: &[&str]) -> ResolvedEntrypoint {
        ResolvedEntrypoint::Known {
            argv: argv.iter().map(|a| a.to_string()).collect(),
            shebang: None,
        }
    }

    #[test]
    fn launch_network_widening_is_an_environment_refusal() {
        let mut environment = environment();
        environment.policy = Some(mvm_core::plan::EnvironmentPolicy {
            allow_hosts: vec!["api.anthropic.com:443".into()],
        });
        let refused = environment_refusals(
            &environment,
            &EnvironmentRequest {
                secrets: &[binding("AGENT_TOKEN")],
                entrypoint: &known(&["/usr/bin/agent"]),
                postures: &[posture(true)],
                network_policy: &mvm_core::network_policy::NetworkPolicy::unrestricted(),
            },
        );
        assert_eq!(refused, vec![EnvironmentRefusal::NetworkBeyondPolicy]);
        assert!(refusal_message(&refused).contains("signed environment policy"));
    }

    #[test]
    fn a_launch_meeting_the_environment_is_admitted() {
        let secrets = [binding("AGENT_TOKEN")];
        let entrypoint = known(&["/usr/bin/agent"]);
        let postures = [posture(true)];
        let refused = environment_refusals(
            &environment(),
            &EnvironmentRequest {
                secrets: &secrets,
                entrypoint: &entrypoint,
                postures: &postures,
                network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
            },
        );
        assert!(refused.is_empty(), "{refused:?}");
    }

    #[test]
    fn requirements_the_launcher_cannot_enforce_are_not_silently_ignored() {
        let mut environment = environment();
        environment.entrypoint.working_dir = Some("/workspace".into());
        environment.volumes = serde_json::from_value(serde_json::json!([
            { "name": "workspace", "guest_path": "/workspace" }
        ]))
        .unwrap();
        environment.services = serde_json::from_value(serde_json::json!([
            { "name": "indexer", "argv": ["/usr/bin/indexer"] }
        ]))
        .unwrap();
        for entrypoint in [
            known(&["/usr/bin/agent"]),
            ResolvedEntrypoint::ad_hoc_override(),
        ] {
            let refused = environment_refusals(
                &environment,
                &EnvironmentRequest {
                    secrets: &[binding("AGENT_TOKEN")],
                    entrypoint: &entrypoint,
                    postures: &[posture(true)],
                    network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
                },
            );
            assert_eq!(
                refused,
                vec![EnvironmentRefusal::UnsupportedRequirements {
                    fields: vec!["entrypoint.working_dir", "volumes", "services"],
                }]
            );
            let message = refusal_message(&refused);
            assert!(message.contains("cannot enforce"));
            assert!(message.contains("entrypoint.working_dir, volumes, services"));
        }
    }

    #[test]
    fn each_unsupported_requirement_is_sufficient_to_refuse() {
        for (field, value) in [
            (
                "entrypoint",
                serde_json::json!({
                    "argv": ["/usr/bin/agent"], "working_dir": "/workspace"
                }),
            ),
            (
                "volumes",
                serde_json::json!([
                    { "name": "workspace", "guest_path": "/workspace" }
                ]),
            ),
            (
                "services",
                serde_json::json!([
                    { "name": "indexer", "argv": ["/usr/bin/indexer"] }
                ]),
            ),
        ] {
            let mut document = serde_json::to_value(environment()).unwrap();
            document[field] = value;
            let environment = serde_json::from_value(document).unwrap();
            let refused = environment_refusals(
                &environment,
                &EnvironmentRequest {
                    secrets: &[binding("AGENT_TOKEN")],
                    entrypoint: &known(&["/usr/bin/agent"]),
                    postures: &[posture(true)],
                    network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
                },
            );
            assert!(
                matches!(
                    refused.as_slice(),
                    [EnvironmentRefusal::UnsupportedRequirements { fields }] if fields.len() == 1
                ),
                "{field}: {refused:?}"
            );
        }
    }

    #[test]
    fn an_unbound_required_slot_is_refused_and_an_optional_one_is_not() {
        let entrypoint = known(&["/usr/bin/agent"]);
        let postures = [posture(true)];
        let refused = environment_refusals(
            &environment(),
            &EnvironmentRequest {
                secrets: &[],
                entrypoint: &entrypoint,
                postures: &postures,
                network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
            },
        );
        assert_eq!(
            refused,
            vec![EnvironmentRefusal::UnboundSecretSlots {
                names: vec!["AGENT_TOKEN".to_string()]
            }]
        );
        assert!(refusal_message(&refused).contains("--secret"));
    }

    #[test]
    fn an_image_running_another_program_is_refused() {
        let secrets = [binding("AGENT_TOKEN")];
        let entrypoint = known(&["/bin/sh"]);
        let refused = environment_refusals(
            &environment(),
            &EnvironmentRequest {
                secrets: &secrets,
                entrypoint: &entrypoint,
                postures: &[posture(true)],
                network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
            },
        );
        assert!(matches!(
            refused.as_slice(),
            [EnvironmentRefusal::EntrypointMismatch { .. }]
        ));
    }

    #[test]
    fn an_explicit_ad_hoc_override_is_not_compared() {
        let secrets = [binding("AGENT_TOKEN")];
        let entrypoint = ResolvedEntrypoint::ad_hoc_override();
        assert!(
            environment_refusals(
                &environment(),
                &EnvironmentRequest {
                    secrets: &secrets,
                    entrypoint: &entrypoint,
                    postures: &[],
                    network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
                },
            )
            .is_empty()
        );
    }

    #[test]
    fn failed_image_entrypoint_resolution_is_refused_without_an_input_grant() {
        use mvm_build::builder_vm::GuestSidecar;
        for metadata in ["missing", "malformed", "empty"] {
            let dir = tempfile::tempdir().expect("image directory");
            let rootfs = dir.path().join("rootfs.ext4");
            std::fs::write(&rootfs, b"unit-only rootfs").unwrap();
            match metadata {
                "malformed" => {
                    std::fs::write(GuestSidecar::path_in(dir.path()), b"not json").unwrap();
                }
                "empty" => {
                    GuestSidecar::for_oci_run("empty", true, true)
                        .write_to_dir(dir.path())
                        .unwrap();
                }
                _ => {}
            }
            let entrypoint = super::super::entrypoint_resolve::resolve_for_rootfs(&rootfs);
            let refused = environment_refusals(
                &environment(),
                &EnvironmentRequest {
                    secrets: &[binding("AGENT_TOKEN")],
                    entrypoint: &entrypoint,
                    postures: &[],
                    network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
                },
            );
            assert!(
                matches!(
                    refused.as_slice(),
                    [EnvironmentRefusal::EntrypointUnresolved { .. }]
                ),
                "{metadata}: {refused:?}"
            );
        }
    }

    #[test]
    fn a_capability_beyond_a_launch_posture_is_refused() {
        let secrets = [binding("AGENT_TOKEN")];
        let entrypoint = known(&["/usr/bin/agent"]);
        let refused = environment_refusals(
            &environment(),
            &EnvironmentRequest {
                secrets: &secrets,
                entrypoint: &entrypoint,
                postures: &[posture(true), posture(false)],
                network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
            },
        );
        assert_eq!(
            refused,
            vec![EnvironmentRefusal::CapabilitiesBeyondPosture {
                capabilities: vec!["egress"]
            }]
        );
    }
}
