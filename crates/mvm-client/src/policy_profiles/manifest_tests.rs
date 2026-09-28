use super::*;
use crate::policy_profiles::model::{
    EnvSection, NetworkSection, ResourcesSection, SecretGrant, SecretsSection, ShareGrant,
    SharesSection,
};

fn flags() -> LaunchFlags {
    LaunchFlags {
        cpus: 2,
        memory_mib: 512,
        ..LaunchFlags::default()
    }
}

fn network(allow: &[&str], deny: &[&str], block: Option<bool>) -> PolicyBody {
    PolicyBody {
        network: NetworkSection {
            allow: allow.iter().map(ToString::to_string).collect(),
            deny: deny.iter().map(ToString::to_string).collect(),
            block,
            routes: Vec::new(),
        },
        ..PolicyBody::default()
    }
}

// ---- network ----------------------------------------------------------------

#[test]
fn flag_hosts_join_the_policys_allow_list() {
    let folded = fold(
        &network(&["a.test:443"], &[], None),
        &LaunchFlags {
            allow_host: vec!["b.test".into(), "a.test".into()],
            ..flags()
        },
    )
    .unwrap();
    assert_eq!(folded.allow_host, ["a.test:443", "b.test:443"]);
}

#[test]
fn a_flag_cannot_reach_a_denied_host() {
    let err = fold(
        &network(&[], &["*.corp.test"], None),
        &LaunchFlags {
            allow_host: vec!["db.corp.test:5432".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert_eq!(err.key.as_deref(), Some("--allow-host"));
    assert!(err.message.contains("denied"), "{err}");

    let err = fold(
        &network(&[], &["api.github.com"], None),
        &LaunchFlags {
            allow_endpoint: vec!["GET https://api.github.com/repos/**".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert_eq!(err.key.as_deref(), Some("--allow-endpoint"));
}

#[test]
fn no_flag_can_turn_a_blocked_network_back_on() {
    let blocked = network(&[], &[], Some(true));
    for asking in [
        LaunchFlags {
            allow_host: vec!["a.test".into()],
            ..flags()
        },
        LaunchFlags {
            net: true,
            ..flags()
        },
        LaunchFlags {
            network_preset: true,
            ..flags()
        },
        LaunchFlags {
            allow_endpoint: vec!["GET https://a.test/**".into()],
            ..flags()
        },
    ] {
        let err = fold(&blocked, &asking).unwrap_err();
        assert!(err.message.contains("blocks the network"), "{err}");
    }
    assert!(fold(&blocked, &flags()).unwrap().allow_host.is_empty());
}

#[test]
fn a_preset_flag_cannot_sidestep_a_deny_list() {
    let err = fold(
        &network(&[], &["api.openai.com"], None),
        &LaunchFlags {
            net: true,
            ..flags()
        },
    )
    .unwrap_err();
    assert!(err.message.contains("--allow-host"), "{err}");
}

// ---- resources ----------------------------------------------------------------

#[test]
fn a_flag_can_tighten_a_bound_but_never_loosen_it() {
    let policy = PolicyBody {
        resources: ResourcesSection {
            cpu_millicores: Some(500),
            wall_clock_secs: Some(60),
            ..ResourcesSection::default()
        },
        ..PolicyBody::default()
    };
    let looser = fold(
        &policy,
        &LaunchFlags {
            cpu_limit: Some(2000),
            timeout: Some(600),
            ..flags()
        },
    )
    .unwrap();
    assert_eq!((looser.cpu_limit, looser.timeout), (Some(500), Some(60)));
    let tighter = fold(
        &policy,
        &LaunchFlags {
            cpu_limit: Some(100),
            timeout: Some(5),
            ..flags()
        },
    )
    .unwrap();
    assert_eq!((tighter.cpu_limit, tighter.timeout), (Some(100), Some(5)));
    let unset = fold(&policy, &flags()).unwrap();
    assert_eq!((unset.cpu_limit, unset.timeout), (Some(500), Some(60)));
}

#[test]
fn sizes_over_a_ceiling_are_refused() {
    let policy = PolicyBody {
        resources: ResourcesSection {
            max_cpus: Some(1),
            max_memory: Some("256M".into()),
            ..ResourcesSection::default()
        },
        ..PolicyBody::default()
    };
    let err = fold(&policy, &flags()).unwrap_err();
    assert_eq!(err.key.as_deref(), Some("--cpus"));
    let err = fold(&policy, &LaunchFlags { cpus: 1, ..flags() }).unwrap_err();
    assert_eq!(err.key.as_deref(), Some("--memory"));
    fold(
        &policy,
        &LaunchFlags {
            cpus: 1,
            memory_mib: 256,
            ..flags()
        },
    )
    .unwrap();
}

// ---- secrets ----------------------------------------------------------------

fn secrets(bind: &[(&str, &[&str])], deny: &[&str]) -> PolicyBody {
    PolicyBody {
        secrets: SecretsSection {
            bind: bind
                .iter()
                .map(|(name, hosts)| SecretGrant {
                    name: (*name).to_string(),
                    hosts: hosts.iter().map(ToString::to_string).collect(),
                })
                .collect(),
            deny: deny.iter().map(ToString::to_string).collect(),
        },
        ..PolicyBody::default()
    }
}

#[test]
fn policy_secrets_become_secret_specs_and_flags_may_narrow_them() {
    let policy = secrets(&[("gh", &["api.github.com", "uploads.github.com"])], &[]);
    assert_eq!(
        fold(&policy, &flags()).unwrap().secret,
        ["gh:api.github.com,uploads.github.com"]
    );
    let narrowed = fold(
        &policy,
        &LaunchFlags {
            secret: vec!["gh:api.github.com".into(), "npm".into()],
            ..flags()
        },
    )
    .unwrap();
    assert_eq!(narrowed.secret, ["gh:api.github.com", "npm"]);
}

#[test]
fn a_flag_cannot_widen_or_reach_a_denied_secret() {
    let policy = secrets(&[("gh", &["api.github.com"])], &["prod-db"]);
    let err = fold(
        &policy,
        &LaunchFlags {
            secret: vec!["gh:api.github.com,evil.test".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert!(err.message.contains("widens"), "{err}");
    let err = fold(
        &policy,
        &LaunchFlags {
            secret: vec!["prod-db".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert!(err.message.contains("denied"), "{err}");
}

#[test]
fn a_policy_deny_reaches_a_secret_the_project_declares() {
    let err = fold(
        &secrets(&[], &["prod-db"]),
        &LaunchFlags {
            declared_secrets: vec!["prod-db".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert_eq!(err.key.as_deref(), Some("[secrets]"));
}

#[cfg(unix)]
#[test]
fn a_share_deny_follows_symlinks_before_the_mount_is_admitted() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let denied = root.path().join("denied");
    let safe = root.path().join("safe");
    std::fs::create_dir(&denied).unwrap();
    std::fs::create_dir(&safe).unwrap();
    let link = safe.join("link");
    symlink(&denied, &link).unwrap();
    let policy: PolicyBody = toml::from_str(&format!(
        "[shares]\ndeny = [{}]\n",
        toml::Value::String(denied.display().to_string())
    ))
    .unwrap();
    let flags = LaunchFlags {
        mounts: vec![format!("{}:/work:ro", link.display())],
        ..flags()
    };
    let error = fold(&policy, &flags).expect_err("symlink into denied tree must be refused");
    assert!(error.message.contains("denies as a share source"));
}

// ---- shares -------------------------------------------------------------------

#[test]
fn policy_shares_become_mounts_and_denied_sources_are_refused() {
    let policy = PolicyBody {
        shares: SharesSection {
            mount: vec![ShareGrant {
                host: "/work".into(),
                guest: "/work".into(),
                writable: false,
            }],
            deny: vec!["/home".into()],
        },
        ..PolicyBody::default()
    };
    assert_eq!(fold(&policy, &flags()).unwrap().mounts, ["/work:/work:ro"]);
    let err = fold(
        &policy,
        &LaunchFlags {
            mounts: vec!["/home/me/.ssh:/ssh".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert_eq!(err.key.as_deref(), Some("--mount"));
    let err = fold(
        &policy,
        &LaunchFlags {
            mounts: vec!["/other:/work".into()],
            ..flags()
        },
    )
    .unwrap_err();
    assert!(err.message.contains("would replace it"), "{err}");
}

// ---- env ----------------------------------------------------------------------

#[test]
fn an_env_allow_list_confines_env_flags_and_readmits_flow_through() {
    let policy = PolicyBody {
        env: EnvSection {
            allow: vec!["MODE".into()],
            deny: vec!["DEBUG".into()],
            readmit: vec!["LD_PRELOAD".into()],
        },
        ..PolicyBody::default()
    };
    let folded = fold(
        &policy,
        &LaunchFlags {
            env_names: vec!["MODE".into(), "LD_PRELOAD".into()],
            ..flags()
        },
    )
    .unwrap();
    assert_eq!(folded.allow_env, ["LD_PRELOAD"]);
    for name in ["OTHER", "DEBUG"] {
        let err = fold(
            &policy,
            &LaunchFlags {
                env_names: vec![name.into()],
                ..flags()
            },
        )
        .unwrap_err();
        assert_eq!(err.key.as_deref(), Some("--env"), "{name}");
    }
}

#[test]
fn without_an_allow_list_env_flags_pass() {
    let folded = fold(
        &PolicyBody::default(),
        &LaunchFlags {
            env_names: vec!["ANYTHING".into()],
            ..flags()
        },
    )
    .unwrap();
    assert!(folded.allow_env.is_empty());
}

// ---- the resolved manifest ------------------------------------------------------

#[test]
fn a_resolved_manifest_round_trips_and_is_revalidated() {
    let manifest = ResolvedManifest {
        resolved_from: vec!["profile `x`".into()],
        policy: network(&["a.test"], &[], None),
    };
    let json = serde_json::to_vec(&manifest).unwrap();
    let back = ResolvedManifest::from_json(&json, "m", None).unwrap();
    assert_eq!(back.policy.network.allow, ["a.test:443"]);

    let bad = serde_json::to_vec(&ResolvedManifest {
        resolved_from: vec![],
        policy: network(&["a.test:22"], &[], None),
    })
    .unwrap();
    assert!(ResolvedManifest::from_json(&bad, "m", None).is_err());
}

#[test]
fn a_signed_plan_or_signature_is_never_accepted_as_a_manifest() {
    for doc in [
        r#"{"plan": {}, "signature": "AAAA", "signer_id": "host:x"}"#,
        r#"{"plan_id": "p", "policy": {}}"#,
        r#"{"policy": {}, "signature": "AAAA"}"#,
    ] {
        let err = ResolvedManifest::from_json(doc.as_bytes(), "m", None).unwrap_err();
        assert!(err.message.contains("never trusted"), "{doc}: {err}");
    }
}

#[test]
fn unknown_keys_in_a_manifest_are_refused() {
    let err = ResolvedManifest::from_json(br#"{"policy": {}, "extra": 1}"#, "m", None).unwrap_err();
    assert!(err.message.contains("unknown field"), "{err}");
    assert!(ResolvedManifest::from_json(b"not json", "m", None).is_err());
}
