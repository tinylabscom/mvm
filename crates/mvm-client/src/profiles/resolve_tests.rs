use super::*;
use crate::profiles::model::NetworkSection;

/// A temporary user policy directory.
struct Dir {
    dir: tempfile::TempDir,
    store: PolicyStore,
}

impl Dir {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::at(dir.path());
        std::fs::create_dir_all(store.profiles_dir()).unwrap();
        std::fs::create_dir_all(store.groups_dir()).unwrap();
        Self { dir, store }
    }

    fn profile(&self, name: &str, text: &str) -> PathBuf {
        let path = self.store.profiles_dir().join(format!("{name}.toml"));
        std::fs::write(&path, text).unwrap();
        path
    }

    fn group(&self, name: &str, text: &str) {
        std::fs::write(self.store.groups_dir().join(format!("{name}.toml")), text).unwrap();
    }

    fn resolve(&self, reference: &str) -> Result<ResolvedPolicy, PolicyError> {
        self.resolve_on(reference, Platform::default())
    }

    fn resolve_on(
        &self,
        reference: &str,
        platform: Platform,
    ) -> Result<ResolvedPolicy, PolicyError> {
        resolve(
            &self.store,
            &PolicySelection::profile(PolicyRef::parse(reference).unwrap()),
            platform,
        )
    }
}

fn allow(resolved: &ResolvedPolicy) -> Vec<String> {
    resolved.policy.network.allow.clone()
}

// ---- built-ins ------------------------------------------------------------

#[test]
fn the_built_in_profiles_resolve_to_what_they_say() {
    let dir = Dir::new();
    assert!(dir.resolve("default").unwrap().policy.is_empty());
    assert_eq!(
        dir.resolve("dev-network")
            .unwrap()
            .policy
            .network
            .allow
            .len(),
        6
    );
    let agent = allow(&dir.resolve("agent-apis").unwrap());
    for host in [
        "api.anthropic.com:443",
        "api.openai.com:443",
        "github.com:443",
    ] {
        assert!(agent.contains(&host.to_string()), "{agent:?}");
    }
    assert_eq!(
        dir.resolve("offline").unwrap().policy.network.block,
        Some(true)
    );
}

// ---- extends ----------------------------------------------------------------

#[test]
fn a_child_inherits_its_parents_and_adds_its_own() {
    let dir = Dir::new();
    dir.profile(
        "team",
        "extends = \"agent-apis\"\n[overrides.network]\nallow = [\"internal.test\"]\n",
    );
    let resolved = dir.resolve("team").unwrap();
    let hosts = allow(&resolved);
    assert!(hosts.contains(&"api.openai.com:443".to_string()));
    assert!(hosts.contains(&"internal.test:443".to_string()));
    let labels: Vec<&str> = resolved.layers.iter().map(|l| l.label.as_str()).collect();
    assert!(
        labels
            .iter()
            .any(|l| l.contains("group `llm-apis` (built-in)")),
        "{labels:?}"
    );
    assert!(
        labels.last().unwrap().contains("profile `team` overrides"),
        "{labels:?}"
    );
}

#[test]
fn extends_accepts_a_list_and_a_diamond_is_applied_once() {
    let dir = Dir::new();
    dir.profile(
        "a",
        "extends = \"default\"\n[overrides.network]\nallow = [\"a.test\"]\n",
    );
    dir.profile(
        "b",
        "extends = \"default\"\n[overrides.network]\nallow = [\"b.test\"]\n",
    );
    dir.profile("both", "extends = [\"a\", \"b\"]\n");
    let resolved = dir.resolve("both").unwrap();
    assert_eq!(allow(&resolved), ["a.test:443", "b.test:443"]);
}

#[test]
fn a_cycle_is_refused_and_named() {
    let dir = Dir::new();
    dir.profile("a", "extends = \"b\"\n");
    dir.profile("b", "extends = \"c\"\n");
    dir.profile("c", "extends = \"a\"\n");
    let err = dir.resolve("a").unwrap_err();
    assert_eq!(err.key.as_deref(), Some("extends"));
    assert!(
        err.message
            .contains("profile `a` -> profile `b` -> profile `c` -> profile `a`"),
        "{err}"
    );
}

#[test]
fn a_self_reference_is_a_cycle() {
    let dir = Dir::new();
    dir.profile("me", "extends = \"me\"\n");
    assert!(dir.resolve("me").unwrap_err().message.contains("cycle"));
}

#[test]
fn the_extends_chain_is_capped_at_ten_levels() {
    let dir = Dir::new();
    // p0 extends p1 ... extends p{n}; p{n} extends nothing.
    let chain = |dir: &Dir, depth: usize| {
        for i in 0..depth {
            dir.profile(&format!("p{i}"), &format!("extends = \"p{}\"\n", i + 1));
        }
        dir.profile(&format!("p{depth}"), "");
    };
    let ok = Dir::new();
    chain(&ok, MAX_EXTENDS_DEPTH);
    ok.resolve("p0").expect("ten levels are allowed");

    chain(&dir, MAX_EXTENDS_DEPTH + 1);
    let err = dir.resolve("p0").unwrap_err();
    assert!(err.message.contains("deeper than 10"), "{err}");
}

#[test]
fn an_unknown_parent_names_the_referring_file_and_key() {
    let dir = Dir::new();
    let file = dir.profile("x", "extends = \"missing\"\n");
    let err = dir.resolve("x").unwrap_err();
    assert_eq!(err.file.as_deref(), Some(file.as_path()));
    assert_eq!(err.key.as_deref(), Some("extends"));
    assert!(err.message.contains("no profile named `missing`"), "{err}");
}

#[test]
fn a_pack_parent_is_refused_as_not_yet_supported() {
    let dir = Dir::new();
    dir.profile("x", "extends = \"acme/agent\"\n");
    assert!(
        dir.resolve("x")
            .unwrap_err()
            .message
            .contains("packs are not yet supported")
    );
}

// ---- groups -----------------------------------------------------------------

#[test]
fn a_child_can_exclude_a_group_a_parent_included() {
    let dir = Dir::new();
    dir.profile(
        "no-github",
        "extends = \"agent-apis\"\n[groups]\nexclude = [\"github\"]\n",
    );
    let hosts = allow(&dir.resolve("no-github").unwrap());
    assert!(!hosts.iter().any(|h| h.contains("github")), "{hosts:?}");
    assert!(hosts.contains(&"api.anthropic.com:443".to_string()));
}

#[test]
fn a_required_group_cannot_be_excluded() {
    let dir = Dir::new();
    let file = dir.profile(
        "sneaky",
        "extends = \"offline\"\n[groups]\nexclude = [\"offline\"]\n",
    );
    let err = dir.resolve("sneaky").unwrap_err();
    assert_eq!(err.file.as_deref(), Some(file.as_path()));
    assert_eq!(err.key.as_deref(), Some("groups.exclude"));
    assert!(err.message.contains("is required"), "{err}");
}

#[test]
fn a_user_group_marked_required_is_held_too() {
    let dir = Dir::new();
    dir.group(
        "baseline",
        "required = true\n[network]\ndeny = [\"*.internal.test\"]\n",
    );
    dir.profile("base", "[groups]\ninclude = [\"baseline\"]\n");
    dir.profile(
        "child",
        "extends = \"base\"\n[[when]]\nexclude = [\"baseline\"]\n",
    );
    let err = dir.resolve("child").unwrap_err();
    assert_eq!(err.key.as_deref(), Some("when[0].exclude"));
}

#[test]
fn a_child_cannot_unblock_what_a_required_group_blocked() {
    let dir = Dir::new();
    dir.profile(
        "leaky",
        "extends = \"offline\"\n[overrides.network]\nblock = false\n",
    );
    let err = dir.resolve("leaky").unwrap_err();
    assert_eq!(err.key.as_deref(), Some("network.block"));

    dir.profile(
        "adds-hosts",
        "extends = \"offline\"\n[overrides.network]\nallow = [\"a.test\"]\n",
    );
    let resolved = dir.resolve("adds-hosts").unwrap();
    assert!(allow(&resolved).is_empty());
    assert!(!resolved.notes.is_empty());
}

#[test]
fn a_group_by_path_resolves_against_the_profile_file() {
    let dir = Dir::new();
    std::fs::write(
        dir.dir.path().join("local-group.toml"),
        "[network]\nallow = [\"local.test\"]\n",
    )
    .unwrap();
    let profile = dir.dir.path().join("p.toml");
    std::fs::write(&profile, "[groups]\ninclude = [\"./local-group.toml\"]\n").unwrap();
    let resolved = dir.resolve(profile.to_str().unwrap()).unwrap();
    assert_eq!(allow(&resolved), ["local.test:443"]);
}

// ---- when -------------------------------------------------------------------

fn when_profile(dir: &Dir) {
    dir.profile(
        "platformed",
        "[[when]]\nos = \"linux\"\n[when.overrides.network]\nallow = [\"linux.test\"]\n\
         [[when]]\nos = \"macos\"\narch = \"aarch64\"\n[when.overrides.network]\nallow = [\"mac-arm.test\"]\n\
         [[when]]\nbackend = [\"firecracker\", \"qemu\"]\ninclude = [\"github\"]\n",
    );
}

#[test]
fn when_blocks_apply_only_on_matching_platforms() {
    let dir = Dir::new();
    when_profile(&dir);
    let linux_fc = Platform {
        os: Some(HostOs::Linux),
        arch: Some(HostArch::X86_64),
        backend: Some(BackendKind::Firecracker),
    };
    let hosts = allow(&dir.resolve_on("platformed", linux_fc).unwrap());
    assert!(hosts.contains(&"linux.test:443".to_string()));
    assert!(hosts.contains(&"github.com:443".to_string()));
    assert!(!hosts.contains(&"mac-arm.test:443".to_string()));

    let mac_hvf = Platform {
        os: Some(HostOs::Macos),
        arch: Some(HostArch::Aarch64),
        backend: Some(BackendKind::Hvf),
    };
    assert_eq!(
        allow(&dir.resolve_on("platformed", mac_hvf).unwrap()),
        ["mac-arm.test:443"]
    );

    let mac_intel = Platform {
        arch: Some(HostArch::X86_64),
        ..mac_hvf
    };
    assert!(allow(&dir.resolve_on("platformed", mac_intel).unwrap()).is_empty());
}

#[test]
fn a_predicate_on_an_unknown_backend_does_not_match() {
    let dir = Dir::new();
    when_profile(&dir);
    let unknown = Platform {
        os: Some(HostOs::Linux),
        arch: None,
        backend: None,
    };
    let hosts = allow(&dir.resolve_on("platformed", unknown).unwrap());
    assert_eq!(hosts, ["linux.test:443"]);
}

// ---- discovery precedence -------------------------------------------------

fn project(profile: Option<&str>, include: &[&str], allow_hosts: &[&str]) -> ProjectPolicy {
    ProjectPolicy {
        manifest: PathBuf::from("/p/mvm.toml"),
        profile: profile.map(str::to_string),
        include: include.iter().map(ToString::to_string).collect(),
        allow_hosts: allow_hosts.iter().map(ToString::to_string).collect(),
    }
}

#[test]
fn a_launch_selects_a_flag_the_project_or_nothing() {
    let chosen = PolicySelection::for_launch(Some("offline"), Some(project(Some("x"), &[], &[])))
        .unwrap()
        .unwrap();
    assert_eq!(chosen.profile, Some(PolicyRef::Name("offline".into())));

    let chosen = PolicySelection::for_launch(None, Some(project(Some("x"), &[], &[])))
        .unwrap()
        .unwrap();
    assert_eq!(chosen.profile, None);
    assert!(chosen.project.is_some());

    assert_eq!(
        PolicySelection::for_launch(None, Some(project(None, &[], &[]))).unwrap(),
        None,
        "a project that says nothing selects nothing"
    );
    assert_eq!(PolicySelection::for_launch(None, None).unwrap(), None);
    assert!(PolicySelection::for_launch(Some("Bad Name"), None).is_err());
}

#[test]
fn an_explicit_policy_replaces_the_project_table_but_keeps_its_network() {
    let dir = Dir::new();
    let selection = PolicySelection::for_launch(
        Some("agent-apis"),
        Some(project(Some("dev-network"), &[], &["project.test"])),
    )
    .unwrap()
    .unwrap();
    let hosts = allow(&resolve(&dir.store, &selection, Platform::default()).unwrap());
    assert!(
        hosts.contains(&"api.openai.com:443".to_string()),
        "{hosts:?}"
    );
    assert!(hosts.contains(&"project.test:443".to_string()), "{hosts:?}");
    assert!(!hosts.contains(&"pypi.org:443".to_string()), "{hosts:?}");
}

#[test]
fn a_projects_network_allow_hosts_apply_with_no_policy_at_all() {
    let dir = Dir::new();
    let selection =
        PolicySelection::for_launch(None, Some(project(None, &[], &["api.example.com"])))
            .unwrap()
            .unwrap();
    assert_eq!(
        allow(&resolve(&dir.store, &selection, Platform::default()).unwrap()),
        ["api.example.com:443"]
    );
}

#[test]
fn a_blocked_profile_drops_the_projects_hosts() {
    let dir = Dir::new();
    let selection =
        PolicySelection::for_launch(Some("offline"), Some(project(None, &[], &["a.test"])))
            .unwrap()
            .unwrap();
    let resolved = resolve(&dir.store, &selection, Platform::default()).unwrap();
    assert!(allow(&resolved).is_empty());
    assert!(!resolved.notes.is_empty());
}

#[test]
fn a_project_table_resolves_its_profile_and_groups_as_project_layers() {
    let dir = Dir::new();
    let dir_project = tempfile::tempdir().unwrap();
    std::fs::write(
        dir_project.path().join("extra.toml"),
        "[network]\nallow = [\"project.test\"]\n",
    )
    .unwrap();
    let selection = PolicySelection {
        profile: None,
        project: Some(ProjectPolicy {
            manifest: dir_project.path().join("mvm.toml"),
            profile: Some("dev-network".into()),
            include: vec!["./extra.toml".into()],
            allow_hosts: Vec::new(),
        }),
    };
    let resolved = resolve(&dir.store, &selection, Platform::default()).unwrap();
    assert!(allow(&resolved).contains(&"project.test:443".to_string()));
    assert!(allow(&resolved).contains(&"pypi.org:443".to_string()));
    let extra = resolved
        .layers
        .iter()
        .find(|l| l.label.contains("extra.toml"))
        .unwrap();
    assert_eq!(extra.origin, LayerOrigin::Project);
}

#[test]
fn a_project_cannot_use_an_escape_hatch() {
    let dir = Dir::new();
    let dir_project = tempfile::tempdir().unwrap();
    std::fs::write(
        dir_project.path().join("hatch.toml"),
        "[env]\nreadmit = [\"LD_PRELOAD\"]\n",
    )
    .unwrap();
    let selection = PolicySelection {
        profile: None,
        project: Some(ProjectPolicy {
            manifest: dir_project.path().join("mvm.toml"),
            profile: None,
            include: vec!["./hatch.toml".into()],
            allow_hosts: Vec::new(),
        }),
    };
    let err = resolve(&dir.store, &selection, Platform::default()).unwrap_err();
    assert_eq!(err.key.as_deref(), Some("env.readmit"));
}

#[test]
fn project_policy_reads_the_policy_table_and_network_allow_hosts() {
    let manifest = mvm_core::manifest::Manifest::from_toml_str(
        "flake = \".\"\n[network]\nallow_hosts = [\"a.test\"]\n[policy]\nprofile = \"offline\"\ninclude = [\"g\"]\n",
    )
    .unwrap();
    let project = ProjectPolicy::from_manifest(Path::new("/p/mvm.toml"), &manifest);
    assert_eq!(project.profile.as_deref(), Some("offline"));
    assert_eq!(project.include, ["g"]);
    assert_eq!(project.allow_hosts, ["a.test"]);
    assert!(!project.is_empty());
}

#[test]
fn a_user_profile_may_use_the_escape_hatch() {
    let dir = Dir::new();
    dir.profile("hatch", "[overrides.env]\nreadmit = [\"LD_PRELOAD\"]\n");
    assert_eq!(
        dir.resolve("hatch").unwrap().policy.env.readmit,
        ["LD_PRELOAD"]
    );
}

// ---- files ------------------------------------------------------------------

#[test]
fn resolve_file_accepts_a_profile_or_a_group() {
    let dir = Dir::new();
    let group = dir.dir.path().join("g.toml");
    std::fs::write(&group, "required = true\n[network]\nallow = [\"g.test\"]\n").unwrap();
    assert_eq!(
        allow(&resolve_file(&dir.store, &group, Platform::default()).unwrap()),
        ["g.test:443"]
    );
    let profile = dir.dir.path().join("p.toml");
    std::fs::write(&profile, "extends = \"agent-apis\"\n").unwrap();
    assert!(!allow(&resolve_file(&dir.store, &profile, Platform::default()).unwrap()).is_empty());
}

#[test]
fn revalidate_checks_a_body_as_a_user_layer() {
    let body = PolicyBody {
        network: NetworkSection {
            allow: vec!["x.test:22".into()],
            ..NetworkSection::default()
        },
        ..PolicyBody::default()
    };
    assert!(revalidate("manifest", None, body).is_err());
}
