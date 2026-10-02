use super::*;
use crate::policy_profiles::model::{GroupFile, ProfileFile};

fn layer(label: &str, origin: LayerOrigin, toml_body: &str) -> Layer {
    let group: GroupFile = toml::from_str(toml_body).expect("test body parses");
    Layer {
        label: label.to_string(),
        file: Some(PathBuf::from(format!("/policies/{label}.toml"))),
        origin,
        body: group.body(),
    }
}

fn user(label: &str, toml_body: &str) -> Layer {
    layer(label, LayerOrigin::User, toml_body)
}

fn merged(layers: &[Layer]) -> ResolvedPolicy {
    merge_layers(layers).expect("merges")
}

fn refused(layers: &[Layer]) -> PolicyError {
    merge_layers(layers).expect_err("the merge must refuse")
}

// ---- allows union, denies union, deny beats allow -------------------------

#[test]
fn allows_are_unioned_and_canonicalized() {
    let resolved = merged(&[
        user(
            "a",
            "[network]\nallow = [\"api.example.com\", \"x.test:8443\"]\n",
        ),
        user(
            "b",
            "[network]\nallow = [\"api.example.com:443\", \"y.test\"]\n",
        ),
    ]);
    assert_eq!(
        resolved.policy.network.allow,
        ["api.example.com:443", "x.test:8443", "y.test:443"]
    );
    assert_eq!(resolved.provenance["network.allow.y.test:443"], "b");
}

#[test]
fn a_deny_beats_an_allow_from_any_layer_in_either_order() {
    for (first, second) in [
        (
            "[network]\nallow = [\"a.test\", \"b.test\"]\n",
            "[network]\ndeny = [\"b.test\"]\n",
        ),
        (
            "[network]\ndeny = [\"b.test\"]\n",
            "[network]\nallow = [\"a.test\", \"b.test\"]\n",
        ),
    ] {
        let resolved = merged(&[user("one", first), user("two", second)]);
        assert_eq!(resolved.policy.network.allow, ["a.test:443"]);
        assert!(
            resolved.notes.iter().any(|n| n.contains("b.test:443")),
            "{:?}",
            resolved.notes
        );
    }
}

#[test]
fn a_wildcard_deny_covers_subdomains_and_a_port_deny_only_its_port() {
    let resolved = merged(&[user(
        "a",
        "[network]\nallow = [\"api.corp.test\", \"corp.test\", \"x.test:8080\", \"x.test\"]\n\
         deny = [\"*.corp.test\", \"x.test:8080\"]\n",
    )]);
    assert_eq!(
        resolved.policy.network.allow,
        ["corp.test:443", "x.test:443"]
    );
}

#[test]
fn denies_union_across_every_section() {
    let resolved = merged(&[
        user(
            "a",
            "[[secrets.bind]]\nname = \"gh\"\n[[secrets.bind]]\nname = \"npm\"\n\
             [env]\nallow = [\"MODE\", \"TOKEN_HINT\"]\n[tools]\nallow = [\"git\", \"curl\"]\n",
        ),
        user(
            "b",
            "[secrets]\ndeny = [\"npm\"]\n[env]\ndeny = [\"TOKEN_HINT\"]\n[tools]\ndeny = [\"curl\"]\n",
        ),
    ]);
    let names: Vec<&str> = resolved
        .policy
        .secrets
        .bind
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, ["gh"]);
    assert_eq!(resolved.policy.env.allow, ["MODE"]);
    assert_eq!(resolved.policy.tools.allow, ["git"]);
}

#[test]
fn a_denied_share_source_is_dropped() {
    let resolved = merged(&[
        user(
            "a",
            "[[shares.mount]]\nhost = \"/home/me/.ssh\"\nguest = \"/ssh\"\n\
             [[shares.mount]]\nhost = \"/work\"\nguest = \"/work\"\n",
        ),
        user("b", "[shares]\ndeny = [\"/home/me\"]\n"),
    ]);
    let hosts: Vec<&str> = resolved
        .policy
        .shares
        .mount
        .iter()
        .map(|m| m.host.as_str())
        .collect();
    assert_eq!(hosts, ["/work"]);
}

// ---- network block --------------------------------------------------------

#[test]
fn a_block_drops_every_allow_and_route() {
    let resolved = merged(&[
        user("parent", "[network]\nblock = true\n"),
        user(
            "child",
            "[network]\nallow = [\"a.test\"]\n[[network.routes]]\nid = \"gh\"\nhost = \"api.github.com\"\n",
        ),
    ]);
    assert_eq!(resolved.policy.network.block, Some(true));
    assert!(resolved.policy.network.allow.is_empty());
    assert!(resolved.policy.network.routes.is_empty());
    assert!(
        resolved
            .notes
            .iter()
            .any(|n| n.contains("blocked by parent"))
    );
}

#[test]
fn a_child_cannot_turn_the_network_back_on() {
    let err = refused(&[
        user("parent", "[network]\nblock = true\n"),
        user("child", "[network]\nblock = false\n"),
    ]);
    assert_eq!(err.layer, "child");
    assert_eq!(err.key.as_deref(), Some("network.block"));
    assert_eq!(err.file.as_deref(), Some(Path::new("/policies/child.toml")));
    assert!(err.message.contains("parent blocked it"), "{err}");
}

#[test]
fn block_false_with_nothing_blocked_is_harmless() {
    let resolved = merged(&[user(
        "a",
        "[network]\nblock = false\nallow = [\"a.test\"]\n",
    )]);
    assert_eq!(resolved.policy.network.block, None);
    assert_eq!(resolved.policy.network.allow, ["a.test:443"]);
}

// ---- routes ---------------------------------------------------------------

#[test]
fn a_later_layer_cannot_add_rules_to_an_earlier_route() {
    let err = refused(&[
        user(
            "a",
            "[[network.routes]]\nid = \"gh\"\nhost = \"api.github.com\"\n",
        ),
        user(
            "b",
            "[[network.routes]]\nid = \"gh-2\"\nhost = \"api.github.com\"\n",
        ),
    ]);
    assert_eq!(err.key.as_deref(), Some("network.routes"));
    assert!(err.message.contains("collides"), "{err}");
}

#[test]
fn a_denied_route_host_is_dropped() {
    let resolved = merged(&[user(
        "a",
        "[network]\ndeny = [\"api.github.com\"]\n[[network.routes]]\nid = \"gh\"\nhost = \"api.github.com\"\n",
    )]);
    assert!(resolved.policy.network.routes.is_empty());
}

// ---- secrets narrow -------------------------------------------------------

#[test]
fn a_later_layer_may_narrow_a_secrets_destinations() {
    let resolved = merged(&[
        user(
            "a",
            "[[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com\", \"uploads.github.com\"]\n",
        ),
        user(
            "b",
            "[[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com\"]\n",
        ),
    ]);
    assert_eq!(resolved.policy.secrets.bind[0].hosts, ["api.github.com"]);
}

#[test]
fn a_later_layer_cannot_widen_a_secrets_destinations() {
    let err = refused(&[
        user(
            "a",
            "[[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com\"]\n",
        ),
        user(
            "b",
            "[[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com\", \"evil.test\"]\n",
        ),
    ]);
    assert_eq!(err.layer, "b");
    assert_eq!(err.key.as_deref(), Some("secrets.bind.hosts"));
    assert!(
        err.message.contains("evil.test") && err.message.contains("widens"),
        "{err}"
    );
}

#[test]
fn an_empty_host_list_keeps_whatever_was_narrowed_before() {
    let resolved = merged(&[
        user(
            "a",
            "[[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com\"]\n",
        ),
        user("b", "[[secrets.bind]]\nname = \"gh\"\n"),
    ]);
    assert_eq!(resolved.policy.secrets.bind[0].hosts, ["api.github.com"]);
}

#[test]
fn a_secret_host_with_a_port_is_refused() {
    let err = refused(&[user(
        "a",
        "[[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com:443\"]\n",
    )]);
    assert_eq!(err.key.as_deref(), Some("secrets.bind.hosts"));
}

// ---- shares ---------------------------------------------------------------

#[test]
fn a_share_is_writable_only_if_every_layer_says_so() {
    let resolved = merged(&[
        user(
            "a",
            "[[shares.mount]]\nhost = \"/work\"\nguest = \"/work\"\nwritable = true\n",
        ),
        user(
            "b",
            "[[shares.mount]]\nhost = \"/work\"\nguest = \"/work\"\n",
        ),
    ]);
    assert!(!resolved.policy.shares.mount[0].writable);
}

#[test]
fn two_sources_for_one_guest_path_are_refused() {
    let err = refused(&[
        user(
            "a",
            "[[shares.mount]]\nhost = \"/work\"\nguest = \"/work\"\n",
        ),
        user(
            "b",
            "[[shares.mount]]\nhost = \"/elsewhere\"\nguest = \"/work\"\n",
        ),
    ]);
    assert_eq!(err.key.as_deref(), Some("shares.mount.guest"));
}

#[test]
fn a_relative_share_resolves_against_its_file_and_a_relative_guest_is_refused() {
    let resolved = merged(&[user(
        "a",
        "[[shares.mount]]\nhost = \"src\"\nguest = \"/src\"\n",
    )]);
    assert_eq!(resolved.policy.shares.mount[0].host, "/policies/src");
    let err = refused(&[user(
        "a",
        "[[shares.mount]]\nhost = \"/src\"\nguest = \"src\"\n",
    )]);
    assert_eq!(err.key.as_deref(), Some("shares.mount.guest"));
}

// ---- env and the escape hatch ---------------------------------------------

#[test]
fn a_denylisted_variable_needs_a_user_authored_readmit() {
    let err = refused(&[user("a", "[env]\nallow = [\"LD_PRELOAD\"]\n")]);
    assert_eq!(err.key.as_deref(), Some("env.allow"));
    assert!(err.message.contains("env.readmit"), "{err}");

    let resolved = merged(&[user(
        "a",
        "[env]\nallow = [\"LD_PRELOAD\"]\nreadmit = [\"LD_PRELOAD\"]\n",
    )]);
    assert_eq!(resolved.policy.env.readmit, ["LD_PRELOAD"]);
}

#[test]
fn an_escape_hatch_outside_user_authored_layers_is_stripped_with_a_note() {
    for origin in [
        LayerOrigin::Project,
        LayerOrigin::Pack,
        LayerOrigin::Builtin,
    ] {
        let resolved = merged(&[layer("x", origin, "[env]\nreadmit = [\"LD_PRELOAD\"]\n")]);
        assert!(
            resolved.policy.env.readmit.is_empty(),
            "{origin:?}: the hatch must not take effect"
        );
        assert!(
            resolved
                .notes
                .iter()
                .any(|note| note.contains("env.readmit") && note.contains("escape hatch")),
            "{origin:?}: the strip is recorded: {:?}",
            resolved.notes
        );
    }
}

#[test]
fn readmitting_a_variable_that_is_not_denied_is_refused() {
    let err = refused(&[user("a", "[env]\nreadmit = [\"MODE\"]\n")]);
    assert!(err.message.contains("not on the denylist"), "{err}");
}

#[test]
fn a_malformed_variable_name_is_refused() {
    let err = refused(&[user("a", "[env]\nallow = [\"1BAD\"]\n")]);
    assert_eq!(err.key.as_deref(), Some("env.allow"));
}

// ---- resources ------------------------------------------------------------

#[test]
fn every_resource_bound_takes_the_smallest() {
    let resolved = merged(&[
        user(
            "a",
            "[resources]\ncpu_millicores = 500\nwall_clock_secs = 60\nmax_cpus = 4\nmax_memory = \"2G\"\n",
        ),
        user(
            "b",
            "[resources]\ncpu_millicores = 1500\nwall_clock_secs = 30\nmax_cpus = 8\nmax_memory = \"512M\"\n",
        ),
    ]);
    let r = &resolved.policy.resources;
    assert_eq!(r.cpu_millicores, Some(500));
    assert_eq!(r.wall_clock_secs, Some(30));
    assert_eq!(r.max_cpus, Some(4));
    assert_eq!(r.max_memory.as_deref(), Some("512M"));
    assert_eq!(resolved.provenance["resources.wall_clock_secs"], "b");
}

#[test]
fn zero_and_unparseable_bounds_are_refused() {
    let err = refused(&[user("a", "[resources]\ncpu_millicores = 0\n")]);
    assert_eq!(err.key.as_deref(), Some("resources.cpu_millicores"));
    let err = refused(&[user("a", "[resources]\nmax_memory = \"lots\"\n")]);
    assert_eq!(err.key.as_deref(), Some("resources.max_memory"));
}

// ---- values and serde -----------------------------------------------------

#[test]
fn malformed_network_entries_name_the_layer_file_and_key() {
    let err = refused(&[user("bad", "[network]\nallow = [\"host:notaport\"]\n")]);
    assert_eq!(err.key.as_deref(), Some("network.allow"));
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("/policies/bad.toml: bad: `network.allow`"),
        "{rendered}"
    );

    let err = refused(&[user("bad", "[network]\nallow = [\"example.com:22\"]\n")]);
    assert!(err.message.contains("SSH"), "{err}");

    let err = refused(&[user("bad", "[network]\ndeny = [\"*\"]\n")]);
    assert_eq!(err.key.as_deref(), Some("network.deny"));
}

#[test]
fn unknown_keys_are_refused_at_every_level() {
    for text in [
        "netwrk = {}\n",
        "[network]\nallowed = []\n",
        "[[secrets.bind]]\nname = \"x\"\nhost = [\"y\"]\n",
        "[[shares.mount]]\nhost = \"/a\"\nguest = \"/b\"\nrw = true\n",
        "[env]\nreadmitted = []\n",
        "[resources]\ncpus = 2\n",
        "[tools]\npermit = []\n",
    ] {
        assert!(
            toml::from_str::<GroupFile>(text).is_err(),
            "must refuse: {text}"
        );
    }
    for text in [
        "extend = \"default\"\n",
        "[groups]\nincludes = []\n",
        "[[when]]\nplatform = \"linux\"\n",
        "[[when]]\nos = \"windows\"\n",
        "[[when]]\nbackend = \"vmware\"\n",
        "[overrides.network]\nallowed = []\n",
    ] {
        assert!(
            toml::from_str::<ProfileFile>(text).is_err(),
            "must refuse: {text}"
        );
    }
}

#[test]
fn documents_round_trip_through_toml() {
    let text = "description = \"d\"\nextends = [\"default\", \"./base.toml\"]\n\
                [groups]\ninclude = [\"registries\"]\nexclude = [\"github\"]\n\
                [[when]]\nos = \"linux\"\nbackend = [\"firecracker\", \"qemu\"]\ninclude = [\"x\"]\n\
                [when.overrides.network]\ndeny = [\"a.test\"]\n\
                [overrides.resources]\nmax_cpus = 2\n";
    let profile: ProfileFile = toml::from_str(text).unwrap();
    let again: ProfileFile = toml::from_str(&toml::to_string(&profile).unwrap()).unwrap();
    assert_eq!(again, profile);

    let group_text = "description = \"g\"\nrequired = true\n[network]\nallow = [\"a.test\"]\nblock = true\n\
                      [[secrets.bind]]\nname = \"gh\"\nhosts = [\"api.github.com\"]\n\
                      [[shares.mount]]\nhost = \"/w\"\nguest = \"/w\"\nwritable = true\n\
                      [env]\nallow = [\"MODE\"]\n[resources]\nmax_memory = \"1G\"\n";
    let group: GroupFile = toml::from_str(group_text).unwrap();
    let again: GroupFile = toml::from_str(&toml::to_string(&group).unwrap()).unwrap();
    assert_eq!(again, group);
}

#[test]
fn no_layers_is_an_empty_policy() {
    let resolved = merged(&[]);
    assert!(resolved.policy.is_empty());
    assert!(resolved.notes.is_empty());
}

/// The committed schema is the generated one. The CI feature lane runs this;
/// regenerate with
/// `cargo run -p mvm-client --features schema --bin emit_policy_schema`.
#[cfg(feature = "schema")]
#[test]
fn the_committed_schema_matches_the_policy_types() {
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(crate::policy_profiles::model::SCHEMA_PATH),
    )
    .expect("the committed schema exists");
    assert_eq!(
        committed.trim_end(),
        crate::policy_profiles::model::json_schema_pretty(),
        "{} is stale; regenerate it with \
         `cargo run -p mvm-client --features schema --bin emit_policy_schema`",
        crate::policy_profiles::model::SCHEMA_PATH
    );
}

/// The docs publish the schema verbatim; the page must carry the generated
/// text, not a copy someone edited.
#[cfg(feature = "schema")]
#[test]
fn the_published_schema_page_carries_the_generated_schema() {
    let page = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../public/src/content/docs/reference/policy-schema.md"),
    )
    .expect("the schema reference page exists");
    let block = page
        .split("```json\n")
        .nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .expect("the page has a json block");
    assert_eq!(block, crate::policy_profiles::model::json_schema_pretty());
}

// ---- tools: whole-tool decisions and per-tool detail ----------------------

#[test]
fn tools_ask_unions_and_beats_allow() {
    let resolved = merged(&[
        user("a", "[tools]\nallow = [\"git\", \"bash\"]\n"),
        user("b", "[tools]\nask = [\"git\"]\nallow = [\"make\"]\n"),
    ]);
    assert_eq!(resolved.policy.tools.allow, ["bash", "make"]);
    assert_eq!(resolved.policy.tools.ask, ["git"]);
}

#[test]
fn tools_deny_beats_ask_and_allow_and_drops_detail() {
    let resolved = merged(&[
        user(
            "a",
            "[tools]\nallow = [\"git\", \"bash\"]\nask = [\"git\"]\n\
             [tools.detail.bash]\nargv = [\"ls *\"]\n",
        ),
        user("b", "[tools]\ndeny = [\"git\", \"bash\"]\n"),
    ]);
    assert!(resolved.policy.tools.allow.is_empty());
    assert!(resolved.policy.tools.ask.is_empty());
    let mut deny = resolved.policy.tools.deny.clone();
    deny.sort();
    assert_eq!(deny, ["bash", "git"]);
    assert!(resolved.policy.tools.detail.is_empty());
}

#[test]
fn tool_detail_unions_denies_and_narrows_the_rest() {
    let resolved = merged(&[
        user(
            "a",
            "[tools]\nallow = [\"bash\"]\n\
             [tools.detail.bash]\nargv = [\"git *\", \"cargo *\"]\n\
             deny = [\"rm *\"]\nroutes = [\"github.com:443\"]\nsecrets = [\"GITHUB_TOKEN\"]\n",
        ),
        user(
            "b",
            "[tools.detail.bash]\nargv = [\"git *\"]\ndeny = [\"sudo *\"]\n",
        ),
    ]);
    let detail = resolved
        .policy
        .tools
        .detail
        .get("bash")
        .expect("bash detail survives");
    assert_eq!(detail.argv, ["git *"]);
    assert_eq!(detail.deny, ["rm *", "sudo *"]);
    assert_eq!(detail.routes, ["github.com:443"]);
    assert_eq!(detail.secrets, ["GITHUB_TOKEN"]);
}

#[test]
fn tool_detail_widening_is_refused_with_the_layer_and_key() {
    let error = refused(&[
        user(
            "a",
            "[tools]\nallow = [\"bash\"]\n[tools.detail.bash]\nargv = [\"git *\"]\n",
        ),
        user("b", "[tools.detail.bash]\nargv = [\"npm *\"]\n"),
    ]);
    assert!(
        error.message.contains("composition only narrows"),
        "{error}"
    );
    assert!(
        error
            .key
            .as_deref()
            .is_some_and(|key| key.contains("tools.detail.bash.argv")),
        "{error}"
    );
}

#[test]
fn tool_detail_routes_and_secrets_only_narrow() {
    let error = refused(&[
        user(
            "a",
            "[tools]\nallow = [\"bash\"]\n\
             [tools.detail.bash]\nroutes = [\"github.com:443\"]\nsecrets = [\"GITHUB_TOKEN\"]\n",
        ),
        user(
            "b",
            "[tools.detail.bash]\nroutes = [\"evil.example:443\"]\n",
        ),
    ]);
    assert!(
        error.message.contains("composition only narrows"),
        "{error}"
    );

    let error = refused(&[
        user(
            "a",
            "[tools]\nallow = [\"bash\"]\n[tools.detail.bash]\nsecrets = [\"GITHUB_TOKEN\"]\n",
        ),
        user("b", "[tools.detail.bash]\nsecrets = [\"OTHER\"]\n"),
    ]);
    assert!(
        error.message.contains("composition only narrows"),
        "{error}"
    );
}

#[test]
fn tool_detail_first_definition_wins_then_narrows() {
    // A later layer may define a tool the earlier ones did not.
    let resolved = merged(&[
        user("a", "[tools]\nallow = [\"bash\"]\n"),
        user("b", "[tools.detail.bash]\nargv = [\"git *\"]\n"),
        user("c", "[tools.detail.bash]\nargv = [\"git *\"]\n"),
    ]);
    let detail = resolved
        .policy
        .tools
        .detail
        .get("bash")
        .expect("bash detail survives");
    assert_eq!(detail.argv, ["git *"]);
}

#[test]
fn tool_detail_narrowing_to_a_pattern_outside_the_grant_is_refused() {
    let error = refused(&[
        user("a", "[tools]\nallow = [\"bash\"]\n"),
        user("b", "[tools.detail.bash]\nargv = [\"git *\"]\n"),
        user("c", "[tools.detail.bash]\nargv = [\"git status *\"]\n"),
    ]);
    assert!(
        error.message.contains("composition only narrows"),
        "{error}"
    );
}

#[test]
fn invalid_tool_names_are_refused() {
    for (key, body) in [
        ("tools.allow", "[tools]\nallow = [\"Bad Name\"]\n"),
        ("tools.ask", "[tools]\nask = [\".hidden\"]\n"),
        ("tools.deny", "[tools]\ndeny = [\"UPPER\"]\n"),
        (
            "tools.detail",
            "[tools.detail.\"bad name\"]\nargv = [\"x\"]\n",
        ),
    ] {
        let error = refused(&[user("a", body)]);
        assert!(
            error.key.as_deref().is_some_and(|at| at.starts_with(key)),
            "{key}: {error}"
        );
    }
}

#[test]
fn invalid_tool_detail_entries_are_refused() {
    for (field, body) in [
        (
            "argv",
            "[tools]\nallow = [\"bash\"]\n[tools.detail.bash]\nargv = [\"\"]\n",
        ),
        (
            "deny",
            "[tools]\nallow = [\"bash\"]\n[tools.detail.bash]\ndeny = [\"line\\nbreak\"]\n",
        ),
        (
            "routes",
            "[tools]\nallow = [\"bash\"]\n[tools.detail.bash]\nroutes = [\"https://evil.example/x\"]\n",
        ),
        (
            "secrets",
            "[tools]\nallow = [\"bash\"]\n[tools.detail.bash]\nsecrets = [\"has space\"]\n",
        ),
    ] {
        let error = refused(&[user("a", body)]);
        assert!(
            error.key.as_deref().is_some_and(|at| at.contains(field)),
            "{field}: {error}"
        );
    }
}

#[test]
fn tools_section_with_detail_round_trips_through_resolution() {
    let text = "[tools]\nallow = [\"bash\"]\nask = [\"git\"]\n\
                [tools.detail.bash]\nargv = [\"git *\"]\nroutes = [\"github.com:443\"]\n";
    let group: GroupFile = toml::from_str(text).expect("test body parses");
    let reparsed: GroupFile =
        toml::from_str(&toml::to_string_pretty(&group).expect("group serializes"))
            .expect("group re-parses");
    assert_eq!(group, reparsed);
    let resolved = merged(&[user("a", text)]);
    let detail = resolved
        .policy
        .tools
        .detail
        .get("bash")
        .expect("bash detail survives");
    assert_eq!(detail.argv, ["git *"]);
    assert_eq!(resolved.policy.tools.ask, ["git"]);
}

#[test]
fn fold_carries_the_resolved_tools_as_contract_rules() {
    let text = "[tools]\nallow = [\"bash\"]\nask = [\"git\"]\ndeny = [\"curl\"]\n\
                [tools.detail.bash]\nargv = [\"git *\"]\nroutes = [\"github.com:443\"]\n\
                secrets = [\"GITHUB_TOKEN\"]\n";
    let resolved = merged(&[user("a", text)]);
    let folded = crate::policy_profiles::fold(
        &resolved.policy,
        &crate::policy_profiles::LaunchFlags::default(),
    )
    .expect("folds");
    let rules = folded.tools;
    assert_eq!(rules.allow, ["bash"]);
    assert_eq!(rules.ask, ["git"]);
    assert_eq!(rules.deny, ["curl"]);
    let detail = rules.detail.get("bash").expect("bash detail");
    assert_eq!(detail.argv, ["git *"]);
    assert_eq!(detail.routes, ["github.com:443"]);
    assert_eq!(detail.secrets, ["GITHUB_TOKEN"]);
}

#[test]
fn fold_without_tools_yields_empty_rules() {
    let resolved = merged(&[user("a", "[network]\nallow = [\"a.test:443\"]\n")]);
    let folded = crate::policy_profiles::fold(
        &resolved.policy,
        &crate::policy_profiles::LaunchFlags::default(),
    )
    .expect("folds");
    assert!(folded.tools.is_empty());
}
