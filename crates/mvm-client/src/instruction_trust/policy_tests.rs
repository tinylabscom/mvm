use std::collections::HashMap;

use ed25519_dalek::SigningKey;

use super::*;

/// A trust store holding whatever keys a test enrols.
#[derive(Default)]
struct Store(HashMap<String, VerifyingKey>);

impl Store {
    fn with(key: &SigningKey) -> Self {
        let mut store = Self::default();
        store.0.insert(
            key_id_from_pubkey(&key.verifying_key()).0,
            key.verifying_key(),
        );
        store
    }
}

impl TrustStore for Store {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        self.0.get(&key_id.0).copied()
    }
}

fn loaded(path: &str, text: &str) -> LoadedPolicy {
    LoadedPolicy {
        path: PathBuf::from(path),
        policy: InstructionTrustPolicy::from_toml_str(text).expect("test policy parses"),
    }
}

const CI_PUBLISHER: &str = r#"
[[publishers]]
kind = "keyless"
name = "ci"
issuer = "https://token.actions.githubusercontent.com"
repository = "acme/agents"
workflow = ".github/workflows/sign-instructions.yml"
ref = "refs/heads/main"
"#;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn keyed_publisher(name: &str, key: &SigningKey) -> String {
    format!(
        "[[publishers]]\nkind = \"keyed\"\nname = \"{name}\"\npublic_key = \"{}\"\n",
        hex::encode(key.verifying_key().to_bytes())
    )
}

// ---- serde ----------------------------------------------------------------

#[test]
fn a_full_policy_round_trips_through_toml() {
    let text = format!(
        "enforcement = \"warn\"\nincludes = [\"**/CLAUDE.md\"]\n{CI_PUBLISHER}{}\n\
         [[blocklist]]\nsha256 = \"{}\"\nreason = \"known bad\"\n",
        keyed_publisher("laptop", &key(1)),
        "ab".repeat(32)
    );
    let policy = InstructionTrustPolicy::from_toml_str(&text).unwrap();
    assert_eq!(policy.enforcement, Some(Enforcement::Warn));
    assert_eq!(policy.publishers.len(), 2);
    assert_eq!(policy.publishers[0].name(), "ci");
    assert_eq!(policy.blocklist[0].reason.as_deref(), Some("known bad"));
    let again = InstructionTrustPolicy::from_toml_str(&policy.to_toml_string()).unwrap();
    assert_eq!(again, policy);
}

#[test]
fn an_empty_document_is_a_policy_with_every_default() {
    let policy = InstructionTrustPolicy::from_toml_str("").unwrap();
    assert_eq!(policy, InstructionTrustPolicy::default());
    let effective =
        EffectivePolicy::merge(Some(loaded("/u.toml", "")), None, &Store::default()).unwrap();
    assert_eq!(effective.enforcement(), Enforcement::Deny);
    assert_eq!(effective.include_patterns().len(), DEFAULT_INCLUDES.len());
}

#[test]
fn unknown_fields_are_refused_at_every_level() {
    for text in [
        "enforce = \"deny\"\n".to_string(),
        format!("{CI_PUBLISHER}subject = \"anyone\"\n"),
        format!(
            "[[blocklist]]\nsha256 = \"{}\"\nallow = true\n",
            "a".repeat(64)
        ),
        "[[publishers]]\nkind = \"keyed\"\nname = \"k\"\nkey_id = \"x\"\ntrusted = true\n"
            .to_string(),
    ] {
        assert!(
            InstructionTrustPolicy::from_toml_str(&text).is_err(),
            "must refuse: {text}"
        );
    }
}

#[test]
fn required_publisher_fields_are_required() {
    for (missing, text) in [
        ("name", CI_PUBLISHER.replace("name = \"ci\"\n", "")),
        (
            "issuer",
            CI_PUBLISHER.replace(
                "issuer = \"https://token.actions.githubusercontent.com\"\n",
                "",
            ),
        ),
        (
            "repository",
            CI_PUBLISHER.replace("repository = \"acme/agents\"\n", ""),
        ),
        (
            "workflow",
            CI_PUBLISHER.replace(
                "workflow = \".github/workflows/sign-instructions.yml\"\n",
                "",
            ),
        ),
        (
            "ref",
            CI_PUBLISHER.replace("ref = \"refs/heads/main\"\n", ""),
        ),
        ("kind", CI_PUBLISHER.replace("kind = \"keyless\"\n", "")),
    ] {
        assert!(
            InstructionTrustPolicy::from_toml_str(&text).is_err(),
            "a publisher without `{missing}` must be refused"
        );
    }
    assert!(
        InstructionTrustPolicy::from_toml_str("[[blocklist]]\nreason = \"x\"\n").is_err(),
        "a blocklist entry without a digest must be refused"
    );
    assert!(InstructionTrustPolicy::from_toml_str("enforcement = \"lenient\"\n").is_err());
}

// ---- validation -----------------------------------------------------------

fn invalid_reason(text: &str) -> String {
    match EffectivePolicy::merge(Some(loaded("/u.toml", text)), None, &Store::default()) {
        Err(PolicyError::Invalid { reason, .. }) => reason,
        other => panic!("expected an invalid policy, got {other:?}"),
    }
}

#[test]
fn a_keyed_publisher_names_exactly_one_key() {
    let both = format!(
        "[[publishers]]\nkind = \"keyed\"\nname = \"k\"\nkey_id = \"{}\"\npublic_key = \"{}\"\n",
        "a".repeat(32),
        "b".repeat(64)
    );
    assert!(invalid_reason(&both).contains("exactly one"));
    let neither = "[[publishers]]\nkind = \"keyed\"\nname = \"k\"\n";
    assert!(invalid_reason(neither).contains("exactly one"));
}

#[test]
fn a_keyed_publisher_by_id_must_be_enrolled() {
    let enrolled = key(7);
    let id = key_id_from_pubkey(&enrolled.verifying_key()).0;
    let text = format!("[[publishers]]\nkind = \"keyed\"\nname = \"k\"\nkey_id = \"{id}\"\n");
    assert!(invalid_reason(&text).contains("not enrolled"));
    let effective = EffectivePolicy::merge(
        Some(loaded("/u.toml", &text)),
        None,
        &Store::with(&enrolled),
    )
    .unwrap();
    assert_eq!(effective.publishers().len(), 1);
}

#[test]
fn malformed_keys_digests_and_globs_are_refused() {
    let bad_key = "[[publishers]]\nkind = \"keyed\"\nname = \"k\"\npublic_key = \"zz\"\n";
    assert!(invalid_reason(bad_key).contains("64 hex"));
    let bad_digest = "[[blocklist]]\nsha256 = \"abc\"\n";
    assert!(invalid_reason(bad_digest).contains("SHA-256"));
    assert!(invalid_reason("includes = [\"[\"]\n").contains("not a valid glob"));
    assert!(invalid_reason("includes = [\"/etc/**\"]\n").contains("relative"));
    assert!(invalid_reason("includes = [\"../**/CLAUDE.md\"]\n").contains("relative"));
}

#[test]
fn keyless_publishers_pin_repository_and_workflow_exactly() {
    for (field, replacement) in [
        ("repository", "repository = \"acme/*\""),
        ("repository", "repository = \"acme\""),
        ("workflow", "workflow = \"sign.yml\""),
        ("workflow", "workflow = \".github/workflows/*.yml\""),
        ("ref", "ref = \"main\""),
        ("issuer", "issuer = \"http://token.example\""),
    ] {
        let original = CI_PUBLISHER
            .lines()
            .find(|l| l.starts_with(&format!("{field} =")))
            .unwrap();
        let text = CI_PUBLISHER.replace(original, replacement);
        assert!(
            !invalid_reason(&text).is_empty(),
            "`{replacement}` must be refused"
        );
    }
}

#[test]
fn publisher_names_are_unique() {
    let text = format!("{CI_PUBLISHER}{CI_PUBLISHER}");
    assert!(invalid_reason(&text).contains("used twice"));
}

#[test]
fn blocklist_digests_are_normalized() {
    let upper = "AB".repeat(32);
    let text = format!("[[blocklist]]\nsha256 = \"sha256:{upper}\"\n");
    let effective =
        EffectivePolicy::merge(Some(loaded("/u.toml", &text)), None, &Store::default()).unwrap();
    assert_eq!(effective.blocked(&"ab".repeat(32)), Some(None));
}

// ---- keyless identity patterns -----------------------------------------------

fn ci_pattern(git_ref: &str) -> KeylessPattern {
    let text = CI_PUBLISHER.replace("refs/heads/main", git_ref);
    let effective =
        EffectivePolicy::merge(Some(loaded("/u.toml", &text)), None, &Store::default()).unwrap();
    match &effective.publishers()[0].trust {
        PublisherTrust::Keyless(pattern) => pattern.clone(),
        PublisherTrust::Keyed { .. } => panic!("keyless publisher expected"),
    }
}

fn san(repository: &str, workflow: &str, git_ref: &str) -> String {
    super::super::identity::workflow_identity(repository, workflow, git_ref)
}

#[test]
fn a_keyless_pattern_matches_only_its_workflow_on_its_ref() {
    let pattern = ci_pattern("refs/heads/main");
    let wf = ".github/workflows/sign-instructions.yml";
    assert!(pattern.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("acme/agents", wf, "refs/heads/main")
    ));
    assert!(
        pattern.matches(
            GITHUB_ACTIONS_ISSUER,
            &san("ACME/Agents", wf, "refs/heads/main")
        ),
        "GitHub names are case-insensitive"
    );
    assert!(!pattern.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("acme/agents", wf, "refs/heads/dev")
    ));
    assert!(!pattern.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("evil/agents", wf, "refs/heads/main")
    ));
    assert!(!pattern.matches(
        GITHUB_ACTIONS_ISSUER,
        &san(
            "acme/agents",
            ".github/workflows/other.yml",
            "refs/heads/main"
        )
    ));
    assert!(!pattern.matches(
        "https://accounts.example.test",
        &san("acme/agents", wf, "refs/heads/main")
    ));
    assert!(!pattern.matches(GITHUB_ACTIONS_ISSUER, "someone@example.test"));
}

#[test]
fn a_keyless_pattern_describes_the_identity_it_accepts() {
    assert_eq!(
        ci_pattern("refs/tags/v*").identity_pattern(),
        "https://github.com/acme/agents/.github/workflows/sign-instructions.yml@refs/tags/v*"
    );
}

#[test]
fn a_ref_glob_star_stays_within_one_segment() {
    let wf = ".github/workflows/sign-instructions.yml";
    let tags = ci_pattern("refs/tags/v*");
    assert!(tags.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("acme/agents", wf, "refs/tags/v1.2.0")
    ));
    assert!(!tags.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("acme/agents", wf, "refs/heads/v1")
    ));
    let one = ci_pattern("refs/heads/*");
    assert!(!one.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("acme/agents", wf, "refs/heads/feature/x")
    ));
    let deep = ci_pattern("refs/heads/**");
    assert!(deep.matches(
        GITHUB_ACTIONS_ISSUER,
        &san("acme/agents", wf, "refs/heads/feature/x")
    ));
}

// ---- merge -------------------------------------------------------------------

#[test]
fn no_policy_anywhere_records_only() {
    let effective = EffectivePolicy::merge(None, None, &Store::default()).unwrap();
    assert_eq!(effective.origin(), PolicyOrigin::Builtin);
    assert_eq!(effective.enforcement(), Enforcement::Audit);
    assert!(effective.publishers().is_empty());
    assert!(effective.includes(Path::new("CLAUDE.md")));
}

#[test]
fn a_project_cannot_weaken_the_users_enforcement() {
    for (user, project, expected) in [
        ("deny", "warn", Enforcement::Deny),
        ("deny", "audit", Enforcement::Deny),
        ("warn", "audit", Enforcement::Warn),
        ("warn", "deny", Enforcement::Deny),
        ("audit", "warn", Enforcement::Warn),
    ] {
        let effective = EffectivePolicy::merge(
            Some(loaded("/u.toml", &format!("enforcement = \"{user}\"\n"))),
            Some(loaded("/p.toml", &format!("enforcement = \"{project}\"\n"))),
            &Store::default(),
        )
        .unwrap();
        assert_eq!(
            effective.enforcement(),
            expected,
            "user {user}, project {project}"
        );
        assert_eq!(effective.origin(), PolicyOrigin::UserAndProject);
    }
    let weakened = EffectivePolicy::merge(
        Some(loaded("/u.toml", "enforcement = \"deny\"\n")),
        Some(loaded("/p.toml", "enforcement = \"audit\"\n")),
        &Store::default(),
    )
    .unwrap();
    assert!(
        weakened.notes().iter().any(|n| n.contains("weaker")),
        "the ignored downgrade is reported: {:?}",
        weakened.notes()
    );
}

#[test]
fn a_project_that_names_no_enforcement_leaves_the_users() {
    let effective = EffectivePolicy::merge(
        Some(loaded("/u.toml", "enforcement = \"warn\"\n")),
        Some(loaded("/p.toml", "")),
        &Store::default(),
    )
    .unwrap();
    assert_eq!(effective.enforcement(), Enforcement::Warn);
}

#[test]
fn a_project_adds_includes_and_blocked_digests_but_removes_neither() {
    let user_digest = "a".repeat(64);
    let project_digest = "b".repeat(64);
    let effective = EffectivePolicy::merge(
        Some(loaded(
            "/u.toml",
            &format!("includes = [\"**/CLAUDE.md\"]\n[[blocklist]]\nsha256 = \"{user_digest}\"\n"),
        )),
        Some(loaded(
            "/p.toml",
            &format!(
                "includes = [\"prompts/*.txt\"]\n[[blocklist]]\nsha256 = \"{project_digest}\"\n"
            ),
        )),
        &Store::default(),
    )
    .unwrap();
    assert!(effective.includes(Path::new("CLAUDE.md")));
    assert!(effective.includes(Path::new("prompts/system.txt")));
    assert!(effective.blocked(&user_digest).is_some());
    assert!(effective.blocked(&project_digest).is_some());
}

#[test]
fn a_project_can_narrow_publishers_but_never_add_one() {
    let user = format!("{CI_PUBLISHER}{}", keyed_publisher("laptop", &key(1)));
    let narrowed = EffectivePolicy::merge(
        Some(loaded("/u.toml", &user)),
        Some(loaded("/p.toml", CI_PUBLISHER)),
        &Store::default(),
    )
    .unwrap();
    let names: Vec<&str> = narrowed
        .publishers()
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, vec!["ci"]);

    let added = EffectivePolicy::merge(
        Some(loaded("/u.toml", CI_PUBLISHER)),
        Some(loaded("/p.toml", &keyed_publisher("attacker", &key(9)))),
        &Store::default(),
    )
    .unwrap();
    assert!(
        added.publishers().is_empty(),
        "an untrusted project publisher narrows the set to nothing rather than joining it"
    );
    assert!(added.notes().iter().any(|n| n.contains("attacker")));

    let silent = EffectivePolicy::merge(
        Some(loaded("/u.toml", CI_PUBLISHER)),
        Some(loaded("/p.toml", "enforcement = \"deny\"\n")),
        &Store::default(),
    )
    .unwrap();
    assert_eq!(
        silent.publishers().len(),
        1,
        "no project publishers keeps the user's"
    );
}

#[test]
fn a_project_policy_alone_is_advisory() {
    for (requested, expected) in [
        ("deny", Enforcement::Warn),
        ("warn", Enforcement::Warn),
        ("audit", Enforcement::Audit),
    ] {
        let effective = EffectivePolicy::merge(
            None,
            Some(loaded(
                "/p.toml",
                &format!("enforcement = \"{requested}\"\n"),
            )),
            &Store::default(),
        )
        .unwrap();
        assert_eq!(effective.origin(), PolicyOrigin::ProjectAdvisory);
        assert_eq!(effective.enforcement(), expected);
        assert!(effective.notes().iter().any(|n| n.contains("advisory")));
    }
    let defaulted =
        EffectivePolicy::merge(None, Some(loaded("/p.toml", "")), &Store::default()).unwrap();
    assert_eq!(
        defaulted.enforcement(),
        Enforcement::Warn,
        "an advisory policy's default deny is capped too"
    );
}

#[test]
fn loading_an_absent_file_is_no_policy_and_a_broken_one_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        InstructionTrustPolicy::load(&dir.path().join("absent.toml"))
            .unwrap()
            .is_none()
    );
    let broken = dir.path().join("broken.toml");
    std::fs::write(&broken, "enforcement = [").unwrap();
    assert!(matches!(
        InstructionTrustPolicy::load(&broken),
        Err(PolicyError::Parse { .. })
    ));
}

/// The committed schema is the generated one. The CI feature lane runs this;
/// regenerate with
/// `cargo run -p mvm-client --features schema --bin emit_instruction_trust_schema`.
#[cfg(feature = "schema")]
#[test]
fn the_committed_schema_matches_the_policy_types() {
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(SCHEMA_PATH),
    )
    .expect("the committed schema exists");
    assert_eq!(
        committed.trim_end(),
        json_schema_pretty(),
        "{SCHEMA_PATH} is stale; regenerate it with \
         `cargo run -p mvm-client --features schema --bin emit_instruction_trust_schema`"
    );
}

/// The signing workflow runs on a push that touches an instruction file, and
/// "an instruction file" is `DEFAULT_INCLUDES`. A pattern added here and not
/// there would leave that file's edits unsigned until someone noticed.
#[test]
fn the_signing_workflow_triggers_on_every_default_include() {
    let workflow = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/sign-instructions.yml"),
    )
    .expect("the signing workflow exists");
    for pattern in DEFAULT_INCLUDES {
        assert!(
            workflow.contains(&format!("- \"{pattern}\"")),
            "sign-instructions.yml push paths must include {pattern}"
        );
    }
}
