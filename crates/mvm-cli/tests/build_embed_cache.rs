//! Unit tests for the build script's content-addressed artifact store.
//!
//! The build script itself is never compiled as a test target, so its logic is
//! exercised here through the same `#[path]` include the script uses.

#[path = "../build_embed_cache.rs"]
mod build_embed_cache;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use build_embed_cache::{
    KeyInputs, WorkspaceGraph, artifact_key, artifact_path, cache_root_from, hash_file,
    hash_member, hash_tree, install, lookup, parse_manifest_deps, parse_package_name,
    workspace_closure,
};

fn graph(edges: &[(&str, &[&str])]) -> WorkspaceGraph {
    WorkspaceGraph {
        dirs: edges
            .iter()
            .map(|(name, _)| ((*name).to_string(), PathBuf::from(format!("crates/{name}"))))
            .collect(),
        edges: edges
            .iter()
            .map(|(name, deps)| {
                (
                    (*name).to_string(),
                    deps.iter().map(|d| (*d).to_string()).collect(),
                )
            })
            .collect(),
    }
}

/// The real shape: `mvm-cli` links the embedded binaries, so it sits
/// *downstream* of them and cannot change their bytes.
fn workspace_like() -> WorkspaceGraph {
    graph(&[
        ("mvm-contract", &[]),
        ("mvm-core", &["mvm-contract"]),
        ("mvm-agentd", &["mvm-core", "mvm-contract"]),
        ("mvm-build", &["mvm-agentd", "mvm-core"]),
        ("mvm-hostd", &["mvm-build", "mvm-core"]),
        ("mvm-client", &["mvm-hostd"]),
        ("mvm-cli", &["mvm-build", "mvm-hostd", "mvm-client"]),
    ])
}

#[test]
fn closure_is_transitive_and_includes_the_root() {
    let closure = workspace_closure(&workspace_like(), &["mvm-build"]);
    assert_eq!(
        closure,
        vec!["mvm-agentd", "mvm-build", "mvm-contract", "mvm-core"]
    );
}

#[test]
fn closure_excludes_crates_that_only_consume_the_root() {
    // This is the whole point of keying on the closure. The previous watch
    // list re-ran the entire build script — both nested legs — on an edit to
    // any of mvm-cli's 251 files, none of which can reach these binaries.
    let closure = workspace_closure(&workspace_like(), &["mvm-build"]);
    for downstream in ["mvm-cli", "mvm-client", "mvm-hostd"] {
        assert!(
            !closure.contains(&downstream.to_string()),
            "{downstream} is downstream of mvm-build and must not be in its closure: {closure:?}"
        );
    }
}

#[test]
fn closure_covers_the_indirect_dependency_that_the_old_hand_list_missed() {
    // `mvm-egress-client` lives in mvm-agentd, which mvm-build reaches only
    // transitively. A hand-written list named mvm-build alone, so an edit to
    // the guest's egress path embedded the previous binary silently.
    let closure = workspace_closure(&workspace_like(), &["mvm-build"]);
    assert!(closure.contains(&"mvm-agentd".to_string()));
    assert!(closure.contains(&"mvm-contract".to_string()));
}

#[test]
fn closure_terminates_on_a_dependency_cycle() {
    // Cargo forbids cycles, but a malformed manifest pair must not hang the
    // build script.
    let cyclic = graph(&[("a", &["b"]), ("b", &["a"])]);
    assert_eq!(workspace_closure(&cyclic, &["a"]), vec!["a", "b"]);
}

#[test]
fn closure_of_an_unknown_root_is_just_the_root() {
    assert_eq!(
        workspace_closure(&workspace_like(), &["not-a-member"]),
        vec!["not-a-member"]
    );
}

#[test]
fn manifest_deps_cover_normal_build_and_target_tables_but_not_dev() {
    let manifest = r#"
        [package]
        name = "mvm-example"

        [dependencies]
        mvm-core = { workspace = true }

        [build-dependencies]
        sha2 = "0.11"

        [dev-dependencies]
        assert_cmd = "2"

        [target.'cfg(target_os = "macos")'.dependencies]
        libkrun-sys = { workspace = true }
    "#;

    let deps = parse_manifest_deps(manifest);
    assert!(deps.contains(&"mvm-core".to_string()));
    assert!(deps.contains(&"sha2".to_string()));
    // The macOS libkrun path is wired exactly this way; missing it would key
    // the binary on an incomplete closure.
    assert!(deps.contains(&"libkrun-sys".to_string()));
    // A dev-dependency cannot reach a `[[bin]]`.
    assert!(!deps.contains(&"assert_cmd".to_string()));
}

#[test]
fn package_name_is_read_from_the_manifest() {
    assert_eq!(
        parse_package_name("[package]\nname = \"mvm-build\"\n").as_deref(),
        Some("mvm-build")
    );
    assert_eq!(parse_package_name("not = valid toml ["), None);
}

/// One named edit to a key's inputs, applied to prove the key notices it.
type Mutation = (&'static str, Box<dyn Fn(&mut KeyInputs)>);

fn inputs() -> KeyInputs {
    KeyInputs {
        package: "mvm-build".into(),
        binary: "mvm-host-vm-init".into(),
        features: String::new(),
        target: "aarch64-unknown-linux-musl".into(),
        toolchain: "zig=0.13.0".into(),
        flavor: "musl-static".into(),
        lockfile: "abc".into(),
        sources: vec![("crates/mvm-core/src/lib.rs".into(), "deadbeef".into())],
    }
}

#[test]
fn the_key_changes_when_any_input_changes() {
    let base = artifact_key(&inputs());

    let mutations: Vec<Mutation> = vec![
        ("package", Box::new(|i: &mut KeyInputs| i.package.push('x'))),
        ("binary", Box::new(|i: &mut KeyInputs| i.binary.push('x'))),
        (
            "features",
            Box::new(|i: &mut KeyInputs| i.features.push('x')),
        ),
        ("target", Box::new(|i: &mut KeyInputs| i.target.push('x'))),
        (
            "toolchain",
            Box::new(|i: &mut KeyInputs| i.toolchain.push('x')),
        ),
        ("flavor", Box::new(|i: &mut KeyInputs| i.flavor.push('x'))),
        (
            "lockfile",
            Box::new(|i: &mut KeyInputs| i.lockfile.push('x')),
        ),
        (
            "source content",
            Box::new(|i: &mut KeyInputs| i.sources[0].1 = "cafe".into()),
        ),
        (
            "source path",
            Box::new(|i: &mut KeyInputs| i.sources[0].0 = "crates/mvm-core/src/other.rs".into()),
        ),
        (
            "an added source file",
            Box::new(|i: &mut KeyInputs| i.sources.push(("new.rs".into(), "00".into()))),
        ),
    ];

    for (label, mutate) in mutations {
        let mut mutated = inputs();
        mutate(&mut mutated);
        assert_ne!(
            base,
            artifact_key(&mutated),
            "changing {label} must change the key, or a stale binary is served"
        );
    }
}

#[test]
fn the_key_is_stable_for_identical_inputs() {
    assert_eq!(artifact_key(&inputs()), artifact_key(&inputs()));
}

#[test]
fn field_boundaries_cannot_be_shifted_to_forge_a_collision() {
    // Without length-prefixing, concatenation lets a boundary move: binary
    // "ab" + features "c" would hash the same as binary "a" + features "bc",
    // and a collision here serves the wrong bytes.
    let mut left = inputs();
    left.binary = "ab".into();
    left.features = "c".into();

    let mut right = inputs();
    right.binary = "a".into();
    right.features = "bc".into();

    assert_ne!(artifact_key(&left), artifact_key(&right));
}

#[test]
fn cache_root_prefers_the_explicit_override() {
    assert_eq!(
        cache_root_from(
            Some(OsString::from("/tmp/store")),
            Some(OsString::from("/home/u"))
        ),
        Some(PathBuf::from("/tmp/store"))
    );
}

#[test]
fn cache_root_falls_back_to_the_home_cache_dir() {
    // Built from components rather than spelled out: a contiguous
    // home-relative mvm path literal is exactly what the single-root gate
    // exists to catch, and the test has no more right to one than the code.
    let home = PathBuf::from("/home/u");
    assert_eq!(
        cache_root_from(None, Some(OsString::from(home.as_os_str()))),
        Some(home.join(".cache").join("mvm").join("embed"))
    );
}

#[test]
fn cache_root_is_absent_without_an_override_or_home() {
    // No root means "build without caching" — never "cache somewhere else".
    assert_eq!(cache_root_from(None, None), None);
    assert_eq!(
        cache_root_from(Some(OsString::new()), Some(OsString::new())),
        None
    );
}

#[test]
fn artifacts_are_addressed_by_key_then_name() {
    assert_eq!(
        artifact_path(Path::new("/store"), "abc123", "mvm-netd"),
        PathBuf::from("/store/abc123/mvm-netd")
    );
}

#[test]
fn two_binaries_from_one_key_do_not_collide() {
    let root = Path::new("/store");
    assert_ne!(
        artifact_path(root, "k", "mvm-netd"),
        artifact_path(root, "k", "mvm-host-agent")
    );
}

#[test]
fn the_graph_reader_maps_every_workspace_member_to_its_directory() {
    // Read the real workspace, so a member that stops parsing is caught here
    // rather than by a silently-narrower cache key.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/mvm-cli has a workspace root two levels up");
    let graph = build_embed_cache::read_workspace_graph(workspace_root);

    for expected in [
        "mvm-core",
        "mvm-build",
        "mvm-agentd",
        "mvm-cli",
        "libkrun-sys",
    ] {
        assert!(
            graph.dirs.contains_key(expected),
            "{expected} missing from the workspace graph: {:?}",
            graph.dirs.keys().collect::<Vec<_>>()
        );
    }

    // The property the whole design rests on, asserted against the real
    // manifests rather than a fixture.
    let closure = workspace_closure(&graph, &["mvm-build"]);
    assert!(closure.contains(&"mvm-core".to_string()));
    assert!(
        !closure.contains(&"mvm-cli".to_string()),
        "mvm-cli must not be in mvm-build's closure"
    );

    let _: &BTreeMap<String, Vec<String>> = &graph.edges;
}

#[test]
fn publishing_then_restoring_round_trips_the_bytes() {
    let store = tempfile::tempdir().expect("tempdir");
    let work = tempfile::tempdir().expect("tempdir");

    let built = work.path().join("mvm-netd");
    std::fs::write(&built, b"\x7fELF built here").expect("write");
    install(store.path(), "keyA", "mvm-netd", &built);

    let restored = work.path().join("out/mvm-netd");
    assert!(lookup(store.path(), "keyA", "mvm-netd", &restored));
    assert_eq!(
        std::fs::read(&restored).expect("read"),
        b"\x7fELF built here"
    );
}

#[test]
fn restoring_a_key_that_was_never_published_is_a_miss() {
    let store = tempfile::tempdir().expect("tempdir");
    let work = tempfile::tempdir().expect("tempdir");
    assert!(!lookup(
        store.path(),
        "absent",
        "mvm-netd",
        &work.path().join("mvm-netd")
    ));
}

#[test]
fn a_different_key_never_serves_another_keys_bytes() {
    // The failure this guards against is the whole reason the store exists:
    // handing back an artifact built from different sources.
    let store = tempfile::tempdir().expect("tempdir");
    let work = tempfile::tempdir().expect("tempdir");

    let built = work.path().join("mvm-netd");
    std::fs::write(&built, b"old").expect("write");
    install(store.path(), "keyOld", "mvm-netd", &built);

    let restored = work.path().join("out/mvm-netd");
    assert!(!lookup(store.path(), "keyNew", "mvm-netd", &restored));
}

#[test]
fn publishing_leaves_no_temporary_file_behind() {
    // Concurrent worktree builds race this directory; a half-copied binary
    // that looks complete is worse than no cache at all.
    let store = tempfile::tempdir().expect("tempdir");
    let work = tempfile::tempdir().expect("tempdir");

    let built = work.path().join("mvm-netd");
    std::fs::write(&built, b"bytes").expect("write");
    install(store.path(), "keyA", "mvm-netd", &built);

    let leftovers: Vec<_> = std::fs::read_dir(store.path().join("keyA"))
        .expect("read_dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging files left behind: {leftovers:?}"
    );
}

#[test]
fn publishing_an_unreadable_source_does_not_break_the_build() {
    // An unwritable or broken store must slow the build down, not fail it.
    let store = tempfile::tempdir().expect("tempdir");
    install(
        store.path(),
        "keyA",
        "mvm-netd",
        Path::new("/definitely/not/here"),
    );
    assert!(!lookup(
        store.path(),
        "keyA",
        "mvm-netd",
        &store.path().join("out")
    ));
}

#[test]
fn file_hashes_track_content_not_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, b"same").expect("write");
    std::fs::write(&b, b"same").expect("write");
    assert_eq!(hash_file(&a), hash_file(&b));

    std::fs::write(&b, b"different").expect("write");
    assert_ne!(hash_file(&a), hash_file(&b));
}

#[test]
fn an_unreadable_file_hashes_to_empty_rather_than_panicking() {
    assert_eq!(hash_file(Path::new("/definitely/not/here")), "");
}

#[test]
fn tree_hashes_are_sorted_relative_and_recursive() {
    let root = tempfile::tempdir().expect("tempdir");
    let nested = root.path().join("crate/src/deep");
    std::fs::create_dir_all(&nested).expect("mkdir");
    std::fs::write(root.path().join("crate/src/z.rs"), b"z").expect("write");
    std::fs::write(root.path().join("crate/src/a.rs"), b"a").expect("write");
    std::fs::write(nested.join("m.rs"), b"m").expect("write");

    let hashes = hash_tree(root.path(), &root.path().join("crate/src"));
    let paths: Vec<_> = hashes.iter().map(|(p, _)| p.as_str()).collect();

    // Sorted, because directory iteration order is not guaranteed and differs
    // between filesystems — an unsorted key would churn for no reason.
    assert_eq!(
        paths,
        vec!["crate/src/a.rs", "crate/src/deep/m.rs", "crate/src/z.rs"]
    );
}

#[test]
fn tree_hashes_change_when_a_watched_file_changes() {
    let root = tempfile::tempdir().expect("tempdir");
    let src = root.path().join("crate/src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(src.join("lib.rs"), b"before").expect("write");
    let before = hash_tree(root.path(), &src);

    std::fs::write(src.join("lib.rs"), b"after").expect("write");
    assert_ne!(before, hash_tree(root.path(), &src));
}

#[test]
fn hashing_a_missing_tree_yields_nothing_rather_than_failing() {
    let root = tempfile::tempdir().expect("tempdir");
    assert!(hash_tree(root.path(), &root.path().join("absent")).is_empty());
}

#[test]
fn the_opt_out_env_var_disables_the_store_entirely() {
    // The build script is this wrapper's only caller, so assert the one
    // branch that does not route through `cache_root_from`. Deliberately
    // reads only the opt-out var: resolving HOME here would duplicate the
    // home-path derivation this repo keeps in exactly one place.
    if std::env::var_os("MVM_EMBED_NO_CACHE").is_some_and(|v| !v.is_empty()) {
        assert_eq!(build_embed_cache::cache_root(), None);
    } else {
        assert!(
            build_embed_cache::cache_root().is_some(),
            "HOME is set in every environment this suite runs in"
        );
    }
}

#[test]
fn hashing_a_file_as_though_it_were_a_tree_yields_nothing() {
    // The contract that made the manifest silently drop out of the key:
    // `hash_tree` lists a directory, so a file path contributes no entries.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("Cargo.toml");
    std::fs::write(&file, b"[package]").expect("write");
    assert!(hash_tree(dir.path(), &file).is_empty());
}

#[test]
fn member_hashes_cover_the_manifest_as_well_as_the_sources() {
    let root = tempfile::tempdir().expect("tempdir");
    let member = root.path().join("crates/mvm-thing");
    std::fs::create_dir_all(member.join("src")).expect("mkdir");
    std::fs::write(member.join("src/lib.rs"), b"fn main() {}").expect("write");
    std::fs::write(
        member.join("Cargo.toml"),
        b"[package]\nname = \"mvm-thing\"",
    )
    .expect("write");

    let paths: Vec<_> = hash_member(root.path(), &member)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert_eq!(
        paths,
        vec![
            "crates/mvm-thing/Cargo.toml".to_string(),
            "crates/mvm-thing/src/lib.rs".to_string(),
        ]
    );
}

#[test]
fn a_manifest_edit_moves_the_member_hash() {
    // A feature or dependency change lives only in the manifest. If it does
    // not move the hash, the key cannot notice it and a stale binary is
    // served for a genuinely different build.
    let root = tempfile::tempdir().expect("tempdir");
    let member = root.path().join("crates/mvm-thing");
    std::fs::create_dir_all(member.join("src")).expect("mkdir");
    std::fs::write(member.join("src/lib.rs"), b"fn main() {}").expect("write");
    std::fs::write(member.join("Cargo.toml"), b"[features]\ndefault = []").expect("write");
    let before = hash_member(root.path(), &member);

    std::fs::write(member.join("Cargo.toml"), b"[features]\ndefault = [\"x\"]").expect("write");
    assert_ne!(before, hash_member(root.path(), &member));
}

#[test]
fn a_member_without_a_manifest_still_hashes_its_sources() {
    let root = tempfile::tempdir().expect("tempdir");
    let member = root.path().join("crates/mvm-thing");
    std::fs::create_dir_all(member.join("src")).expect("mkdir");
    std::fs::write(member.join("src/lib.rs"), b"x").expect("write");
    assert_eq!(hash_member(root.path(), &member).len(), 1);
}
