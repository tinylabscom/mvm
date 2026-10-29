use super::*;
use crate::image_source::repository_fixture as fixture;

fn git_rev_parse(root: &Path, rev: &str) -> String {
    assert_eq!(rev, "HEAD");
    let repo = gix::open_opts(root, gix::open::Options::isolated()).unwrap();
    repo.head().unwrap().into_peeled_id().unwrap().to_string()
}

fn git_rev_parse_tree(root: &Path, rev: &str) -> String {
    assert_eq!(rev, "HEAD");
    let repo = gix::open_opts(root, gix::open::Options::isolated()).unwrap();
    let id = repo.head().unwrap().into_peeled_id().unwrap();
    repo.find_commit(id).unwrap().tree_id().unwrap().to_string()
}

fn git_ls_tree_entry(root: &Path, tree_hex: &str, name: &str) -> String {
    let repo = gix::open_opts(root, gix::open::Options::isolated()).unwrap();
    let tree = repo
        .find_tree(gix::ObjectId::from_hex(tree_hex.as_bytes()).unwrap())
        .unwrap();
    tree.iter()
        .map(Result::unwrap)
        .find(|entry| entry.filename() == name.as_bytes())
        .unwrap()
        .oid()
        .to_string()
}

fn repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("a"), b"base\n").unwrap();
    fixture::commit_all(tmp.path(), "fixture");
    tmp
}

fn config(root: &Path, body: &str) {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(root.join(".git/config"))
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
}

#[test]
fn boolean_settings_are_validated_even_for_clean_repositories() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    for key in ["filemode", "ignorecase", "symlinks", "bare", "autocrlf"] {
        let tmp = repo();
        config(tmp.path(), &format!("\n[core]\n{key}=garbage\n"));
        assert!(probe_identity(tmp.path()).is_err(), "{key}");
    }
    for value in ["yes", "on", "1", "0x1", "01", "1k", "true"] {
        let tmp = repo();
        config(
            tmp.path(),
            &format!("\n[core]\nfilemode={value}\nignorecase={value}\nsymlinks={value}\n"),
        );
        assert_eq!(state(tmp.path()), WorktreeState::Clean, "{value}");
    }
    for value in ["false", "no", "off", "0", "0x0", "0k", ""] {
        let tmp = repo();
        config(
            tmp.path(),
            &format!(
                "\n[core]\nfilemode={value}\nignorecase={value}\nsymlinks={value}\nbare={value}\nautocrlf={value}\n"
            ),
        );
        assert_eq!(state(tmp.path()), WorktreeState::Clean, "{value}");
    }
    let tmp = repo();
    config(tmp.path(), "\n[extensions]\nworktreeconfig=garbage\n");
    assert!(
        probe_identity(tmp.path())
            .unwrap_err()
            .contains("worktreeconfig")
    );
    let tmp = repo();
    config(
        tmp.path(),
        "\n[core]\nautocrlf=input\nfilemode\nignorecase=\n",
    );
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
}

#[test]
fn system_policy_defaults_and_explicit_override_precedence() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    #[cfg(windows)]
    for key in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        env.remove(key);
    }
    let tmp = repo();
    let system = tmp.path().join(".git/system-config");
    std::fs::write(&system, b"[core]\nautocrlf=garbage\n").unwrap();
    env.remove("GIT_CONFIG_NOSYSTEM");
    env.remove("GIT_CONFIG_SYSTEM");
    env.remove("GIT_ATTR_NOSYSTEM");
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    env.set("GIT_CONFIG_SYSTEM", &system);
    assert!(probe_identity(tmp.path()).is_err());
    env.set("GIT_CONFIG_NOSYSTEM", "true");
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    env.set("GIT_ATTR_NOSYSTEM", "false");
    assert!(
        probe_identity(tmp.path())
            .unwrap_err()
            .contains("attributes")
    );
    env.set("GIT_ATTR_NOSYSTEM", "true");
    for name in ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"] {
        env.set(name, "");
        assert!(probe_identity(tmp.path()).unwrap_err().contains(name));
        env.remove(name);
    }
    #[cfg(not(windows))]
    {
        env.remove("GIT_CONFIG_SYSTEM");
        env.set("GIT_CONFIG_NOSYSTEM", "false");
        assert!(probe_identity(tmp.path()).unwrap_err().contains("unproven"));
    }
}

#[cfg(unix)]
#[test]
fn symlink_and_nonregular_directory_rules_fail_closed() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    for name in [".gitattributes", ".gitignore"] {
        let tmp = repo();
        std::os::unix::fs::symlink("a", tmp.path().join(name)).unwrap();
        assert!(probe_identity(tmp.path()).unwrap_err().contains("regular"));
        std::fs::remove_file(tmp.path().join(name)).unwrap();
        std::fs::create_dir(tmp.path().join(name)).unwrap();
        assert!(probe_identity(tmp.path()).unwrap_err().contains("regular"));
    }
}

fn state(root: &Path) -> WorktreeState {
    probe_identity(root).unwrap().worktree
}

#[cfg(windows)]
#[test]
fn proven_windows_attributes_opt_in_is_separate_from_system_config() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let installation = tempfile::tempdir().unwrap();
    env.remove("ProgramFiles");
    env.remove("ProgramFiles(x86)");
    env.set("LOCALAPPDATA", installation.path());
    let etc = installation.path().join("Programs/Git/etc");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("gitattributes"), b"a text\n").unwrap();
    std::fs::write(etc.join("gitconfig"), b"").unwrap();
    env.remove("GIT_CONFIG_NOSYSTEM");
    env.set("GIT_CONFIG_SYSTEM", etc.join("gitconfig"));
    env.remove("GIT_ATTR_NOSYSTEM");
    std::fs::write(tmp.path().join("a"), b"base\r\n").unwrap();
    assert!(state(tmp.path()).is_dirty());
    env.set("GIT_ATTR_NOSYSTEM", "false");
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    env.set("GIT_ATTR_NOSYSTEM", "true");
    assert!(state(tmp.path()).is_dirty());
}

fn write_raw_index(root: &Path, entries: &[IndexEntry], extensions: &[([u8; 4], Vec<u8>)]) {
    use sha1::Digest;
    let mut bytes = b"DIRC".to_vec();
    bytes.extend(3u32.to_be_bytes());
    bytes.extend(u32::try_from(entries.len()).unwrap().to_be_bytes());
    for entry in entries {
        let start = bytes.len();
        bytes.extend([0; 24]);
        bytes.extend(entry.mode.to_be_bytes());
        bytes.extend([0; 12]);
        bytes.extend(&entry.oid);
        let mut flags = u16::try_from(entry.path.len().min(4095)).unwrap()
            | u16::try_from(entry.stage << 12).unwrap();
        if entry.flags & 1 != 0 {
            flags |= 0x8000;
        }
        let extended: u16 = (if entry.flags & 2 != 0 { 0x2000 } else { 0 })
            | (if entry.flags & 4 != 0 { 0x4000 } else { 0 });
        if extended != 0 {
            flags |= 0x4000;
        }
        bytes.extend(flags.to_be_bytes());
        if extended != 0 {
            bytes.extend(extended.to_be_bytes());
        }
        bytes.extend(&entry.path);
        bytes.push(0);
        let padding = (8 - (bytes.len() - start) % 8) % 8;
        bytes.extend(vec![0; padding]);
    }
    for (signature, body) in extensions {
        bytes.extend(signature);
        bytes.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend(body);
    }
    bytes.extend(sha1::Sha1::digest(&bytes).to_vec());
    std::fs::write(root.join(".git/index"), bytes).unwrap();
}

#[test]
fn neutral_python_reference_vectors_exercise_rust_encoder() {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/local-producer-v2.json"
    ))
    .unwrap();
    let decode = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    for vector in data["vectors"].as_array().unwrap() {
        let index = vector["index"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| IndexEntry {
                path: decode(&e[0]),
                mode: e[1].as_u64().unwrap().try_into().unwrap(),
                stage: e[2].as_u64().unwrap().try_into().unwrap(),
                flags: e[3].as_u64().unwrap().try_into().unwrap(),
                oid: decode(&e[4]),
            })
            .collect::<Vec<_>>();
        let files = |name: &str| {
            vector[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| FileEntry {
                    path: decode(&e[0]),
                    mode: e[1].as_u64().unwrap().try_into().unwrap(),
                    body: decode(&e[2]),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            hex::encode(fingerprint(
                &decode(&vector["head"]),
                &index,
                &files("working"),
                &files("untracked")
            )),
            vector["output"].as_str().unwrap(),
        );
    }
}

#[test]
fn staged_bytes_are_distinct_even_when_working_bytes_return_to_head() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let clean = state(tmp.path());
    assert_eq!(clean, WorktreeState::Clean);
    std::fs::write(tmp.path().join("a"), b"staged\n").unwrap();
    fixture::stage(tmp.path());
    std::fs::write(tmp.path().join("a"), b"base\n").unwrap();
    let first = state(tmp.path());
    assert!(first.is_dirty());
    std::fs::write(tmp.path().join("a"), b"other staged\n").unwrap();
    fixture::stage(tmp.path());
    std::fs::write(tmp.path().join("a"), b"base\n").unwrap();
    assert_ne!(first, state(tmp.path()));
}

#[test]
fn index_stat_cache_does_not_change_the_identity() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::write(tmp.path().join("u"), b"untracked").unwrap();
    let first = state(tmp.path());
    // Read the current index, modify stat fields (file_size, ino), rewrite.
    // The fingerprint must not change because stat fields are not observed.
    let entries = git_index::read(&tmp.path().join(".git/index")).unwrap();
    // Rewriting the index with the same semantic entries but different on-disk
    // bytes (write_raw_index zeroes stat fields) has the same effect.
    write_raw_index(tmp.path(), &entries, &[]);
    assert_eq!(first, state(tmp.path()));
}

#[test]
fn index_performance_flags_do_not_hide_working_edits() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    for flag in [1, 4] {
        let tmp = repo();
        let mut entries = git_index::read(&tmp.path().join(".git/index")).unwrap();
        assert!(!entries.is_empty());
        entries[0].flags |= flag;
        write_raw_index(tmp.path(), &entries, &[]);
        std::fs::write(tmp.path().join("a"), b"visible edit\n").unwrap();
        assert!(state(tmp.path()).is_dirty());
    }
}

#[test]
fn conflict_stages_are_preserved() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let entries = git_index::read(&tmp.path().join(".git/index")).unwrap();
    assert!(!entries.is_empty());
    let mut stage2 = entries[0].clone();
    stage2.stage = 2;
    write_raw_index(tmp.path(), &[stage2.clone()], &[]);
    let ours = state(tmp.path());
    assert!(ours.is_dirty());
    let mut stage3 = stage2;
    stage3.stage = 3;
    write_raw_index(tmp.path(), &[stage3], &[]);
    assert_ne!(ours, state(tmp.path()));
}

#[test]
fn ignores_include_nested_negations_and_administrative_files_never_contribute() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::write(tmp.path().join(".gitignore"), b"*.log\n!keep.log\n").unwrap();
    fixture::commit_all(tmp.path(), "ignores");
    std::fs::write(tmp.path().join("ignored.log"), b"ignored").unwrap();
    std::fs::write(tmp.path().join(".git/administrative"), b"not source").unwrap();
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    std::fs::write(tmp.path().join("keep.log"), b"included").unwrap();
    assert!(state(tmp.path()).is_dirty());
}

#[test]
fn active_external_transforms_are_refused_without_execution() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    for attr in ["filter=run", "working-tree-encoding=UTF-16"] {
        let tmp = repo();
        std::fs::write(tmp.path().join(".gitattributes"), format!("a {attr}\n")).unwrap();
        config(
            tmp.path(),
            "\n[filter \"run\"]\nclean = nonexistent-clean\nsmudge = nonexistent-smudge\nprocess = nonexistent-process\nrequired = true\n[core]\nhooksPath = nonexistent-hooks\nfsmonitor = nonexistent-monitor\n",
        );
        let error = probe_identity(tmp.path()).unwrap_err();
        assert!(error.contains("unsupported external filter"), "{error}");
    }
}

#[test]
fn built_in_text_and_ident_normalization_is_in_process() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::write(tmp.path().join(".gitattributes"), b"a text ident\n").unwrap();
    std::fs::write(tmp.path().join("a"), b"$Id$\n").unwrap();
    fixture::commit_all(tmp.path(), "attributes");
    std::fs::write(tmp.path().join("a"), b"$Id: expanded $\r\n").unwrap();
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    std::fs::write(tmp.path().join("u"), b"dirty").unwrap();
    let first = state(tmp.path());
    std::fs::write(tmp.path().join("a"), b"$Id: another expansion $\n").unwrap();
    assert_ne!(first, state(tmp.path()));
}

#[cfg(unix)]
#[test]
fn raw_paths_modes_symlinks_and_deletions_are_observed() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let tmp = repo();
    let mut raw = tmp.path().join(OsStr::from_bytes(b"x\xff\n"));
    if let Err(error) = std::fs::write(&raw, [0, 255, 10]) {
        assert_eq!(error.raw_os_error(), Some(libc::EILSEQ), "{error}");
        eprintln!(
            "raw-byte filename capability unavailable on this filesystem: {error}; mode/link/deletion witnesses still run"
        );
        raw = tmp.path().join("x-valid-utf8\n");
        std::fs::write(&raw, [0, 255, 10]).unwrap();
    }
    let first = state(tmp.path());
    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(first, state(tmp.path()));
    std::fs::remove_file(&raw).unwrap();
    if let Err(error) = std::os::unix::fs::symlink(OsStr::from_bytes(b"target\xff"), &raw) {
        assert_eq!(error.raw_os_error(), Some(libc::EILSEQ), "{error}");
        eprintln!("raw-byte link target capability unavailable on this filesystem: {error}");
        std::os::unix::fs::symlink("a", &raw).unwrap();
    }
    let link = state(tmp.path());
    std::fs::remove_file(tmp.path().join("a")).unwrap();
    assert_ne!(link, state(tmp.path()));
}

#[test]
fn linked_worktree_uses_its_own_head_and_index() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let linked = tempfile::tempdir().unwrap();
    let admin = tmp.path().join(".git/worktrees/witness");
    std::fs::create_dir_all(&admin).unwrap();
    let head = probe_identity(tmp.path()).unwrap().commit;
    std::fs::write(admin.join("HEAD"), format!("{}\n", head.as_str())).unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", linked.path().join(".git").display()),
    )
    .unwrap();
    std::fs::write(
        linked.path().join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    std::fs::copy(tmp.path().join(".git/index"), admin.join("index")).unwrap();
    std::fs::write(linked.path().join("a"), b"base\n").unwrap();
    assert_eq!(state(linked.path()), WorktreeState::Clean);
    std::fs::write(linked.path().join("a"), b"linked edit\n").unwrap();
    assert!(state(linked.path()).is_dirty());
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    assert_eq!(
        Path::new(&toplevel(linked.path()).unwrap()),
        linked.path().canonicalize().unwrap()
    );
}

#[test]
fn uninitialized_gitlink_differs_from_malformed_initialized_submodule() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let head_hex = git_rev_parse(tmp.path(), "HEAD");
    let head_oid = hex::decode(&head_hex).unwrap();
    let entries = git_index::read(&tmp.path().join(".git/index")).unwrap();
    assert!(!entries.is_empty());
    let mut submod = entries[0].clone();
    submod.path = b"s".to_vec();
    submod.mode = 0o160000;
    submod.oid = head_oid;
    write_raw_index(tmp.path(), &[submod], &[]);
    assert!(state(tmp.path()).is_dirty());
    std::fs::create_dir(tmp.path().join("s")).unwrap();
    std::fs::write(tmp.path().join("s/.git"), "malformed\n").unwrap();
    assert!(probe_identity(tmp.path()).is_err());
}

#[test]
fn unsafe_paths_are_refused() {
    for name in [
        b"../outside".as_slice(),
        b"/absolute",
        b"a/.git/config",
        b"a\0b",
    ] {
        assert!(validate_path(name).is_err());
    }
    #[cfg(windows)]
    for name in [
        b"C:/drive".as_slice(),
        b"\\rooted",
        b"a\\..\\escape",
        b"C:relative",
    ] {
        assert!(validate_path(name).is_err());
    }
}

#[test]
fn sparse_directories_expand_in_process_without_hiding_present_edits() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::create_dir(tmp.path().join("d")).unwrap();
    std::fs::write(tmp.path().join("d/a"), b"sparse\n").unwrap();
    fixture::commit_all(tmp.path(), "sparse");
    let tree_hex = git_rev_parse_tree(tmp.path(), "HEAD");
    let subtree_hex = git_ls_tree_entry(tmp.path(), &tree_hex, "d");
    let subtree_oid = hex::decode(&subtree_hex).unwrap();
    let mut entries = git_index::read(&tmp.path().join(".git/index")).unwrap();
    entries.retain(|e| !e.path.starts_with(b"d/"));
    entries.push(IndexEntry {
        path: b"d/".to_vec(),
        mode: 0o040000,
        stage: 0,
        flags: 4,
        oid: subtree_oid,
    });
    write_raw_index(tmp.path(), &entries, &[(*b"sdir", Vec::new())]);
    std::fs::remove_file(tmp.path().join("d/a")).unwrap();
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    std::fs::write(tmp.path().join("d/a"), b"visible edit\n").unwrap();
    assert!(state(tmp.path()).is_dirty());
    write_raw_index(tmp.path(), &entries, &[(*b"sdir", vec![1])]);
    assert!(
        probe_identity(tmp.path())
            .unwrap_err()
            .contains("sparse-index")
    );
    write_raw_index(
        tmp.path(),
        &entries,
        &[(*b"sdir", Vec::new()), (*b"sdir", Vec::new())],
    );
    assert!(
        probe_identity(tmp.path())
            .unwrap_err()
            .contains("sparse-index")
    );
}

#[test]
fn initialized_submodule_dirty_bytes_are_recursive_inputs_and_cycles_are_bounded() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let sub = tmp.path().join("s");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("a"), b"submodule\n").unwrap();
    fixture::commit_all(&sub, "submodule");
    let child_head_hex = git_rev_parse(&sub, "HEAD");
    let child_head_oid = hex::decode(&child_head_hex).unwrap();
    let entries = git_index::read(&tmp.path().join(".git/index")).unwrap();
    assert!(!entries.is_empty());
    let mut submod = entries[0].clone();
    submod.path = b"s".to_vec();
    submod.mode = 0o160000;
    submod.oid = child_head_oid;
    write_raw_index(tmp.path(), &[submod], &[]);
    let before = state(tmp.path());
    std::fs::write(sub.join("u"), b"recursive untracked\n").unwrap();
    assert_ne!(before, state(tmp.path()));
    let canonical = tmp.path().canonicalize().unwrap();
    assert!(observe(tmp.path(), &mut BTreeSet::from([canonical])).is_err());
    let mut maximum: BTreeSet<_> = (0..64)
        .map(|i| PathBuf::from(format!("depth-{i}")))
        .collect();
    assert!(observe(tmp.path(), &mut maximum).is_err());
}

#[test]
fn observation_needs_no_executables_and_ignores_repository_redirects() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let other = repo();
    std::fs::write(tmp.path().join("u"), b"dirty\n").unwrap();
    let expected = probe_identity(tmp.path()).unwrap();
    env.set("PATH", "");
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
    ] {
        env.set(key, other.path());
    }
    assert_eq!(expected, probe_identity(tmp.path()).unwrap());
}

#[cfg(unix)]
#[test]
fn rule_observation_never_invokes_available_hostile_git() {
    use std::os::unix::fs::PermissionsExt;
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let bin = tempfile::tempdir().unwrap();
    let marker = bin.path().join("invoked");
    let executable = bin.path().join("git");
    std::fs::write(
        &executable,
        b"#!/bin/sh\n: > \"$PROCESS_BAN_MARKER\"\nexit 99\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    env.set("PATH", bin.path());
    env.set("PROCESS_BAN_MARKER", &marker);
    env.set("GIT_EXEC_PATH", bin.path());
    env.set("GIT_CONFIG_SYSTEM", bin.path().join("system"));
    env.set("GIT_CONFIG_NOSYSTEM", "true");
    std::fs::write(tmp.path().join(".gitattributes"), b"a text\n").unwrap();
    std::fs::write(tmp.path().join(".gitignore"), b"ignored\n").unwrap();
    fixture::commit_all(tmp.path(), "rules");
    std::fs::write(tmp.path().join("ignored"), b"ignored\n").unwrap();
    std::fs::write(tmp.path().join("a"), b"base\r\n").unwrap();
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    config(tmp.path(), "\n[filter \"hostile\"]\nprocess=git\n");
    std::fs::write(tmp.path().join(".gitattributes"), b"a filter=hostile\n").unwrap();
    assert!(probe_identity(tmp.path()).is_err());
    assert!(
        !marker.exists(),
        "Git discovery or a filter executed a subprocess"
    );
}

#[test]
fn split_indexes_hydrate_shared_entries_replacements_and_deletions() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::write(tmp.path().join("u"), b"untracked").unwrap();
    let before = state(tmp.path());
    let original = std::fs::read(tmp.path().join(".git/index")).unwrap();
    let checksum = &original[original.len() - 20..];
    let shared = tmp
        .path()
        .join(format!(".git/sharedindex.{}", hex::encode(checksum)));
    std::fs::write(&shared, &original).unwrap();
    let empty = [
        0u32.to_be_bytes().as_slice(),
        1u32.to_be_bytes().as_slice(),
        0u64.to_be_bytes().as_slice(),
        0u32.to_be_bytes().as_slice(),
    ]
    .concat();
    let link = [checksum, empty.as_slice(), empty.as_slice()].concat();
    write_raw_index(tmp.path(), &[], &[(*b"link", link)]);
    assert_eq!(before, state(tmp.path()));
    let objects = gix::open_opts(tmp.path(), gix::open::Options::isolated()).unwrap();
    let blob_oid = objects
        .write_blob(b"replacement\n")
        .unwrap()
        .as_bytes()
        .to_vec();
    let replacement = IndexEntry {
        path: Vec::new(),
        mode: 0o100644,
        stage: 0,
        flags: 0,
        oid: blob_oid,
    };
    let bit = [
        1u32.to_be_bytes().as_slice(),
        2u32.to_be_bytes().as_slice(),
        (1u64 << 33).to_be_bytes().as_slice(),
        1u64.to_be_bytes().as_slice(),
        0u32.to_be_bytes().as_slice(),
    ]
    .concat();
    write_raw_index(
        tmp.path(),
        &[replacement],
        &[(
            *b"link",
            [checksum, empty.as_slice(), bit.as_slice()].concat(),
        )],
    );
    assert_ne!(before, state(tmp.path()));
    write_raw_index(
        tmp.path(),
        &[],
        &[(
            *b"link",
            [checksum, bit.as_slice(), empty.as_slice()].concat(),
        )],
    );
    assert!(
        git_index::read(&tmp.path().join(".git/index"))
            .unwrap()
            .is_empty()
    );
    std::fs::remove_file(shared).unwrap();
    assert!(probe_identity(tmp.path()).is_err());
}

#[test]
fn native_config_keeps_context_and_level_precedence_without_mutating_files() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let configs = tempfile::tempdir().unwrap();
    let metadata = tmp
        .path()
        .join(".git")
        .to_str()
        .unwrap()
        .trim_end_matches(['\\', '/'])
        .replace('\\', "/");
    let included = configs.path().join("included");
    let branch = configs.path().join("branch");
    std::fs::write(&included, b"[identity]\ngitdir = true\n").unwrap();
    std::fs::write(&branch, b"[identity]\nbranch = true\n").unwrap();
    let system = configs.path().join("system");
    std::fs::write(&system,format!(
        "[identity]\nchoice=system\n[includeIf \"gitdir:{metadata}\"]\npath=\"{}\"\n[includeIf \"onbranch:main\"]\npath=\"{}\"\n",
        included.to_str().unwrap().replace('\\',"/"),branch.to_str().unwrap().replace('\\',"/"))).unwrap();
    let global = configs.path().join("global");
    std::fs::write(&global, b"[identity]\nchoice=global\n").unwrap();
    config(tmp.path(), "\n[identity]\nchoice=local\n");
    let before = std::fs::read(tmp.path().join(".git/config")).unwrap();
    env.remove("GIT_CONFIG_NOSYSTEM");
    env.set("GIT_CONFIG_SYSTEM", &system);
    env.set("GIT_CONFIG_GLOBAL", &global);
    let rules = git_rules::Rules::open(&tmp.path().join(".git"), &[]).unwrap();
    assert_eq!(rules.boolean("identity.gitdir").unwrap(), Some(true));
    assert_eq!(rules.boolean("identity.branch").unwrap(), Some(true));
    assert_eq!(
        rules.string("identity.choice").unwrap(),
        Some(b"local".to_vec())
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".git/config")).unwrap(),
        before
    );
    env.set("GIT_CONFIG_NOSYSTEM", "1");
    let rules = git_rules::Rules::open(&tmp.path().join(".git"), &[]).unwrap();
    assert_eq!(rules.boolean("identity.branch").unwrap(), None);
    assert_eq!(
        rules.string("identity.choice").unwrap(),
        Some(b"local".to_vec())
    );
}

#[test]
fn unsupported_config_includes_fail_closed_in_root_and_contributing_sources() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    for directive in [
        "[includeIf \"hasconfig:remote.*.url:*\"]\npath=not-read\n",
        "[include]\npath=%(prefix)/not-read\n",
    ] {
        let tmp = repo();
        let sources = tempfile::tempdir().unwrap();
        let child = sources.path().join("child");
        std::fs::write(&child, directive).unwrap();
        config(
            tmp.path(),
            &format!(
                "\n[include]\npath=\"{}\"\n",
                child.to_str().unwrap().replace('\\', "/")
            ),
        );
        let error = probe_identity(tmp.path()).unwrap_err();
        assert!(
            error.contains("unsupported") && error.contains("include"),
            "{error}"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_placeholders_and_case_ignored_tracked_names_are_not_untracked() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::os::unix::fs::symlink("a", tmp.path().join("link")).unwrap();
    fixture::commit_all(tmp.path(), "link");
    std::fs::remove_file(tmp.path().join("link")).unwrap();
    std::fs::write(tmp.path().join("link"), b"a").unwrap();
    config(tmp.path(), "\n[core]\nsymlinks=false\nignorecase=true\n");
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    std::fs::rename(tmp.path().join("a"), tmp.path().join("A")).unwrap();
    // On a case-sensitive host the original tracked path is now missing, but
    // the case-folded name must not be added to the untracked snapshot.
    let index = git_index::read(&tmp.path().join(".git/index")).unwrap();
    let rules = git_rules::Rules::open(tmp.path(), &index).unwrap();
    let mut untracked = Vec::new();
    walk_untracked(
        tmp.path(),
        Path::new(""),
        &distinct(&index),
        &rules,
        &mut untracked,
    )
    .unwrap();
    assert!(untracked.is_empty());
}

#[test]
fn deleted_cached_home_never_overrides_current_declared_rule_paths() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let first = tempfile::tempdir().unwrap();
    std::fs::write(first.path().join(".gitconfig"), b"").unwrap();
    std::fs::write(first.path().join("attributes"), b"a text\n").unwrap();
    std::fs::write(first.path().join("ignore"), b"ignored\n").unwrap();
    config(
        tmp.path(),
        "\n[core]\nattributesfile=~/attributes\nexcludesfile=~/ignore\n",
    );
    std::fs::write(tmp.path().join("a"), b"base\r\n").unwrap();
    std::fs::write(tmp.path().join("ignored"), b"not source\n").unwrap();
    env.remove("XDG_CONFIG_HOME");
    env.remove("GIT_CONFIG_GLOBAL");
    env.set("HOME", first.path());
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    let missing = tmp.path().join("missing-home");
    env.set("HOME", &missing);
    drop(first);
    assert!(!missing.exists());
    assert!(state(tmp.path()).is_dirty());
    let rules = git_rules::Rules::open(tmp.path(), &[]).unwrap();
    let expected = missing.join("attributes");
    assert_eq!(
        rules.string("core.attributesfile").unwrap(),
        Some(repository_path_bytes(&expected).unwrap())
    );
    let third = tempfile::tempdir().unwrap();
    std::fs::write(third.path().join("attributes"), b"a text\n").unwrap();
    std::fs::write(third.path().join("ignore"), b"ignored\n").unwrap();
    env.set("HOME", third.path());
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
}

#[test]
fn nonexistent_optional_home_and_xdg_config_are_absent_not_native_fallbacks() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let missing_home = tmp.path().join("nonexistent-home");
    let missing_xdg = tmp.path().join("nonexistent-xdg");
    env.set("HOME", &missing_home);
    env.set("XDG_CONFIG_HOME", &missing_xdg);
    env.remove("GIT_CONFIG_GLOBAL");
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    let rules = git_rules::Rules::open(tmp.path(), &[]).unwrap();
    assert_eq!(
        rules.string("core.excludesfile").unwrap(),
        Some(repository_path_bytes(&missing_xdg.join("git/ignore")).unwrap())
    );
    assert!(!missing_home.exists());
    assert!(!missing_xdg.exists());
}

#[test]
fn relative_rule_resources_are_worktree_rooted_from_outside_cwd() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::write(tmp.path().join("rules.ignore"), b"*.log\n").unwrap();
    std::fs::write(tmp.path().join("rules.attrs"), b"a text\n").unwrap();
    fixture::commit_all(tmp.path(), "rule resources");
    config(
        tmp.path(),
        "\n[core]\nexcludesfile=rules.ignore\nattributesfile=rules.attrs\n",
    );
    std::fs::write(tmp.path().join("a"), b"base\r\n").unwrap();
    std::fs::write(tmp.path().join("noise.log"), b"ignored\n").unwrap();
    assert_ne!(
        std::env::current_dir().unwrap().canonicalize().unwrap(),
        tmp.path().canonicalize().unwrap()
    );
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    let rules = git_rules::Rules::open(tmp.path(), &[]).unwrap();
    assert_eq!(
        rules.string("core.attributesfile").unwrap(),
        Some(repository_path_bytes(&tmp.path().join("rules.attrs")).unwrap())
    );
    assert_eq!(
        rules.string("core.excludesfile").unwrap(),
        Some(repository_path_bytes(&tmp.path().join("rules.ignore")).unwrap())
    );
}

#[cfg(unix)]
#[test]
fn whitespace_rule_resources_and_workdir_preserve_native_bytes() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    for suffix in [" ", "\t", "\n", "=literal\\name "] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(format!("repo{suffix}"));
        std::fs::create_dir(&root).unwrap();
        // A trimmed workdir must not accidentally point at a usable sibling.
        std::fs::create_dir(tmp.path().join(format!("repo{suffix}").trim_end())).unwrap();
        std::fs::write(root.join("a"), b"base\n").unwrap();
        fixture::commit_all(&root, "native whitespace root");
        let ignore = tmp.path().join(format!(" ignore{suffix}"));
        let attributes = tmp.path().join(format!(" attributes{suffix}"));
        std::fs::write(&ignore, b"ignored.txt\n").unwrap();
        std::fs::write(&attributes, b"a text\n").unwrap();
        std::fs::write(
            tmp.path().join(format!(" ignore{suffix}").trim_end()),
            b"not-ignored.txt\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join(format!(" attributes{suffix}").trim_end()),
            b"a -text\n",
        )
        .unwrap();
        for (key, path) in [("excludesfile", &ignore), ("attributesfile", &attributes)] {
            let quoted = path
                .to_str()
                .unwrap()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\t', "\\t")
                .replace('\n', "\\n");
            config(&root, &format!("\n[core]\n{key}=\"{quoted}\"\n"));
        }
        let before = probe_identity(&root).unwrap();
        std::fs::write(root.join("a"), b"base\r\n").unwrap();
        std::fs::write(root.join("ignored.txt"), b"ignored\n").unwrap();
        assert_eq!(state(&root), WorktreeState::Clean, "{suffix:?}");
        assert_eq!(probe_identity(&root).unwrap(), before, "{suffix:?}");
        std::fs::write(root.join("a"), b"dirty\r\n").unwrap();
        let dirty = probe_identity(&root).unwrap();
        assert!(matches!(dirty.worktree, WorktreeState::Dirty { .. }));
        std::fs::write(root.join("ignored.txt"), b"changed ignored\n").unwrap();
        assert_eq!(probe_identity(&root).unwrap(), dirty, "{suffix:?}");
    }
}

#[cfg(unix)]
#[test]
fn raw_rule_resources_and_workdir_preserve_native_bytes() {
    use std::os::unix::ffi::OsStrExt;
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(std::ffi::OsStr::from_bytes(b"repo\xff"));
    if let Err(error) = std::fs::create_dir(&root) {
        #[cfg(target_os = "macos")]
        {
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ), "{error}");
            eprintln!("raw-byte directory capability unavailable on this filesystem: {error}");
            return;
        }
        #[cfg(not(target_os = "macos"))]
        panic!("raw-byte directory creation failed: {error}");
    }
    std::fs::write(root.join("a"), b"base\n").unwrap();
    fixture::commit_all(&root, "raw root");
    let ignore = tmp.path().join(std::ffi::OsStr::from_bytes(b"ignore\xff"));
    std::fs::write(&ignore, b"ignored.txt\n").unwrap();
    let mut bytes = std::fs::read(root.join(".git/config")).unwrap();
    bytes.extend_from_slice(b"\n[core]\nexcludesfile=\"");
    bytes.extend_from_slice(ignore.as_os_str().as_bytes());
    bytes.extend_from_slice(b"\"\n");
    std::fs::write(root.join(".git/config"), bytes).unwrap();
    assert_ne!(std::env::current_dir().unwrap(), root);
    let before = probe_identity(&root).unwrap();
    std::fs::write(root.join("ignored.txt"), b"ignored\n").unwrap();
    assert_eq!(state(&root), WorktreeState::Clean);
    assert_eq!(probe_identity(&root).unwrap(), before);
    std::fs::write(root.join("a"), b"dirty\n").unwrap();
    let dirty = probe_identity(&root).unwrap();
    std::fs::write(root.join("ignored.txt"), b"different ignored bytes\n").unwrap();
    assert_eq!(probe_identity(&root).unwrap(), dirty);
    std::fs::remove_file(&ignore).unwrap();
    std::fs::create_dir(&ignore).unwrap();
    assert!(probe_identity(&root).is_err());
}

#[test]
fn nested_fixture_index_uses_git_separators() {
    let _env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    std::fs::create_dir_all(tmp.path().join("nested/deeper")).unwrap();
    std::fs::write(tmp.path().join("nested/deeper/file"), b"nested\n").unwrap();
    #[cfg(unix)]
    std::fs::write(tmp.path().join("nested/literal\\name"), b"backslash\n").unwrap();
    fixture::commit_all(tmp.path(), "nested");
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
}

#[test]
fn prefix_rule_resources_are_expanded_without_include_prefix_semantics() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = repo();
    let prefix = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let prefix_path = {
        env.remove("ProgramFiles");
        env.remove("ProgramFiles(x86)");
        env.set("LOCALAPPDATA", prefix.path());
        prefix.path().join("Programs/Git")
    };
    #[cfg(not(windows))]
    let prefix_path = prefix.path().to_path_buf();
    std::fs::create_dir_all(prefix_path.join("etc")).unwrap();
    std::fs::write(prefix_path.join("etc/gitconfig"), b"").unwrap();
    std::fs::write(prefix_path.join("rules.ignore"), b"*.log\n").unwrap();
    std::fs::write(prefix_path.join("rules.attrs"), b"a text\n").unwrap();
    env.remove("GIT_CONFIG_NOSYSTEM");
    env.set("GIT_CONFIG_SYSTEM", prefix_path.join("etc/gitconfig"));
    #[cfg(windows)]
    let suffix = String::new();
    #[cfg(not(windows))]
    let suffix = format!(
        "{}/",
        prefix.path().to_str().unwrap().trim_start_matches('/')
    );
    config(
        tmp.path(),
        &format!(
            "\n[core]\nexcludesfile=%(prefix)/{suffix}rules.ignore\nattributesfile=%(prefix)/{suffix}rules.attrs\n"
        ),
    );
    std::fs::write(tmp.path().join("a"), b"base\r\n").unwrap();
    std::fs::write(tmp.path().join("noise.log"), b"ignored\n").unwrap();
    #[cfg(windows)]
    assert_eq!(state(tmp.path()), WorktreeState::Clean);
    #[cfg(not(windows))]
    assert!(
        probe_identity(tmp.path())
            .unwrap_err()
            .contains("installation prefix")
    );
}
