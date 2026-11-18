use super::*;
use crate::util::test_env::TestEnv;
use std::os::unix::fs::{PermissionsExt, symlink};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn loosen(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn empty_parent_resolves_to_current_directory_without_creating_anything() {
    assert_eq!(
        directories(Path::new("")).unwrap().target,
        std::env::current_dir().unwrap().canonicalize().unwrap()
    );
}

#[test]
fn repairs_loose_home_and_creates_missing_owned_chain_privately() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    loosen(&home);
    create_output_parent(home.join("audit/nested")).unwrap();
    for path in [&home, &home.join("audit"), &home.join("audit/nested")] {
        assert_eq!(mode(path), 0o700);
    }
    std::fs::remove_dir_all(&home).unwrap();
    create_output_parent(home.join("audit/nested")).unwrap();
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&home.join("audit")), 0o700);
}

#[test]
fn external_existing_modes_and_textual_prefix_siblings_are_not_changed() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    let external = root.path().join("mvm-other");
    loosen(&external);
    loosen(&external.join("nested"));
    create_output_parent(external.join("nested")).unwrap();
    assert_eq!(mode(&external), 0o755);
    assert_eq!(mode(&external.join("nested")), 0o755);
    create_output_parent(external.join("new/leaf")).unwrap();
    assert!(external.join("new/leaf").is_dir());
    assert_eq!(mode(&external), 0o755);
    assert!(
        !home.exists(),
        "external output must not initialize unrelated home"
    );
}

#[test]
fn relative_paths_and_parent_components_use_filesystem_meaning() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    let original_root_mode = mode(root.path());
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    let external = root.path().join("output");
    loosen(&external);
    let cwd = std::env::current_dir().unwrap();
    // No global chdir: walk back from cwd to the filesystem root.
    let mut relative = PathBuf::new();
    for _ in cwd
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
    {
        relative.push("..");
    }
    relative.push(home.strip_prefix("/").unwrap());
    create_output_parent(relative.join("missing/x/../leaf")).unwrap();
    assert!(
        home.join("missing/x").is_dir(),
        "do not collapse missing x/.."
    );
    assert_eq!(mode(&home.join("missing/leaf")), 0o700);
    create_output_parent(home.join("../output")).unwrap();
    assert_eq!(mode(&external), 0o755);
    assert_eq!(
        mode(root.path()),
        original_root_mode,
        "temp root must not be changed"
    );
}

#[test]
fn directory_aliases_into_and_out_of_home_follow_resolved_ownership() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    let outside = root.path().join("outside");
    loosen(&home.join("nested"));
    loosen(&outside);
    let home_alias = root.path().join("home-alias");
    symlink(&home, &home_alias).unwrap();
    env.set("MVM_HOME", &home_alias);
    symlink(home.join("nested"), root.path().join("in")).unwrap();
    symlink(&outside, home.join("out")).unwrap();
    create_output_parent(root.path().join("in/leaf")).unwrap();
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&home.join("nested")), 0o700);
    create_output_parent(home.join("out")).unwrap();
    assert_eq!(mode(&outside), 0o755);
    // The '..' is relative to the symlink target, not the lexical spelling.
    loosen(&root.path().join("sibling"));
    create_output_parent(home.join("out/../sibling")).unwrap();
    assert_eq!(mode(&root.path().join("sibling")), 0o755);
    assert!(!home.join("sibling").exists());
}

#[test]
fn missing_components_before_parent_traversal_are_created_in_order() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("home-prefix/x/../mvm");
    env.set("MVM_HOME", &home);
    create_output_parent(root.path().join("home-prefix/mvm/cache")).unwrap();
    assert!(root.path().join("home-prefix/x").is_dir());
    assert!(home.join("cache").is_dir());
    assert_eq!(mode(&home), 0o700);
    let outside = root.path().join("external");
    loosen(&outside);
    create_output_parent(outside.join("missing/x/../leaf")).unwrap();
    assert!(outside.join("missing/x").is_dir());
    assert!(outside.join("missing/leaf").is_dir());
    assert_eq!(mode(&outside), 0o755);
}

#[test]
fn nondirectory_and_dangling_symlink_errors_never_fall_back_to_external() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    std::fs::write(root.path().join("file"), b"untouched").unwrap();
    symlink(root.path().join("file"), root.path().join("file-link")).unwrap();
    symlink(root.path().join("absent"), root.path().join("dangling")).unwrap();
    for bad in ["file/../output", "file-link/../output", "dangling/child"] {
        assert!(
            create_output_parent(root.path().join(bad)).is_err(),
            "{bad}"
        );
    }
    assert!(!root.path().join("output").exists());
    assert!(!root.path().join("absent").exists());
    // An unclassifiable home must not permit even an otherwise external output.
    env.set("MVM_HOME", root.path().join("dangling"));
    assert!(create_output_parent(root.path().join("external")).is_err());
    assert!(!root.path().join("external").exists());
}

#[test]
fn dedicated_parent_escape_and_symlink_parent_preserve_external_ancestors() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    loosen(root.path());
    loosen(&home);
    create_private_dir_resolved(home.join("../dedicated")).unwrap();
    assert_eq!(mode(root.path()), 0o755);
    assert_eq!(mode(&root.path().join("dedicated")), 0o700);
    let outside = root.path().join("outside");
    loosen(&outside);
    loosen(&outside.join("branch"));
    symlink(outside.join("branch"), home.join("alias")).unwrap();
    create_private_dir_resolved(home.join("alias/../missing/x/../leaf")).unwrap();
    assert_eq!(mode(&outside), 0o755);
    assert_eq!(mode(&outside.join("branch")), 0o755);
    assert_eq!(mode(&outside.join("missing/x")), 0o700);
    assert_eq!(mode(&outside.join("missing/leaf")), 0o700);
    assert!(!home.join("missing").exists());
}

#[test]
fn permission_errors_never_select_external_creation() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    env.set("MVM_HOME", root.path().join("mvm"));
    let denied = root.path().join("denied");
    std::fs::create_dir(&denied).unwrap();
    std::fs::write(denied.join("probe"), []).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let traversal_denied = std::fs::metadata(denied.join("probe")).is_err();
    let result = create_output_parent(denied.join("new"));
    let traversed_parent = create_output_parent(denied.join("../sibling"));
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
    if traversal_denied {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(!denied.join("new").exists());
        assert_eq!(
            traversed_parent.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    } else {
        // A privileged test process cannot witness Unix DAC denial.
        eprintln!("permission-denial witness unavailable: process bypasses directory DAC");
    }
}
