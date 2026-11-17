//! Tests for the rootfs planning and materialization cluster in `rootfs.rs`.

use mvm_core::rootfs_source::RootfsSource;
use mvm_fs::oci::ImageReference;

use super::*;

/// `std::env::set_current_dir` is process-wide; this Mutex stops
/// `cargo test`'s thread pool from racing between two cwd-mutating tests.
/// The lock is held for the lifetime of [`CwdGuard`].
static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct CwdGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
    prev: PathBuf,
}

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir).expect("chdir");
        CwdGuard {
            _guard: guard,
            prev,
        }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
    }
}

fn reference(s: &str) -> ImageReference {
    s.parse().expect("parses as an OCI reference")
}

/// Both steps a caller takes with a declaration string — parse it, then
/// plan the work — so these tests keep exercising the grammar rather than
/// hand-building the parsed value.
fn plan_rootfs(image: &str) -> Result<RootfsPlan> {
    let source: RootfsSource = image.parse().map_err(|e| MvmError::InvalidSpec {
        reason: format!("{e}"),
    })?;
    plan_rootfs_source(source)
}

#[test]
fn plan_rootfs_routes_file_dir_and_registry() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rootfs.ext4");
    std::fs::write(&file, b"x").unwrap();

    // An existing file → a materialized rootfs.
    assert_eq!(
        plan_rootfs(&file.to_string_lossy()).unwrap(),
        RootfsPlan::Materialized(file.clone())
    );
    // An existing directory → an unpacked tree.
    assert_eq!(
        plan_rootfs(&dir.path().to_string_lossy()).unwrap(),
        RootfsPlan::UnpackedDir(dir.path().to_path_buf())
    );
    // A reference → a pull (no network touched here).
    assert_eq!(
        plan_rootfs("docker.io/library/alpine:3.20").unwrap(),
        RootfsPlan::Pull(reference("docker.io/library/alpine:3.20"))
    );
}

#[test]
fn a_mistyped_local_path_is_refused_and_never_planned_as_a_pull() {
    let dir = tempfile::tempdir().unwrap();
    // The user meant `rootfs.ext4`; nothing exists at what they typed.
    let typo = dir.path().join("rootfs.ext5");

    let planned = plan_rootfs(&typo.to_string_lossy());

    // `Pull` is the only variant that reaches a registry, so refusing to
    // produce one is what "no fetch was attempted" means here.
    assert!(
        !matches!(planned, Ok(RootfsPlan::Pull(_))),
        "a typo'd local path must not be planned as a registry pull: {planned:?}"
    );
    let err = planned.expect_err("an absent declared path is an error");
    assert!(
        matches!(err, MvmError::InvalidSpec { .. }),
        "expected a spec error naming the path, got {err:?}"
    );
    assert!(
        err.to_string().contains(&typo.display().to_string()),
        "the error must name the path the caller typed: {err}"
    );
}

#[tokio::test]
async fn resolve_local_rootfs_refuses_a_mistyped_path_before_any_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let typo = dir.path().join("rootfs.ext5");

    let declared: RootfsSource = typo.to_string_lossy().parse().expect("a path parses");
    let err = crate::local::resolve_local_rootfs(&declared, "m")
        .await
        .expect_err("an absent declared path is an error");

    assert!(matches!(err, MvmError::InvalidSpec { .. }), "got {err:?}");
    assert!(err.to_string().contains(&typo.display().to_string()));
}

#[test]
fn a_registry_reference_survives_a_colliding_working_directory_entry() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpine:3.20"), b"decoy").unwrap();
    std::fs::create_dir(dir.path().join("busybox")).unwrap();
    let _cwd = CwdGuard::enter(dir.path());

    // Both names exist in the cwd; neither is a declared path, so both
    // stay references.
    assert_eq!(
        plan_rootfs("alpine:3.20").unwrap(),
        RootfsPlan::Pull(reference("alpine:3.20"))
    );
    assert_eq!(
        plan_rootfs("busybox").unwrap(),
        RootfsPlan::Pull(reference("busybox"))
    );
    // The explicitly-relative form is how the caller asks for the file.
    assert_eq!(
        plan_rootfs("./alpine:3.20").unwrap(),
        RootfsPlan::Materialized(PathBuf::from("./alpine:3.20"))
    );
}

#[test]
fn an_unbootable_declaration_names_what_is_wrong() {
    let empty = plan_rootfs("").expect_err("empty is not a source");
    assert!(matches!(empty, MvmError::InvalidSpec { .. }), "{empty:?}");

    let flake = plan_rootfs_source(RootfsSource::Flake {
        flake_ref: "./nix".into(),
        attr: "rootfs".into(),
    })
    .expect_err("a flake is built, not booted");
    assert!(flake.to_string().contains("./nix#rootfs"), "{flake}");
}

#[test]
fn run_rootfs_output_is_name_sanitized_and_under_cache() {
    let out = run_rootfs_output("my/app:1.2");
    assert!(out.ends_with("rootfs.ext4"));
    let s = out.to_string_lossy();
    assert!(s.contains("local-run"));
    // Path-hostile characters in the name are replaced.
    assert!(s.contains("my_app_1_2"));
}

#[test]
fn host_verity_sidecars_reads_well_formed_pair() {
    let dir = tempfile::tempdir().unwrap();
    let rootfs = dir.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"x").unwrap();
    // No sidecars yet → unverified.
    assert_eq!(host_verity_sidecars(&rootfs), (None, None));

    std::fs::write(dir.path().join("rootfs.verity"), b"tree").unwrap();
    let hex = "a".repeat(64);
    std::fs::write(dir.path().join("rootfs.roothash"), format!("{hex}\n")).unwrap();
    let (v, h) = host_verity_sidecars(&rootfs);
    assert!(v.unwrap().ends_with("rootfs.verity"));
    assert_eq!(h.unwrap(), hex);

    // A malformed (non-hex / wrong-length) roothash is rejected.
    std::fs::write(dir.path().join("rootfs.roothash"), "nothex\n").unwrap();
    assert_eq!(host_verity_sidecars(&rootfs), (None, None));
}
