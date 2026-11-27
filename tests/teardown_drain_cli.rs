//! What each teardown verb leaves behind in the standby pool and the
//! Firecracker idle pool.
//!
//! `machine stop --all` and `machine rm --all` drain both: nothing a future
//! launch was being kept warm for survives them, except what a launcher is in
//! the middle of consuming. `reconcile` and `cache prune` recover only what a
//! crashed process left; a healthy standby is the pool doing its job.

use assert_cmd::cargo::CommandCargoExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

struct Home {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Home {
    /// An mvm home holding one unclaimed and one claimed saved-state standby
    /// (each with a state dir), an idle-pool entry whose process never came
    /// up, and a claim whose launcher died mid-adoption.
    fn seeded() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("mvm-home");
        let home = Self { _tmp: tmp, root };
        home.standby("standby-idle", "idle");
        home.standby("standby-claimed", "claimed");
        let abandoned = home.idle_pool().join("idle-abandoned");
        let crashed = home.idle_pool().join("claimed-idle-crashed-aabbccdd");
        for dir in [&abandoned, &crashed] {
            std::fs::create_dir_all(dir).expect("idle-pool entry");
        }
        std::fs::write(
            crashed.join("claim.journal"),
            home.root.join("vms/gone").to_string_lossy().as_bytes(),
        )
        .expect("claim journal");
        for dir in [&abandoned, &crashed] {
            std::fs::File::open(dir)
                .expect("open entry")
                .set_modified(SystemTime::now() - Duration::from_secs(3600))
                .expect("age entry");
        }
        home
    }

    fn standby(&self, id: &str, state: &str) {
        let dir = self.root.join("pool").join(id);
        std::fs::create_dir_all(&dir).expect("standby dir");
        let handle = serde_json::json!({
            "id": id,
            "control_socket": "",
            "pid": 0,
            "kernel_sha256": "aa",
            "vcpus": 1,
            "mem_mib": 256,
            "binding_nonce": "ab".repeat(32),
            "spawned_unix_secs": 1,
            "state": state,
        });
        std::fs::write(dir.join("standby.json"), handle.to_string()).expect("standby record");
        std::fs::create_dir_all(self.root.join("vms").join(id)).expect("standby state dir");
    }

    fn idle_pool(&self) -> PathBuf {
        self.root.join("fc-idle")
    }

    /// Run `mvmctl` against this home. `MVM_SKIP_RECONCILE=1` is set for the
    /// verbs that drain: the reconcile pass before a lifecycle command
    /// recovers crashed idle-pool entries on its own, so without it a drain
    /// that never ran would still leave the pool empty.
    fn run(&self, args: &[&str]) -> std::process::Output {
        let out = self.mvmctl(args).output().expect("spawn mvmctl");
        assert!(
            out.status.success(),
            "mvmctl {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn mvmctl(&self, args: &[&str]) -> Command {
        #[allow(deprecated)]
        let mut command = Command::cargo_bin("mvmctl").expect("locate mvmctl");
        command
            .args(args)
            .env("HOME", self.root.parent().expect("parent"))
            .env("MVM_HOME", &self.root)
            .stdin(std::process::Stdio::null());
        if args.first() == Some(&"machine") {
            command.env("MVM_SKIP_RECONCILE", "1");
        }
        command
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|it| {
                it.map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn standbys(&self) -> Vec<String> {
        Self::names(&self.root.join("pool"))
            .into_iter()
            .filter(|name| {
                self.root
                    .join("pool")
                    .join(name)
                    .join("standby.json")
                    .exists()
            })
            .collect()
    }

    fn assert_drained(&self) {
        assert_eq!(self.standbys(), ["standby-claimed"]);
        assert!(!self.root.join("vms/standby-idle").exists());
        assert!(
            self.root.join("vms/standby-claimed").is_dir(),
            "a claimed standby belongs to its launcher"
        );
        assert_eq!(Self::names(&self.idle_pool()), Vec::<String>::new());
    }

    fn assert_recovered(&self) {
        assert_eq!(self.standbys(), ["standby-claimed", "standby-idle"]);
        assert!(self.root.join("vms/standby-idle").is_dir());
        assert_eq!(Self::names(&self.idle_pool()), Vec::<String>::new());
    }
}

#[test]
fn stop_all_drains_the_standby_and_idle_pools() {
    let home = Home::seeded();
    let _ = home.run(&["machine", "stop", "--all", "--yes"]);
    home.assert_drained();
}

#[test]
fn rm_all_drains_the_standby_and_idle_pools() {
    let home = Home::seeded();
    let _ = home.run(&["machine", "rm", "--all", "--yes"]);
    home.assert_drained();
}

#[test]
fn reconcile_recovers_what_a_crash_left_in_the_idle_pool() {
    let home = Home::seeded();
    let _ = home.run(&["reconcile"]);
    home.assert_recovered();
}

#[test]
fn cache_prune_recovers_what_a_crash_left_in_the_idle_pool() {
    let home = Home::seeded();
    let _ = home.run(&["cache", "prune"]);
    home.assert_recovered();
}

/// `machine rm --all` drains only once the removal is confirmed. A declined
/// prompt (here a run with no terminal and no `--yes`) removes nothing, warm
/// standbys and idle processes included, and a standby is not listed as a VM
/// with no definition.
#[test]
fn rm_all_that_is_not_confirmed_drains_nothing() {
    let home = Home::seeded();
    let _ = home.run(&["machine", "create", "kept", "--image", "alpine"]);

    let out = home.run(&["machine", "rm", "--all"]);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("aborted"), "stdout: {stdout}");
    assert!(
        !stdout.contains("standby-"),
        "a standby is not an undefined VM: {stdout}"
    );
    assert_eq!(home.standbys(), ["standby-claimed", "standby-idle"]);
    assert_eq!(
        Home::names(&home.idle_pool()),
        ["claimed-idle-crashed-aabbccdd", "idle-abandoned"]
    );
}
