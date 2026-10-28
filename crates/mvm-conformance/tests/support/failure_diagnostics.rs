//! Bounded observations only; never acceptance evidence or raw output export.

use mvm_core::launch_trace::failure::{MAX_RECORD_BYTES, PREFIX, Record, decode};
use serde::Serialize;
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Output,
    sync::Mutex,
};

pub(super) const DESTINATION_ENV: &str = "MVM_E2E_FAILURE_MANIFEST";
const INITIALIZED_ENV: &str = "MVM_E2E_FAILURE_INITIALIZED";
const MAX_SCAN_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 16;
const MAX_COMMANDS: usize = 128;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    #[default]
    Absent,
    Collected,
    Unreadable,
}

#[derive(Default, Serialize)]
struct Observation {
    status: Status,
    records: Vec<Record>,
    rejected: u32,
    oversize: u32,
    dropped: u32,
    skipped_bytes: u32,
}

#[derive(Serialize)]
struct CommandObservation {
    scenario: u32,
    command: u32,
    success: Option<bool>,
    exit_code: Option<i32>,
    observation: Observation,
}

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollectionState {
    #[default]
    NotStarted,
    InProgress,
    Complete,
    Unreadable,
    Loss,
}

#[derive(Serialize)]
struct Manifest {
    schema_version: u32,
    state: CollectionState,
    scenario: u32,
    command: u32,
    dropped_commands: u32,
    commands: Vec<CommandObservation>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: 1,
            state: CollectionState::NotStarted,
            scenario: 0,
            command: 0,
            dropped_commands: 0,
            commands: Vec::new(),
        }
    }
}

struct Collector {
    path: PathBuf,
    manifest: Manifest,
    persistence_failed: bool,
}

impl Collector {
    fn initialize(path: &Path, inherited: Option<&str>) -> io::Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let manifest = Manifest::default();
        let expected = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
        if let Some(identity) = inherited {
            // The shell initialized this invocation before any build/bootstrap.
            // Neither existence nor a parseable old manifest is authorization.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)?;
            let metadata = file.metadata()?;
            mvm_core::private_fs::require_current_owner(&metadata)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != 0o600
                || identity != format!("{}:{}", metadata.dev(), metadata.ino())
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut bytes = Vec::new();
            file.take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes != expected {
                return Err(io::ErrorKind::InvalidData.into());
            }
        } else {
            use mvm_core::private_fs::OpenOptionsModeExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open_with_mode(0o600, path)?;
            file.set_permissions(mvm_core::private_fs::permissions(path, 0o600)?)?;
            file.write_all(&expected)?;
            file.sync_all()?;
        }
        Ok(Self {
            path: path.to_owned(),
            manifest,
            persistence_failed: false,
        })
    }

    fn snapshot(&mut self) -> io::Result<()> {
        self.snapshot_with(persist)
    }

    fn snapshot_with(
        &mut self,
        mut write: impl FnMut(&Path, &Manifest) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.persistence_failed {
            self.manifest.state = CollectionState::Unreadable;
        }
        let result = write(&self.path, &self.manifest);
        if result.is_err() {
            self.persistence_failed = true;
            self.manifest.state = CollectionState::Unreadable;
            // A rename can precede a failed parent sync. Repair is best effort;
            // exported snapshots never assert successful durable finalization.
            let _ = write(&self.path, &self.manifest);
        }
        result
    }

    fn finalize(&mut self) -> io::Result<()> {
        self.finalize_with(persist)
    }

    fn finalize_with(
        &mut self,
        write: impl FnMut(&Path, &Manifest) -> io::Result<()>,
    ) -> io::Result<()> {
        self.manifest.state = if self
            .manifest
            .commands
            .iter()
            .any(|command| command.observation.status == Status::Unreadable)
        {
            CollectionState::Unreadable
        } else if self.manifest.dropped_commands > 0
            || self.manifest.commands.iter().any(|command| {
                let o = &command.observation;
                o.rejected > 0 || o.oversize > 0 || o.dropped > 0 || o.skipped_bytes > 0
            })
        {
            CollectionState::Loss
        } else {
            CollectionState::Complete
        };
        self.snapshot_with(write)
    }
}

static COLLECTOR: Mutex<Option<Collector>> = Mutex::new(None);

fn report(status: &[u8]) {
    let _ = io::stderr().write_all(status);
}

pub(crate) fn initialize() {
    let Some(destination) = std::env::var_os(DESTINATION_ENV) else {
        return;
    };
    let initialized = std::env::var(INITIALIZED_ENV).ok();
    let result = Collector::initialize(Path::new(&destination), initialized.as_deref());
    match (COLLECTOR.lock(), result) {
        (Ok(mut collector), Ok(initialized)) => {
            *collector = Some(initialized);
            report(b"failure-manifest: initialized\n");
        }
        _ => report(b"failure-manifest: unreadable\n"),
    }
}

pub(crate) fn finalize() {
    let Ok(mut collector) = COLLECTOR.lock() else {
        report(b"failure-manifest: unreadable\n");
        return;
    };
    if let Some(mut collector) = collector.take() {
        if collector.finalize().is_err() {
            report(b"failure-manifest: unreadable\n");
        } else {
            match collector.manifest.state {
                CollectionState::Complete => report(b"failure-manifest: complete\n"),
                CollectionState::Loss => report(b"failure-manifest: loss\n"),
                _ => report(b"failure-manifest: unreadable\n"),
            }
        }
    }
}

fn collect(stderr: &[u8]) -> Observation {
    let scan = &stderr[..stderr.len().min(MAX_SCAN_BYTES)];
    let mut observation = Observation {
        skipped_bytes: u32::try_from(stderr.len() - scan.len()).unwrap_or(u32::MAX),
        ..Observation::default()
    };
    for line in scan.split_inclusive(|byte| *byte == b'\n') {
        let Some(payload) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let Some(payload) = payload.strip_suffix(b"\n") else {
            observation.rejected = observation.rejected.saturating_add(1);
            continue;
        };
        if payload.len() > MAX_RECORD_BYTES {
            observation.oversize = observation.oversize.saturating_add(1);
        } else if let Some(record) = decode(payload) {
            if observation.records.len() == MAX_RECORDS {
                observation.dropped = observation.dropped.saturating_add(1);
            } else {
                observation.records.push(record);
            }
        } else {
            observation.rejected = observation.rejected.saturating_add(1);
        }
    }
    observation.status = if observation.records.is_empty() {
        Status::Absent
    } else {
        Status::Collected
    };
    observation
}

fn persist(path: &Path, manifest: &Manifest) -> io::Result<()> {
    // The configured parent is operator-owned and trusted. Never read or
    // traverse VM state; replacement uses a fresh private inode.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => return Err(io::ErrorKind::InvalidInput.into()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let bytes = serde_json::to_vec(manifest).map_err(io::Error::other)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    mvm_core::util::atomic_io::write_private(path, &bytes)
}

fn update(f: impl FnOnce(&mut Manifest)) {
    let Ok(mut collector) = COLLECTOR.lock() else {
        report(b"failure-manifest: unreadable\n");
        return;
    };
    let Some(collector) = collector.as_mut() else {
        return;
    };
    collector.manifest.state = CollectionState::InProgress;
    f(&mut collector.manifest);
    if collector.snapshot().is_err() {
        report(b"failure-manifest: unreadable\n");
    }
}

pub(super) fn begin_scenario() {
    update(|manifest| {
        manifest.scenario = manifest.scenario.saturating_add(1);
        manifest.command = 0;
    });
}

pub(super) fn observe(output: &io::Result<Output>) {
    update(|manifest| observe_into(manifest, output));
}

fn observe_into(manifest: &mut Manifest, output: &io::Result<Output>) {
    manifest.command = manifest.command.saturating_add(1);
    if manifest.commands.len() == MAX_COMMANDS {
        manifest.dropped_commands = manifest.dropped_commands.saturating_add(1);
        return;
    }
    let (success, exit_code, observation) = match output {
        Ok(output) => (
            Some(output.status.success()),
            output.status.code(),
            collect(&output.stderr),
        ),
        Err(_) => (
            None,
            None,
            Observation {
                status: Status::Unreadable,
                ..Observation::default()
            },
        ),
    };
    manifest.commands.push(CommandObservation {
        scenario: manifest.scenario,
        command: manifest.command,
        success,
        exit_code,
        observation,
    });
    // Records have a closed fixed-size schema. Keep an independent
    // aggregate bound as well as the command and per-command limits.
    if serde_json::to_vec(&manifest).map_or(true, |bytes| bytes.len() > MAX_MANIFEST_BYTES) {
        manifest.commands.pop();
        manifest.dropped_commands = manifest.dropped_commands.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn postrename_sync_failure_and_failed_repair_export_only_unverified_observations() {
        use super::*;
        use std::os::unix::fs::OpenOptionsExt;
        for repair_succeeds in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            let destination = dir.path().join("export");
            let mut collector = Collector::initialize(&source, None).unwrap();
            let mut attempts = 0;
            let result = collector.finalize_with(|path, manifest| {
                attempts += 1;
                if attempts == 2 {
                    return if repair_succeeds {
                        persist(path, manifest)
                    } else {
                        Err(io::ErrorKind::PermissionDenied.into())
                    };
                }
                // Model atomic_io's failure boundary: file sync and rename have
                // completed, but the parent-directory sync returns an error.
                let staging = dir.path().join("staging");
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&staging)?;
                file.write_all(&serde_json::to_vec(manifest).unwrap())?;
                file.sync_all()?;
                std::fs::rename(staging, path)?;
                Err(io::ErrorKind::Other.into())
            });
            assert!(result.is_err());
            assert_eq!(attempts, 2);
            assert_eq!(collector.manifest.state, CollectionState::Unreadable);
            let disk: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&source).unwrap()).unwrap();
            assert_eq!(
                disk["state"],
                if repair_succeeds {
                    "unreadable"
                } else {
                    "complete"
                }
            );
            let output = crate::exporter(&source, &destination, &dir.path().join("output"));
            assert!(output.status.success());
            assert!(output.stdout.is_empty());
            assert_eq!(output.stderr, b"failure-manifest: exported\n");
            let bytes = std::fs::read(destination).unwrap();
            let exported: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(exported["finalization"], "unverified");
            assert_eq!(
                exported["state"],
                if repair_succeeds {
                    "unreadable"
                } else {
                    "observed"
                }
            );
            assert!(!String::from_utf8(bytes).unwrap().contains("complete"));
        }
    }

    #[test]
    fn initializer_schema_matches_exactly_and_handoff_is_single_use() {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest");
        let output_path = dir.path().join("output");
        let output = crate::initializer(&path, &output_path);
        assert!(output.status.success());
        assert_eq!(output.stderr, b"failure-manifest: initialized\n");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec(&Manifest::default()).unwrap()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_to_string(output_path).unwrap(),
            format!("failure_manifest={}\n", path.display())
        );
        let identity = std::str::from_utf8(&output.stdout).unwrap().trim();
        assert!(Collector::initialize(&path, Some("0:0")).is_err());
        let mut collector = Collector::initialize(&path, Some(identity)).unwrap();
        collector.manifest.state = CollectionState::InProgress;
        collector.snapshot().unwrap();
        assert!(Collector::initialize(&path, Some(identity)).is_err());
        collector.finalize().unwrap();
        assert_eq!(collector.manifest.state, CollectionState::Complete);
    }

    // Runs in a subprocess so environment and the production singleton cannot
    // race other tests. No CLI/runtime/VM command is launched.
    #[test]
    fn lifecycle_child() {
        use super::*;
        let Ok(case) = std::env::var("MVM_DIAGNOSTIC_TEST_CASE") else {
            return;
        };
        initialize();
        begin_scenario();
        let output = std::process::Command::new("sh")
            .args(["-c", "printf 'SENTINEL_SECRET' >&2"])
            .output();
        observe(&output);
        if case != "interrupted" {
            finalize();
        }
    }

    #[test]
    fn bootstrap_failure_and_interruption_keep_current_partial_manifest() {
        for (case, state) in [
            ("bootstrap_failure", "not_started"),
            ("interrupted", "in_progress"),
            ("normal", "complete"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("manifest");
            let output = dir.path().join("output");
            let result = crate::run_script_seam(&path, &output, case);
            assert_eq!(result.status.code(), Some(37), "{result:?}");
            let bytes = std::fs::read(&path).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["state"], state);
            assert!(
                !String::from_utf8(bytes)
                    .unwrap()
                    .contains("SENTINEL_SECRET")
            );
            assert_eq!(
                std::fs::read_to_string(output).unwrap(),
                format!("failure_manifest={}\n", path.display())
            );
        }
    }

    #[test]
    fn stale_and_symlink_refusal_never_authorize_upload_or_later_overwrite() {
        use std::os::unix::fs::symlink;
        for kind in ["file", "symlink", "hardlink"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("manifest");
            let target = dir.path().join("target");
            std::fs::write(&target, b"SENTINEL_SECRET").unwrap();
            if kind == "symlink" {
                symlink(&target, &path).unwrap();
            } else if kind == "hardlink" {
                std::fs::hard_link(&target, &path).unwrap();
            } else {
                std::fs::write(&path, b"SENTINEL_SECRET").unwrap();
            }
            let output = dir.path().join("output");
            let result = crate::run_script_seam(&path, &output, "normal");
            assert_eq!(result.status.code(), Some(37));
            assert_eq!(result.stderr, b"failure-manifest: refused\n");
            assert!(!output.exists());
            assert_eq!(std::fs::read(path).unwrap(), b"SENTINEL_SECRET");
            assert_eq!(std::fs::read(target).unwrap(), b"SENTINEL_SECRET");
        }
    }

    #[test]
    fn initialization_io_failure_and_newline_destination_do_not_authorize_upload() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("output");
        for (name, code, marker) in [
            (
                "missing/manifest",
                3,
                b"failure-manifest: unreadable\n".as_slice(),
            ),
            (
                "manifest\ninjected=true",
                2,
                b"failure-manifest: refused\n".as_slice(),
            ),
            (
                "manifest\rinjected=true",
                2,
                b"failure-manifest: refused\n".as_slice(),
            ),
        ] {
            let result = crate::initializer(&dir.path().join(name), &output);
            assert_eq!(result.status.code(), Some(code));
            assert_eq!(result.stderr, marker);
            assert!(!output.exists());
        }
        let path = dir.path().join("unpublishable");
        let result = crate::initializer(&path, dir.path());
        assert_eq!(result.status.code(), Some(3));
        assert_eq!(result.stderr, b"failure-manifest: unreadable\n");
        assert!(result.stdout.is_empty());
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(value["state"], "not_started");
    }

    #[test]
    fn lifecycle_is_fresh_partial_and_sticky_on_persistence_failure() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest");
        let mut collector = Collector::initialize(&path, None).unwrap();
        assert_eq!(collector.manifest.state, CollectionState::NotStarted);
        assert!(Collector::initialize(&path, None).is_err());
        collector.manifest.state = CollectionState::InProgress;
        collector.snapshot().unwrap();
        let partial: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(partial["state"], "in_progress");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(collector.snapshot().is_err());
        std::fs::remove_dir(&path).unwrap();
        collector.finalize().unwrap();
        assert_eq!(collector.manifest.state, CollectionState::Unreadable);
        let final_record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(final_record["state"], "unreadable");
        assert_eq!(final_record["schema_version"], 1);
    }

    #[test]
    fn normal_absence_completes_but_invalid_utf8_and_cutoff_report_loss() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let mut collector = Collector::initialize(&dir.path().join("manifest"), None).unwrap();
        collector.finalize().unwrap();
        assert_eq!(collector.manifest.state, CollectionState::Complete);
        let mut invalid = PREFIX.to_vec();
        invalid.extend_from_slice(b"\xff\n");
        assert_eq!(collect(&invalid).rejected, 1);
        let mut cutoff = vec![b'\n'; MAX_SCAN_BYTES - PREFIX.len() - 1];
        cutoff.extend_from_slice(PREFIX);
        cutoff.extend_from_slice(b"{}\n");
        let observation = collect(&cutoff);
        assert_eq!(observation.rejected, 1);
        assert_eq!(observation.skipped_bytes, 2);
    }

    #[test]
    fn failed_finalization_leaves_partial_snapshot_and_loss_never_completes() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("active");
        let moved = dir.path().join("moved");
        std::fs::create_dir(&parent).unwrap();
        let mut collector = Collector::initialize(&parent.join("manifest"), None).unwrap();
        collector.manifest.state = CollectionState::InProgress;
        collector.snapshot().unwrap();
        std::fs::rename(&parent, &moved).unwrap();
        assert!(collector.finalize().is_err());
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(moved.join("manifest")).unwrap()).unwrap();
        assert_eq!(value["state"], "in_progress");
        std::fs::rename(&moved, &parent).unwrap();
        collector.finalize().unwrap();
        assert_eq!(collector.manifest.state, CollectionState::Unreadable);
        let mut collector = Collector::initialize(&parent.join("loss"), None).unwrap();
        collector.manifest.dropped_commands = 1;
        collector.finalize().unwrap();
        assert_eq!(collector.manifest.state, CollectionState::Loss);
    }

    #[test]
    fn sentinel_output_and_unknown_fields_never_enter_manifest() {
        use super::*;
        let mut bytes = b"SENTINEL_SECRET\n".to_vec();
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(b"{\"detail\":\"SENTINEL_SECRET\"}\n");
        bytes.extend_from_slice(b"MVM_FAILURE_V1 {\"phase\":\"transient_boot\",\"category\":\"unknown\",\"stage\":\"absent\",\"exit_code\":null}\n");
        let observation = collect(&bytes);
        assert_eq!(observation.records.len(), 1);
        assert_eq!(observation.rejected, 1);
        assert!(
            !serde_json::to_string(&observation)
                .unwrap()
                .contains("SENTINEL_SECRET")
        );
    }

    #[test]
    fn bounds_and_absence_are_explicit() {
        use super::*;
        assert_eq!(collect(b"").status, Status::Absent);
        let many = b"MVM_FAILURE_V1 {\"phase\":\"transient_boot\",\"category\":\"unknown\",\"stage\":\"absent\",\"exit_code\":null}\n".repeat(MAX_RECORDS + 3);
        let observation = collect(&many);
        assert_eq!(observation.records.len(), MAX_RECORDS);
        assert_eq!(observation.dropped, 3);
        let mut oversize = PREFIX.to_vec();
        oversize.extend(vec![b'x'; MAX_RECORD_BYTES + 1]);
        oversize.push(b'\n');
        assert_eq!(collect(&oversize).oversize, 1);
        let observation = collect(&vec![b'x'; MAX_SCAN_BYTES + 5]);
        assert_eq!(observation.skipped_bytes, 5);
    }

    #[test]
    fn command_and_aggregate_bounds_preserve_loss_and_unreadability() {
        use super::*;
        let mut manifest = Manifest::default();
        let failed = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        for _ in 0..MAX_COMMANDS + 3 {
            observe_into(&mut manifest, &failed);
        }
        assert_eq!(manifest.commands.len(), MAX_COMMANDS);
        assert_eq!(manifest.dropped_commands, 3);
        assert_eq!(manifest.commands[0].observation.status, Status::Unreadable);
        assert_eq!(manifest.commands[0].success, None);
        assert!(serde_json::to_vec(&manifest).unwrap().len() <= MAX_MANIFEST_BYTES);
    }

    #[test]
    fn success_without_records_is_explicit_and_output_is_unchanged() {
        use super::*;
        use std::os::unix::process::ExitStatusExt;
        let output = Ok(Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"SENTINEL_SECRET".to_vec(),
            stderr: b"SENTINEL_SECRET".to_vec(),
        });
        let mut manifest = Manifest::default();
        observe_into(&mut manifest, &output);
        assert_eq!(manifest.commands[0].success, Some(true));
        assert_eq!(manifest.commands[0].exit_code, Some(0));
        assert_eq!(manifest.commands[0].observation.status, Status::Absent);
        assert!(
            !serde_json::to_string(&manifest)
                .unwrap()
                .contains("SENTINEL_SECRET")
        );
        assert!(output.is_ok_and(|output| {
            output.stdout == b"SENTINEL_SECRET" && output.stderr == b"SENTINEL_SECRET"
        }));
    }

    #[test]
    fn a_record_beyond_the_scan_limit_is_never_accepted() {
        use super::*;
        let mut bytes = vec![b'\n'; MAX_SCAN_BYTES];
        bytes.extend_from_slice(b"MVM_FAILURE_V1 {\"phase\":\"transient_boot\",\"category\":\"unknown\",\"stage\":\"absent\",\"exit_code\":null}\n");
        let observation = collect(&bytes);
        assert!(observation.records.is_empty());
        assert!(observation.skipped_bytes > 0);
    }

    #[test]
    fn manifest_refuses_links_and_directories_and_is_private() {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"SENTINEL_SECRET").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(persist(&link, &Manifest::default()).is_err());
        assert!(persist(dir.path(), &Manifest::default()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"SENTINEL_SECRET");
        let hard_link = dir.path().join("hard-link");
        std::fs::hard_link(&target, &hard_link).unwrap();
        persist(&hard_link, &Manifest::default()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"SENTINEL_SECRET");
        let output = dir.path().join("manifest");
        persist(&output, &Manifest::default()).unwrap();
        assert_eq!(
            std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
