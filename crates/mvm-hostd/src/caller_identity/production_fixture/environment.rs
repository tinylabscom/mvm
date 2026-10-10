//! Validated, immutable child environment. Recorded strings are never commands.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

pub(super) const RECORD_NAME: &str = "caller-credential.json";
const MARKER: &[u8] = b"native-cold-registration-v1\n";
const WRITABLE: &[(&str, &str)] = &[
    ("MVM_HOME", "mvm"),
    ("TMPDIR", "tmp"),
    ("CARGO_HOME", "cargo"),
    ("CARGO_TARGET_DIR", "target"),
];
const INPUTS: &[&str] = &[
    "MVM_CALLER_WITNESS_SOURCE",
    "MVM_CALLER_WITNESS_KERNEL",
    "MVM_HVF_SUPERVISOR_PATH",
    "MVM_HOST_AGENT_PATH",
    "MVM_SIGNER_HELPER_PATH",
    "MVM_SUBSTITUTION_ENDPOINT_PATH",
    "RUSTUP_HOME",
];
pub(super) const SAFE_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "TMPDIR",
    "MVM_HOME",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "RUSTUP_HOME",
    "MVM_CALLER_WITNESS_ROOT",
    "MVM_CALLER_WITNESS_SOURCE",
    "MVM_CALLER_WITNESS_KERNEL",
    "MVM_HVF_SUPERVISOR_PATH",
    "MVM_RESIDENCY",
    "MVM_HOST_AGENT_PATH",
    "MVM_SIGNER_HELPER_PATH",
    "MVM_SUBSTITUTION_ENDPOINT_PATH",
    "MVM_KERNEL_SOURCE",
    "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE",
    "MVM_NO_LEGACY_BANNER",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    values: Vec<(String, String)>,
    root: PathBuf,
    program: PathBuf,
    record: PathBuf,
}

fn text(value: OsString) -> Result<String> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("fixture value must be UTF-8"))?;
    ensure!(!value.trim().is_empty(), "fixture value must not be empty");
    Ok(value)
}

fn absolute(value: &str) -> Result<&Path> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute() && !value.trim().is_empty(),
        "fixture paths must be nonempty and absolute"
    );
    ensure!(
        !value.split('/').any(|part| part == "." || part == ".."),
        "fixture paths must not contain dot traversal"
    );
    Ok(path)
}

fn canonical(value: &str) -> Result<PathBuf> {
    let path = absolute(value)?.canonicalize()?;
    ensure!(
        path.to_str().is_some(),
        "canonical fixture path must be UTF-8"
    );
    Ok(path)
}

fn canonical_owned(value: &str) -> Result<PathBuf> {
    let path = canonical(value)?;
    let raw = absolute(value)?;
    let spelling = if let Ok(relative) = raw.strip_prefix("/tmp") {
        Path::new("/tmp").canonicalize()?.join(relative)
    } else {
        raw.to_path_buf()
    };
    ensure!(
        spelling == path,
        "owned fixture paths must be canonical, not symlink aliases"
    );
    Ok(path)
}

pub(super) fn private_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
        "fixture metadata must be a single-link regular file"
    );
    ensure!(
        meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o777 == 0o600,
        "fixture metadata must be private and current-user-owned"
    );
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "isolated path must be a real directory"
    );
    ensure!(
        meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o777 == 0o700,
        "isolated directories must be private and current-user-owned"
    );
    Ok(())
}

fn trusted_input(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    ensure!(
        meta.is_file() || meta.is_dir(),
        "invalid prepared input kind"
    );
    ensure!(
        (meta.uid() == rustix::process::geteuid().as_raw() || meta.uid() == 0)
            && meta.mode() & 0o022 == 0,
        "prepared inputs must not be group/other writable"
    );
    Ok(())
}

impl Snapshot {
    pub(super) fn from_process() -> Result<Self> {
        for name in [
            "MVM_SKIP_HASH_VERIFY",
            "MVM_SKIP_COSIGN_VERIFY",
            "MVM_HVF_BOOTARGS",
            "MVM_IMAGES_DIR",
            "MVM_ALLOW_LOCAL_BUILDER_BUILD",
        ] {
            ensure!(
                std::env::var_os(name).is_none(),
                "verification/source-build override is forbidden"
            );
        }
        let values = SAFE_ENV
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
            .collect();
        let program = std::env::var_os("MVM_CALLER_WITNESS_BIN")
            .context("prepared witness binary required")?;
        let record = std::env::var_os("MVM_CALLER_FIXTURE_RECORD")
            .context("cleanup record path required")?;
        Self::validate(values, program, record)
    }

    pub(super) fn validate(
        values: Vec<(OsString, OsString)>,
        program: OsString,
        record: OsString,
    ) -> Result<Self> {
        let mut map = BTreeMap::new();
        for (name, value) in values {
            let name = text(name)?;
            ensure!(
                SAFE_ENV.contains(&name.as_str()),
                "unapproved fixture environment name"
            );
            ensure!(
                map.insert(name, text(value)?).is_none(),
                "duplicate fixture environment name"
            );
        }
        let get = |name: &str| {
            map.get(name)
                .map(String::as_str)
                .context("required fixture environment missing")
        };
        let home = canonical(get("HOME")?)?;
        ensure!(
            home.is_dir() && fs::metadata(&home)?.uid() == rustix::process::geteuid().as_raw(),
            "HOME must name the current user's existing home directory"
        );
        let default = match home.join(".mvm").canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => home.join(".mvm"),
            Err(error) => return Err(error.into()),
        };
        let root = canonical_owned(get("MVM_CALLER_WITNESS_ROOT")?)?;
        let temporary = Path::new("/tmp").canonicalize()?;
        ensure!(
            root != temporary
                && root.starts_with(&temporary)
                && root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("mvm-caller-native.")),
            "explicit isolated witness root under /tmp required"
        );
        ensure!(
            !root.starts_with(&home) && !root.starts_with(&default) && !default.starts_with(&root),
            "witness root must not alias the user's home/default state"
        );
        private_directory(&root)?;
        let marker = root.join("caller-witness-owned");
        private_file(&marker)?;
        ensure!(
            fs::metadata(&marker)?.len() == MARKER.len() as u64 && fs::read(&marker)? == MARKER,
            "owned witness root marker missing"
        );
        let mut normalized = BTreeMap::new();
        normalized.insert(
            "HOME".to_string(),
            home.to_str().context("HOME encoding")?.to_string(),
        );
        normalized.insert(
            "MVM_CALLER_WITNESS_ROOT".into(),
            root.to_str().context("root encoding")?.to_string(),
        );
        for (name, member) in WRITABLE {
            let path = canonical_owned(get(name)?)?;
            ensure!(
                path == root.join(member)
                    && !path.starts_with(&default)
                    && !path.starts_with(&home),
                "child writable paths must be the owned isolated directories, not aliases"
            );
            private_directory(&path)?;
            normalized.insert(
                (*name).into(),
                path.to_str().context("path encoding")?.into(),
            );
        }
        for required in [
            "MVM_CALLER_WITNESS_SOURCE",
            "MVM_CALLER_WITNESS_KERNEL",
            "MVM_HVF_SUPERVISOR_PATH",
        ] {
            get(required)?;
        }
        for name in INPUTS {
            if let Some(value) = map.get(*name) {
                let path = canonical(value)?;
                trusted_input(&path)?;
                normalized.insert(
                    (*name).into(),
                    path.to_str().context("input encoding")?.into(),
                );
            }
        }
        let mut paths = Vec::new();
        for value in get("PATH")?.split(':') {
            let path = canonical(value)?;
            ensure!(
                path.is_dir(),
                "PATH members must name prepared absolute directories"
            );
            paths.push(path.to_str().context("PATH encoding")?.to_string());
        }
        normalized.insert("PATH".into(), paths.join(":"));
        for (name, expected) in [
            ("MVM_RESIDENCY", "cold"),
            ("MVM_KERNEL_SOURCE", "download"),
            ("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE", "download"),
        ] {
            ensure!(
                get(name)? == expected,
                "fixture execution mode is not approved"
            );
            normalized.insert(name.into(), expected.into());
        }
        if let Some(value) = map.get("MVM_NO_LEGACY_BANNER") {
            ensure!(value == "1", "invalid fixture banner mode");
            normalized.insert("MVM_NO_LEGACY_BANNER".into(), value.clone());
        }
        let program = canonical(&text(program)?)?;
        trusted_input(&program)?;
        ensure!(
            program.is_file() && fs::metadata(&program)?.mode() & 0o111 != 0,
            "prepared executable required"
        );
        let record_text = text(record)?;
        let record_path = absolute(&record_text)?;
        ensure!(
            record_path.file_name().and_then(|v| v.to_str()) == Some(RECORD_NAME)
                && record_path
                    .parent()
                    .context("record parent missing")?
                    .canonicalize()?
                    == root,
            "record must be the fixed member of the owned witness root"
        );
        let record = root.join(RECORD_NAME);
        Ok(Self {
            values: normalized.into_iter().collect(),
            root,
            program,
            record,
        })
    }

    pub(super) fn revalidate(&self) -> Result<()> {
        let checked = Self::validate(
            self.values
                .iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            self.program.clone().into_os_string(),
            self.record.clone().into_os_string(),
        )?;
        ensure!(&checked == self, "fixture paths changed after validation");
        Ok(())
    }

    pub(super) fn validate_record(
        &self,
        program: &Path,
        values: &[(String, String)],
    ) -> Result<()> {
        let recorded = Self::validate(
            values
                .iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            program.as_os_str().to_owned(),
            self.record.clone().into_os_string(),
        )?;
        ensure!(
            &recorded == self,
            "recorded environment does not match the independently validated fixture"
        );
        Ok(())
    }

    pub(super) fn check_native_home(&self) -> Result<()> {
        self.revalidate()?;
        let actual = canonical(&text(std::env::var_os("HOME").context("HOME required")?)?)?;
        ensure!(
            self.values
                .iter()
                .any(|(name, value)| name == "HOME" && Path::new(value) == actual),
            "native access requires the validated real HOME"
        );
        Ok(())
    }

    pub(super) fn command(&self, program: &Path) -> Result<Command> {
        self.revalidate()?;
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(self.values.iter().cloned())
            .env("MVM_CALLER_WITNESS_BIN", &self.program)
            .env("MVM_CALLER_FIXTURE_RECORD", &self.record)
            .stdin(Stdio::null());
        Ok(command)
    }

    pub(super) fn values(&self) -> &[(String, String)] {
        &self.values
    }
    pub(super) fn program(&self) -> &Path {
        &self.program
    }
    pub(super) fn record(&self) -> &Path {
        &self.record
    }
}
