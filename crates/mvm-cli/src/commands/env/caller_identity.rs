//! Explicit host-native enrollment; the disk record contains public data only.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args as ClapArgs, Subcommand};
use mvm_core::{atomic_io, config, private_fs};
use mvm_hostd::caller_identity::{EnrolledIdentity, IdentityClient, IdentityError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Action {
    /// Explicitly enroll a new dedicated native caller identity (macOS only)
    Enroll,
    /// Read public enrollment metadata without accessing native custody
    #[command(alias = "status")]
    Show,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    installation: Uuid,
    state: State,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum State {
    Pending,
    Enrolled { public_key: [u8; 32] },
}

fn record_path(home: &Path) -> PathBuf {
    config::mvm_config_dir_at(home).join("caller-identity.json")
}

fn supported() -> Result<()> {
    if !cfg!(all(target_os = "macos", feature = "native-caller-identity")) {
        return Err(IdentityError::Unsupported.into());
    }
    Ok(())
}

fn validate_record(record: &Record) -> Result<()> {
    ensure!(
        record.version == 1,
        "unsupported caller identity record version; refusing enrollment or rotation"
    );
    ensure!(
        !record.installation.is_nil(),
        "invalid caller identity installation; refusing enrollment or rotation"
    );
    if let State::Enrolled { public_key } = record.state {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .context("invalid caller identity public pin")?;
        ensure!(!key.is_weak(), "invalid weak caller identity public pin");
    }
    Ok(())
}

fn read_record(home: &Path) -> Result<Option<Record>> {
    let path = record_path(home);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("reading caller identity metadata"),
    };
    ensure!(
        metadata.is_file(),
        "caller identity record must be a regular file, not a symlink"
    );
    private_fs::require_current_owner(&metadata)?;
    ensure!(
        private_fs::mode_bits(&path, &metadata)? == 0o600,
        "caller identity record must have private mode 0600"
    );
    let bytes = std::fs::read(&path).context("reading caller identity record")?;
    let record: Record = serde_json::from_slice(&bytes)
        .context("invalid caller identity record; refusing enrollment or rotation")?;
    validate_record(&record)?;
    Ok(Some(record))
}

/// Read the exact public enrollment pin. Never enrolls or accesses private keys.
pub(crate) fn load_enrolled_identity() -> Result<EnrolledIdentity> {
    load_at(&config::mvm_home_strict()?)
}

fn load_at(home: &Path) -> Result<EnrolledIdentity> {
    let record = read_record(home)?.context(
        "caller identity is not enrolled; explicitly run `mvmctl env caller-identity enroll` before launching",
    )?;
    match record.state {
        State::Pending => bail!(
            "caller identity enrollment is pending for installation {}; native enrollment may have completed; refusing re-enrollment or rotation; retain this record for operator recovery",
            record.installation
        ),
        State::Enrolled { public_key } => Ok(EnrolledIdentity {
            installation: record.installation,
            public_key,
        }),
    }
}

fn enroll_with(
    home: &Path,
    enroll: impl FnOnce(Uuid) -> Result<EnrolledIdentity>,
) -> Result<EnrolledIdentity> {
    // Even malformed or pending records reserve the namespace.
    ensure!(
        read_record(home)?.is_none(),
        "caller identity record already exists; refusing re-enrollment or rotation"
    );
    let directory = config::mvm_config_dir_at(home);
    private_fs::ensure_private_dir(home)?;
    private_fs::ensure_private_dir(&directory)?;
    let path = record_path(home);
    let mut record = Record {
        version: 1,
        installation: Uuid::new_v4(),
        state: State::Pending,
    };
    atomic_io::atomic_write_new(&path, &serde_json::to_vec_pretty(&record)?)
        .context("caller identity namespace reservation failed; refusing enrollment")?;
    private_fs::sync_managed_directory_chain(home, &directory)
        .context("syncing caller identity namespace reservation; native enrollment not started")?;
    let identity = enroll(record.installation).context(
        "native enrollment did not complete; pending record retained; do not delete it or retry enrollment",
    )?;
    ensure!(
        identity.installation == record.installation,
        "native enrollment returned another installation; pending record retained"
    );
    ensure!(
        read_record(home)?.as_ref() == Some(&record),
        "caller identity reservation changed during enrollment; refusing to replace unknown state"
    );
    record.state = State::Enrolled {
        public_key: identity.public_key,
    };
    validate_record(&record)?;
    // Only the winner of the create-only reservation can reach this transition.
    atomic_io::atomic_write_durable(&path, &serde_json::to_vec_pretty(&record)?)
        .context("saving exact caller identity pin; do not retry enrollment")?;
    Ok(identity)
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let home = config::mvm_home_strict()?;
    match args.action {
        Action::Enroll => {
            supported()?;
            let identity = enroll_with(&home, |installation| {
                let client = IdentityClient::native()?;
                Ok(client
                    .enroll(installation, Instant::now() + Duration::from_secs(30))?
                    .wait()?
                    .identity())
            })?;
            println!("{}", serde_json::to_string_pretty(&identity)?);
        }
        Action::Show => {
            let record = read_record(&home)?.context(
                "caller identity is not enrolled; explicitly run `mvmctl env caller-identity enroll`",
            )?;
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(installation: Uuid) -> EnrolledIdentity {
        EnrolledIdentity {
            installation,
            public_key: ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes(),
        }
    }

    #[test]
    fn read_never_creates_and_missing_requests_explicit_enrollment() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("absent");
        assert!(read_record(&home).unwrap().is_none());
        assert!(
            load_at(&home)
                .unwrap_err()
                .to_string()
                .contains("explicitly run")
        );
        assert!(!home.exists());
    }

    #[test]
    fn reservation_precedes_native_work_and_failure_keeps_namespace() {
        for error in [IdentityError::Deadline, IdentityError::Unavailable] {
            let temp = tempfile::tempdir().unwrap();
            let mut reserved = None;
            assert!(
                enroll_with(temp.path(), |installation| {
                    let record = read_record(temp.path())?.unwrap();
                    assert_eq!(record.installation, installation);
                    assert_eq!(record.state, State::Pending);
                    reserved = Some(installation);
                    Err(error.into())
                })
                .is_err()
            );
            let record = read_record(temp.path()).unwrap().unwrap();
            assert_eq!(Some(record.installation), reserved);
            assert_eq!(record.state, State::Pending);
            assert!(
                load_at(temp.path())
                    .unwrap_err()
                    .to_string()
                    .contains("pending")
            );
            assert!(enroll_with(temp.path(), |_| panic!("must not enroll twice")).is_err());
        }
    }

    #[test]
    fn exact_pin_roundtrips_and_duplicate_cannot_enroll() {
        let temp = tempfile::tempdir().unwrap();
        let expected = enroll_with(temp.path(), |installation| Ok(identity(installation))).unwrap();
        assert_eq!(load_at(temp.path()).unwrap(), expected);
        let record = read_record(temp.path()).unwrap().unwrap();
        let json = serde_json::to_vec(&record).unwrap();
        assert_eq!(serde_json::from_slice::<Record>(&json).unwrap(), record);
        assert_eq!(
            private_fs::mode_bits(
                temp.path(),
                &std::fs::metadata(config::mvm_config_dir_at(temp.path())).unwrap()
            )
            .unwrap(),
            0o700
        );
        assert!(enroll_with(temp.path(), |_| panic!("must not enroll twice")).is_err());
        assert_eq!(load_at(temp.path()).unwrap(), expected);
    }

    #[cfg(not(all(target_os = "macos", feature = "native-caller-identity")))]
    #[test]
    fn unsupported_build_reports_existing_identity_error_without_native_access() {
        assert_eq!(
            supported().unwrap_err().downcast_ref::<IdentityError>(),
            Some(&IdentityError::Unsupported)
        );
    }

    #[test]
    fn wrong_installation_keeps_pending() {
        let temp = tempfile::tempdir().unwrap();
        assert!(enroll_with(temp.path(), |_| Ok(identity(Uuid::new_v4()))).is_err());
        assert_eq!(
            read_record(temp.path()).unwrap().unwrap().state,
            State::Pending
        );
    }

    #[test]
    fn changed_reservation_is_not_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            enroll_with(temp.path(), |installation| {
                atomic_io::atomic_write_durable(&record_path(temp.path()), b"unknown state")?;
                Ok(identity(installation))
            })
            .is_err()
        );
        assert_eq!(
            std::fs::read(record_path(temp.path())).unwrap(),
            b"unknown state"
        );
    }

    #[test]
    fn racing_enrollment_cannot_enter_native_seam_twice() {
        let temp = tempfile::tempdir().unwrap();
        enroll_with(temp.path(), |installation| {
            assert!(
                enroll_with(temp.path(), |_| panic!("reserved namespace cannot enroll")).is_err()
            );
            Ok(identity(installation))
        })
        .unwrap();
    }

    #[test]
    fn corrupt_unsupported_unknown_and_invalid_records_refuse() {
        for bytes in [
            b"not json".as_slice(),
            br#"{"version":2,"installation":"983f508d-e45f-4eaf-9bdc-38b806728412","state":{"kind":"pending"}}"#,
            br#"{"version":1,"installation":"983f508d-e45f-4eaf-9bdc-38b806728412","state":{"kind":"unknown"}}"#,
            br#"{"version":1,"installation":"00000000-0000-0000-0000-000000000000","state":{"kind":"pending"}}"#,
            br#"{"version":1,"installation":"983f508d-e45f-4eaf-9bdc-38b806728412","state":{"kind":"pending"},"private_key":"refused"}"#,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let directory = config::mvm_config_dir_at(temp.path());
            private_fs::ensure_private_dir(&directory).unwrap();
            atomic_io::atomic_write_new(&record_path(temp.path()), bytes).unwrap();
            assert!(read_record(temp.path()).is_err());
            assert!(enroll_with(temp.path(), |_| panic!("must not enroll corrupt state")).is_err());
        }
    }
}
