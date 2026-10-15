use crate::core::{Evidence, MAX_PATH, Record};
use crate::{Error, Result};

pub(crate) use crate::protocol::MAX_FRAME;

pub(crate) fn path_is_valid(path: &str) -> bool {
    path.len() <= MAX_PATH
        && path.starts_with('/')
        && path != "/"
        && !path.as_bytes().contains(&0)
        && path[1..]
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

pub(crate) fn same_evidence(expected: &Evidence, current: &Evidence) -> Result<()> {
    if expected == current && expected.start_ticks != 0 {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}

/// Compare the still-pinned original object and a freshly resolved pathname.
pub(crate) fn same_pin(
    expected: &crate::core::Object,
    pinned: &crate::core::Object,
    fresh: &crate::core::Object,
) -> Result<()> {
    if expected == pinned && expected == fresh {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}

pub(crate) fn decode_record(bytes: &[u8]) -> Result<Record> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| Error::Refused)?;
    let e = &record.evidence;
    if record.version != 1
        || e.pid <= 1
        || e.start_ticks == 0
        || !path_is_valid(&e.state_dir)
        || !path_is_valid(&e.api_socket)
        || e.boot_id.len() != 36
        || e.directory.uid != e.owner_uid
        || e.executable.uid != 0
    {
        return Err(Error::Refused);
    }
    Ok(record)
}

pub(crate) fn trusted_metadata(uid: u32, mode: u32) -> Result<()> {
    if uid != 0 || mode & 0o6022 != 0 {
        return Err(Error::Refused);
    }
    Ok(())
}

pub(crate) fn authenticate_server(
    uid: u32,
    installed: &crate::core::Object,
    running: &crate::core::Object,
) -> Result<()> {
    if uid == 0 && installed.uid == 0 && installed == running {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}

pub(crate) fn cmdline_binds(bytes: &[u8], socket: &str) -> bool {
    if bytes.len() > MAX_FRAME || !bytes.ends_with(&[0]) {
        return false;
    }
    let args: Vec<_> = bytes[..bytes.len() - 1].split(|b| *b == 0).collect();
    let mut bindings = args.windows(2).filter(|arg| arg[0] == b"--api-sock");
    bindings
        .next()
        .is_some_and(|arg| arg[1] == socket.as_bytes())
        && bindings.next().is_none()
        && !args
            .iter()
            .any(|arg| arg.starts_with(b"--api-sock=") || *arg == b"--no-api")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Object;
    use crate::protocol::RegistrationId;

    fn evidence() -> Evidence {
        Evidence {
            pid: 42,
            start_ticks: 99,
            owner_uid: 1000,
            state_dir: "/home/u/state".into(),
            api_socket: "/home/u/state/api.sock".into(),
            directory: Object {
                dev: 1,
                ino: 2,
                uid: 1000,
                mode: 0o40700,
            },
            socket: Object {
                dev: 1,
                ino: 3,
                uid: 0,
                mode: 0o140600,
            },
            executable: Object {
                dev: 1,
                ino: 4,
                uid: 0,
                mode: 0o100755,
            },
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        }
    }
    #[test]
    fn every_identity_binding_is_required() {
        let original = evidence();
        same_evidence(&original, &original).unwrap();
        let mut faults = Vec::new();
        let mut changed = original.clone();
        changed.start_ticks += 1;
        faults.push(changed);
        let mut changed = original.clone();
        changed.pid += 1;
        faults.push(changed);
        let mut changed = original.clone();
        changed.executable.ino += 1;
        faults.push(changed);
        let mut changed = original.clone();
        changed.socket.ino += 1;
        faults.push(changed);
        let mut changed = original.clone();
        changed.directory.ino += 1;
        faults.push(changed);
        let mut changed = original.clone();
        changed.owner_uid += 1;
        faults.push(changed);
        let mut changed = original.clone();
        changed.boot_id.clear();
        faults.push(changed);
        for changed in faults {
            assert!(same_evidence(&original, &changed).is_err());
        }
    }
    #[test]
    fn native_descriptor_pins_detect_real_replacements_and_permission_mutation() {
        use std::fs::{self, File};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fn object(m: std::fs::Metadata) -> Object {
            Object {
                dev: m.dev(),
                ino: m.ino(),
                uid: m.uid(),
                mode: m.mode(),
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        fs::create_dir(&path).unwrap();
        let pin = File::open(&path).unwrap();
        let expected = object(pin.metadata().unwrap());
        let check = || {
            same_pin(
                &expected,
                &object(pin.metadata().unwrap()),
                &object(fs::symlink_metadata(&path).unwrap()),
            )
        };
        check().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        // Ensure a permission mutation even under a restrictive caller umask.
        let changed_mode = expected.mode ^ 0o100;
        fs::set_permissions(&path, fs::Permissions::from_mode(changed_mode & 0o777)).unwrap();
        assert!(check().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(expected.mode & 0o777)).unwrap();
        check().unwrap();
        fs::rename(&path, temp.path().join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(check().is_err());
        // The old descriptor still names the original inode, never the replacement.
        assert_eq!(pin.metadata().unwrap().ino(), expected.ino);
    }
    #[test]
    fn corrupted_missing_or_oversized_records_fail_closed() {
        let record = Record {
            version: 1,
            id: RegistrationId::from_bytes([0; 32]),
            evidence: evidence(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        decode_record(&bytes).unwrap();
        for bytes in [b"{}".as_slice(), b"{", &vec![b' '; MAX_FRAME + 1]] {
            assert!(decode_record(bytes).is_err());
        }
        let mut value = serde_json::to_value(&record).unwrap();
        value["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("start_ticks");
        assert!(decode_record(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn paths_modes_and_command_bindings_are_strict() {
        for path in [
            "/", "relative", "/x/../y", "/x/./y", "/x//y", "/x/", "/x\0y",
        ] {
            assert!(!path_is_valid(path));
        }
        assert!(path_is_valid("/home/u/state"));
        assert!(trusted_metadata(0, 0o100755).is_ok());
        for (uid, mode) in [(1000, 0o100755), (0, 0o100775), (0, 0o104755)] {
            assert!(trusted_metadata(uid, mode).is_err());
        }
        assert!(cmdline_binds(b"firecracker\0--api-sock\0/x/s\0", "/x/s"));
        for args in [
            b"firecracker\0--api-sock\0/x/other\0".as_slice(),
            b"firecracker\0--api-sock=/x/s\0",
            b"firecracker\0--api-sock\0/x/s\0--api-sock\0/x/s\0",
            b"firecracker\0--api-sock\0/x/s",
            b"firecracker\0--no-api\0--api-sock\0/x/s\0",
        ] {
            assert!(!cmdline_binds(args, "/x/s"));
        }
    }
    #[test]
    fn root_claims_and_user_owned_server_binaries_do_not_authenticate() {
        let trusted = Object {
            dev: 1,
            ino: 1,
            uid: 0,
            mode: 0o100755,
        };
        authenticate_server(0, &trusted, &trusted).unwrap();
        assert!(authenticate_server(1000, &trusted, &trusted).is_err());
        let user = Object {
            uid: 1000,
            ..trusted.clone()
        };
        assert!(authenticate_server(0, &trusted, &user).is_err());
        assert!(authenticate_server(0, &user, &user).is_err());
        let substituted = Object {
            ino: 2,
            ..trusted.clone()
        };
        assert!(authenticate_server(0, &trusted, &substituted).is_err());
    }
}
