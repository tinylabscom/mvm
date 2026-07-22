//! Extended-attribute handling: collecting `SCHILY.xattr.*` pax
//! records off a tar entry, filtering them through
//! [`super::XattrPolicy`]'s allow-list, and applying the survivors to
//! the materialized filesystem entry.

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::{RefusalReason, UnpackOptions, UnpackReport, XattrPolicy, XattrWarning};

/// Pax key prefix used by OCI layer producers for extended
/// attributes. The suffix after this prefix is the filesystem xattr
/// name, e.g. `SCHILY.xattr.user.foo` -> `user.foo`.
const PAX_XATTR_PREFIX: &[u8] = b"SCHILY.xattr.";

#[derive(Debug)]
pub(super) struct PendingXattr {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// Why an xattr was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrWarningReason {
    /// [`XattrPolicy::DropAll`] is active.
    PolicyDropAll,
    /// The xattr name is outside the allow-list.
    NotAllowlisted,
    /// The pax key did not contain a usable xattr name.
    MalformedName,
    /// The xattr passed policy but the host filesystem rejected it.
    ApplyFailed,
}

pub(super) fn collect_entry_xattrs<R: Read>(
    entry: &mut tar::Entry<R>,
    raw_path: &[u8],
    options: &UnpackOptions,
    report: &mut UnpackReport,
) -> Result<Vec<PendingXattr>, RefusalReason> {
    let Some(pax_extensions) = entry
        .pax_extensions()
        .map_err(|_| RefusalReason::MalformedHeader)?
    else {
        return Ok(Vec::new());
    };

    let mut attrs = Vec::new();
    for extension in pax_extensions {
        let extension = extension.map_err(|_| RefusalReason::MalformedHeader)?;
        let key = extension.key_bytes();
        let Some(name) = key.strip_prefix(PAX_XATTR_PREFIX) else {
            continue;
        };

        match classify_xattr_name(options.xattr_policy, name) {
            Ok(()) => attrs.push(PendingXattr {
                name: name.to_vec(),
                value: extension.value_bytes().to_vec(),
            }),
            Err(reason) => record_xattr_warning(report, raw_path, name, reason),
        }
    }

    Ok(attrs)
}

fn classify_xattr_name(policy: XattrPolicy, name: &[u8]) -> Result<(), XattrWarningReason> {
    if name.is_empty() || name.contains(&0) {
        return Err(XattrWarningReason::MalformedName);
    }
    if policy == XattrPolicy::DropAll {
        return Err(XattrWarningReason::PolicyDropAll);
    }
    if is_allowlisted_xattr(name) {
        Ok(())
    } else {
        Err(XattrWarningReason::NotAllowlisted)
    }
}

fn is_allowlisted_xattr(name: &[u8]) -> bool {
    name.starts_with(b"user.") || name == b"security.capability" || name == b"security.selinux"
}

pub(super) fn apply_collected_xattrs(
    target: &Path,
    raw_path: &[u8],
    attrs: Vec<PendingXattr>,
    report: &mut UnpackReport,
) {
    for attr in attrs {
        let name = OsStr::from_bytes(&attr.name);
        match ::xattr::set(target, name, &attr.value) {
            Ok(()) => report.xattrs_written += 1,
            Err(_) => {
                record_xattr_warning(
                    report,
                    raw_path,
                    &attr.name,
                    XattrWarningReason::ApplyFailed,
                );
            }
        }
    }
}

fn record_xattr_warning(
    report: &mut UnpackReport,
    raw_path: &[u8],
    name: &[u8],
    reason: XattrWarningReason,
) {
    report.xattrs_dropped += 1;
    report.xattr_warnings.push(XattrWarning {
        raw_path: raw_path.to_vec(),
        name: name.to_vec(),
        reason,
    });
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    // ── allow-listed pax xattrs ───────────────────────

    #[test]
    fn xattr_policy_allowlist_accepts_only_plan85_names() {
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"user.mvm.test"),
            Ok(())
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"security.capability"),
            Ok(())
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"security.selinux"),
            Ok(())
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"trusted.overlay.opaque"),
            Err(XattrWarningReason::NotAllowlisted)
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::DropAll, b"user.mvm.test"),
            Err(XattrWarningReason::PolicyDropAll)
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b""),
            Err(XattrWarningReason::MalformedName)
        );
    }

    #[test]
    fn allowed_user_xattr_is_preserved_when_host_supports_xattrs() {
        let probe = TempDir::new().unwrap();
        let probe_file = probe.path().join("probe");
        std::fs::write(&probe_file, b"probe").unwrap();
        if ::xattr::set(&probe_file, "user.mvm.probe", b"1").is_err() {
            eprintln!(
                "skipping xattr preservation assertion: host filesystem rejected user.* xattrs"
            );
            return;
        }

        let tar_bytes = build_tar(|b| {
            add_file_with_pax_xattrs(
                b,
                "bin/tool",
                b"run\n",
                &[("SCHILY.xattr.user.mvm.test", b"ok".as_slice())],
            );
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.xattrs_written, 1);
        assert_eq!(report.xattrs_dropped, 0);
        assert!(
            report.xattr_warnings.is_empty(),
            "{:?}",
            report.xattr_warnings
        );
        assert_eq!(
            ::xattr::get(tmp.path().join("bin/tool"), "user.mvm.test").unwrap(),
            Some(b"ok".to_vec())
        );
    }

    #[test]
    fn denied_xattr_is_dropped_with_warning() {
        let tar_bytes = build_tar(|b| {
            add_file_with_pax_xattrs(
                b,
                "bin/tool",
                b"run\n",
                &[("SCHILY.xattr.trusted.overlay.opaque", b"y".as_slice())],
            );
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.xattrs_written, 0);
        assert_eq!(report.xattrs_dropped, 1);
        assert_eq!(report.xattr_warnings.len(), 1);
        assert_eq!(report.xattr_warnings[0].raw_path, b"bin/tool");
        assert_eq!(report.xattr_warnings[0].name, b"trusted.overlay.opaque");
        assert_eq!(
            report.xattr_warnings[0].reason,
            XattrWarningReason::NotAllowlisted
        );
        assert!(report.refused.is_empty(), "{:?}", report.refused);
    }

    #[test]
    fn drop_all_xattr_policy_drops_allowlisted_xattr() {
        let tar_bytes = build_tar(|b| {
            add_file_with_pax_xattrs(
                b,
                "bin/tool",
                b"run\n",
                &[("SCHILY.xattr.user.mvm.test", b"ok".as_slice())],
            );
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            xattr_policy: XattrPolicy::DropAll,
            ..UnpackOptions::default()
        };
        let report = super::super::unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts)
            .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.xattrs_written, 0);
        assert_eq!(report.xattrs_dropped, 1);
        assert_eq!(
            report.xattr_warnings[0].reason,
            XattrWarningReason::PolicyDropAll
        );
    }
}
