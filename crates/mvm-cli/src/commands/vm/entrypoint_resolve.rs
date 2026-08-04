//! What a workload will run, as far as the host can tell before it runs it.
//!
//! Admission needs this for exactly one decision: whether to let a writer
//! stream bytes into a sealed production workload's stdin. A shell reading
//! stdin is a shell session; the refusal that stops it can only fire if
//! something on the host knows the entrypoint is a shell.
//!
//! **The host cannot look inside the image.** By the time a workload boots,
//! its rootfs is a materialized ext4 blob and `/etc/mvm/entrypoint` is
//! unreachable from here — mvm writes ext4, it does not read it, and mounting
//! a guest filesystem on the host is exactly the privilege this project
//! refuses to take. So resolution reads the sidecar the build path wrote
//! *beside* the rootfs, which is the same file the sealed-image check already
//! consults.
//!
//! **Absence is not safety.** An image whose sidecar records no argv — built
//! before the field existed, or by a path that could not resolve one — comes
//! back [`ResolvedEntrypoint::Unresolved`], and the caller must treat that as
//! "cannot tell", not "not a shell". Admission does: it refuses the input
//! grant rather than issuing one over an entrypoint nobody checked.

use std::path::Path;

/// What the host believes a workload's PID 1 will exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands::vm) enum ResolvedEntrypoint {
    /// The build path recorded what this image runs.
    Known {
        /// The argv PID 1 execs.
        argv: Vec<String>,
        /// The shebang line, when the entrypoint is a script the resolver
        /// could read.
        ///
        /// Always `None` from [`resolve_for_rootfs`], and that is a property
        /// of where it looks rather than of the images: the sidecar records an
        /// argv, and the script it may name lives inside an ext4 blob the host
        /// does not open. A resolver working from a staging tree — before
        /// materialization, while the files are still files — is what would
        /// fill this in.
        shebang: Option<Vec<u8>>,
    },
    /// Nothing on the host says what this image runs.
    Unresolved {
        /// Why, in the words the refusal quotes back to the operator.
        because: String,
    },
}

impl ResolvedEntrypoint {
    /// The argv when it is known, or an empty slice when it is not.
    ///
    /// Test-only, and deliberately so. It flattens `Known { argv: [] }` and
    /// `Unresolved` into the same answer, and those are different facts with
    /// different safety: admission matches on the variant precisely because
    /// only one of them may be admitted. A test asserting shape can collapse
    /// them; nothing deciding a grant may.
    #[cfg(test)]
    fn argv(&self) -> &[String] {
        match self {
            Self::Known { argv, .. } => argv,
            Self::Unresolved { .. } => &[],
        }
    }

    /// A launch path that did not try to work out what the image runs.
    ///
    /// Distinct from a failed resolution only in the words; both are "the host
    /// cannot say", and both refuse a workload input grant.
    pub(in crate::commands::vm) fn unresolved(because: impl Into<String>) -> Self {
        Self::Unresolved {
            because: because.into(),
        }
    }
}

/// Resolve the entrypoint of the image whose rootfs lives at `rootfs_path`.
///
/// Reads `mvm-meta.json` from the rootfs's own directory — the sidecar every
/// build path writes next to the blob, and the one
/// [`image_is_sealed`](super::agent_verbs::image_is_sealed) already reads to
/// decide the posture this resolution feeds.
pub(in crate::commands::vm) fn resolve_for_rootfs(rootfs_path: &Path) -> ResolvedEntrypoint {
    let Some(dir) = rootfs_path.parent() else {
        return ResolvedEntrypoint::unresolved(format!(
            "the rootfs path {} has no directory to read a sidecar from",
            rootfs_path.display()
        ));
    };
    match mvm_build::builder_vm::GuestSidecar::read_from_dir(dir) {
        Ok(Some(sidecar)) if !sidecar.entrypoint_argv.is_empty() => ResolvedEntrypoint::Known {
            argv: sidecar.entrypoint_argv,
            shebang: None,
        },
        Ok(Some(_)) => ResolvedEntrypoint::unresolved(format!(
            "the image sidecar in {} records no entrypoint argv \
             (it was built before the build path recorded one)",
            dir.display()
        )),
        Ok(None) => ResolvedEntrypoint::unresolved(format!(
            "no image sidecar (mvm-meta.json) beside the rootfs in {}",
            dir.display()
        )),
        Err(error) => ResolvedEntrypoint::unresolved(format!(
            "the image sidecar in {} could not be read: {error:#}",
            dir.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::builder_vm::GuestSidecar;

    fn image_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a scratch dir for the image");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs bytes").expect("write the rootfs stand-in");
        (dir, rootfs)
    }

    #[test]
    fn a_sidecar_carrying_argv_resolves_to_it() {
        let (dir, rootfs) = image_dir();
        GuestSidecar::for_oci_run("resolvable", true, true)
            .with_entrypoint_argv(vec!["/usr/bin/worker".to_string(), "--once".to_string()])
            .write_to_dir(dir.path())
            .expect("write the sidecar");

        assert_eq!(
            resolve_for_rootfs(&rootfs),
            ResolvedEntrypoint::Known {
                argv: vec!["/usr/bin/worker".to_string(), "--once".to_string()],
                shebang: None,
            }
        );
    }

    #[test]
    fn a_sidecar_without_argv_is_unresolved_not_empty_argv() {
        // The distinction the whole module exists for: an image built before
        // the field existed must not read as "runs nothing", because
        // "runs nothing" classifies as not-a-shell and would admit the grant.
        let (dir, rootfs) = image_dir();
        GuestSidecar::for_oci_run("silent", true, true)
            .write_to_dir(dir.path())
            .expect("write the sidecar");

        let resolved = resolve_for_rootfs(&rootfs);
        assert!(
            matches!(resolved, ResolvedEntrypoint::Unresolved { .. }),
            "an argv-less sidecar must not resolve: {resolved:?}"
        );
        assert!(resolved.argv().is_empty());
    }

    #[test]
    fn a_missing_sidecar_is_unresolved_and_names_the_directory() {
        let (dir, rootfs) = image_dir();
        let ResolvedEntrypoint::Unresolved { because } = resolve_for_rootfs(&rootfs) else {
            panic!("a rootfs with no sidecar beside it cannot resolve");
        };
        assert!(
            because.contains(&dir.path().display().to_string()),
            "the reason must name where it looked: {because}"
        );
    }

    #[test]
    fn a_malformed_sidecar_is_unresolved_rather_than_a_panic() {
        let (dir, rootfs) = image_dir();
        std::fs::write(
            GuestSidecar::path_in(dir.path()),
            b"{ this is not the sidecar you are looking for",
        )
        .expect("write the broken sidecar");

        assert!(matches!(
            resolve_for_rootfs(&rootfs),
            ResolvedEntrypoint::Unresolved { .. }
        ));
    }

    #[test]
    fn a_shell_form_image_resolves_to_the_shell_verbatim() {
        // The shape mkGuest's `entrypoint.shell` form records. Resolution must
        // hand the shell through unchanged — the admission gate classifies it,
        // and it can only classify what it is given.
        let (dir, rootfs) = image_dir();
        GuestSidecar::for_oci_run("dev-shell", true, true)
            .with_entrypoint_argv(vec!["/bin/sh".to_string(), "-i".to_string()])
            .write_to_dir(dir.path())
            .expect("write the sidecar");

        assert_eq!(resolve_for_rootfs(&rootfs).argv(), ["/bin/sh", "-i"]);
    }
}
