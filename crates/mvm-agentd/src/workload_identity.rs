//! Name the fixed workload uid/gid inside the workload rootfs.
//!
//! The agent and every workload process run as uid [`WORKLOAD_UID`], but an
//! arbitrary image — an OCI base like `alpine`, a distroless tree, `scratch` —
//! carries its own `/etc/passwd` that has never heard of it. Everything that
//! resolves a uid to a name then fails: `whoami` exits nonzero, `id` prints a
//! bare number, `ls -l` shows digits, and library code calling `getpwuid()`
//! gets `NULL` and often treats that as fatal.
//!
//! Nix-built images get these entries from `mk-guest.nix`; this module is the
//! equivalent for images mvm did not build. It only ever *appends* an entry
//! for the workload identity, and never when the uid, gid, or name is already
//! spoken for — the image's own accounts win, and no existing line (uid 0
//! least of all) is rewritten.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::guest_mount::{WORKLOAD_GID, WORKLOAD_UID};

/// Account name given to the workload identity.
pub const WORKLOAD_USER: &str = "mvm-worker";

/// Login shell recorded for the workload account.
const WORKLOAD_SHELL: &str = "/bin/sh";

const PASSWD_PATH: &str = "/etc/passwd";
const GROUP_PATH: &str = "/etc/group";

/// The `/etc/passwd` line naming the workload identity.
fn passwd_entry(home: &str) -> String {
    format!(
        "{WORKLOAD_USER}:x:{WORKLOAD_UID}:{WORKLOAD_GID}:mvm workload:{home}:{WORKLOAD_SHELL}\n"
    )
}

/// The `/etc/group` line naming the workload group.
fn group_entry() -> String {
    format!("{WORKLOAD_USER}:x:{WORKLOAD_GID}:\n")
}

/// Whether a colon-separated database already claims `name` or `id` in its
/// name and id columns. Comment and blank lines carry neither.
fn claims(existing: &str, name: &str, id: u32) -> bool {
    existing.lines().any(|line| {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let mut fields = line.split(':');
        let entry_name = fields.next().unwrap_or_default();
        // Field 1 is the password placeholder in both databases; field 2 is
        // the numeric id in both.
        let entry_id = fields.nth(1).unwrap_or_default();
        entry_name == name || entry_id.parse::<u32>() == Ok(id)
    })
}

/// Append `entry` to `existing` when neither `name` nor `id` is taken,
/// returning the new file content. `None` means the file already covers the
/// identity and must be left byte-for-byte alone.
fn with_entry(existing: &str, name: &str, id: u32, entry: &str) -> Option<String> {
    if claims(existing, name, id) {
        return None;
    }
    let mut updated = String::with_capacity(existing.len() + entry.len() + 1);
    updated.push_str(existing);
    // A database whose last line has no terminator would otherwise absorb the
    // new entry into it.
    if !existing.is_empty() && !existing.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(entry);
    Some(updated)
}

/// A missing database is not an error — `scratch` images ship neither file,
/// and creating them is exactly what makes the identity resolvable there.
fn read_or_empty(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

fn update_database(path: &Path, name: &str, id: u32, entry: &str) -> io::Result<()> {
    let existing = read_or_empty(path)?;
    let Some(updated) = with_entry(&existing, name, id, entry) else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, updated)?;
    Ok(())
}

/// Give the workload uid/gid a name in the account databases under `root`.
///
/// Runs as root after the pivot and before the privilege drop, so the write
/// lands in the workload's own rootfs (or its writable overlay) while the
/// agent can still perform it.
pub fn provision_in(root: &Path, home: &str) -> io::Result<()> {
    let joined = |absolute: &str| -> PathBuf { root.join(absolute.trim_start_matches('/')) };
    update_database(
        &joined(PASSWD_PATH),
        WORKLOAD_USER,
        WORKLOAD_UID,
        &passwd_entry(home),
    )?;
    update_database(
        &joined(GROUP_PATH),
        WORKLOAD_USER,
        WORKLOAD_GID,
        &group_entry(),
    )
}

/// Provision the workload identity in the live root.
///
/// A read-only rootfs that refuses the write is reported but not fatal: an
/// unnamed uid degrades `whoami` and friends, it does not stop the workload.
pub fn provision() -> io::Result<()> {
    provision_in(Path::new("/"), crate::guest_mount::workload_home())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_mount::WORKLOAD_HOME;

    fn passwd_of(dir: &Path) -> String {
        fs::read_to_string(dir.join("etc/passwd")).unwrap()
    }

    /// The reported bug: an Alpine rootfs knows nothing about uid 901, so
    /// `whoami` fails with `unknown uid 901`. After provisioning, the uid
    /// resolves — and Alpine's own accounts are untouched.
    #[test]
    fn names_the_workload_uid_in_an_image_that_never_heard_of_it() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        let alpine = "root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/sbin/nologin\n";
        fs::write(dir.path().join("etc/passwd"), alpine).unwrap();
        fs::write(
            dir.path().join("etc/group"),
            "root:x:0:root\nbin:x:1:root,bin\n",
        )
        .unwrap();

        provision_in(dir.path(), WORKLOAD_HOME).unwrap();

        let passwd = passwd_of(dir.path());
        assert!(passwd.starts_with(alpine), "existing accounts rewritten");
        assert!(
            passwd.contains(&format!(
                "{WORKLOAD_USER}:x:901:901:mvm workload:{WORKLOAD_HOME}:"
            )),
            "workload uid not named: {passwd}"
        );
        let group = fs::read_to_string(dir.path().join("etc/group")).unwrap();
        assert!(group.contains("mvm-worker:x:901:"), "{group}");
    }

    /// A `scratch` image ships no account databases at all; provisioning
    /// creates them rather than failing.
    #[test]
    fn creates_the_databases_when_the_image_ships_none() {
        let dir = tempfile::tempdir().unwrap();
        provision_in(dir.path(), WORKLOAD_HOME).unwrap();
        assert!(passwd_of(dir.path()).contains("mvm-worker:x:901:901:"));
    }

    /// An image that already assigns uid 901 to one of its own accounts keeps
    /// it. Appending a second entry for the same uid would make `getpwuid`
    /// resolution order-dependent.
    #[test]
    fn leaves_an_image_that_already_claims_the_uid_alone() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        let existing = "root:x:0:0:root:/root:/bin/sh\napp:x:901:901:app:/app:/bin/sh\n";
        fs::write(dir.path().join("etc/passwd"), existing).unwrap();

        provision_in(dir.path(), WORKLOAD_HOME).unwrap();

        assert_eq!(passwd_of(dir.path()), existing);
    }

    /// Provisioning twice — a warm VM reactivated, or both guest inits running
    /// the same step — must not append the entry a second time.
    #[test]
    fn is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        provision_in(dir.path(), WORKLOAD_HOME).unwrap();
        let once = passwd_of(dir.path());
        provision_in(dir.path(), WORKLOAD_HOME).unwrap();
        assert_eq!(passwd_of(dir.path()), once);
    }

    /// A final line with no newline must not swallow the appended entry.
    #[test]
    fn terminates_an_unterminated_final_line_before_appending() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh",
        )
        .unwrap();

        provision_in(dir.path(), WORKLOAD_HOME).unwrap();

        let passwd = passwd_of(dir.path());
        assert!(
            passwd.starts_with("root:x:0:0:root:/root:/bin/sh\nmvm-worker:"),
            "{passwd}"
        );
    }

    /// Claim 2 is that no guest write can mint a uid-0 entry. This provisioner
    /// runs as root pre-drop, so the guard that matters is that it only ever
    /// appends the workload identity and never rewrites a line.
    #[test]
    fn never_writes_a_uid_zero_entry() {
        let dir = tempfile::tempdir().unwrap();
        provision_in(dir.path(), WORKLOAD_HOME).unwrap();
        let passwd = passwd_of(dir.path());
        for line in passwd.lines() {
            let uid = line.split(':').nth(2).unwrap_or_default();
            assert_ne!(uid, "0", "provisioner emitted a uid-0 entry: {line}");
        }
    }

    #[test]
    fn a_taken_name_blocks_the_append_even_at_another_id() {
        let taken = format!("{WORKLOAD_USER}:x:5000:5000:other:/x:/bin/sh\n");
        assert!(with_entry(&taken, WORKLOAD_USER, WORKLOAD_UID, "ignored").is_none());
    }

    #[test]
    fn comments_and_blank_lines_claim_nothing() {
        let content = "# comment\n\n";
        assert!(with_entry(content, WORKLOAD_USER, WORKLOAD_UID, "new\n").is_some());
    }
}
