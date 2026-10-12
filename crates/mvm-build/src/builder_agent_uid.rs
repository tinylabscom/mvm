//! The uid a builder guest runs its guest agent under.
//!
//! The builder image is mounted read-only and its account rows are baked by
//! mkGuest, so the agent has to run under a uid the booted image already names.
//! Builder images built from mkGuest's fixed identity set (root 0,
//! `mvm-worker` 901, `mvm-dns` 987, `mvm-crng` 988, `mvm-egress` 989, plus the
//! builder's `mvm-builder` 902) name 901. Builder images built before that set
//! was fixed — the published ABI 1 image among them — name the agent at 990
//! and have no 901. Both kinds exist at ABI 2, so the image's own rows decide,
//! not its builder boot ABI.

/// The uid the guest agent is dropped to: `mvm-worker`, the identity every
/// guest agent runs under. Distinct from the dispatched-build uid (902), so a
/// build step cannot signal or trace the agent.
pub const AGENT_UID: u32 = mvm_agentd::guest_mount::WORKLOAD_UID;

/// The agent uid mkGuest named, as `mvm-agent`, before its identity set was
/// fixed. Builder images built then name this uid and not [`AGENT_UID`].
pub const LEGACY_AGENT_UID: u32 = 990;

/// The booted image's account database.
pub const IMAGE_PASSWD: &str = "/etc/passwd";

/// Whether `passwd` (an `/etc/passwd` body) has a row whose uid field is `uid`.
pub fn passwd_names_uid(passwd: &str, uid: u32) -> bool {
    passwd
        .lines()
        .filter_map(|line| line.split(':').nth(2))
        .any(|field| field.parse::<u32>() == Ok(uid))
}

/// The uid to run the agent under, given the booted image's `/etc/passwd`:
/// [`AGENT_UID`] unless the image names [`LEGACY_AGENT_UID`] and not
/// [`AGENT_UID`]. An unreadable passwd, or one naming neither, gets
/// [`AGENT_UID`].
pub fn agent_uid_for_image(passwd: Option<&str>) -> u32 {
    match passwd {
        Some(rows)
            if !passwd_names_uid(rows, AGENT_UID) && passwd_names_uid(rows, LEGACY_AGENT_UID) =>
        {
            LEGACY_AGENT_UID
        }
        _ => AGENT_UID,
    }
}

/// [`agent_uid_for_image`] over the running guest's [`IMAGE_PASSWD`].
pub fn booted_image_agent_uid() -> u32 {
    agent_uid_for_image(std::fs::read_to_string(IMAGE_PASSWD).ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rows mkGuest writes for a builder image from its fixed identity set.
    const FIXED_SET_BUILDER_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
mvm-worker:x:901:901:mvm workload:/home/mvm-worker:/bin/sh
mvm-dns:x:987:987:mvm addon DNS:/var/empty:/bin/false
mvm-crng:x:988:988:mvm CRNG reseed:/var/empty:/bin/false
mvm-egress:x:989:989:mvm FlowMux egress:/var/empty:/bin/false
mvm-builder:x:902:902:mvm build worker:/tmp:/bin/sh
";

    /// The rows the published builder image carries: mkGuest from before the
    /// identity set was fixed, which named the agent at 990 and had no 901.
    const LEGACY_BUILDER_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
mvm-egress:x:989:989:mvm FlowMux egress:/var/empty:/bin/false
mvm-agent:x:990:990:mvm guest agent:/var/empty:/bin/false
mvm-builder:x:902:902:mvm build worker:/tmp:/bin/sh
";

    #[test]
    fn the_agent_uid_is_the_fixed_worker_identity_and_not_the_build_uid() {
        assert_eq!(AGENT_UID, 901);
        assert_eq!(AGENT_UID, mvm_agentd::guest_mount::WORKLOAD_UID);
        // The dispatched-build uid, which the builder image names `mvm-builder`.
        assert_ne!(AGENT_UID, 902);
        assert_ne!(
            AGENT_UID,
            mvm_agentd::guest_mount::EGRESS_CLIENT_IDENTITY.uid()
        );
    }

    #[test]
    fn an_image_built_from_the_fixed_identity_set_runs_its_agent_as_901() {
        assert!(!passwd_names_uid(
            FIXED_SET_BUILDER_PASSWD,
            LEGACY_AGENT_UID
        ));
        assert_eq!(agent_uid_for_image(Some(FIXED_SET_BUILDER_PASSWD)), 901);
    }

    /// The published builder image has no row for 901. Moving its agent there
    /// would recreate, on the image already in users' caches, the unnamed-uid
    /// agent this selection exists to avoid.
    #[test]
    fn the_published_legacy_image_keeps_its_agent_on_the_uid_it_names() {
        assert!(!passwd_names_uid(LEGACY_BUILDER_PASSWD, AGENT_UID));
        assert_eq!(agent_uid_for_image(Some(LEGACY_BUILDER_PASSWD)), 990);
    }

    #[test]
    fn an_image_naming_both_uids_prefers_the_fixed_identity() {
        let both = format!("{LEGACY_BUILDER_PASSWD}mvm-worker:x:901:901::/:/bin/sh\n");
        assert_eq!(agent_uid_for_image(Some(&both)), 901);
    }

    #[test]
    fn an_unreadable_or_unrelated_passwd_falls_back_to_the_fixed_identity() {
        assert_eq!(agent_uid_for_image(None), 901);
        assert_eq!(agent_uid_for_image(Some("")), 901);
        assert_eq!(
            agent_uid_for_image(Some("root:x:0:0:root:/root:/bin/sh\n")),
            901
        );
    }

    /// Only the uid field counts: 990 as a gid, in a gecos field or as part of
    /// a longer number is not a row for uid 990.
    #[test]
    fn passwd_rows_are_matched_on_the_uid_field_only() {
        let lookalikes = "\
a:x:1990:1990::/:/bin/false
b:x:5:990:gid only:/:/bin/false
c:x:6:6:990:/990:/bin/false
malformed:x
";
        assert!(!passwd_names_uid(lookalikes, 990));
        assert_eq!(agent_uid_for_image(Some(lookalikes)), 901);
    }
}
