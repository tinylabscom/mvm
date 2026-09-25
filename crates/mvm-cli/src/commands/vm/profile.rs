//! The `--profile` presets and the single table of what each one grants.

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RunProfile {
    /// No environment variables or host shares.
    Restrictive,
    /// Environment variables, read-only host shares, and writable disk images.
    Standard,
    /// As standard, plus a writable host-directory share on a persistent
    /// machine and the dev guest profile for a sealed-image entrypoint run.
    Dev,
    /// Local escape hatch; requires MVM_ACK_PERMISSIVE_RUN=1.
    Permissive,
}

/// What one profile permits.
///
/// The presets used to be spelled out in four places — the transient
/// validator, a stringly-typed `matches!(profile, "dev" | "permissive")` for
/// writable volumes, another for dev init, and prose in the docs. Four
/// declarations of one policy is four chances to disagree, and the one a
/// reader would check is not necessarily the one that runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProfileGrants {
    /// `--env` is accepted.
    pub env: bool,
    /// `--mount` is accepted at all.
    pub host_shares: bool,
    /// A `:rw` **host-directory** share is accepted on a persistent machine.
    /// The guest would write into a host directory, and a directory share's
    /// content digest is pinned at admission, so this stays with the profiles
    /// that also unseal the guest. A transient run's directory snapshot is
    /// read-only under every profile, which is why this is not simply
    /// "writable directories".
    pub writable_host_dirs_when_persistent: bool,
    /// A `:rw` **disk image** (`HOST.img:/GUEST:SIZE:rw`) is accepted. The
    /// guest writes into its own ext4 image file, never into the host
    /// filesystem, so persisting data does not have to unseal the guest. The
    /// guest mount allow-list, not the profile, keeps it off system paths.
    pub writable_disk_images: bool,
    /// The guest gets the dev profile — a dev-shell agent, and DevOnly verbs
    /// on an image that would otherwise be sealed.
    pub dev_guest: bool,
    /// Refuses unless `MVM_ACK_PERMISSIVE_RUN=1` is set.
    pub needs_acknowledgement: bool,
}

impl RunProfile {
    /// Every profile, in increasing order of what it permits.
    pub(crate) const ALL: [Self; 4] = [
        Self::Restrictive,
        Self::Standard,
        Self::Dev,
        Self::Permissive,
    ];

    /// The name the CLI, the receipt, and the docs all use.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Restrictive => "restrictive",
            Self::Standard => "standard",
            Self::Dev => "dev",
            Self::Permissive => "permissive",
        }
    }

    /// Parse the name a persisted machine spec stored.
    ///
    /// Returns `None` for anything else rather than falling back to a
    /// default: a spec carrying a profile nobody recognises should stop the
    /// boot and say so, not be silently treated as whichever preset the
    /// comparison happened to miss.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == name)
    }

    /// The single declaration of what this profile permits.
    pub(crate) const fn grants(self) -> ProfileGrants {
        match self {
            Self::Restrictive => ProfileGrants {
                env: false,
                host_shares: false,
                writable_host_dirs_when_persistent: false,
                writable_disk_images: false,
                dev_guest: false,
                needs_acknowledgement: false,
            },
            Self::Standard => ProfileGrants {
                env: true,
                host_shares: true,
                writable_host_dirs_when_persistent: false,
                writable_disk_images: true,
                dev_guest: false,
                needs_acknowledgement: false,
            },
            Self::Dev => ProfileGrants {
                env: true,
                host_shares: true,
                writable_host_dirs_when_persistent: true,
                writable_disk_images: true,
                dev_guest: true,
                needs_acknowledgement: false,
            },
            Self::Permissive => ProfileGrants {
                env: true,
                host_shares: true,
                writable_host_dirs_when_persistent: true,
                writable_disk_images: true,
                dev_guest: true,
                needs_acknowledgement: true,
            },
        }
    }

    /// One line describing what this profile permits, for `doctor` and help.
    pub(crate) fn summary(self) -> String {
        let g = self.grants();
        let mut parts = Vec::new();
        parts.push(if g.env { "env allowed" } else { "no env" });
        parts.push(
            match (g.host_shares, g.writable_host_dirs_when_persistent) {
                (false, _) => "no host shares",
                (true, false) => "read-only host directories",
                (true, true) => "host directories, writable on a persistent machine",
            },
        );
        if g.writable_disk_images {
            parts.push("writable disk images");
        }
        if g.dev_guest {
            parts.push("dev guest profile");
        }
        if g.needs_acknowledgement {
            parts.push("requires MVM_ACK_PERMISSIVE_RUN=1");
        }
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preset table, asserted as a table. Phase 3's "preset-to-policy
    /// mapping" is exactly this: what each profile permits, written once and
    /// checked once, so a change to `grants()` has to be a deliberate edit to
    /// a row here rather than something that slips through four call sites.
    #[test]
    fn each_preset_grants_exactly_what_the_contract_says() {
        // (profile, env, host_shares, writable_dirs_when_persistent,
        //  writable_disk_images, dev_guest, ack)
        let expected = [
            (
                RunProfile::Restrictive,
                false,
                false,
                false,
                false,
                false,
                false,
            ),
            (RunProfile::Standard, true, true, false, true, false, false),
            (RunProfile::Dev, true, true, true, true, true, false),
            (RunProfile::Permissive, true, true, true, true, true, true),
        ];
        assert_eq!(
            expected.len(),
            RunProfile::ALL.len(),
            "a profile was added without a row here"
        );
        for (profile, env, shares, writable_dirs, writable_disks, dev_guest, ack) in expected {
            let g = profile.grants();
            let name = profile.as_str();
            assert_eq!(g.env, env, "{name}: --env");
            assert_eq!(g.host_shares, shares, "{name}: --mount");
            assert_eq!(
                g.writable_host_dirs_when_persistent, writable_dirs,
                "{name}: :rw directory share on a persistent machine"
            );
            assert_eq!(
                g.writable_disk_images, writable_disks,
                "{name}: :rw disk image"
            );
            assert_eq!(g.dev_guest, dev_guest, "{name}: dev guest profile");
            assert_eq!(g.needs_acknowledgement, ack, "{name}: acknowledgement");
        }
    }

    /// Permissions must only widen as the presets loosen. A preset that
    /// permitted something a looser one refuses would make "stricter" a
    /// meaningless word in the docs and the help.
    #[test]
    fn the_presets_are_ordered_from_strictest_to_loosest() {
        let mut prev = RunProfile::Restrictive.grants();
        for profile in RunProfile::ALL.into_iter().skip(1) {
            let g = profile.grants();
            for (label, was, now) in [
                ("env", prev.env, g.env),
                ("host_shares", prev.host_shares, g.host_shares),
                (
                    "writable_host_dirs",
                    prev.writable_host_dirs_when_persistent,
                    g.writable_host_dirs_when_persistent,
                ),
                (
                    "writable_disk_images",
                    prev.writable_disk_images,
                    g.writable_disk_images,
                ),
                ("dev_guest", prev.dev_guest, g.dev_guest),
            ] {
                assert!(
                    now || !was,
                    "{} revokes `{label}`, which a looser preset granted",
                    profile.as_str()
                );
            }
            prev = g;
        }
    }

    #[test]
    fn a_profile_name_round_trips_and_an_unknown_one_refuses() {
        for profile in RunProfile::ALL {
            assert_eq!(RunProfile::from_name(profile.as_str()), Some(profile));
        }
        assert_eq!(RunProfile::from_name("dev-mode"), None);
        assert_eq!(RunProfile::from_name(""), None);
    }

    /// Persisting data must not require unsealing the guest: the profile that
    /// grants a writable disk image without a directory share also withholds
    /// the dev guest. If this ever fails, `--profile dev` is back to being the
    /// only way to keep state, and it drags the dev shell along with it.
    #[test]
    fn a_writable_disk_image_does_not_need_the_dev_guest() {
        let g = RunProfile::Standard.grants();
        assert!(g.writable_disk_images, "standard grants writable disks");
        assert!(!g.dev_guest, "standard keeps the guest sealed");
        assert!(
            !g.writable_host_dirs_when_persistent,
            "standard still withholds writable host directories"
        );
    }

    /// The one-line description `doctor` prints must say that disk images are
    /// writable and directories are not, and restrictive must mention neither.
    #[test]
    fn the_summary_separates_writable_disks_from_host_directories() {
        let standard = RunProfile::Standard.summary();
        assert!(
            standard.contains("read-only host directories"),
            "{standard}"
        );
        assert!(standard.contains("writable disk images"), "{standard}");
        let dev = RunProfile::Dev.summary();
        assert!(
            dev.contains("host directories, writable on a persistent machine"),
            "{dev}"
        );
        assert!(dev.contains("writable disk images"), "{dev}");
        let restrictive = RunProfile::Restrictive.summary();
        assert!(restrictive.contains("no host shares"), "{restrictive}");
        assert!(!restrictive.contains("writable"), "{restrictive}");
    }
}
