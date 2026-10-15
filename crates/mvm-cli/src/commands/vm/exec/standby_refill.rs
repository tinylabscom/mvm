//! Whether a run leaves a standby of its image behind, and of what shape.

/// What decides whether a run can leave a standby behind, and of what.
pub(super) struct RefillSource<'a> {
    pub(super) image_ref: Option<&'a str>,
    pub(super) manifest: bool,
    /// The image came from a runtime pack or a caller-resolved source (a
    /// deployment's image), neither of which `pool refill` can re-resolve.
    pub(super) resolved_elsewhere: bool,
    pub(super) hypervisor: Option<&'a str>,
    pub(super) cpus: u32,
    pub(super) memory_mib: u32,
    /// Whether the run boots the guest's egress client.
    pub(super) egress: bool,
}

/// The standby a run of this source leaves behind, or `None` when its image is
/// not one a refill can resolve the same way.
///
/// The refill resolves its launch through `pool warm`'s path, which takes an
/// OCI reference or nothing (the default image) and auto-selects the backend.
/// Anything else would prepare a standby whose compatibility key no later run
/// of this source computes, so it would sit unclaimed until released.
pub(super) fn standby_refill_for(
    source: &RefillSource<'_>,
) -> Option<crate::commands::pool::StandbyRefill> {
    if source.manifest || source.resolved_elsewhere || source.hypervisor.is_some() {
        return None;
    }
    Some(crate::commands::pool::StandbyRefill {
        image: source.image_ref.map(str::to_string),
        cpus: source.cpus,
        memory_mib: source.memory_mib,
        egress: source.egress,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refill_source(image_ref: Option<&str>) -> RefillSource<'_> {
        RefillSource {
            image_ref,
            manifest: false,
            resolved_elsewhere: false,
            hypervisor: None,
            cpus: 2,
            memory_mib: 512,
            egress: false,
        }
    }

    #[test]
    fn an_oci_or_default_image_run_leaves_a_standby_of_its_shape() {
        assert_eq!(
            standby_refill_for(&refill_source(Some("alpine"))),
            Some(crate::commands::pool::StandbyRefill {
                image: Some("alpine".into()),
                cpus: 2,
                memory_mib: 512,
                egress: false,
            })
        );
        assert!(
            standby_refill_for(&RefillSource {
                egress: true,
                ..refill_source(Some("alpine"))
            })
            .is_some_and(|r| r.egress),
            "an egress-allowing run leaves a standby that boots the egress client"
        );
        assert_eq!(
            standby_refill_for(&refill_source(None)).map(|r| r.image),
            Some(None),
            "a bare run leaves a standby of the default image"
        );
    }

    #[test]
    fn a_source_the_refill_cannot_resolve_the_same_way_leaves_none() {
        let manifest = RefillSource {
            manifest: true,
            ..refill_source(None)
        };
        let pack = RefillSource {
            resolved_elsewhere: true,
            ..refill_source(None)
        };
        let hypervisor = RefillSource {
            hypervisor: Some("libkrun"),
            ..refill_source(Some("alpine"))
        };
        for source in [manifest, pack, hypervisor] {
            assert_eq!(standby_refill_for(&source), None);
        }
    }
}
