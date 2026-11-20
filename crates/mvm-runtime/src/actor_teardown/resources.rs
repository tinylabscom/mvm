use super::*;
use mvm_contract::protocol::actor_budget::ActorResources;
use std::collections::BTreeSet;
use std::os::unix::fs::FileTypeExt;

impl ActorOwner {
    /// Check that the signed charge covers the original owner's known resource baseline.
    ///
    /// Counts one live/resident VM, actual retained native/helper exit-observer
    /// descriptors, and distinct captured paths whose verified metadata is a socket.
    /// This is not an exhaustive open-FD/socket census or a physical-memory
    /// measurement. Configured memory, CPU, channels and other reservations remain
    /// separate admission obligations; this observation cannot replace them.
    ///
    /// # Errors
    /// Refuses undercharge, failed/quarantined or exited custody, unreadable or
    /// replaced resources, changed process identities, and count overflow.
    pub fn verify_resource_envelope(&self, charge: &ActorResources) -> Result<()> {
        ensure!(
            self.native_exit.is_none()
                && !self.terminal
                && self.startup_failure.is_none()
                && self.entrypoint != entrypoint::DispatchState::Uncertain
                && self.quarantined.is_empty()
                && self.journal.unverified_helpers.is_empty(),
            "actor resource observations require verified running custody"
        );
        ensure!(self.is_running()?, "original actor VM is not running");
        ensure!(
            self.original().identity()? == self.journal.instance,
            "original actor generation changed"
        );
        let mut baseline = ActorResources {
            live_vms: 1,
            resident_vmms: 1,
            file_descriptors: self.original().retained_process_descriptor_count()?,
            ..ActorResources::default()
        };
        for helper in &self.helpers {
            let original = EndpointPid::of_child(helper.owner.id());
            ensure!(
                helper.owner.exit_status().is_none()
                    && helper.owner.id() == helper.identity.pid
                    && original.started == Some(helper.identity.started)
                    && mvm_vmm::host::process_liveness::pid_is_alive(original.pid),
                "original actor helper identity is not live"
            );
            baseline.file_descriptors = baseline
                .file_descriptors
                .checked_add(helper.owner.retained_process_descriptor_count())
                .context("actor observer descriptor count overflow")?;
        }
        let resources = std::iter::once(&self.state)
            .chain(self.socket_directory.iter())
            .chain(self.helpers.iter().flat_map(|helper| &helper.resources));
        let mut sockets = BTreeSet::new();
        for resource in resources {
            let metadata = std::fs::symlink_metadata(&resource.path).with_context(|| {
                format!(
                    "inspect original actor resource {}",
                    resource.path.display()
                )
            })?;
            resource.verify_metadata(&metadata)?;
            if metadata.file_type().is_socket() && sockets.insert(&resource.path) {
                baseline.host_sockets = baseline
                    .host_sockets
                    .checked_add(1)
                    .context("actor socket count overflow")?;
            }
        }
        ensure!(
            baseline.fits_within(*charge),
            "signed actor charge does not cover captured resource baseline: {baseline:?}"
        );
        Ok(())
    }
}
