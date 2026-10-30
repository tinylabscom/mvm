//! Removing a persistent definition, and undoing one a launch wrote but never
//! booted.
//!
//! A persistent launch writes its definition before it boots, so a launch
//! that fails anywhere after that write — a refused secret reference, an image
//! that will not materialize, a refused admission — would leave a stopped
//! machine behind that nobody asked for and that `mvmctl machine ls` keeps
//! reporting. A definition the failed launch created is removed the way an
//! explicit `remove` removes one. A definition that was already there is left
//! alone: it belongs to whoever created it, and the failure says nothing about
//! whether they still want it.

use mvm_core::client::Result;
use mvm_core::config::machine_state_dir;

use super::{LocalBackend, remove_dir_if_present, remove_vm_runtime_dirs};

/// Whether persisting a definition wrote it from nothing or found one in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DefinitionOrigin {
    /// This call wrote the definition; nothing named it before.
    Created,
    /// A definition of this name already existed, reused or recreated.
    Existing,
}

impl LocalBackend {
    /// Delete `name`'s persistent definition and everything it owns: session
    /// resources, the per-VM runtime dir and the definition directory. The
    /// caller decides whether a running machine may be stopped first.
    pub(super) fn remove_definition(&self, name: &str) -> Result<()> {
        self.release_session_resources(name)?;
        // A stale substitution-endpoint socket left in the runtime dir blocks
        // the next launch under the same name: the endpoint dies binding it,
        // before its ready handshake.
        remove_vm_runtime_dirs(name)?;
        // The definition directory carries machine.json plus the secret-refs
        // sidecar, already cleared above; drop it whole.
        remove_dir_if_present(&machine_state_dir(name))
    }

    /// Settle `result` for a launch whose definition has `origin`: a failure
    /// removes a definition this launch created, stopping its machine first
    /// if the failure came after the boot. A failed stop preserves its state.
    /// The launch's own error is returned; an additional rollback failure is
    /// logged separately.
    pub(super) fn discard_definition_on_failure<T>(
        &self,
        name: &str,
        origin: DefinitionOrigin,
        result: Result<T>,
    ) -> Result<T> {
        if result.is_err() && origin == DefinitionOrigin::Created {
            if self.machine_running(name)
                && let Err(stop) = self.stop_for_recreate(name)
            {
                tracing::warn!(
                    error = %stop,
                    machine = name,
                    "rollback stop failed; preserving the failed launch definition and resources"
                );
                return result;
            }
            match self.remove_definition(name) {
                Ok(()) => mvm_core::audit_emit!(
                    ConfigChange,
                    vm: name,
                    "action=machine.remove mode=persistent reason=launch_failed"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    machine = name,
                    "removing the definition of a failed launch"
                ),
            }
        }
        result
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use std::path::Path;

    use mvm_core::client::{MvmClient, MvmError};
    use mvm_core::config::{machine_spec_path, vm_state_dir};
    use mvm_core::util::test_env::TestEnv;

    use super::super::{LaunchRequest, LifecycleMode, MachineSecretRef};
    use super::*;
    use crate::secret::{SecretService, SecretValueInput};

    fn isolated(home: &Path) -> TestEnv {
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home);
        // The published guest runtime, which nothing in an empty home has
        // prepared: what a released `mvmctl` and its host library launch under.
        env.remove(crate::launch::runtime_overlay::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV);
        env
    }

    fn persistent(image: &Path, name: &str) -> super::super::LaunchRequestBuilder {
        let source = image.to_string_lossy().parse().expect("image parses");
        LaunchRequest::builder(LifecycleMode::Persistent, source).name(name)
    }

    fn rootfs(home: &Path) -> std::path::PathBuf {
        let path = home.join("rootfs.ext4");
        std::fs::write(&path, b"hashable-rootfs-bytes\n").unwrap();
        path
    }

    /// An image tree that boots only once the guest runtime is injected.
    fn unpacked_tree(home: &Path) -> std::path::PathBuf {
        let tree = home.join("unpacked");
        std::fs::create_dir_all(tree.join("etc")).unwrap();
        std::fs::write(tree.join("etc/hostname"), b"image\n").unwrap();
        tree
    }

    /// A secret service whose store holds `name` with no egress binding, so
    /// admission refuses any reference to it.
    fn unbound_secret_service(home: &Path, name: &str) -> std::sync::Arc<SecretService> {
        let service = SecretService::builder()
            .store(std::sync::Arc::new(
                mvm_core::crypto::secret_store::FileSecretStore::with_dir(home.join("secrets")),
            ))
            .bindings(std::sync::Arc::new(
                mvm_hostd::keyholder::FileBindingStore::with_dir(home.join("bindings")),
            ))
            .machines_root(mvm_core::config::machine_state_root())
            .build()
            .unwrap();
        service
            .put("local", name, SecretValueInput::new("sk-x".into()))
            .unwrap();
        std::sync::Arc::new(service)
    }

    async fn inventory_names(client: &LocalBackend) -> Vec<String> {
        crate::inventory::list_local_inventory(client)
            .await
            .expect("inventory")
            .into_iter()
            .map(|record| record.name)
            .collect()
    }

    fn assert_nothing_left(name: &str, names: &[String]) {
        assert!(!names.iter().any(|n| n == name), "{name} listed: {names:?}");
        assert!(!machine_spec_path(name).exists(), "definition kept");
        assert!(!machine_state_dir(name).exists(), "definition dir kept");
        assert!(!vm_state_dir(name).exists(), "state dir kept");
    }

    /// The reported case: an image whose guest runtime is not prepared fails
    /// while it materializes, after the definition was written.
    #[tokio::test]
    async fn a_launch_whose_image_cannot_take_the_guest_runtime_leaves_no_machine() {
        let home = tempfile::tempdir().unwrap();
        let _env = isolated(home.path());
        let client = LocalBackend::with_hypervisor("mock");
        let request = persistent(&unpacked_tree(home.path()), "sdk-no-runtime")
            .build()
            .unwrap();

        let err = client.launch(request).await.unwrap_err();

        assert!(
            err.to_string().contains("guest runtime is not prepared"),
            "{err}"
        );
        assert_nothing_left("sdk-no-runtime", &inventory_names(&client).await);
    }

    #[tokio::test]
    async fn a_launch_refused_at_admission_leaves_no_machine() {
        let home = tempfile::tempdir().unwrap();
        let _env = isolated(home.path());
        let client = LocalBackend::with_hypervisor("mock")
            .with_secret_service(unbound_secret_service(home.path(), "unbound"));
        let request = persistent(&rootfs(home.path()), "sdk-refused")
            .secret_ref(MachineSecretRef {
                tenant: "local".into(),
                name: "unbound".into(),
                placeholder_var: None,
                guest_path: None,
                destinations: vec![],
            })
            .build()
            .unwrap();

        let err = client.launch(request).await.unwrap_err();

        assert!(matches!(err, MvmError::Rejected { .. }), "{err}");
        assert_nothing_left("sdk-refused", &inventory_names(&client).await);
    }

    /// `create` writes a definition without booting it, and a refusal there
    /// is the same unasked-for record.
    #[tokio::test]
    async fn a_create_refused_at_admission_leaves_no_machine() {
        let home = tempfile::tempdir().unwrap();
        let _env = isolated(home.path());
        let client = LocalBackend::with_hypervisor("mock")
            .with_secret_service(unbound_secret_service(home.path(), "unbound"));
        let request = persistent(&rootfs(home.path()), "sdk-create-refused")
            .secret_ref(MachineSecretRef {
                tenant: "local".into(),
                name: "unbound".into(),
                placeholder_var: None,
                guest_path: None,
                destinations: vec![],
            })
            .build()
            .unwrap();

        client.create_from_request(&request).unwrap_err();

        assert_nothing_left("sdk-create-refused", &inventory_names(&client).await);
    }

    /// A definition the failed launch did not write is not its to remove.
    #[tokio::test]
    async fn a_failed_launch_keeps_a_definition_that_was_already_there() {
        let home = tempfile::tempdir().unwrap();
        let _env = isolated(home.path());
        let client = LocalBackend::with_hypervisor("mock");
        let tree = unpacked_tree(home.path());
        client
            .create_from_request(&persistent(&tree, "sdk-kept").build().unwrap())
            .expect("create");

        client
            .launch(persistent(&tree, "sdk-kept").build().unwrap())
            .await
            .unwrap_err();

        assert!(machine_spec_path("sdk-kept").exists(), "definition removed");
        assert!(
            inventory_names(&client)
                .await
                .contains(&"sdk-kept".to_string())
        );
    }

    #[tokio::test]
    async fn a_successful_launch_keeps_its_machine() {
        let home = tempfile::tempdir().unwrap();
        let _env = isolated(home.path());
        let client = LocalBackend::with_hypervisor("mock");

        let outcome = client
            .launch(persistent(&rootfs(home.path()), "sdk-up").build().unwrap())
            .await
            .expect("launch");

        assert!(machine_spec_path("sdk-up").exists());
        assert!(
            inventory_names(&client)
                .await
                .contains(&"sdk-up".to_string())
        );
        client
            .stop_machine(&outcome.machine.id)
            .await
            .expect("stop");
    }
}
