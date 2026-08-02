//! The per-port Unix-socket guest channel.
//!
//! This is the concrete [`GuestChannelProvider`] for every backend whose
//! host-facing endpoint is a per-VM, per-port Unix socket: Firecracker's
//! vsock multiplexer, libkrun's per-port sockets, and the HVF supervisor's
//! listener directory. The three differ only in which directory the socket
//! lives in, which is exactly the kind of detail this abstraction exists to
//! keep out of the policy layer.
//!
//! The Unix socket is the VMM's own termination of the guest's
//! virtio-vsock connection. It is not a second transport and it is not a
//! bypass — a guest that connects to vsock port 5254 arrives here, and
//! there is nowhere else for it to arrive.
//!
//! **The path is not the identity.** Socket paths are reusable across
//! boots: the same machine restarting binds the same path. So a connection
//! accepted here is tagged with the [`VmInstanceIdentity`] the *listener*
//! was created for, which the host minted for this boot. Nothing
//! downstream re-derives identity from the endpoint.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use mvm_net::channel::{
    ChannelError, GuestChannelProvider, GuestConnection, GuestListener, GuestService, GuestStream,
    VmInstanceIdentity,
};

/// Which directory convention a backend uses for its per-port sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdsLayout {
    /// `<vm_state_dir>/vsock-<port>.sock` — libkrun and the Firecracker
    /// multiplexer's per-port sockets.
    PerVmDir,
    /// `<vm_state_dir>/vsock/vsock-<port>.sock` — the HVF supervisor's
    /// listener directory, the same shape one level deeper.
    HvfVsockDir,
}

impl UdsLayout {
    /// The socket path for one service on one machine.
    ///
    /// Routed through `mvm_core::config` rather than assembled inline, so
    /// this honours `MVM_HOME` and cannot drift from the paths the rest of
    /// the runtime resolves.
    pub fn socket_path(self, vm_id: &str, service: GuestService) -> PathBuf {
        match self {
            Self::PerVmDir => mvm_core::config::vm_vsock_port_socket(vm_id, service.port()),
            Self::HvfVsockDir => mvm_core::config::vm_hvf_vsock_port_socket(vm_id, service.port()),
        }
    }
}

/// A [`GuestChannelProvider`] over per-port Unix sockets.
#[derive(Debug, Clone)]
pub struct UdsGuestChannelProvider {
    layout: UdsLayout,
    backend_name: &'static str,
}

impl UdsGuestChannelProvider {
    /// Provider for libkrun / Firecracker's per-VM socket directory.
    pub fn per_vm_dir(backend_name: &'static str) -> Self {
        Self {
            layout: UdsLayout::PerVmDir,
            backend_name,
        }
    }

    /// Provider for the HVF supervisor's vsock listener directory.
    pub fn hvf() -> Self {
        Self {
            layout: UdsLayout::HvfVsockDir,
            backend_name: "hvf",
        }
    }

    pub fn layout(&self) -> UdsLayout {
        self.layout
    }

    /// Where `service` for `instance` lives.
    pub fn socket_path(&self, instance: &VmInstanceIdentity, service: GuestService) -> PathBuf {
        self.layout.socket_path(&instance.vm_id, service)
    }
}

impl GuestChannelProvider for UdsGuestChannelProvider {
    fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    fn offers(&self, _service: GuestService) -> bool {
        // Every service is a port on the same transport, so a backend that
        // offers one offers all of them.
        true
    }

    fn bind_service(
        &self,
        instance: &VmInstanceIdentity,
        service: GuestService,
    ) -> Result<Box<dyn GuestListener>, ChannelError> {
        let path = self.socket_path(instance, service);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ChannelError::Io {
                operation: "creating the socket directory",
                service,
                instance: instance.audit_label(),
                source,
            })?;
        }
        // A socket left by a previous boot would make `bind` fail with
        // EADDRINUSE even though nothing is listening. Removing it is safe
        // because the path is per-VM and this boot owns it.
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).map_err(|source| ChannelError::Io {
            operation: "binding",
            service,
            instance: instance.audit_label(),
            source,
        })?;
        restrict_socket_permissions(&path).map_err(|source| ChannelError::Io {
            operation: "restricting permissions on",
            service,
            instance: instance.audit_label(),
            source,
        })?;

        Ok(Box::new(UdsListener {
            listener,
            path,
            instance: instance.clone(),
            service,
        }))
    }

    fn connect_service(
        &self,
        instance: &VmInstanceIdentity,
        service: GuestService,
    ) -> Result<Box<dyn GuestStream>, ChannelError> {
        let path = self.socket_path(instance, service);
        let stream = UnixStream::connect(&path).map_err(|source| ChannelError::Io {
            operation: "connecting to",
            service,
            instance: instance.audit_label(),
            source,
        })?;
        Ok(Box::new(stream))
    }

    fn revoke_instance(&self, instance: &VmInstanceIdentity) -> Result<(), ChannelError> {
        // Remove every service socket this instance could have. Best-effort
        // per path: revocation runs on stop, on crash recovery, and on
        // failed startup, so most of these will already be gone.
        for service in [
            GuestService::MachineControl,
            GuestService::NetworkControl,
            GuestService::NetworkData { queue: 0 },
            GuestService::WorkloadExit,
            GuestService::Broker,
            GuestService::Substitution,
        ] {
            let _ = std::fs::remove_file(self.socket_path(instance, service));
        }
        Ok(())
    }
}

/// One bound service socket.
struct UdsListener {
    listener: UnixListener,
    path: PathBuf,
    instance: VmInstanceIdentity,
    service: GuestService,
}

impl GuestListener for UdsListener {
    fn accept(&mut self) -> Result<GuestConnection<Box<dyn GuestStream>>, ChannelError> {
        let (stream, _addr) = self.listener.accept().map_err(|source| ChannelError::Io {
            operation: "accepting on",
            service: self.service,
            instance: self.instance.audit_label(),
            source,
        })?;
        // The identity comes from the listener, not from the connection:
        // the peer address of a Unix socket is unnamed, and the path is
        // reusable, so neither could tell us which boot this is.
        Ok(GuestConnection::new(
            self.instance.clone(),
            self.service,
            Box::new(stream) as Box<dyn GuestStream>,
        ))
    }

    fn close(&mut self) -> Result<(), ChannelError> {
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }

    fn instance(&self) -> &VmInstanceIdentity {
        &self.instance
    }

    fn service(&self) -> GuestService {
        self.service
    }
}

impl Drop for UdsListener {
    /// The socket file must not outlive the listener: a stale path makes
    /// the next boot's `bind` fail, and a path that exists with nothing
    /// behind it is indistinguishable from a live service to anything
    /// probing the directory.
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Owner-only (0700) on the socket, matching the existing per-VM vsock
/// proxy socket posture.
#[cfg(unix)]
fn restrict_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn instance() -> VmInstanceIdentity {
        VmInstanceIdentity::new("node-1", "vm-uds-test", "boot-1", "sha256:plan")
    }

    /// Point `MVM_HOME` at a scenario-local directory so the socket paths
    /// are the real ones, resolved the real way, without touching a
    /// developer's home.
    struct HomeGuard {
        _dir: tempfile::TempDir,
        previous: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("temp home");
            let previous = std::env::var_os("MVM_HOME");
            // SAFETY: these tests run serially within this module and
            // restore the previous value on drop.
            unsafe { std::env::set_var("MVM_HOME", dir.path()) };
            Self {
                _dir: dir,
                previous,
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            // SAFETY: as above.
            unsafe {
                match &self.previous {
                    Some(prev) => std::env::set_var("MVM_HOME", prev),
                    None => std::env::remove_var("MVM_HOME"),
                }
            }
        }
    }

    #[test]
    fn each_service_gets_its_own_socket_path() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();
        let control = provider.socket_path(&instance, GuestService::NetworkControl);
        let data = provider.socket_path(&instance, GuestService::NetworkData { queue: 0 });
        let machine = provider.socket_path(&instance, GuestService::MachineControl);
        assert_ne!(control, data, "control and data must not share a socket");
        assert_ne!(
            data, machine,
            "packets must not share the control RPC socket"
        );
    }

    #[test]
    fn the_hvf_layout_lives_one_directory_deeper() {
        let _home = HomeGuard::new();
        let per_vm = UdsGuestChannelProvider::per_vm_dir("libkrun")
            .socket_path(&instance(), GuestService::NetworkControl);
        let hvf =
            UdsGuestChannelProvider::hvf().socket_path(&instance(), GuestService::NetworkControl);
        assert_ne!(per_vm, hvf);
        assert!(hvf.to_string_lossy().contains("vsock"), "{hvf:?}");
    }

    #[test]
    fn a_bound_service_accepts_a_connection_tagged_with_the_listeners_identity() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();
        let mut listener = provider
            .bind_service(&instance, GuestService::NetworkControl)
            .expect("bind");

        let path = provider.socket_path(&instance, GuestService::NetworkControl);
        let writer = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&path).expect("connect");
            stream.write_all(b"hello").expect("write");
        });

        let mut conn = listener.accept().expect("accept");
        let mut buf = [0u8; 5];
        conn.stream.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"hello");

        // The identity is the listener's, not anything read off the wire.
        assert_eq!(conn.instance, instance);
        assert_eq!(conn.service, GuestService::NetworkControl);
        writer.join().unwrap();
    }

    #[test]
    fn binding_over_a_stale_socket_from_a_previous_boot_succeeds() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();

        let first = provider
            .bind_service(&instance, GuestService::NetworkControl)
            .expect("first bind");
        // Leak the socket file exactly as an unclean shutdown would.
        std::mem::forget(first);
        assert!(
            provider
                .socket_path(&instance, GuestService::NetworkControl)
                .exists()
        );

        // A later boot must not be blocked by its predecessor's leftovers.
        let _second = provider
            .bind_service(&instance, GuestService::NetworkControl)
            .expect("a stale socket must not block the next boot");
    }

    #[test]
    fn closing_a_listener_removes_its_socket() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();
        let path = provider.socket_path(&instance, GuestService::NetworkControl);
        {
            let _listener = provider
                .bind_service(&instance, GuestService::NetworkControl)
                .expect("bind");
            assert!(path.exists());
        }
        assert!(
            !path.exists(),
            "a dropped listener must not leave its socket behind"
        );
    }

    #[test]
    fn revoking_an_instance_removes_every_service_socket() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();
        let control = provider
            .bind_service(&instance, GuestService::NetworkControl)
            .expect("bind control");
        let data = provider
            .bind_service(&instance, GuestService::NetworkData { queue: 0 })
            .expect("bind data");
        let control_path = provider.socket_path(&instance, GuestService::NetworkControl);
        let data_path = provider.socket_path(&instance, GuestService::NetworkData { queue: 0 });
        // Leak both so revocation is what removes them, not Drop.
        std::mem::forget(control);
        std::mem::forget(data);
        assert!(control_path.exists() && data_path.exists());

        provider.revoke_instance(&instance).expect("revoke");
        assert!(
            !control_path.exists(),
            "revocation must remove the control socket"
        );
        assert!(
            !data_path.exists(),
            "revocation must remove the data socket"
        );
    }

    #[test]
    fn revoking_twice_is_not_an_error() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();
        provider.revoke_instance(&instance).expect("first revoke");
        provider.revoke_instance(&instance).expect("second revoke");
    }

    #[test]
    fn connecting_to_an_unbound_service_fails_rather_than_hanging() {
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        match provider.connect_service(&instance(), GuestService::NetworkData { queue: 0 }) {
            Err(ChannelError::Io { .. }) => {}
            Err(other) => panic!("expected an I/O refusal, got {other}"),
            Ok(_) => panic!("connecting to an unbound service must not succeed"),
        }
    }

    #[test]
    fn the_socket_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let _home = HomeGuard::new();
        let provider = UdsGuestChannelProvider::per_vm_dir("libkrun");
        let instance = instance();
        let _listener = provider
            .bind_service(&instance, GuestService::NetworkControl)
            .expect("bind");
        let path = provider.socket_path(&instance, GuestService::NetworkControl);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the guest channel socket must be owner-only");
    }
}
