//! Rust-native Vz supervisor objc2 bridge (Plan 152 WS-B).
//!
//! Drives Apple's `Virtualization.framework` directly from Rust via the
//! `objc2` stack — the replacement for the Swift `crates/mvm-vz-supervisor`.
//! One guest per process; nothing depends on this as a library beyond the
//! sibling `mvm-vz-supervisor` `[[bin]]`.
//!
//! **Threading (Plan 152 WS-B decision).** Every `VZVirtualMachine` call runs
//! on a private serial dispatch queue — the model the Swift supervisor already
//! shipped (`Supervisor.swift`), ported rather than swapped for a main-thread
//! `CFRunLoop`. The non-`Send` objc2 handles live behind that queue; a small
//! [`SerialQueue::dispatch`] bridges each queue hop to an `async` await so the
//! process main thread stays free for the control socket + vsock proxy (later
//! slices). All `unsafe` is contained in this module.
//!
//! **Slice 1 scope.** Cold boot + clean lifecycle/exit propagation, plus the
//! config translation for cpu/memory/kernel/disks/virtio-fs/vsock-device/
//! console/entropy/balloon/platform. Deliberately fail-closed (not silently
//! dropped) on the not-yet-ported surfaces — `network` and `Restore` startup —
//! so a config that needs them refuses on the Rust supervisor while the Swift
//! one still backs production behind the parity gate. The vsock host-side
//! proxy, the control socket, snapshot/restore, and the gvproxy attachment +
//! payload_tap are the next WS-B slices.

use std::cell::Cell;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use anyhow::{Result, anyhow, bail};
use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2::{AnyThread, DefinedClass, define_class, msg_send};
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSObject, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleSerialPortAttachment,
    VZGenericPlatformConfiguration, VZLinuxBootLoader, VZSharedDirectory, VZSingleDirectoryShare,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioSocketConnection, VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration,
    VZVirtioTraditionalMemoryBalloonDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration, VZVirtualMachineDelegate, VZVirtualMachineState,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixListener;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use mvm_build::vz::{StartupMode, SupervisorConfig};

/// Unique per-process counter so each VM's dispatch queue gets a distinct
/// label (libdispatch keys its worker bookkeeping off the label).
static VM_COUNTER: AtomicU64 = AtomicU64::new(0);

fn mib_to_bytes(mib: u64) -> u64 {
    mib * 1024 * 1024
}

// ---------------------------------------------------------------------------
// Terminal-state channel
// ---------------------------------------------------------------------------

/// Coarse lifecycle state the supervisor blocks on. We only need to tell a
/// non-terminal transition apart from the two terminal outcomes; the full
/// `VZVirtualMachineState` is collapsed onto this.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunState {
    /// Created but `start()` not yet observed to complete.
    Pending,
    /// Running (or any other non-terminal framework state).
    Running,
    /// Guest powered itself off cleanly (`guestDidStopVirtualMachine:`).
    Stopped,
    /// Guest stopped with an error (`virtualMachine:didStopWithError:` or a
    /// framework `Error` state). Carries the localized description.
    Errored(String),
}

/// Collapse Apple's `VZVirtualMachineState` onto [`RunState`]. Any state that
/// is not `Stopped`/`Error` is non-terminal here (`Running`), so reading the
/// authoritative property right after `start()` never races the delegate's
/// terminal push into a false positive.
fn collapse_state(s: VZVirtualMachineState) -> RunState {
    match s {
        VZVirtualMachineState::Stopped => RunState::Stopped,
        VZVirtualMachineState::Error => RunState::Errored(String::new()),
        _ => RunState::Running,
    }
}

// ---------------------------------------------------------------------------
// Serial dispatch queue (GCD ↔ tokio bridge)
// ---------------------------------------------------------------------------

/// A private serial dispatch queue. `Virtualization.framework` requires every
/// `VZVirtualMachine` operation to run on the queue the VM was created with;
/// this wraps it with an `async` dispatch that bridges the GCD callback back
/// to tokio without blocking a thread. Cloneable (the inner queue is
/// reference-counted) so each vsock-proxy task can hop onto the VM's queue.
#[derive(Clone)]
struct SerialQueue {
    inner: DispatchRetained<DispatchQueue>,
}

impl SerialQueue {
    fn new(label: &str) -> Self {
        Self {
            inner: DispatchQueue::new(label, DispatchQueueAttr::SERIAL),
        }
    }

    fn clone_inner(&self) -> DispatchRetained<DispatchQueue> {
        self.inner.clone()
    }

    /// Run `f` on the serial queue and await its result. The tokio task yields
    /// while the queue executes, so no thread is parked.
    async fn dispatch<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.inner.exec_async(move || {
            let _ = tx.send(f());
        });
        rx.await
            .map_err(|_| anyhow!("dispatch queue dropped before the operation completed"))
    }
}

// ---------------------------------------------------------------------------
// VM delegate (objc2 class)
// ---------------------------------------------------------------------------

/// Ivars for [`VmDelegate`]. The delegate runs exclusively on the VM's serial
/// queue, so a `Cell` (not a lock) is enough to mutate from the `&self`
/// objc callbacks.
struct VmDelegateIvars {
    state_tx: Cell<Option<watch::Sender<RunState>>>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; VmDelegate adds no Drop.
    #[unsafe(super(NSObject))]
    #[ivars = VmDelegateIvars]
    #[name = "MvmVzSupervisorDelegate"]
    struct VmDelegate;

    unsafe impl NSObjectProtocol for VmDelegate {}

    unsafe impl VZVirtualMachineDelegate for VmDelegate {
        /// Guest initiated a clean power-off.
        #[unsafe(method(guestDidStopVirtualMachine:))]
        fn guest_did_stop(&self, _vm: &VZVirtualMachine) {
            self.push(RunState::Stopped);
        }

        /// VM stopped due to an error; surface the localized description.
        #[unsafe(method(virtualMachine:didStopWithError:))]
        fn vm_did_stop_with_error(&self, _vm: &VZVirtualMachine, error: &NSError) {
            self.push(RunState::Errored(error.localizedDescription().to_string()));
        }
    }
);

impl VmDelegate {
    fn new(tx: watch::Sender<RunState>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(VmDelegateIvars {
            state_tx: Cell::new(Some(tx)),
        });
        unsafe { msg_send![super(this), init] }
    }

    /// Send a terminal state, keeping the sender alive for the (impossible but
    /// cheap to guard) case of a second callback.
    fn push(&self, state: RunState) {
        if let Some(tx) = self.ivars().state_tx.take() {
            let _ = tx.send(state);
            self.ivars().state_tx.set(Some(tx));
        }
    }

    fn as_protocol(&self) -> &ProtocolObject<dyn VZVirtualMachineDelegate> {
        ProtocolObject::from_ref(self)
    }
}

// ---------------------------------------------------------------------------
// Completion-handler bridge
// ---------------------------------------------------------------------------

/// Build an `RcBlock` for the framework's `(NSError*) -> void` completion
/// handlers, forwarding success/failure to a oneshot. `RcBlock` needs `Fn`, so
/// the single-use sender lives behind a `Cell`.
fn completion_block(tx: oneshot::Sender<Result<()>>) -> RcBlock<dyn Fn(*mut NSError)> {
    let tx = Cell::new(Some(tx));
    RcBlock::new(move |error: *mut NSError| {
        let result = if error.is_null() {
            Ok(())
        } else {
            // SAFETY: non-null per the check; the framework keeps the NSError
            // valid for the duration of the callback.
            Err(anyhow!("{}", ns_error_to_string(unsafe { &*error })))
        };
        if let Some(tx) = tx.take() {
            let _ = tx.send(result);
        }
    })
}

fn ns_error_to_string(error: &NSError) -> String {
    format!(
        "{} ({}:{})",
        error.localizedDescription(),
        error.domain(),
        error.code()
    )
}

fn nsurl_from_path(path: &str) -> Retained<NSURL> {
    let s = NSString::from_str(path);
    NSURL::initFileURLWithPath(NSURL::alloc(), &s)
}

// ---------------------------------------------------------------------------
// vsock byte stream (guest connection fd → AsyncFd)
// ---------------------------------------------------------------------------

/// Carries a `VZVirtioSocketConnection` across the dispatch-queue → tokio hop.
/// Non-`Send` on its own; sound because we only ever touch its fd (via `dup`),
/// which is thread-safe — the retained object just keeps the fd alive.
struct SendableConnection(Retained<VZVirtioSocketConnection>);

// SAFETY: only the fd is used after the hop; fds are thread-safe.
unsafe impl Send for SendableConnection {}

/// Keeps the objc connection alive for as long as the stream's dup'd fd is in
/// use. No objc methods are called after construction.
struct ConnectionHandle {
    _connection: Retained<VZVirtioSocketConnection>,
}

// SAFETY: only retained to defer deallocation; never touched concurrently.
unsafe impl Send for ConnectionHandle {}
unsafe impl Sync for ConnectionHandle {}

/// A bidirectional async byte stream over a guest vsock connection. Wraps the
/// connection's (dup'd, non-blocking) fd in `AsyncFd`, so it composes with
/// `tokio::io::copy_bidirectional`. Ported idiom — the framework hands us a
/// POSIX fd on connect, which we own independently via `dup`.
struct VsockStream {
    fd: AsyncFd<OwnedFd>,
    _connection: Arc<ConnectionHandle>,
}

impl VsockStream {
    fn from_connection(connection: Retained<VZVirtioSocketConnection>) -> Result<Self> {
        // SAFETY: fileDescriptor() returns the framework-owned POSIX fd.
        let raw = unsafe { connection.fileDescriptor() };
        if raw < 0 {
            bail!("vsock connection has a closed file descriptor");
        }
        // dup so our lifetime is independent of the objc connection; VZ keeps
        // the original.
        // SAFETY: `raw` is a valid open fd from the framework.
        let dup = unsafe { libc::dup(raw) };
        if dup < 0 {
            bail!("dup vsock fd: {}", io::Error::last_os_error());
        }
        // SAFETY: `dup` is a valid fd we own; set non-blocking for AsyncFd.
        let flags = unsafe { libc::fcntl(dup, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            // SAFETY: closing the fd we just opened.
            unsafe { libc::close(dup) };
            bail!("set O_NONBLOCK on vsock fd: {}", io::Error::last_os_error());
        }
        // SAFETY: transfer ownership of the dup'd fd to OwnedFd.
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        Ok(Self {
            fd: AsyncFd::new(owned).map_err(|e| anyhow!("register vsock fd with tokio: {e}"))?,
            _connection: Arc::new(ConnectionHandle {
                _connection: connection,
            }),
        })
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            let fd = self.fd.as_fd().as_raw_fd();
            // SAFETY: reading a valid fd into a sized buffer.
            let n = unsafe { libc::read(fd, unfilled.as_mut_ptr().cast(), unfilled.len()) };
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let fd = self.fd.as_fd().as_raw_fd();
            // SAFETY: writing a valid buffer to a valid fd.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.fd.as_fd().as_raw_fd();
        // SAFETY: SHUT_WR on a valid fd; ENOTCONN is benign (already closed).
        if unsafe { libc::shutdown(fd, libc::SHUT_WR) } < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::NotConnected {
                return Poll::Ready(Err(err));
            }
        }
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// VM handle + supervisor
// ---------------------------------------------------------------------------

/// Holds the VM and its delegate together. Both are non-`Send`; access is only
/// ever made from inside [`SerialQueue::dispatch`], which is what makes the
/// `unsafe impl Send`/`Sync` sound.
struct VmHandle {
    vm: Retained<VZVirtualMachine>,
    _delegate: Retained<VmDelegate>,
}

// SAFETY: every field touch happens on the VM's serial dispatch queue.
unsafe impl Send for VmHandle {}
// SAFETY: shared access is funnelled through the same serial queue.
unsafe impl Sync for VmHandle {}

/// Cheaply-clonable connector to a running VM's vsock device. Each vsock-proxy
/// task holds one so it can dial the guest (`connectToPort`) on the VM's queue
/// without sharing the whole supervisor.
#[derive(Clone)]
struct VmConn {
    queue: SerialQueue,
    handle: Arc<VmHandle>,
}

impl VmConn {
    /// Dial the guest's vsock `port`, returning a byte stream. The
    /// `connectToPort` call runs on the VM's queue; the `AsyncFd` stream is
    /// built back on the tokio thread (it needs the reactor).
    async fn connect(&self, port: u32) -> Result<VsockStream> {
        let (tx, rx) = oneshot::channel::<Result<SendableConnection>>();
        let tx = Cell::new(Some(tx));
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || {
                // SAFETY: socketDevices() is a queue-bound property accessor.
                let devices = unsafe { handle.vm.socketDevices() };
                let device = devices
                    .to_vec()
                    .into_iter()
                    .next()
                    .and_then(|d| Retained::downcast::<VZVirtioSocketDevice>(d).ok());
                let Some(device) = device else {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(Err(anyhow!("VM has no virtio-socket device")));
                    }
                    return;
                };
                let block = RcBlock::new(
                    move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                        let result = if !err.is_null() {
                            // SAFETY: non-null per the check; valid in-callback.
                            Err(anyhow!("{}", ns_error_to_string(unsafe { &*err })))
                        } else if conn.is_null() {
                            Err(anyhow!("vsock connect returned a null connection"))
                        } else {
                            // SAFETY: non-null framework connection; retain it.
                            unsafe { Retained::retain(conn) }
                                .map(SendableConnection)
                                .ok_or_else(|| anyhow!("failed to retain vsock connection"))
                        };
                        if let Some(tx) = tx.take() {
                            let _ = tx.send(result);
                        }
                    },
                );
                // SAFETY: connectToPort_completionHandler must run on the queue.
                unsafe { device.connectToPort_completionHandler(port, &block) };
            })
            .await?;
        let conn = rx
            .await
            .map_err(|_| anyhow!("vsock connect completion handler was never called"))??;
        VsockStream::from_connection(conn.0)
    }
}

/// One Vz guest, driven from Rust. Created with [`VzSupervisor::boot`], which
/// builds the config, instantiates the VM on its queue, installs the delegate,
/// binds the vsock host proxy, and cold-boots it.
pub struct VzSupervisor {
    handle: Arc<VmHandle>,
    queue: SerialQueue,
    state_tx: watch::Sender<RunState>,
    state_rx: watch::Receiver<RunState>,
    /// Per-port vsock proxy accept loops; aborted on [`shutdown`](Self::shutdown).
    vsock_tasks: Vec<JoinHandle<()>>,
    /// Bound `vsock-<port>.sock` paths, unlinked on shutdown.
    vsock_paths: Vec<PathBuf>,
}

impl VzSupervisor {
    /// Build the configuration, create the VM on a fresh serial queue, install
    /// the delegate, and cold-boot. Returns once `start()` has completed (the
    /// guest is running) — call [`wait`](Self::wait) to block until it stops.
    pub async fn boot(config: &SupervisorConfig) -> Result<Self> {
        let label = format!(
            "com.mvm.vz-supervisor.{}",
            VM_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let queue = SerialQueue::new(&label);
        let (state_tx, state_rx) = watch::channel(RunState::Pending);
        let delegate_tx = state_tx.clone();

        // Captured before `config` is moved into the create closure.
        let vsock_dir = config.vsock.socket_dir.clone();
        let vsock_ports = config.vsock.ports.clone();

        let config = config.clone();
        let queue_inner = queue.clone_inner();
        let handle = queue
            .dispatch(move || -> Result<Arc<VmHandle>> {
                let vz_config = build_vz_config(&config)?;
                // SAFETY: initWithConfiguration_queue binds the VM to this
                // queue; we are executing on it.
                let vm = unsafe {
                    VZVirtualMachine::initWithConfiguration_queue(
                        VZVirtualMachine::alloc(),
                        &vz_config,
                        &queue_inner,
                    )
                };
                let delegate = VmDelegate::new(delegate_tx);
                // SAFETY: setDelegate must run on the VM's queue (we are on it).
                unsafe { vm.setDelegate(Some(delegate.as_protocol())) };
                Ok(Arc::new(VmHandle {
                    vm,
                    _delegate: delegate,
                }))
            })
            .await??;

        let mut this = Self {
            handle,
            queue,
            state_tx,
            state_rx,
            vsock_tasks: Vec::new(),
            vsock_paths: Vec::new(),
        };
        // Bind the host-side vsock proxy before start, so a client (mvmctl /
        // mvmd) can reach the guest agent the moment it boots — the Swift
        // supervisor's ordering.
        this.start_vsock_proxy(&vsock_dir, &vsock_ports)?;
        this.start().await?;
        Ok(this)
    }

    fn connector(&self) -> VmConn {
        VmConn {
            queue: self.queue.clone(),
            handle: Arc::clone(&self.handle),
        }
    }

    /// Bind one `<socket_dir>/vsock-<port>.sock` (mode 0700) UNIX listener per
    /// requested guest port and spawn an accept loop that dials the guest and
    /// splices the two. The host-dials-guest direction mvmctl's agent RPC uses.
    fn start_vsock_proxy(&mut self, socket_dir: &str, ports: &[u32]) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if ports.is_empty() {
            return Ok(());
        }
        let dir = Path::new(socket_dir);
        std::fs::create_dir_all(dir).map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| anyhow!("chmod 0700 {}: {e}", dir.display()))?;
        for &port in ports {
            let path = dir.join(format!("vsock-{port}.sock"));
            // UnixListener::bind fails on a stale socket file — best-effort unlink.
            let _ = std::fs::remove_file(&path);
            let listener =
                UnixListener::bind(&path).map_err(|e| anyhow!("bind {}: {e}", path.display()))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| anyhow!("chmod 0700 {}: {e}", path.display()))?;
            self.vsock_tasks.push(tokio::spawn(run_port_proxy(
                self.connector(),
                listener,
                port,
            )));
            self.vsock_paths.push(path);
        }
        Ok(())
    }

    /// Abort the vsock proxy accept loops and unlink their sockets. Best-effort;
    /// process exit would reap them anyway, but this keeps the state dir clean.
    pub fn shutdown(&self) {
        for task in &self.vsock_tasks {
            task.abort();
        }
        for path in &self.vsock_paths {
            let _ = std::fs::remove_file(path);
        }
    }

    async fn start(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || {
                let block = completion_block(tx);
                // SAFETY: startWithCompletionHandler must run on the VM's queue.
                unsafe { handle.vm.startWithCompletionHandler(&block) };
            })
            .await?;
        rx.await
            .map_err(|_| anyhow!("start completion handler was never called"))??;
        self.push_current_state().await;
        Ok(())
    }

    /// Re-read the framework's authoritative state and publish it. Called after
    /// `start()` so the watcher sees `Running` (or an already-terminal state if
    /// the guest exited instantly) without guessing.
    async fn push_current_state(&self) {
        let handle = Arc::clone(&self.handle);
        let tx = self.state_tx.clone();
        let _ = self
            .queue
            .dispatch(move || {
                // SAFETY: `state` is a queue-bound property; we are on the queue.
                let _ = tx.send(collapse_state(unsafe { handle.vm.state() }));
            })
            .await;
    }

    /// Request a graceful guest shutdown (ACPI power button). Returns once the
    /// request is delivered; observe [`wait`](Self::wait) for the actual stop.
    pub async fn request_stop(&self) -> Result<()> {
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || {
                // SAFETY: requestStopWithError must run on the VM's queue.
                unsafe { handle.vm.requestStopWithError() }
                    .map_err(|e| anyhow!("requestStop failed: {}", ns_error_to_string(&e)))
            })
            .await?
    }

    /// Block until the guest reaches a terminal state. Returns the process exit
    /// code: 0 on a clean guest power-off, 1 on a framework error stop.
    pub async fn wait(&self) -> Result<i32> {
        let mut rx = self.state_rx.clone();
        loop {
            match rx.borrow_and_update().clone() {
                RunState::Stopped => return Ok(0),
                RunState::Errored(msg) => {
                    if !msg.is_empty() {
                        eprintln!("mvm-vz-supervisor: guest stopped with error: {msg}");
                    }
                    return Ok(1);
                }
                RunState::Pending | RunState::Running => {}
            }
            if rx.changed().await.is_err() {
                bail!("state channel closed before the guest reached a terminal state");
            }
        }
    }
}

/// Accept loop for one proxied vsock port: each host connection dials the guest
/// and is spliced to it until either side closes. Per-connection failures are
/// logged and dropped; the loop only ends if the listener itself errors.
async fn run_port_proxy(conn: VmConn, listener: UnixListener, port: u32) {
    loop {
        let host = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                tracing::warn!(port, error = %e, "vsock accept failed; stopping port proxy");
                return;
            }
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            match conn.connect(port).await {
                Ok(mut guest) => {
                    let mut host = host;
                    if let Err(e) = tokio::io::copy_bidirectional(&mut host, &mut guest).await {
                        tracing::debug!(port, error = %e, "vsock bridge closed with error");
                    }
                }
                Err(e) => tracing::warn!(port, error = %e, "vsock connect to guest failed"),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Config translation
// ---------------------------------------------------------------------------

/// Translate a [`SupervisorConfig`] into a validated
/// `VZVirtualMachineConfiguration`. All `unsafe` objc2 calls are here.
///
/// Fail-closed on the surfaces not yet ported (see module docs): a `network`
/// device or a `Restore` startup mode is refused rather than dropped.
fn build_vz_config(config: &SupervisorConfig) -> Result<Retained<VZVirtualMachineConfiguration>> {
    if config.network.is_some() {
        bail!(
            "vz network attachment is not yet wired in the Rust supervisor (Plan 152 WS-B slice 2); \
             the Swift supervisor still backs networked guests"
        );
    }
    if let StartupMode::Restore { .. } = config.startup_mode {
        bail!(
            "vz Restore startup is not yet wired in the Rust supervisor (Plan 152 WS-B slice 2); \
             boot a fresh guest or use the Swift supervisor for snapshot restore"
        );
    }

    // SAFETY: new() returns a default-initialized configuration.
    let vz_config = unsafe { VZVirtualMachineConfiguration::new() };
    // SAFETY: plain setters with validated scalar values.
    unsafe {
        vz_config.setCPUCount(config.resources.cpu_count as usize);
        vz_config.setMemorySize(mib_to_bytes(config.resources.memory_mib));
    }

    // Direct kernel boot (VZLinuxBootLoader) — no EFI, smaller surface.
    let kernel_url = nsurl_from_path(&config.kernel.path);
    // SAFETY: initWithKernelURL builds a Linux boot loader from the kernel path.
    let boot_loader =
        unsafe { VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url) };
    let cmdline = NSString::from_str(&config.kernel.cmdline);
    // SAFETY: setCommandLine copies the command-line string.
    unsafe { boot_loader.setCommandLine(&cmdline) };
    if let Some(initrd) = &config.kernel.initrd_path {
        let initrd_url = nsurl_from_path(initrd);
        // SAFETY: setInitialRamdiskURL accepts an optional initrd URL.
        unsafe { boot_loader.setInitialRamdiskURL(Some(&initrd_url)) };
    }
    // SAFETY: setBootLoader accepts any VZBootLoader subclass.
    unsafe { vz_config.setBootLoader(Some(&boot_loader)) };

    // Linux guests require a generic platform. Slice 1 uses the default machine
    // identifier; the SAVE/Restore machine-id sidecar is a later slice.
    // SAFETY: new() returns a valid generic platform configuration.
    let platform = unsafe { VZGenericPlatformConfiguration::new() };
    // SAFETY: setPlatform accepts any VZPlatformConfiguration subclass.
    unsafe { vz_config.setPlatform(&platform) };

    // Disks → virtio-blk in declared order (rootfs /dev/vda, overlay, verity
    // sidecar, app-deps volume …). Raw image format per Plan 97.
    if !config.disks.is_empty() {
        let mut devices = Vec::with_capacity(config.disks.len());
        for disk in &config.disks {
            let url = nsurl_from_path(&disk.path);
            // SAFETY: initWithURL_readOnly_error validates the disk image path.
            let attachment = unsafe {
                VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                    VZDiskImageStorageDeviceAttachment::alloc(),
                    &url,
                    disk.read_only,
                )
            }
            .map_err(|e| anyhow!("disk {:?}: {}", disk.id, ns_error_to_string(&e)))?;
            // SAFETY: initWithAttachment wraps the attachment in a virtio-block device.
            let device = unsafe {
                VZVirtioBlockDeviceConfiguration::initWithAttachment(
                    VZVirtioBlockDeviceConfiguration::alloc(),
                    &attachment,
                )
            };
            devices.push(Retained::into_super(device));
        }
        let array = NSArray::from_retained_slice(&devices);
        // SAFETY: setStorageDevices installs the block devices.
        unsafe { vz_config.setStorageDevices(&array) };
    }

    // virtio-fs shares. Workload microVMs get none by default; the builder VM
    // mounts /work + /job read-only and /out read-write. `read_only` is
    // enforced by Vz itself — the guest can't remount rw.
    if !config.virtio_fs.is_empty() {
        let mut devices = Vec::with_capacity(config.virtio_fs.len());
        for share in &config.virtio_fs {
            let url = nsurl_from_path(&share.host_path);
            // SAFETY: initWithURL_readOnly describes a shared host directory.
            let shared = unsafe {
                VZSharedDirectory::initWithURL_readOnly(
                    VZSharedDirectory::alloc(),
                    &url,
                    share.read_only,
                )
            };
            // SAFETY: initWithDirectory wraps it in a single-directory share.
            let single = unsafe {
                VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &shared)
            };
            let tag = NSString::from_str(&share.tag);
            // SAFETY: initWithTag creates the virtio-fs device for the mount tag.
            let device = unsafe {
                VZVirtioFileSystemDeviceConfiguration::initWithTag(
                    VZVirtioFileSystemDeviceConfiguration::alloc(),
                    &tag,
                )
            };
            // SAFETY: setShare assigns the directory share.
            unsafe { device.setShare(Some(&single)) };
            devices.push(Retained::into_super(device));
        }
        let array = NSArray::from_retained_slice(&devices);
        // SAFETY: setDirectorySharingDevices installs the shares.
        unsafe { vz_config.setDirectorySharingDevices(&array) };
    }

    // virtio-vsock device. CID 3 is the Vz default for the first guest; the
    // host dials per-port unix sockets via the (later-slice) vsock proxy.
    // SAFETY: new() returns a default vsock device configuration.
    let vsock = unsafe { VZVirtioSocketDeviceConfiguration::new() };
    let vsock_array = NSArray::from_retained_slice(&[Retained::into_super(vsock)]);
    // SAFETY: setSocketDevices installs the vsock device.
    unsafe { vz_config.setSocketDevices(&vsock_array) };

    // Console: always attach a serial port so `console=hvc0` has a sink. Writes
    // go to the requested capture file (created if absent), else /dev/null.
    // Capture is write-only — no host input fd (claim 15 / sealed-prod parity).
    let console_path = match &config.console_output_path {
        Some(path) => {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .map_err(|e| anyhow!("create console log {path}: {e}"))?;
            path.as_str()
        }
        None => "/dev/null",
    };
    let console_ns = NSString::from_str(console_path);
    let console_fh = NSFileHandle::fileHandleForWritingAtPath(&console_ns)
        .ok_or_else(|| anyhow!("open console handle at {console_path}"))?;
    // SAFETY: attachment built from a writable handle, no reader.
    let attachment = unsafe {
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            None,
            Some(&console_fh),
        )
    };
    // SAFETY: new() + setAttachment build a virtio console serial port.
    let serial = unsafe { VZVirtioConsoleDeviceSerialPortConfiguration::new() };
    // SAFETY: setAttachment assigns the file-handle attachment.
    unsafe { serial.setAttachment(Some(&attachment)) };
    let serial_array = NSArray::from_retained_slice(&[Retained::into_super(serial)]);
    // SAFETY: setSerialPorts installs the console.
    unsafe { vz_config.setSerialPorts(&serial_array) };

    // Entropy — minimal Linux guests block in early getrandom(2) without it.
    // SAFETY: new() returns a default entropy device configuration.
    let entropy = unsafe { VZVirtioEntropyDeviceConfiguration::new() };
    let entropy_array = NSArray::from_retained_slice(&[Retained::into_super(entropy)]);
    // SAFETY: setEntropyDevices installs the entropy device.
    unsafe { vz_config.setEntropyDevices(&entropy_array) };

    // Memory balloon (host-driven reclaim). The floor is enforced host-side;
    // here we only wire the device when enabled.
    if let Some(balloon) = &config.balloon
        && balloon.enabled
    {
        // SAFETY: new() returns a default traditional balloon configuration.
        let device = unsafe { VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new() };
        let array = NSArray::from_retained_slice(&[Retained::into_super(device)]);
        // SAFETY: setMemoryBalloonDevices installs the balloon (Apple caps at one).
        unsafe { vz_config.setMemoryBalloonDevices(&array) };
    }

    // SAFETY: validateWithError checks the assembled configuration's invariants.
    unsafe { vz_config.validateWithError() }
        .map_err(|e| anyhow!("VZ configuration invalid: {}", ns_error_to_string(&e)))?;

    // Save/restore is a separate, weaker guarantee than validity (VZ boots
    // configs it can't snapshot). Surface it as a warning now; SAVE/RESTORE
    // land in a later slice (Plan 152 WS-E).
    if let Err(e) = unsafe { vz_config.validateSaveRestoreSupportWithError() } {
        tracing::warn!(
            error = %ns_error_to_string(&e),
            "VZ config does not support save/restore"
        );
    }

    Ok(vz_config)
}

// ---------------------------------------------------------------------------
// PID file
// ---------------------------------------------------------------------------

/// Write the supervisor PID into `vm_state_dir` (created mode 0700 if absent),
/// the convention `mvmctl` reads to find a running Vz guest. Mirrors the Swift
/// supervisor's `writePidFile`.
pub fn write_pid_file(config: &SupervisorConfig) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = Path::new(&config.vm_state_dir);
    std::fs::create_dir_all(dir).map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow!("chmod 0700 {}: {e}", dir.display()))?;
    let pid_path = config.resolved_pid_file();
    std::fs::write(&pid_path, format!("{}\n", std::process::id()))
        .map_err(|e| anyhow!("write pid file {}: {e}", pid_path.display()))
}

/// Best-effort PID-file removal on supervisor exit.
pub fn remove_pid_file(config: &SupervisorConfig) {
    let _ = std::fs::remove_file(config.resolved_pid_file());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mib_to_bytes_is_binary_megabytes() {
        assert_eq!(mib_to_bytes(1), 1024 * 1024);
        assert_eq!(mib_to_bytes(512), 512 * 1024 * 1024);
    }

    #[test]
    fn collapse_state_terminal_vs_running() {
        assert_eq!(
            collapse_state(VZVirtualMachineState::Stopped),
            RunState::Stopped
        );
        assert_eq!(
            collapse_state(VZVirtualMachineState::Error),
            RunState::Errored(String::new())
        );
        assert_eq!(
            collapse_state(VZVirtualMachineState::Running),
            RunState::Running
        );
        assert_eq!(
            collapse_state(VZVirtualMachineState::Starting),
            RunState::Running
        );
    }
}
